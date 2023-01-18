use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router, Server,
};
use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream, StreamExt},
};
use tokio::sync::mpsc::{channel, Receiver};
use tokio::time::timeout;

use crate::relying_party::protocol::communication::{
    AuthenticatorAgent, AuthenticatorAgentChannel, ClientAgent, FailCeremony, RelyingPartyAgent,
};
use crate::relying_party::protocol::websockets::session::{Session, SessionChannel, SessionInfo};
use crate::relying_party::{Ceremony, RelyingPartyOperation};
use crate::security::session_token::SessionToken;
use crate::security::uuid::SessionId;

mod session;

pub struct Websockets {
    socket_address: SocketAddr,
    relying_party: RelyingPartyOperation,
}

impl Websockets {
    pub async fn init(relying_party: RelyingPartyOperation) -> Websockets {
        let socket_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        Websockets {
            socket_address,
            relying_party,
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut session = Session::init().await;

        tokio::spawn(async move {
            session.1.run().await;
        });

        Server::bind(&self.socket_address)
            .serve(self.router(session.0).await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self, session_channel: SessionChannel) -> Router {
        let register_session_channel = session_channel.to_owned();
        let authenticate_session_channel = session_channel.to_owned();
        let registration_ceremony_session_channel = session_channel.to_owned();
        let authentication_ceremony_session_channel = session_channel;
        // let register_relying_party = self.relying_party.to_owned();
        // let authenticate_relying_party = self.relying_party.to_owned();
        let registration_ceremony_relying_party = self.relying_party.to_owned();
        let authentication_ceremony_relying_party = self.relying_party.to_owned();

        Router::new()
            .route(
                "/register",
                get(move |connection| establish(connection, register_session_channel)),
            )
            .route(
                "/authenticate",
                get(move |connection| establish(connection, authenticate_session_channel)),
            )
            .route(
                "/registration_ceremony/:session",
                get({
                    move |session, connection| {
                        registration_ceremony_session(
                            session,
                            connection,
                            registration_ceremony_session_channel,
                            registration_ceremony_relying_party,
                        )
                    }
                }),
            )
            .route(
                "/authentication_ceremony/:session",
                get({
                    move |session, connection| {
                        authentication_ceremony_session(
                            session,
                            connection,
                            authentication_ceremony_session_channel,
                            authentication_ceremony_relying_party,
                        )
                    }
                }),
            )
    }
}

async fn establish(connection: WebSocketUpgrade, available_session: SessionChannel) -> Response {
    connection.on_upgrade(|socket| initialize(socket, available_session))
}

async fn initialize(socket: WebSocket, available_session: SessionChannel) {
    let (mut socket_outgoing, mut socket_incoming) = socket.split();
    let (message, mut receive_outgoing_message) = channel::<Message>(1);
    let terminate_session = message.to_owned();

    tokio::spawn(async move {
        if let Some(_message) = socket_incoming.next().await {
            let _ = terminate_session.send(Message::Close(None)).await;
        }
    });

    tokio::spawn(async move {
        while let Some(message) = receive_outgoing_message.recv().await {
            match message {
                Message::Text(json) => {
                    let _ = socket_outgoing.send(Message::Text(json)).await;
                }
                Message::Binary(_) => {
                    let _ = socket_outgoing.close().await;
                }
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(_) => {
                    let _ = socket_outgoing.close().await;
                }
            }
        }
    });

    match available_session.allocate().await {
        Ok(session_info) => match serde_json::to_string(&session_info) {
            Ok(json) => {
                let _ = message.send(Message::Text(json)).await;
                let _ = message.send(Message::Close(None)).await;
            }
            Err(error) => {
                println!("serde -> {:?}", error);

                let _ = message.send(Message::Close(None)).await;
            }
        },
        Err(_) => {
            let _ = message.send(Message::Close(None)).await;
        }
    }
}

async fn registration_ceremony_session(
    Path(session): Path<String>,
    connection: WebSocketUpgrade,
    available_session: SessionChannel,
    relying_party: RelyingPartyOperation,
) -> Response {
    let mut session_id: SessionId = [0; 32];

    if session.len() == 32 {
        session_id.copy_from_slice(session.as_bytes());
    } else {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match available_session.consume(session_id).await {
        Ok(session_info) => match session_id == session_info.id {
            true => connection.on_upgrade(move |socket| {
                handle_registration_ceremony_session(socket, session_info, relying_party)
            }),
            false => StatusCode::BAD_REQUEST.into_response(),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_registration_ceremony_session(
    socket: WebSocket,
    session_info: SessionInfo,
    relying_party: RelyingPartyOperation,
) {
    let (mut socket_outgoing, mut socket_incoming) = socket.split();

    match token_verification(
        &mut socket_outgoing,
        &mut socket_incoming,
        session_info.token,
    )
    .await
    {
        true => {
            let (outgoing_message, mut outgoing_messages) = channel::<Message>(1);
            let fail_ceremony = FailCeremony::init();
            let socket_incoming_fail_ceremony = fail_ceremony.to_owned();
            let socket_outgoing_fail_ceremony = fail_ceremony.to_owned();
            let mut relying_party_agent =
                RelyingPartyAgent::init(outgoing_message.to_owned(), fail_ceremony.to_owned())
                    .await;
            let client_agent = ClientAgent::init(relying_party_agent.0.to_owned()).await;
            let mut authenticator_agent =
                AuthenticatorAgent::init(client_agent.0, fail_ceremony.to_owned()).await;

            tokio::spawn(async move {
                handle_socket_incoming(
                    &mut socket_incoming,
                    authenticator_agent.0,
                    socket_incoming_fail_ceremony,
                )
                .await;
            });

            tokio::spawn(async move {
                handle_socket_outgoing(
                    &mut outgoing_messages,
                    &mut socket_outgoing,
                    socket_outgoing_fail_ceremony,
                )
                .await;
            });

            let ceremony = Ceremony::Registration(client_agent.1, fail_ceremony.to_owned());

            if let Err(error) = relying_party.initiate(ceremony).await {
                println!("relying party operation -> {:?}", error);

                fail_ceremony.error();
            }

            tokio::spawn(async move {
                authenticator_agent.1.run().await;
            });

            relying_party_agent.1.run().await;
        }
        false => {
            println!("connection closed");
        }
    }
}

async fn authentication_ceremony_session(
    Path(session): Path<String>,
    connection: WebSocketUpgrade,
    available_session: SessionChannel,
    relying_party: RelyingPartyOperation,
) -> Response {
    let mut session_id: SessionId = [0; 32];

    if session.len() == 32 {
        session_id.copy_from_slice(session.as_bytes());
    } else {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match available_session.consume(session_id).await {
        Ok(session_info) => match session_id == session_info.id {
            true => connection.on_upgrade(move |socket| {
                handle_authentication_ceremony_session(socket, session_info, relying_party)
            }),
            false => StatusCode::BAD_REQUEST.into_response(),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_authentication_ceremony_session(
    socket: WebSocket,
    session_info: SessionInfo,
    relying_party: RelyingPartyOperation,
) {
    let (mut socket_outgoing, mut socket_incoming) = socket.split();

    match token_verification(
        &mut socket_outgoing,
        &mut socket_incoming,
        session_info.token,
    )
    .await
    {
        true => {
            let (outgoing_message, mut outgoing_messages) = channel::<Message>(1);
            let fail_ceremony = FailCeremony::init();
            let socket_incoming_fail_ceremony = fail_ceremony.to_owned();
            let socket_outgoing_fail_ceremony = fail_ceremony.to_owned();
            let mut relying_party_agent =
                RelyingPartyAgent::init(outgoing_message.to_owned(), fail_ceremony.to_owned())
                    .await;
            let client_agent = ClientAgent::init(relying_party_agent.0.to_owned()).await;
            let mut authenticator_agent =
                AuthenticatorAgent::init(client_agent.0, fail_ceremony.to_owned()).await;

            tokio::spawn(async move {
                handle_socket_incoming(
                    &mut socket_incoming,
                    authenticator_agent.0,
                    socket_incoming_fail_ceremony,
                )
                .await;
            });

            tokio::spawn(async move {
                handle_socket_outgoing(
                    &mut outgoing_messages,
                    &mut socket_outgoing,
                    socket_outgoing_fail_ceremony,
                )
                .await;
            });

            let ceremony = Ceremony::Authentication(client_agent.1, fail_ceremony.to_owned());

            if let Err(error) = relying_party.initiate(ceremony).await {
                println!("relying party operation -> {:?}", error);

                fail_ceremony.error();
            }

            tokio::spawn(async move {
                authenticator_agent.1.run().await;
            });

            relying_party_agent.1.run().await;
        }
        false => {
            println!("authentication ceremony failed...");
        }
    }
}

async fn token_verification(
    socket_outgoing: &mut SplitSink<WebSocket, Message>,
    socket_incoming: &mut SplitStream<WebSocket>,
    token: SessionToken,
) -> bool {
    match timeout(Duration::from_millis(300000), socket_incoming.next()).await {
        Ok(incoming_message) => {
            if let Some(Ok(Message::Binary(data))) = incoming_message {
                match data == token {
                    true => {
                        let data = b"ok".to_vec();

                        let _ = socket_outgoing.send(Message::Binary(data)).await;

                        true
                    }
                    false => {
                        let _ = socket_outgoing.close().await;

                        false
                    }
                }
            } else {
                let _ = socket_outgoing.close().await;

                false
            }
        }
        Err(error) => {
            println!("token verification timeout! -> {:?}", error);

            let _ = socket_outgoing.close().await;

            false
        }
    }
}

async fn handle_socket_incoming(
    socket_incoming: &mut SplitStream<WebSocket>,
    authenticator_agent: AuthenticatorAgentChannel,
    fail_ceremony: FailCeremony,
) {
    let mut error = fail_ceremony.subscribe();

    loop {
        tokio::select! {
            biased;

            _ = error.recv() => {
                println!("shutting down task socket incoming task...");

                break;
            }

            Some(Ok(message)) = socket_incoming.next() => {
                match message {
                    Message::Text(_) => {
                        fail_ceremony.error();
                    }
                    Message::Binary(data) => {
                        authenticator_agent.translate(data).await;
                    }
                    Message::Ping(_) => {}
                    Message::Pong(_) => {}
                    Message::Close(_) => {
                        fail_ceremony.error();
                    }
                }
            }
        }
    }
}

async fn handle_socket_outgoing(
    outgoing_messages: &mut Receiver<Message>,
    socket_outgoing: &mut SplitSink<WebSocket, Message>,
    fail_ceremony: FailCeremony,
) {
    let mut error = fail_ceremony.subscribe();

    loop {
        tokio::select! {
            biased;

            _ = error.recv() => {
                println!("shutting down socket outgoing task...");

                let _ = socket_outgoing
                    .send(Message::Close(None))
                    .await;
                let _ = socket_outgoing.close().await;

                outgoing_messages.close();

                break;
            }

            Some(message) = outgoing_messages.recv() => {
                match message {
                    Message::Text(_) => {
                        fail_ceremony.error();
                    }
                    Message::Binary(data) => {
                        let _ = socket_outgoing.send(Message::Binary(data)).await;
                    }
                    Message::Ping(_) => {}
                    Message::Pong(_) => {}
                    Message::Close(Some(close_frame)) => {
                        let _ = socket_outgoing
                            .send(Message::Close(Some(close_frame)))
                            .await;
                        let _ = socket_outgoing.close().await;

                        outgoing_messages.close();

                        break;
                    }
                    Message::Close(None) => {
                        fail_ceremony.error();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authenticator_responses::{
        AuthenticatorAttestationResponse, AuthenticatorResponse,
    };
    use crate::api::public_key_credential::PublicKeyCredential;
    use crate::relying_party::protocol::communication::WebAuthnData;
    use crate::relying_party::RelyingParty;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite;

    #[tokio::test]
    async fn registration_ceremony_session() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_relying_party = RelyingParty::init().await;

        tokio::spawn(async move {
            test_relying_party.1.run().await;
        });

        let mut test_websockets = Websockets::init(test_relying_party.0).await;

        tokio::spawn(async move {
            test_websockets.run().await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let test_websockets_connection =
            connect_async("ws://127.0.0.1:8080/registration_ceremony/test").await;

        assert!(test_websockets_connection.is_err());

        if let tungstenite::Error::Http(response) = test_websockets_connection.unwrap_err() {
            println!("response status -> {:?}", &response.status());
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let mut test_client_connection = connect_async("ws://127.0.0.1:8080/register").await?;
        let test_session_info: SessionInfo =
            if let Some(Ok(tungstenite::Message::Text(test_message))) =
                test_client_connection.0.next().await
            {
                serde_json::from_str(&test_message)?
            } else {
                panic!("a message should have been receieved!");
            };

        let test_session_id = String::from_utf8(test_session_info.id.to_vec())?;
        let test_sesion_uri = format!(
            "ws://127.0.0.1:8080/registration_ceremony/{}",
            test_session_id,
        );

        let mut test_client_connection = connect_async(&test_sesion_uri).await?;

        test_client_connection
            .0
            .send(tungstenite::Message::Binary(
                test_session_info.token.to_vec(),
            ))
            .await?;

        if let Some(Ok(test_message)) = test_client_connection.0.next().await {
            assert_eq!(test_message, tungstenite::Message::Binary(b"ok".to_vec()));
        } else {
            panic!("a message should have been receieved!");
        }

        assert!(test_client_connection.0.close(None).await.is_ok());

        let mut test_client_connection = connect_async("ws://127.0.0.1:8080/register").await?;
        let test_session_info: SessionInfo =
            if let Some(Ok(tungstenite::Message::Text(test_message))) =
                test_client_connection.0.next().await
            {
                serde_json::from_str(&test_message)?
            } else {
                panic!("a message should have been receieved!");
            };

        let test_session_id = String::from_utf8(test_session_info.id.to_vec())?;
        let test_sesion_uri = format!(
            "ws://127.0.0.1:8080/registration_ceremony/{}",
            test_session_id,
        );

        let mut test_client_connection = connect_async(&test_sesion_uri).await?;

        test_client_connection
            .0
            .send(tungstenite::Message::Binary([0u8; 16].to_vec()))
            .await?;

        if let Some(Ok(test_message)) = test_client_connection.0.next().await {
            assert_eq!(test_message, tungstenite::Message::Close(None));
        } else {
            panic!("a message should have been receieved!");
        }

        let test_client_connection = connect_async(&test_sesion_uri).await;

        assert!(test_client_connection.is_err());

        if let tungstenite::Error::Http(response) = test_client_connection.unwrap_err() {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        Ok(())
    }

    #[tokio::test]
    async fn authentication_ceremony_session() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_relying_party = RelyingParty::init().await;

        tokio::spawn(async move {
            test_relying_party.1.run().await;
        });

        let mut test_websockets = Websockets::init(test_relying_party.0).await;

        tokio::spawn(async move {
            test_websockets.run().await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let test_ws_connection =
            connect_async("ws://127.0.0.1:8080/authentication_ceremony/test").await;

        assert!(test_ws_connection.is_err());

        if let tungstenite::Error::Http(response) = test_ws_connection.unwrap_err() {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let mut test_ws_connection = connect_async("ws://127.0.0.1:8080/authenticate").await?;
        let test_session_info: SessionInfo =
            if let Some(Ok(tungstenite::Message::Text(test_message))) =
                test_ws_connection.0.next().await
            {
                serde_json::from_str(&test_message)?
            } else {
                panic!("a message should have been receieved!");
            };

        let test_session_id = String::from_utf8(test_session_info.id.to_vec())?;
        let test_sesion_uri = format!(
            "ws://127.0.0.1:8080/authentication_ceremony/{}",
            test_session_id,
        );

        let mut test_ws_connection = connect_async(&test_sesion_uri).await?;

        test_ws_connection
            .0
            .send(tungstenite::Message::Binary(
                test_session_info.token.to_vec(),
            ))
            .await?;

        if let Some(Ok(test_message)) = test_ws_connection.0.next().await {
            assert_eq!(test_message, tungstenite::Message::Binary(b"ok".to_vec()));
        } else {
            panic!("a message should have been receieved!");
        }

        assert!(test_ws_connection.0.close(None).await.is_ok());

        let mut test_client_connection = connect_async("ws://127.0.0.1:8080/register").await?;
        let test_session_info: SessionInfo =
            if let Some(Ok(tungstenite::Message::Text(test_message))) =
                test_client_connection.0.next().await
            {
                serde_json::from_str(&test_message)?
            } else {
                panic!("a message should have been receieved!");
            };

        let test_session_id = String::from_utf8(test_session_info.id.to_vec())?;
        let test_sesion_uri = format!(
            "ws://127.0.0.1:8080/authentication_ceremony/{}",
            test_session_id,
        );

        let mut test_client_connection = connect_async(&test_sesion_uri).await?;

        test_client_connection
            .0
            .send(tungstenite::Message::Binary([0u8; 16].to_vec()))
            .await?;

        if let Some(Ok(test_message)) = test_client_connection.0.next().await {
            assert_eq!(test_message, tungstenite::Message::Close(None));
        } else {
            panic!("a message should have been receieved!");
        }

        let test_ws_connection = connect_async(&test_sesion_uri).await;

        assert!(test_ws_connection.is_err());

        if let tungstenite::Error::Http(response) = test_ws_connection.unwrap_err() {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        Ok(())
    }

    #[tokio::test]
    async fn token_verification() -> Result<(), Box<dyn std::error::Error>> {
        async fn test_router() -> Router {
            Router::new().route("/test", get(test_handler))
        }

        async fn test_handler(ws: WebSocketUpgrade) -> Response {
            ws.on_upgrade(test_handle_socket)
        }

        async fn test_handle_socket(test_socket: WebSocket) {
            let (mut test_socket_outgoing, mut test_socket_incoming) = test_socket.split();
            let test_token = [0u8; 16];

            super::token_verification(
                &mut test_socket_outgoing,
                &mut test_socket_incoming,
                test_token,
            )
            .await;
        }

        tokio::spawn(async move {
            Server::bind(&"127.0.0.1:8080".parse().unwrap())
                .serve(test_router().await.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let mut test_client_socket = connect_async("ws://127.0.0.1:8080/test").await?;
        let test_valid_token = String::from_utf8([0u8; 16].to_vec())?;

        test_client_socket
            .0
            .send(tungstenite::Message::Text(test_valid_token))
            .await?;

        if let Some(Ok(test_message)) = test_client_socket.0.next().await {
            assert_eq!(test_message, tungstenite::Message::Close(None));
        } else {
            panic!("a message should have been receieved!");
        }

        let mut test_client_socket = connect_async("ws://127.0.0.1:8080/test").await?;
        let test_valid_token: SessionToken = [0; 16];

        test_client_socket
            .0
            .send(tungstenite::Message::Binary(test_valid_token.to_vec()))
            .await?;

        if let Some(Ok(test_message)) = test_client_socket.0.next().await {
            assert_eq!(test_message, tungstenite::Message::Binary(b"ok".to_vec()));
        } else {
            panic!("a message should have been receieved!");
        }

        test_client_socket
            .0
            .send(tungstenite::Message::Close(None))
            .await?;

        let mut test_client_socket = connect_async("ws://127.0.0.1:8080/test").await?;
        let test_invalid_token: SessionToken = [1; 16];

        test_client_socket
            .0
            .send(tungstenite::Message::Binary(test_invalid_token.to_vec()))
            .await?;

        if let Some(Ok(test_message)) = test_client_socket.0.next().await {
            assert_eq!(test_message, tungstenite::Message::Close(None));
        } else {
            panic!("a message should have been receieved!");
        }

        Ok(())
    }

    #[tokio::test]
    async fn handle_socket_incoming_outgoing() -> Result<(), Box<dyn std::error::Error>> {
        async fn test_router() -> Router {
            Router::new().route("/test", get(test_handler))
        }

        async fn test_handler(ws: WebSocketUpgrade) -> Response {
            ws.on_upgrade(test_handle_socket)
        }

        async fn test_handle_socket(test_socket: WebSocket) {
            let (mut test_socket_outgoing, mut test_socket_incoming) = test_socket.split();
            // let (test_outgoing_message, mut test_outgoing_messages) = channel::<Message>(1);
            // let test_fail_ceremony = FailCeremony::init();
            // let test_socket_incoming_fail_ceremony = test_fail_ceremony.to_owned();
            // let test_socket_outgoing_fail_ceremony = test_fail_ceremony.to_owned();

            let (test_outgoing_message, mut test_outgoing_messages) = channel::<Message>(1);
            let test_fail_ceremony = FailCeremony::init();
            let test_socket_incoming_fail_ceremony = test_fail_ceremony.to_owned();
            let test_socket_outgoing_fail_ceremony = test_fail_ceremony.to_owned();
            let mut test_relying_party_agent = RelyingPartyAgent::init(
                test_outgoing_message.to_owned(),
                test_fail_ceremony.to_owned(),
            )
            .await;
            let test_client_agent = ClientAgent::init(test_relying_party_agent.0.to_owned()).await;
            let mut test_authenticator_agent = AuthenticatorAgent::init(
                test_client_agent.0.to_owned(),
                test_fail_ceremony.to_owned(),
            )
            .await;

            // tokio::spawn(async move {
            //     test_client_agent.0.subscribe();
            // });

            tokio::spawn(async move {
                test_authenticator_agent.1.run().await;
            });

            tokio::spawn(async move {
                test_relying_party_agent.1.run().await;
            });

            tokio::spawn(async move {
                handle_socket_incoming(
                    &mut test_socket_incoming,
                    // test_outgoing_message,
                    test_authenticator_agent.0,
                    test_socket_incoming_fail_ceremony,
                )
                .await;
            });

            tokio::spawn(async move {
                handle_socket_outgoing(
                    &mut test_outgoing_messages,
                    &mut test_socket_outgoing,
                    test_socket_outgoing_fail_ceremony,
                )
                .await;
            });
        }

        tokio::spawn(async move {
            Server::bind(&"127.0.0.1:8080".parse().unwrap())
                .serve(test_router().await.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let mut test_client_socket = connect_async("ws://127.0.0.1:8080/test").await?;

        test_client_socket
            .0
            .send(tungstenite::Message::Text(String::from("test")))
            .await?;

        if let Some(Ok(test_message)) = test_client_socket.0.next().await {
            // let test_close_frame = tungstenite::protocol::frame::CloseFrame {
            //     code: tungstenite::protocol::frame::coding::CloseCode::Unsupported,
            //     reason: Cow::from("WebSocket.binaryType = 'blob'"),
            // };

            // assert_eq!(
            //     test_message,
            //     tungstenite::Message::Close(Some(test_close_frame)),
            // );
            assert_eq!(test_message, tungstenite::Message::Close(None));
        } else {
            panic!("a message should have been receieved!");
        }

        let mut test_client_socket = connect_async("ws://127.0.0.1:8080/test").await?;

        // let test_webauthndata = r#"{"message":"public_key_credential","contents":[0],"timestamp": "2018-01-26T18:30:09.453Z"}"#.as_bytes();
        let test_id = [0u8; 16].to_vec();
        let test_client_data_json = Vec::with_capacity(0);
        let test_attestation_object = Vec::with_capacity(0);
        let test_response = AuthenticatorResponse::AuthenticatorAttestationResponse(
            AuthenticatorAttestationResponse {
                client_data_json: test_client_data_json,
                attestation_object: test_attestation_object,
            },
        );
        let test_credential = PublicKeyCredential::generate(test_id, test_response).await;
        let test_message = String::from("public_key_credential");
        let test_contents = serde_json::to_vec(&test_credential).expect("json");
        let test_webauthndata = WebAuthnData::generate(test_message, test_contents).await?;

        test_client_socket
            .0
            .send(tungstenite::Message::Binary(test_webauthndata))
            .await?;

        println!("we've sent the data!");

        // if let Some(Ok(test_message)) = test_client_socket.0.next().await {
        //     println!("some test message -> {:?}", &test_message);

        //     assert_eq!(
        //         test_message,
        //         tungstenite::Message::Binary(b"test_data".to_vec()),
        //     );
        //     // assert_eq!(test_message, tungstenite::Message::Close(None));
        // } else {
        //     panic!("a message should have been receieved!");
        // }

        println!("now lets send the close...");

        test_client_socket
            .0
            .send(tungstenite::Message::Close(None))
            .await?;

        if let Some(Ok(test_message)) = test_client_socket.0.next().await {
            assert_eq!(test_message, tungstenite::Message::Close(None));
        } else {
            panic!("a message should have been receieved!");
        }

        Ok(())
    }
}
