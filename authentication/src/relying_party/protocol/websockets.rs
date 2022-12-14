use axum::{
    extract::ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade},
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Error, Router, Server,
};
use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream, StreamExt},
};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::timeout;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::relying_party::protocol::websockets::session::{Session, SessionChannel, SessionInfo};
use crate::security::session_token::SessionToken;
use crate::security::uuid::SessionId;

mod session;

pub struct Websockets {
    socket_address: SocketAddr,
}

impl Websockets {
    pub async fn init() -> Websockets {
        let socket_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        Websockets { socket_address }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut session = Session::init().await;

        tokio::spawn(async move {
            if let Err(error) = session.1.run().await {
                println!("session -> {:?}", error);
            }
        });

        Server::bind(&self.socket_address)
            .serve(self.router(session.0).await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self, session: SessionChannel) -> Router {
        Router::new()
            .route("/register", get(establish))
            .route("/authenticate", get(establish))
            .route(
                "/registration_ceremony/:session",
                get(registration_ceremony_session),
            )
            .route(
                "/authentication_ceremony/:session",
                get(authentication_ceremony_session),
            )
            .with_state(session)
    }
}

async fn establish(
    connection: WebSocketUpgrade,
    State(session): State<SessionChannel>,
) -> Response {
    connection.on_upgrade(|socket| initialize(socket, session))
}

async fn registration_ceremony_session(
    Path(session): Path<String>,
    State(available_session): State<SessionChannel>,
    connection: WebSocketUpgrade,
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
                handle_registration_ceremony_session(socket, session_info.token)
            }),
            false => StatusCode::BAD_REQUEST.into_response(),
        },
        Err(error) => error.into_response(),
    }
}
async fn authentication_ceremony_session(
    Path(session): Path<String>,
    State(available_session): State<SessionChannel>,
    connection: WebSocketUpgrade,
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
                handle_authentication_ceremony_session(socket, session_info.token)
            }),
            false => StatusCode::BAD_REQUEST.into_response(),
        },
        Err(error) => error.into_response(),
    }
}

async fn initialize(socket: WebSocket, session: SessionChannel) {
    let (mut socket_outgoing, mut socket_incoming) = socket.split();
    let (message, mut receive_outgoing_message) = channel::<Message>(1);
    let terminate_session = message.to_owned();

    tokio::spawn(async move {
        if let Some(message) = socket_incoming.next().await {
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

    match session.allocate().await {
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

async fn handle_registration_ceremony_session(socket: WebSocket, token: SessionToken) {
    let (mut socket_outgoing, mut socket_incoming) = socket.split();

    run_token_verification(&mut socket_outgoing, &mut socket_incoming, token).await;

    let (outgoing_message, mut outgoing_messages) = channel::<Message>(1);

    tokio::spawn(async move {
        handle_socket_incoming(&mut socket_incoming, outgoing_message).await;
    });

    tokio::spawn(async move {
        handle_socket_outgoing(&mut outgoing_messages, &mut socket_outgoing).await;
    });
}

async fn handle_authentication_ceremony_session(socket: WebSocket, token: SessionToken) {
    let (mut socket_outgoing, mut socket_incoming) = socket.split();

    run_token_verification(&mut socket_outgoing, &mut socket_incoming, token).await;

    let (outgoing_message, mut outgoing_messages) = channel::<Message>(1);

    tokio::spawn(async move {
        handle_socket_incoming(&mut socket_incoming, outgoing_message).await;
    });

    tokio::spawn(async move {
        handle_socket_outgoing(&mut outgoing_messages, &mut socket_outgoing).await;
    });
}

async fn run_token_verification(
    socket_outgoing: &mut SplitSink<WebSocket, Message>,
    socket_incoming: &mut SplitStream<WebSocket>,
    token: SessionToken,
) {
    match timeout(Duration::from_millis(30000), socket_incoming.next()).await {
        Ok(incoming_message) => {
            if let Some(Ok(Message::Binary(data))) = incoming_message {
                match data == token {
                    true => {
                        let data = b"ok".to_vec();

                        let _ = socket_outgoing.send(Message::Binary(data)).await;
                    }
                    false => {
                        let _ = socket_outgoing.close().await;
                    }
                }
            } else {
                let _ = socket_outgoing.close().await;
            }
        }
        Err(error) => {
            println!("timeout! -> {:?}", error);

            let _ = socket_outgoing.close().await;
        }
    }
}

async fn handle_socket_incoming(
    socket_incoming: &mut SplitStream<WebSocket>,
    outgoing_message: Sender<Message>,
) {
    while let Some(Ok(message)) = socket_incoming.next().await {
        match message {
            Message::Text(json) => {
                let _ = outgoing_message.send(Message::Close(None)).await;
            }
            Message::Binary(_) => {
                let _ = outgoing_message.send(Message::Close(None)).await;
            }
            Message::Ping(_) => {}
            Message::Pong(_) => {}
            Message::Close(_) => {
                let _ = outgoing_message.send(Message::Close(None)).await;
            }
        }
    }
}

async fn handle_socket_outgoing(
    outgoing_messages: &mut Receiver<Message>,
    socket_outgoing: &mut SplitSink<WebSocket, Message>,
) {
    while let Some(message) = outgoing_messages.recv().await {
        match message {
            Message::Text(_) => {
                let _ = socket_outgoing.close().await;
            }
            Message::Binary(data) => {
                let _ = socket_outgoing.close().await;
            }
            Message::Ping(_) => {}
            Message::Pong(_) => {}
            Message::Close(_) => {
                let _ = socket_outgoing.close().await;

                outgoing_messages.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite;

    #[tokio::test]
    async fn registration_ceremony_session() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_websockets = Websockets::init().await;

        tokio::spawn(async move {
            test_websockets.run().await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let test_websockets_connection =
            connect_async("ws://127.0.0.1:8080/registration_ceremony/test").await;

        assert!(test_websockets_connection.is_err());

        if let tungstenite::Error::Http(response) = test_websockets_connection.unwrap_err() {
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
        let mut test_websockets = Websockets::init().await;

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
    async fn run_token_verification() -> Result<(), Box<dyn std::error::Error>> {
        async fn test_router() -> Router {
            Router::new().route("/test", get(test_handler))
        }

        async fn test_handler(ws: WebSocketUpgrade) -> Response {
            ws.on_upgrade(test_handle_socket)
        }

        async fn test_handle_socket(test_socket: WebSocket) {
            let (mut test_socket_outgoing, mut test_socket_incoming) = test_socket.split();
            let test_token = [0u8; 16];

            super::run_token_verification(
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
            let (test_outgoing_message, mut test_outgoing_messages) = channel::<Message>(1);

            tokio::spawn(async move {
                handle_socket_incoming(&mut test_socket_incoming, test_outgoing_message).await;
            });

            tokio::spawn(async move {
                handle_socket_outgoing(&mut test_outgoing_messages, &mut test_socket_outgoing)
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
            assert_eq!(test_message, tungstenite::Message::Close(None));
        } else {
            panic!("a message should have been receieved!");
        }

        Ok(())
    }
}
