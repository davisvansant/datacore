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
    Path(session): Path<[u8; 16]>,
    State(available_session): State<SessionChannel>,
    connection: WebSocketUpgrade,
) -> Response {
    match available_session.consume(session).await {
        Ok(session_info) => match session == session_info.id {
            true => connection.on_upgrade(move |socket| {
                handle_registration_ceremony_session(socket, session_info.token)
            }),
            false => StatusCode::BAD_REQUEST.into_response(),
        },
        Err(error) => error.into_response(),
    }
}
async fn authentication_ceremony_session(
    Path(session): Path<[u8; 16]>,
    State(available_session): State<SessionChannel>,
    connection: WebSocketUpgrade,
) -> Response {
    match available_session.consume(session).await {
        Ok(session_info) => match session == session_info.id {
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

async fn handle_registration_ceremony_session(socket: WebSocket, token: [u8; 16]) {
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

async fn handle_authentication_ceremony_session(socket: WebSocket, token: [u8; 16]) {
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
    token: [u8; 16],
) {
    match timeout(Duration::from_millis(30000), socket_incoming.next()).await {
        Ok(incoming_message) => {
            if let Some(Ok(Message::Binary(data))) = incoming_message {
                match data == token.to_vec() {
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
