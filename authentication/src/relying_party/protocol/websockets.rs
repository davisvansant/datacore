use axum::{
    extract::ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade},
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Error, Router,
};
use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream, StreamExt},
};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::relying_party::protocol::websockets::session::{Session, SessionChannel, SessionInfo};

mod session;

pub struct Websockets {
    router: Router,
}

impl Websockets {
    pub async fn init() -> Websockets {
        let session = Session::init().await;

        let router = Router::new()
            .route("/register", get(register))
            .route("/authenticate", get(authenticate))
            .route(
                "/registration_ceremony/:session",
                get(registration_ceremony_session),
            )
            .route(
                "/authentication_ceremony/:session",
                get(authentication_ceremony_session),
            )
            .with_state(session.0);

        Websockets { router }
    }
}

async fn register(connection: WebSocketUpgrade, State(session): State<SessionChannel>) -> Response {
    connection.on_upgrade(|socket| initialize(socket, session))
}
async fn authenticate(
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

async fn handle_registration_ceremony_session(mut socket: WebSocket, token: [u8; 16]) {
    while let Some(message) = socket.recv().await {
        match message {
            Ok(Message::Text(data)) => {}
            Ok(Message::Binary(data)) => {}
            Ok(Message::Ping(data)) => {}
            Ok(Message::Pong(data)) => {}
            Ok(Message::Close(close_frame)) => {}
            Err(error) => {}
        }
    }
}

async fn handle_authentication_ceremony_session(mut socket: WebSocket, token: [u8; 16]) {
    while let Some(message) = socket.recv().await {
        match message {
            Ok(Message::Text(data)) => {}
            Ok(Message::Binary(data)) => {}
            Ok(Message::Ping(data)) => {}
            Ok(Message::Pong(data)) => {}
            Ok(Message::Close(close_frame)) => {}
            Err(error) => {}
        }
    }
}
