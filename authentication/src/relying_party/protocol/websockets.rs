use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

pub struct Websockets {
    router: Router,
}

impl Websockets {
    pub async fn init() -> Websockets {
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
            );

        Websockets { router }
    }
}

async fn register(connection: WebSocketUpgrade) -> Response {
    connection.on_upgrade(handle_register)
}
async fn authenticate(connection: WebSocketUpgrade) -> Response {
    connection.on_upgrade(handle_authenticate)
}
async fn registration_ceremony_session(
    Path(session): Path<String>,
    connection: WebSocketUpgrade,
) -> Response {
    let test_session = "session";
    match session == test_session {
        true => connection.on_upgrade(handle_registration_ceremony_session),
        false => StatusCode::BAD_REQUEST.into_response(),
    }
}
async fn authentication_ceremony_session(
    Path(session): Path<u32>,
    connection: WebSocketUpgrade,
) -> Response {
    let test_session = 100;
    match session == test_session {
        true => connection.on_upgrade(handle_registration_ceremony_session),
        false => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn handle_register(mut socket: WebSocket) {
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

async fn handle_authenticate(mut socket: WebSocket) {
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

async fn handle_registration_ceremony_session(mut socket: WebSocket) {
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

async fn handle_authentication_ceremony_session(mut socket: WebSocket) {
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
