use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

use crate::security::session_token::{generate_session_token, SessionToken};
use crate::security::uuid::{generate_session_id, SessionId};

use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub token: SessionToken,
}

impl SessionInfo {
    pub async fn generate() -> SessionInfo {
        SessionInfo {
            id: generate_session_id().await,
            token: generate_session_token().await,
        }
    }
}

#[derive(Debug)]
pub enum Request {
    Allocate,
    Consume(SessionId),
}

#[derive(Debug)]
pub enum Response {
    SessionInfo(SessionInfo),
    Error,
}

#[derive(Clone)]
pub struct SessionChannel {
    request: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl SessionChannel {
    pub async fn init() -> (
        SessionChannel,
        mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
    ) {
        let (request, receiver) = mpsc::channel(100);

        (SessionChannel { request }, receiver)
    }

    pub async fn allocate(&self) -> Result<SessionInfo, StatusCode> {
        let (request, response) = oneshot::channel();

        match self.request.send((Request::Allocate, request)).await {
            Ok(()) => {
                if let Ok(Response::SessionInfo(session_info)) = response.await {
                    Ok(session_info)
                } else {
                    Err(StatusCode::BAD_REQUEST)
                }
            }
            Err(error) => {
                println!(
                    "websocket protocol | session channel | allocate -> {:?}",
                    error,
                );

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    pub async fn consume(&self, id: SessionId) -> Result<SessionInfo, StatusCode> {
        let (request, response) = oneshot::channel();

        match self.request.send((Request::Consume(id), request)).await {
            Ok(()) => {
                if let Ok(Response::SessionInfo(session_info)) = response.await {
                    Ok(session_info)
                } else {
                    Err(StatusCode::BAD_REQUEST)
                }
            }
            Err(error) => {
                println!(
                    "websocket protocol | session channel | consume -> {:?}",
                    error,
                );

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

pub struct Session {
    available: HashMap<SessionId, SessionToken>,
    timeout: SessionChannel,
    timeout_handles: HashMap<SessionId, JoinHandle<()>>,
    receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl Session {
    pub async fn init() -> (SessionChannel, Session) {
        let available = HashMap::with_capacity(100);
        let session_channel = SessionChannel::init().await;
        let timeout_handles = HashMap::with_capacity(100);

        (
            session_channel.0.to_owned(),
            Session {
                available,
                timeout: session_channel.0,
                timeout_handles,
                receiver: session_channel.1,
            },
        )
    }

    pub async fn run(&mut self) {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                Request::Allocate => {
                    let session_info = self.allocate().await;

                    println!("allocating - > {:?}", &session_info);
                    println!("{:?}", String::from_utf8(session_info.id.to_vec()).unwrap());
                    println!(
                        "{:?}",
                        String::from_utf8(session_info.token.to_vec()).unwrap(),
                    );

                    let _ = response.send(Response::SessionInfo(session_info));
                }
                Request::Consume(id) => match self.consume(id).await {
                    Some(session_info) => {
                        let _ = response.send(Response::SessionInfo(session_info));
                    }
                    None => {
                        let _ = response.send(Response::Error);
                    }
                },
            }
        }
    }

    async fn allocate(&mut self) -> SessionInfo {
        let session_info = SessionInfo::generate().await;

        self.available.insert(session_info.id, session_info.token);

        let timeout = self.timeout.to_owned();
        let id = session_info.id.to_owned();

        let timeout_handle = tokio::spawn(async move {
            sleep(Duration::from_millis(300000)).await;

            if let Err(error) = timeout.consume(id).await {
                println!(
                    "websocket protocol | available session | allocate timeout -> {:?}",
                    error,
                );
            }
        });

        self.timeout_handles.insert(session_info.id, timeout_handle);

        session_info
    }

    async fn consume(&mut self, id: SessionId) -> Option<SessionInfo> {
        self.available.remove_entry(&id).map(|(id, token)| {
            match self.timeout_handles.remove(&id) {
                Some(timeout_handle) => timeout_handle.abort(),
                None => println!("handle already removed!"),
            }

            SessionInfo { id, token }
        })
    }
}
