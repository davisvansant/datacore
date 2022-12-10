use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;

use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Deserialize, Serialize)]
pub struct SessionInfo {
    pub id: [u8; 16],
    pub token: [u8; 16],
}

impl SessionInfo {
    pub async fn generate() -> SessionInfo {
        SessionInfo {
            id: [0; 16],
            token: [0; 16],
        }
    }
}

#[derive(Debug)]
pub enum Request {
    Allocate,
    Consume([u8; 16]),
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
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
            Err(error) => {
                println!("allocate request -> {:?}", error);

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    pub async fn consume(&self, id: [u8; 16]) -> Result<SessionInfo, StatusCode> {
        let (request, response) = oneshot::channel();
        match self.request.send((Request::Consume(id), request)).await {
            Ok(()) => match response.await {
                Ok(Response::SessionInfo(session_info)) => Ok(session_info),
                Ok(Response::Error) => Err(StatusCode::INTERNAL_SERVER_ERROR),
                Err(error) => {
                    println!("consume response -> {:?}", error);

                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            },
            Err(error) => {
                println!("consume request -> {:?}", error);

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

pub struct Session {
    available: HashMap<[u8; 16], [u8; 16]>,
    receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
    timeout: SessionChannel,
}

impl Session {
    pub async fn init() -> (SessionChannel, Session) {
        let available = HashMap::with_capacity(100);
        let (sender, receiver) = SessionChannel::init().await;

        (
            sender.to_owned(),
            Session {
                available,
                receiver,
                timeout: sender,
            },
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                Request::Allocate => {
                    let session_info = self.allocate().await;
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

        Ok(())
    }

    async fn allocate(&mut self) -> SessionInfo {
        let session_info = SessionInfo::generate().await;

        self.available.insert(session_info.id, session_info.token);

        let timeout = self.timeout.to_owned();
        let id = session_info.id.to_owned();

        tokio::spawn(async move {
            sleep(Duration::from_millis(30000)).await;

            if let Err(error) = timeout.consume(id).await {
                println!("timeout error -> {:?}", error);
            }
        });

        session_info
    }

    async fn consume(&mut self, id: [u8; 16]) -> Option<SessionInfo> {
        match self.available.remove_entry(&id) {
            Some((id, token)) => Some(SessionInfo { id, token }),
            None => None,
        }
    }
}
