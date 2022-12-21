use axum::http::StatusCode;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, Duration};

use crate::relying_party::SessionInfo;
use crate::security::session_token::SessionToken;
use crate::security::uuid::SessionId;

use std::collections::HashMap;

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
pub struct AvailableChannel {
    request: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl AvailableChannel {
    pub async fn init() -> (
        AvailableChannel,
        mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
    ) {
        let (request, receiver) = mpsc::channel(100);

        (AvailableChannel { request }, receiver)
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

    pub async fn consume(&self, id: SessionId) -> Result<SessionInfo, StatusCode> {
        let (request, response) = oneshot::channel();

        match self.request.send((Request::Consume(id), request)).await {
            Ok(()) => match response.await {
                Ok(Response::SessionInfo(session_info)) => Ok(session_info),
                Ok(Response::Error) => Err(StatusCode::BAD_REQUEST),
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

pub struct Available {
    session: HashMap<SessionId, SessionToken>,
    timeout: AvailableChannel,
    receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl Available {
    pub async fn init() -> (AvailableChannel, Available) {
        let session = HashMap::with_capacity(100);
        let available_channel = AvailableChannel::init().await;

        (
            available_channel.0.to_owned(),
            Available {
                session,
                timeout: available_channel.0,
                receiver: available_channel.1,
            },
        )
    }

    pub async fn run(&mut self) {
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
    }

    async fn allocate(&mut self) -> SessionInfo {
        let session_info = SessionInfo::generate().await;

        self.session.insert(session_info.id, session_info.token);

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

    async fn consume(&mut self, id: SessionId) -> Option<SessionInfo> {
        self.session
            .remove_entry(&id)
            .map(|(id, token)| SessionInfo { id, token })
    }
}
