use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

use crate::error::{AuthenticationError, AuthenticationErrorType};
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

    pub async fn allocate(&self) -> Result<SessionInfo, Box<dyn std::error::Error>> {
        let (request, response) = oneshot::channel();

        self.request.send((Request::Allocate, request)).await?;

        match response.await? {
            Response::SessionInfo(session_info) => Ok(session_info),
            Response::Error => panic!("unexpected response!"),
        }
    }

    pub async fn consume(&self, id: SessionId) -> Result<SessionInfo, Box<dyn std::error::Error>> {
        let (request, response) = oneshot::channel();

        self.request.send((Request::Consume(id), request)).await?;

        match response.await? {
            Response::SessionInfo(session_info) => Ok(session_info),
            Response::Error => Err(Box::new(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })),
        }
    }
}

pub struct Available {
    session: HashMap<SessionId, SessionToken>,
    timeout: AvailableChannel,
    timeout_handles: HashMap<SessionId, JoinHandle<()>>,
    receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl Available {
    pub async fn init() -> (AvailableChannel, Available) {
        let session = HashMap::with_capacity(100);
        let available_channel = AvailableChannel::init().await;
        let timeout_handles = HashMap::with_capacity(100);

        (
            available_channel.0.to_owned(),
            Available {
                session,
                timeout: available_channel.0,
                timeout_handles,
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

        let timeout_handle = tokio::spawn(async move {
            sleep(Duration::from_millis(300000)).await;

            if let Err(error) = timeout.consume(id).await {
                println!(
                    "relying party | available session | allocate timeout -> {:?}",
                    error,
                );
            }
        });

        self.timeout_handles.insert(session_info.id, timeout_handle);

        session_info
    }

    async fn consume(&mut self, id: SessionId) -> Option<SessionInfo> {
        self.session.remove_entry(&id).map(|(id, token)| {
            match self.timeout_handles.remove(&id) {
                Some(timeout_handle) => timeout_handle.abort(),
                None => println!("handle already removed!"),
            }

            SessionInfo { id, token }
        })
    }
}
