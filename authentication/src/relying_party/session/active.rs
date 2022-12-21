use axum::http::StatusCode;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use std::collections::HashMap;

use crate::security::uuid::SessionId;

#[derive(Debug)]
pub enum Request {
    Insert((SessionId, JoinHandle<()>)),
    Abort(SessionId),
}

#[derive(Clone)]
pub struct ActiveChannel {
    request: Sender<Request>,
}

impl ActiveChannel {
    pub async fn init() -> (ActiveChannel, Receiver<Request>) {
        let (request, receiver) = channel(100);

        (ActiveChannel { request }, receiver)
    }

    pub async fn insert(
        &self,
        id: SessionId,
        join_handle: JoinHandle<()>,
    ) -> Result<(), StatusCode> {
        match self.request.send(Request::Insert((id, join_handle))).await {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("spawn -> {:?}", error);

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    pub async fn abort(&self, id: SessionId) -> Result<(), StatusCode> {
        match self.request.send(Request::Abort(id)).await {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("abort -> {:?}", error);

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

pub struct Active {
    session: HashMap<SessionId, JoinHandle<()>>,
    receiver: Receiver<Request>,
}

impl Active {
    pub async fn init() -> (ActiveChannel, Active) {
        let session = HashMap::with_capacity(100);
        let active_channel = ActiveChannel::init().await;

        (
            active_channel.0,
            Active {
                session,
                receiver: active_channel.1,
            },
        )
    }

    pub async fn run(&mut self) {
        while let Some(request) = self.receiver.recv().await {
            match request {
                Request::Insert((id, join_handle)) => {
                    self.insert(id, join_handle).await;
                }
                Request::Abort(id) => {
                    self.abort(id).await;
                }
            }
        }
    }

    async fn insert(&mut self, id: SessionId, join_handle: JoinHandle<()>) {
        self.session.insert(id, join_handle);
    }

    async fn abort(&mut self, id: SessionId) {
        // self.session.remove(&id);
        if let Some(join_handle) = self.session.remove(&id) {
            join_handle.abort();
        };
    }
}
