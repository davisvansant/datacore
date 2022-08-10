use tokio::sync::mpsc::{channel, Receiver, Sender};

pub type ReceiveRequest = Receiver<Request>;

#[derive(Debug)]
pub enum Request {
    StartTimer(String),
    AbortTimer(String),
    Shutdown,
}

#[derive(Clone)]
pub struct AuthorizationCodeLifetimeRequest {
    channel: Sender<Request>,
}

impl AuthorizationCodeLifetimeRequest {
    pub async fn init() -> (AuthorizationCodeLifetimeRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (
            AuthorizationCodeLifetimeRequest { channel: sender },
            receiver,
        )
    }
}
