use tokio::sync::mpsc::{channel, Receiver, Sender};

pub type ReceiveRequest = Receiver<Request>;

#[derive(Debug)]
pub enum Request {
    Shutdown,
}

#[derive(Clone)]
pub struct AccessTokensRequest {
    channel: Sender<Request>,
}

impl AccessTokensRequest {
    pub async fn init() -> (AccessTokensRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (AccessTokensRequest { channel: sender }, receiver)
    }
}
