use tokio::sync::mpsc::{channel, Receiver, Sender};

pub type ReceiveRequest = Receiver<Request>;

#[derive(Debug)]
pub enum Request {
    Shutdown,
}

pub struct AuthorizationCodesRequest {
    channel: Sender<Request>,
}

impl AuthorizationCodesRequest {
    pub async fn init() -> (AuthorizationCodesRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (AuthorizationCodesRequest { channel: sender }, receiver)
    }
}
