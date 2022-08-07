use tokio::sync::mpsc::{channel, Receiver, Sender};

pub type ReceiveRequest = Receiver<Request>;

#[derive(Debug)]
pub enum Request {
    Ok(()),
    Shutdown,
}

pub struct SendRequest {
    channel: Sender<Request>,
}

impl SendRequest {
    pub async fn init() -> (SendRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (SendRequest { channel: sender }, receiver)
    }

    pub async fn ok(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.send(Request::Ok(())).await?;

        Ok(())
    }
}
