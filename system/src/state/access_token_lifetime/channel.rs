use tokio::sync::mpsc::{channel, Receiver, Sender};

pub type ReceiveRequest = Receiver<Request>;

#[derive(Debug)]
pub enum Request {
    StartTimer(String),
    AbortTimer(String),
    Shutdown,
}

#[derive(Clone)]
pub struct AccessTokenLifetimeRequest {
    channel: Sender<Request>,
}

impl AccessTokenLifetimeRequest {
    pub async fn init() -> (AccessTokenLifetimeRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (AccessTokenLifetimeRequest { channel: sender }, receiver)
    }

    pub async fn start_timer(
        &self,
        access_token: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.send(Request::StartTimer(access_token)).await?;

        Ok(())
    }

    pub async fn abort_timer(
        &self,
        access_token: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.send(Request::AbortTimer(access_token)).await?;

        Ok(())
    }
}
