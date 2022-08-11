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

    pub async fn start_timer(
        &self,
        authorization_code: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.channel
            .send(Request::StartTimer(authorization_code))
            .await?;

        Ok(())
    }

    pub async fn abort_timer(
        &self,
        authorization_code: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.channel
            .send(Request::AbortTimer(authorization_code))
            .await?;

        Ok(())
    }
}
