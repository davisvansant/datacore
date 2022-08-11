use tokio::sync::mpsc::{channel, Receiver, Sender};

pub type ReceiveRequest = Receiver<Request>;

#[derive(Debug)]
pub enum Request {
    Issue(String),
    Revoke(String),
    Authenticate((String, String)),
    Shutdown,
}

#[derive(Clone)]
pub struct AuthorizationCodesRequest {
    channel: Sender<Request>,
}

impl AuthorizationCodesRequest {
    pub async fn init() -> (AuthorizationCodesRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (AuthorizationCodesRequest { channel: sender }, receiver)
    }

    pub async fn issue(&self, client_id: String) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.send(Request::Issue(client_id)).await?;

        Ok(())
    }

    pub async fn revoke(
        &self,
        authorization_code: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.channel
            .send(Request::Revoke(authorization_code))
            .await?;

        Ok(())
    }

    pub async fn authenticate(
        &self,
        authorization_code: String,
        client_id: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.channel
            .send(Request::Authenticate((authorization_code, client_id)))
            .await?;

        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.send(Request::Shutdown).await?;

        Ok(())
    }
}
