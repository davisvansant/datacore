use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;

pub type ReceiveRequest = Receiver<(Request, oneshot::Sender<Response>)>;

#[derive(Debug)]
pub enum Request {
    Issue(String),
    Revoke(String),
    Authenticate((String, String)),
    Shutdown,
}

#[derive(Debug)]
pub enum Response {
    AuthorizationCode(String),
}

#[derive(Clone)]
pub struct AuthorizationCodesRequest {
    channel: Sender<(Request, oneshot::Sender<Response>)>,
}

impl AuthorizationCodesRequest {
    pub async fn init() -> (AuthorizationCodesRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (AuthorizationCodesRequest { channel: sender }, receiver)
    }

    pub async fn issue(&self, client_id: String) -> Result<String, Box<dyn std::error::Error>> {
        let (send_response, receive_response) = oneshot::channel();

        self.channel
            .send((Request::Issue(client_id), send_response))
            .await?;

        match receive_response.await? {
            Response::AuthorizationCode(authorization_code) => Ok(authorization_code),
        }
    }

    pub async fn revoke(
        &self,
        authorization_code: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_send_response, _receive_response) = oneshot::channel();

        self.channel
            .send((Request::Revoke(authorization_code), _send_response))
            .await?;

        Ok(())
    }

    pub async fn authenticate(
        &self,
        authorization_code: String,
        client_id: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_send_response, _receive_response) = oneshot::channel();

        self.channel
            .send((
                Request::Authenticate((authorization_code, client_id)),
                _send_response,
            ))
            .await?;

        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error>> {
        let (_send_response, _receive_response) = oneshot::channel();

        self.channel
            .send((Request::Shutdown, _send_response))
            .await?;

        Ok(())
    }
}
