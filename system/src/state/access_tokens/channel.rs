use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;

pub type ReceiveRequest = Receiver<(Request, oneshot::Sender<Response>)>;

#[derive(Debug)]
pub enum Request {
    Issue(String),
    Shutdown,
}

#[derive(Debug)]
pub enum Response {
    AccessToken(String),
}

#[derive(Clone)]
pub struct AccessTokensRequest {
    channel: Sender<(Request, oneshot::Sender<Response>)>,
}

impl AccessTokensRequest {
    pub async fn init() -> (AccessTokensRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (AccessTokensRequest { channel: sender }, receiver)
    }

    pub async fn issue(&self, client_id: String) -> Result<String, Box<dyn std::error::Error>> {
        let (send_response, receive_response) = oneshot::channel();

        self.channel
            .send((Request::Issue(client_id), send_response))
            .await?;

        match receive_response.await? {
            Response::AccessToken(access_token) => Ok(access_token),
        }
    }
}
