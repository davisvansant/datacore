use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;

pub type ReceiveRequest = Receiver<(Request, oneshot::Sender<Response>)>;

#[derive(Debug)]
pub enum Request {
    Register,
    Read(String),
    Update(String, String),
    Remove(String),
    Shutdown,
}

#[derive(Debug)]
pub enum Response {
    ClientInformation(String),
}

#[derive(Clone)]
pub struct ClientRegistryRequest {
    channel: Sender<(Request, oneshot::Sender<Response>)>,
}

impl ClientRegistryRequest {
    pub async fn init() -> (ClientRegistryRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (ClientRegistryRequest { channel: sender }, receiver)
    }

    pub async fn register(
        &self,
        client_metadata: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let (send_response, receive_response) = oneshot::channel();

        self.channel
            .send((Request::Register, send_response))
            .await?;

        match receive_response.await? {
            Response::ClientInformation(client_information) => Ok(client_information),
        }
    }

    pub async fn read(&self, client_id: String) -> Result<(), Box<dyn std::error::Error>> {
        let (_send_response, _receive_response) = oneshot::channel();

        self.channel
            .send((Request::Read(client_id), _send_response))
            .await?;

        Ok(())
    }

    pub async fn update(
        &self,
        client_id: String,
        client_metadata: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_send_response, _receive_response) = oneshot::channel();

        self.channel
            .send((Request::Update(client_id, client_metadata), _send_response))
            .await?;

        Ok(())
    }

    pub async fn remove(&self, client_id: String) -> Result<(), Box<dyn std::error::Error>> {
        let (_send_response, _receive_response) = oneshot::channel();

        self.channel
            .send((Request::Remove(client_id), _send_response))
            .await?;

        Ok(())
    }
}
