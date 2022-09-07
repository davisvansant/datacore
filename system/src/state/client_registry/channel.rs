use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;

use crate::endpoint::client_registration::register::error::ClientRegistrationError;
use crate::endpoint::client_registration::register::error::ClientRegistrationErrorCode;

pub type ReceiveRequest = Receiver<(Request, oneshot::Sender<Response>)>;

#[derive(Debug)]
pub enum Request {
    Register(String),
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
    ) -> Result<String, ClientRegistrationError> {
        let (send_response, receive_response) = oneshot::channel();

        let client_registration_error = ClientRegistrationError {
            error: ClientRegistrationErrorCode::InvalidClientMetadata,
            error_description: String::from("Internal error"),
        };

        if let Err(error) = self
            .channel
            .send((Request::Register(client_metadata), send_response))
            .await
        {
            println!("client registry request -> {:?}", error);

            return Err(client_registration_error);
        }

        match receive_response.await {
            Ok(Response::ClientInformation(client_information)) => Ok(client_information),
            _ => Err(client_registration_error),
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
