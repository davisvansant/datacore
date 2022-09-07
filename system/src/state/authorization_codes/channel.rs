use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;

use crate::endpoint::authorization_server::authorization::error::AuthorizationError;
use crate::endpoint::authorization_server::authorization::error::AuthorizationErrorCode;

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

    pub async fn issue(&self, client_id: String) -> Result<String, AuthorizationError> {
        let (send_response, receive_response) = oneshot::channel();

        let authorization_error = AuthorizationError {
            error: AuthorizationErrorCode::ServerError,
            error_description: None,
            error_uri: None,
        };

        if let Err(error) = self
            .channel
            .send((Request::Issue(client_id), send_response))
            .await
        {
            println!("issue request -> {:?}", error);

            return Err(authorization_error);
        }

        match receive_response.await {
            Ok(Response::AuthorizationCode(authorization_code)) => Ok(authorization_code),
            _ => Err(authorization_error),
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
