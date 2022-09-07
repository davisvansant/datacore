use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;

use crate::endpoint::authorization_server::token::error::AccessTokenError;
use crate::endpoint::authorization_server::token::error::AccessTokenErrorCode;
use crate::endpoint::token_introspection::introspect::response::IntrospectionResponse;

pub type ReceiveRequest = Receiver<(Request, oneshot::Sender<Response>)>;

#[derive(Debug)]
pub enum Request {
    Issue(String),
    Expire(String),
    Introspect(String),
    Shutdown,
}

#[derive(Debug)]
pub enum Response {
    AccessToken(String),
    ActiveToken((String, String)),
    IntrospectionResponse(IntrospectionResponse),
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
            _ => {
                let error = String::from("unexpected response");

                Err(Box::from(error))
            }
        }
    }

    pub async fn expire(&self, access_token: String) -> Result<(), Box<dyn std::error::Error>> {
        let (_send_response, _receive_response) = oneshot::channel();

        self.channel
            .send((Request::Expire(access_token), _send_response))
            .await?;

        Ok(())
    }

    pub async fn introspect(
        &self,
        access_token: String,
    ) -> Result<IntrospectionResponse, AccessTokenError> {
        let (send_response, receive_response) = oneshot::channel();

        let access_token_error = AccessTokenError {
            error: AccessTokenErrorCode::InvalidRequest,
            error_description: None,
            error_uri: None,
        };

        if let Err(error) = self
            .channel
            .send((Request::Introspect(access_token), send_response))
            .await
        {
            println!("introspect channel -> {:?}", error);

            return Err(access_token_error);
        }

        match receive_response.await {
            Ok(Response::IntrospectionResponse(introspection_response)) => {
                Ok(introspection_response)
            }
            _ => Err(access_token_error),
        }
    }
}
