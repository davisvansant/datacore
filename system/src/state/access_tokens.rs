use rand::distributions::{Alphanumeric, DistString};
use rand::thread_rng;
use std::collections::HashMap;

use channel::{AccessTokensRequest, ReceiveRequest, Request, Response};

pub mod channel;

pub struct AccessTokens {
    receiver: ReceiveRequest,
    issued: HashMap<String, String>,
    expired: HashMap<String, String>,
}

impl AccessTokens {
    pub async fn init() -> (AccessTokens, AccessTokensRequest) {
        let (send_request, receive_request) = AccessTokensRequest::init().await;
        let capacity = 50;
        let issued = HashMap::with_capacity(capacity);
        let expired = HashMap::with_capacity(capacity);

        (
            AccessTokens {
                receiver: receive_request,
                issued,
                expired,
            },
            send_request,
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                Request::Issue(client_id) => {
                    let access_token = self.issue(client_id).await?;

                    response.send(Response::AccessToken(access_token));
                }
                Request::Introspect(access_token) => {
                    let client_id = self.introspect(&access_token).await?;

                    response.send(Response::ActiveToken((access_token, client_id)));
                }
                Request::Shutdown => self.receiver.close(),
            }
        }

        Ok(())
    }

    async fn issue(&mut self, client_id: String) -> Result<String, Box<dyn std::error::Error>> {
        let access_token = generate().await;
        let issued_access_token = access_token.to_owned();

        match self.issued.insert(access_token, client_id) {
            None => Ok(issued_access_token),
            Some(associated_client_id) => {
                let error = String::from("issued token is already associated with a client id");

                Err(Box::from(error))
            }
        }
    }

    async fn introspect(
        &mut self,
        access_token: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match self.issued.get(access_token) {
            None => {
                let error = String::from("invalid access token");

                Err(Box::from(error))
            }

            Some(client_id) => Ok(client_id.to_owned()),
        }
    }
}

async fn generate() -> String {
    Alphanumeric.sample_string(&mut thread_rng(), 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let (test_access_tokens, _) = AccessTokens::init().await;

        assert!(test_access_tokens.issued.is_empty());
        assert!(test_access_tokens.expired.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn issue() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_access_tokens, _) = AccessTokens::init().await;

        let test_client_id = String::from("some_test_client_id");

        assert_eq!(test_access_tokens.issued.len(), 0);

        let test_access_token_ok = test_access_tokens.issue(test_client_id.to_owned()).await;

        assert!(test_access_token_ok.is_ok());
        assert_eq!(test_access_tokens.issued.len(), 1);

        Ok(())
    }
}
