use rand::distributions::{Alphanumeric, DistString};
use rand::thread_rng;
use std::collections::HashMap;

use channel::{AccessTokensRequest, ReceiveRequest, Request};

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
        while let Some(request) = self.receiver.recv().await {
            match request {
                Request::Issue(client_id) => {
                    self.issue(client_id).await?;

                    println!("send issued token back to client...");
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
}
