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
                Request::Shutdown => self.receiver.close(),
            }
        }

        Ok(())
    }
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
