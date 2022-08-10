use std::collections::HashMap;

use channel::{AuthorizationCodesRequest, ReceiveRequest, Request};

pub mod channel;

pub struct AuthorizationCodes {
    receiver: ReceiveRequest,
    issued: HashMap<String, String>,
    expired: HashMap<String, String>,
}

impl AuthorizationCodes {
    pub async fn init() -> (AuthorizationCodes, AuthorizationCodesRequest) {
        let (send_request, receive_request) = AuthorizationCodesRequest::init().await;
        let capacity = 50;
        let issued = HashMap::with_capacity(capacity);
        let expired = HashMap::with_capacity(capacity);

        (
            AuthorizationCodes {
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
        let (test_authorization_codes, _) = AuthorizationCodes::init().await;

        assert!(test_authorization_codes.issued.is_empty());
        assert!(test_authorization_codes.expired.is_empty());

        Ok(())
    }
}
