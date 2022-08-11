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
                Request::Issue => {
                    let authorization_code = self.issue().await?;
                }
                Request::Revoke(authorization_code) => self.revoke(authorization_code).await?,
                Request::Authenticate((authorization_code, client_id)) => {
                    self.authenticate(authorization_code, client_id).await?;
                }
                Request::Shutdown => self.receiver.close(),
            }
        }

        Ok(())
    }

    async fn issue(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let authorization_code = String::from("some_awesome_authorization_code");
        let client_id = String::from("some_awesome_client_id");

        match self.issued.insert(authorization_code.to_owned(), client_id) {
            None => {
                println!("issued code!");

                Ok(authorization_code)
            }
            Some(old_authorization_code) => {
                let error = String::from("authorization code is currently in use...");

                Err(Box::from(error))
            }
        }
    }

    async fn revoke(
        &mut self,
        authorization_code: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.issued.remove_entry(&authorization_code) {
            None => {
                let error = String::from("authorization code not found...");

                Err(Box::from(error))
            }
            Some((authorization_code, client_id)) => {
                match self.expired.insert(authorization_code, client_id) {
                    None => {
                        println!("added authorization code to expired list...");

                        Ok(())
                    }
                    Some(client_id) => {
                        let error = format!(
                            "authorization code in use by another client id {:?}",
                            client_id,
                        );

                        Err(Box::from(error))
                    }
                }
            }
        }
    }

    async fn authenticate(
        &mut self,
        authorization_code: String,
        verify_client_id: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.issued.remove(&authorization_code) {
            None => {
                let error = String::from("invalid authorization code");

                Err(Box::from(error))
            }
            Some(valid_client_id) => match verify_client_id == valid_client_id {
                true => Ok(()),
                false => {
                    let error = String::from("invalid client id for issued authentication code");

                    Err(Box::from(error))
                }
            },
        }
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
