use rand::distributions::{Alphanumeric, DistString};
use rand::thread_rng;
use std::collections::HashMap;

use channel::{AuthorizationCodesRequest, ReceiveRequest, Request, Response};

pub mod channel;

use crate::state::authorization_code_lifetime::channel::AuthorizationCodeLifetimeRequest;
use crate::state::authorization_code_lifetime::AuthorizationCodeLifetime;

pub struct AuthorizationCodes {
    receiver: ReceiveRequest,
    authorization_code_lifetime_request: AuthorizationCodeLifetimeRequest,
    issued: HashMap<String, String>,
    expired: HashMap<String, String>,
}

impl AuthorizationCodes {
    pub async fn init() -> (AuthorizationCodes, AuthorizationCodesRequest) {
        let (send_request, receive_request) = AuthorizationCodesRequest::init().await;
        let capacity = 50;
        let issued = HashMap::with_capacity(capacity);
        let expired = HashMap::with_capacity(capacity);

        let (mut authorization_code_lifetime, authorization_code_lifetime_request) =
            AuthorizationCodeLifetime::init(send_request.to_owned()).await;

        tokio::spawn(async move {
            if let Err(error) = authorization_code_lifetime.run().await {
                println!("authorication code lifetime -> {:?}", error);
            }
        });

        (
            AuthorizationCodes {
                receiver: receive_request,
                authorization_code_lifetime_request,
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
                    let authorization_code = self.issue(client_id).await?;

                    let _ = response.send(Response::AuthorizationCode(authorization_code));
                }
                Request::Revoke(authorization_code) => self.revoke(authorization_code).await?,
                Request::Authenticate((authorization_code, client_id)) => {
                    self.authenticate(&authorization_code, &client_id).await?;
                }
                Request::Shutdown => self.receiver.close(),
            }
        }

        Ok(())
    }

    async fn issue(&mut self, client_id: String) -> Result<String, Box<dyn std::error::Error>> {
        let authorization_code = generate().await;

        match self.issued.insert(authorization_code.to_owned(), client_id) {
            None => {
                println!("issued code!");

                self.authorization_code_lifetime_request
                    .start_timer(authorization_code.to_owned())
                    .await?;

                Ok(authorization_code)
            }
            Some(old_authorization_code) => {
                let error = format!(
                    "authorization code is currently in use -> {:?}",
                    old_authorization_code,
                );

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
                let expired_authorization_code = authorization_code.to_owned();

                match self.expired.insert(authorization_code, client_id) {
                    None => {
                        println!("added authorization code to expired list...");

                        self.authorization_code_lifetime_request
                            .abort_timer(expired_authorization_code)
                            .await?;

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
        authorization_code: &str,
        verify_client_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let used_authorization_code = authorization_code.to_owned();

        match self.issued.remove(authorization_code) {
            None => {
                let error = String::from("invalid authorization code");

                Err(Box::from(error))
            }
            Some(valid_client_id) => match verify_client_id == valid_client_id {
                true => {
                    self.authorization_code_lifetime_request
                        .abort_timer(used_authorization_code)
                        .await?;

                    Ok(())
                }
                false => {
                    let error = String::from("invalid client id for issued authentication code");

                    Err(Box::from(error))
                }
            },
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
        let (test_authorization_codes, _) = AuthorizationCodes::init().await;

        assert!(test_authorization_codes.issued.is_empty());
        assert!(test_authorization_codes.expired.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn issue() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_authorization_codes, _) = AuthorizationCodes::init().await;
        let test_client_id = String::from("some_test_client_id");

        assert_eq!(test_authorization_codes.issued.len(), 0);

        let test_issue_ok = test_authorization_codes.issue(test_client_id).await;

        assert!(test_issue_ok.is_ok());
        assert_eq!(test_authorization_codes.issued.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn revoke() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_authorization_codes, _) = AuthorizationCodes::init().await;
        let test_client_id = String::from("some_test_client_id");
        let test_authorization_code = test_authorization_codes.issue(test_client_id).await?;

        assert_eq!(test_authorization_codes.issued.len(), 1);
        assert_eq!(test_authorization_codes.expired.len(), 0);

        let test_revoke_ok = test_authorization_codes
            .revoke(test_authorization_code)
            .await;

        assert!(test_revoke_ok.is_ok());
        assert_eq!(test_authorization_codes.issued.len(), 0);
        assert_eq!(test_authorization_codes.expired.len(), 1);

        let test_invalid_access_token = String::from("some_invalid_access_token");
        let test_revoke_error = test_authorization_codes
            .revoke(test_invalid_access_token)
            .await;

        assert!(test_revoke_error.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn authenticate() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_authorization_codes, _) = AuthorizationCodes::init().await;
        let test_client_id = String::from("some_test_client_id");
        let test_authorization_code = test_authorization_codes
            .issue(test_client_id.to_owned())
            .await?;

        assert_eq!(test_authorization_codes.issued.len(), 1);

        let test_authenticate_ok = test_authorization_codes
            .authenticate(&test_authorization_code, &test_client_id)
            .await;

        assert!(test_authenticate_ok.is_ok());
        assert_eq!(test_authorization_codes.issued.len(), 0);

        let test_client_id = String::from("some_other_test_client_id");
        let test_authorization_code = test_authorization_codes
            .issue(test_client_id.to_owned())
            .await?;
        let test_invalid_client_id = "some_test_invalid_client_id";
        let test_authenticate_error = test_authorization_codes
            .authenticate(&test_authorization_code, test_invalid_client_id)
            .await;

        assert!(test_authenticate_error.is_err());
        assert_eq!(test_authorization_codes.issued.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn generate() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_code = super::generate().await;

        println!("{:?}", &test_authorization_code);

        assert!(test_authorization_code.is_ascii());
        assert_eq!(test_authorization_code.len(), 16);

        Ok(())
    }
}
