use rand::distributions::{Alphanumeric, DistString};
use rand::thread_rng;
use std::collections::HashMap;

use crate::endpoint::authorization_server::token::response::{
    AccessTokenResponse, AccessTokenType,
};
use crate::endpoint::token_introspection::introspect::response::IntrospectionResponse;
use crate::state::access_token_lifetime::channel::AccessTokenLifetimeRequest;
use crate::state::access_token_lifetime::AccessTokenLifetime;

use channel::{AccessTokensRequest, ReceiveRequest, Request, Response};

pub mod channel;

pub struct AccessTokens {
    receiver: ReceiveRequest,
    issued: HashMap<String, String>,
    expired: HashMap<String, String>,
    access_token_lifetime_request: AccessTokenLifetimeRequest,
}

impl AccessTokens {
    pub async fn init() -> (AccessTokens, AccessTokensRequest) {
        let (send_request, receive_request) = AccessTokensRequest::init().await;
        let capacity = 50;
        let issued = HashMap::with_capacity(capacity);
        let expired = HashMap::with_capacity(capacity);

        let (mut access_token_lifetime, access_token_lifetime_request) =
            AccessTokenLifetime::init(send_request.to_owned()).await;

        tokio::spawn(async move {
            if let Err(error) = access_token_lifetime.run().await {
                println!("access token lifetime -> {:?}", error);
            }
        });

        (
            AccessTokens {
                receiver: receive_request,
                issued,
                expired,
                access_token_lifetime_request,
            },
            send_request,
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                Request::Issue(client_id) => {
                    let access_token_response = self.issue(client_id).await?;

                    let _ = response.send(Response::AccessTokenResponse(access_token_response));
                }
                Request::Expire(access_token) => {
                    self.expire(&access_token).await?;
                }
                Request::Introspect(access_token) => {
                    let introspection_response = self.introspect(&access_token).await;

                    let _ = response.send(Response::IntrospectionResponse(Box::new(
                        introspection_response,
                    )));
                }
                Request::Shutdown => self.receiver.close(),
            }
        }

        Ok(())
    }

    async fn issue(
        &mut self,
        client_id: String,
    ) -> Result<AccessTokenResponse, Box<dyn std::error::Error>> {
        let access_token = generate().await;
        let access_token_response = AccessTokenResponse {
            access_token: access_token.to_owned(),
            token_type: AccessTokenType::Bearer,
            expires_in: 3600,
        };

        self.access_token_lifetime_request
            .start_timer(access_token.to_owned())
            .await?;

        match self.issued.insert(access_token, client_id) {
            None => Ok(access_token_response),
            Some(associated_client_id) => {
                let error = format!(
                    "issued token is already associated with a client {:?}",
                    associated_client_id,
                );

                Err(Box::from(error))
            }
        }
    }

    async fn expire(&mut self, access_token: &str) -> Result<(), Box<dyn std::error::Error>> {
        match self.issued.remove_entry(access_token) {
            None => {
                let error = String::from("invalid access token");

                Err(Box::from(error))
            }
            Some((expired_access_token, expired_client_id)) => {
                match self
                    .expired
                    .insert(expired_access_token.to_owned(), expired_client_id)
                {
                    None => {
                        self.access_token_lifetime_request
                            .abort_timer(expired_access_token)
                            .await?;

                        Ok(())
                    }
                    Some(old_expired_client_id_value) => {
                        let error = format!(
                            "expired access token client id -> {:?}",
                            old_expired_client_id_value,
                        );

                        Err(Box::from(error))
                    }
                }
            }
        }
    }

    async fn introspect(&self, access_token: &str) -> IntrospectionResponse {
        match self.issued.get(access_token) {
            None => IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            },
            Some(client_id) => IntrospectionResponse {
                active: true,
                scope: None,
                client_id: Some(client_id.to_string()),
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
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

    #[tokio::test]
    async fn expire() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_access_tokens, _) = AccessTokens::init().await;

        let test_client_id = String::from("some_test_client_id");
        let test_access_token_response = test_access_tokens.issue(test_client_id).await?;

        assert_eq!(test_access_tokens.expired.len(), 0);

        test_access_tokens
            .expire(&test_access_token_response.access_token)
            .await?;

        assert_eq!(test_access_tokens.expired.len(), 1);
        assert!(test_access_tokens
            .expire("test_invalid_access_token")
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn introspect() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_access_tokens, _) = AccessTokens::init().await;

        let test_client_id = String::from("some_test_client_id");
        let test_access_token_response = test_access_tokens.issue(test_client_id).await?;
        let test_introspection_response_true = test_access_tokens
            .introspect(&test_access_token_response.access_token)
            .await;

        assert!(test_introspection_response_true.active);

        let test_invalid_access_token = "some_invalid_access_token";
        let test_introspection_response_false = test_access_tokens
            .introspect(test_invalid_access_token)
            .await;

        assert!(!test_introspection_response_false.active);

        Ok(())
    }

    #[tokio::test]
    async fn generate() -> Result<(), Box<dyn std::error::Error>> {
        let test_access_token = super::generate().await;

        assert!(test_access_token.is_ascii());
        assert_eq!(test_access_token.len(), 16);

        Ok(())
    }
}
