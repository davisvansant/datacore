use std::collections::HashMap;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::sleep;

use channel::{AuthorizationCodeLifetimeRequest, ReceiveRequest, Request};

pub mod channel;

use crate::state::authorization_codes::channel::AuthorizationCodesRequest;

pub struct AuthorizationCodeLifetime {
    receiver: ReceiveRequest,
    authorization_codes_request: AuthorizationCodesRequest,
    timer_handles: HashMap<String, JoinHandle<()>>,
}

impl AuthorizationCodeLifetime {
    pub async fn init(
        authorization_codes_request: AuthorizationCodesRequest,
    ) -> (AuthorizationCodeLifetime, AuthorizationCodeLifetimeRequest) {
        let (send_request, receive_request) = AuthorizationCodeLifetimeRequest::init().await;
        let timer_handles = HashMap::with_capacity(50);

        (
            AuthorizationCodeLifetime {
                receiver: receive_request,
                authorization_codes_request,
                timer_handles,
            },
            send_request,
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(request) = self.receiver.recv().await {
            match request {
                Request::StartTimer(authorization_code) => {
                    self.start_timer(authorization_code).await?;
                }
                Request::AbortTimer(authorization_code) => {
                    self.abort_timer(authorization_code).await?;
                }
                Request::Shutdown => self.receiver.close(),
            }
        }

        Ok(())
    }

    async fn start_timer(
        &mut self,
        authorization_code: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let authorization_codes_request = self.authorization_codes_request.to_owned();
        let expired_authorization_code = authorization_code.to_owned();

        let handle = tokio::spawn(async move {
            sleep(Duration::from_secs(600)).await;

            println!("authorization code expired...send request to remove from active");

            if let Err(error) = authorization_codes_request
                .revoke(expired_authorization_code)
                .await
            {
                println!("authorization codes request -> {:?}", error);
            }
        });

        match self.timer_handles.insert(authorization_code, handle) {
            None => println!("added new handle"),
            Some(previous_handle) => {
                println!("updated authorization code handle -> {:?}", previous_handle);
            }
        }

        Ok(())
    }

    async fn abort_timer(
        &mut self,
        authorization_code: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.timer_handles.remove(&authorization_code) {
            None => {
                let error = String::from("authorization code not found or no longer in use");

                Err(Box::from(error))
            }
            Some(timer_handle) => {
                timer_handle.abort();

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_codes_request = AuthorizationCodesRequest::init().await;
        let (test_authorization_code_lifetime, _) =
            AuthorizationCodeLifetime::init(test_authorization_codes_request.0).await;

        assert_eq!(test_authorization_code_lifetime.timer_handles.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn start_timer() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_codes_request = AuthorizationCodesRequest::init().await;
        let (mut test_authorization_code_lifetime, _) =
            AuthorizationCodeLifetime::init(test_authorization_codes_request.0).await;
        let test_authorization_code = String::from("some_test_authorization_code");

        test_authorization_code_lifetime
            .start_timer(test_authorization_code.to_owned())
            .await?;

        assert_eq!(test_authorization_code_lifetime.timer_handles.len(), 1);

        if let Some(test_join_handle) = test_authorization_code_lifetime
            .timer_handles
            .get(&test_authorization_code)
        {
            assert!(!test_join_handle.is_finished());
        }

        let test_timer_authorization_code = String::from("test_timer_authorization_code");
        let test_timer = tokio::spawn(async move {
            sleep(Duration::from_nanos(1)).await;

            // the hands of fate
        });

        test_authorization_code_lifetime
            .timer_handles
            .insert(test_timer_authorization_code.to_owned(), test_timer);

        if let Some(test_timer_handle) = test_authorization_code_lifetime
            .timer_handles
            .get(&test_timer_authorization_code)
        {
            sleep(Duration::from_millis(1)).await;

            assert!(test_timer_handle.is_finished());
        }

        Ok(())
    }

    #[tokio::test]
    async fn abort_timer() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_codes_request = AuthorizationCodesRequest::init().await;
        let (mut test_authorization_code_lifetime, _) =
            AuthorizationCodeLifetime::init(test_authorization_codes_request.0).await;
        let test_authorization_code = String::from("some_test_authorization_code");

        test_authorization_code_lifetime
            .start_timer(test_authorization_code.to_owned())
            .await?;

        let test_invalid_authorization_code = String::from("some_invalid_authorization_code");

        let test_authorization_code_lifetime_error = test_authorization_code_lifetime
            .abort_timer(test_invalid_authorization_code)
            .await;

        assert!(test_authorization_code_lifetime_error.is_err());

        test_authorization_code_lifetime
            .abort_timer(test_authorization_code.to_owned())
            .await?;

        assert_eq!(test_authorization_code_lifetime.timer_handles.len(), 0);

        Ok(())
    }
}
