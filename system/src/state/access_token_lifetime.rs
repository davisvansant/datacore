use std::collections::HashMap;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

use crate::state::access_tokens::channel::AccessTokensRequest;
use channel::{AccessTokenLifetimeRequest, ReceiveRequest, Request};

pub mod channel;

pub struct AccessTokenLifetime {
    receiver: ReceiveRequest,
    access_tokens_request: AccessTokensRequest,
    timer_handles: HashMap<String, JoinHandle<()>>,
}

impl AccessTokenLifetime {
    pub async fn init(
        access_tokens_request: AccessTokensRequest,
    ) -> (AccessTokenLifetime, AccessTokenLifetimeRequest) {
        let (send_request, receive_request) = AccessTokenLifetimeRequest::init().await;
        let timer_handles = HashMap::with_capacity(50);

        (
            AccessTokenLifetime {
                receiver: receive_request,
                access_tokens_request,
                timer_handles,
            },
            send_request,
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(request) = self.receiver.recv().await {
            match request {
                Request::StartTimer(access_token) => {
                    self.start_timer(access_token).await?;
                }
                Request::AbortTimer(access_token) => {
                    self.abort_timer(access_token).await?;
                }
                Request::Shutdown => self.receiver.close(),
            }
        }

        Ok(())
    }

    async fn start_timer(
        &mut self,
        access_token: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let access_tokens_request = self.access_tokens_request.to_owned();
        let expired_access_token = access_token.to_owned();

        let handle = tokio::spawn(async move {
            sleep(Duration::from_secs(3600)).await;

            println!("access token expired...send request to remove from active");

            if let Err(error) = access_tokens_request.expire(expired_access_token).await {
                println!("access tokens request -> {:?}", error);
            }
        });

        match self.timer_handles.insert(access_token, handle) {
            None => println!("added new handle"),
            Some(previous_handle) => {
                println!("updated acess token handle -> {:?}", previous_handle);
            }
        }

        Ok(())
    }

    async fn abort_timer(
        &mut self,
        access_token: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.timer_handles.remove(&access_token) {
            None => {
                let error = String::from("access token not found or no longer in use");

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
    use tokio::time::{pause, resume};

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_access_tokens_request = AccessTokensRequest::init().await;
        let test_access_token_lifetime =
            AccessTokenLifetime::init(test_access_tokens_request.0).await;

        assert!(test_access_token_lifetime.0.timer_handles.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn start_timer() -> Result<(), Box<dyn std::error::Error>> {
        let test_access_tokens_request = AccessTokensRequest::init().await;
        let mut test_access_token_lifetime =
            AccessTokenLifetime::init(test_access_tokens_request.0).await;

        test_access_token_lifetime
            .0
            .start_timer(String::from("test_access_token"))
            .await?;

        assert_eq!(test_access_token_lifetime.0.timer_handles.len(), 1);

        pause();
        sleep(Duration::from_secs(4000)).await;
        resume();

        if let Some(test_timer_handle) = test_access_token_lifetime
            .0
            .timer_handles
            .get("test_access_token")
        {
            assert!(test_timer_handle.is_finished());
        }

        Ok(())
    }

    #[tokio::test]
    async fn abort_timer() -> Result<(), Box<dyn std::error::Error>> {
        let test_access_tokens_request = AccessTokensRequest::init().await;
        let mut test_access_token_lifetime =
            AccessTokenLifetime::init(test_access_tokens_request.0).await;

        test_access_token_lifetime
            .0
            .start_timer(String::from("test_access_token"))
            .await?;

        test_access_token_lifetime
            .0
            .start_timer(String::from("another_test_access_token"))
            .await?;

        assert_eq!(test_access_token_lifetime.0.timer_handles.len(), 2);

        pause();
        sleep(Duration::from_secs(1000)).await;

        if let Some(test_timer_handle) = test_access_token_lifetime
            .0
            .timer_handles
            .get("test_access_token")
        {
            assert!(!test_timer_handle.is_finished());
        }

        resume();

        test_access_token_lifetime
            .0
            .abort_timer(String::from("test_access_token"))
            .await?;

        assert_eq!(test_access_token_lifetime.0.timer_handles.len(), 1);

        pause();
        sleep(Duration::from_secs(5000)).await;

        if let Some(test_timer_handle) = test_access_token_lifetime
            .0
            .timer_handles
            .get("another_test_access_token")
        {
            assert!(test_timer_handle.is_finished());
        }

        resume();

        test_access_token_lifetime
            .0
            .abort_timer(String::from("another_test_access_token"))
            .await?;

        assert_eq!(test_access_token_lifetime.0.timer_handles.len(), 0);

        Ok(())
    }
}
