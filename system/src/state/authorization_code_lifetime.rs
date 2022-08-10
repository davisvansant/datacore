use std::collections::HashMap;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::sleep;

use channel::{AuthorizationCodeLifetimeRequest, ReceiveRequest, Request};

mod channel;

pub struct AuthorizationCodeLifetime {
    receiver: ReceiveRequest,
    timer_handles: HashMap<String, JoinHandle<()>>,
}

impl AuthorizationCodeLifetime {
    pub async fn init() -> (AuthorizationCodeLifetime, AuthorizationCodeLifetimeRequest) {
        let (send_request, receive_request) = AuthorizationCodeLifetimeRequest::init().await;
        let timer_handles = HashMap::with_capacity(50);

        (
            AuthorizationCodeLifetime {
                receiver: receive_request,
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
        let handle = tokio::spawn(async move {
            sleep(Duration::from_secs(600));

            println!("authorization code expired...send request to remove from active");
        });

        match self.timer_handles.insert(authorization_code, handle) {
            None => println!("added new handle"),
            Some(previous_handle) => println!("updated authorization code handle..."),
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
