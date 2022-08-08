pub use channel::{ReceiveRequest, Request, SendRequest};

use access_tokens::AccessTokens;
use authorization_codes::AuthorizationCodes;
use clients::Clients;

mod access_tokens;
mod authorization_codes;
mod channel;
mod clients;

pub enum Data {
    InMemory,
}

pub struct State {
    receiver: ReceiveRequest,
    clients: Option<Clients>,
    authorization_codes: Option<AuthorizationCodes>,
    access_tokens: Option<AccessTokens>,
}

impl State {
    pub async fn init(data: Data) -> (State, SendRequest) {
        let (send_request, receive_request) = SendRequest::init().await;

        match data {
            Data::InMemory => {
                let clients = Clients::init().await;
                let authorization_codes = AuthorizationCodes::init().await;
                let access_tokens = AccessTokens::init().await;

                (
                    State {
                        receiver: receive_request,
                        clients: Some(clients),
                        authorization_codes: Some(authorization_codes),
                        access_tokens: Some(access_tokens),
                    },
                    send_request,
                )
            }
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(request) = self.receiver.recv().await {
            match request {
                Request::Ok(()) => println!("received a request!"),
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
        let (test_state, _test_send_request) = State::init(Data::InMemory).await;

        assert!(test_state.clients.is_some());
        assert!(test_state.authorization_codes.is_some());
        assert!(test_state.access_tokens.is_some());

        Ok(())
    }
}
