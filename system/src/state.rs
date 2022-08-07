pub use channel::{ReceiveRequest, Request, SendRequest};

mod channel;

pub struct State {
    receiver: ReceiveRequest,
}

impl State {
    pub async fn init() -> (State, SendRequest) {
        let (send_request, receive_request) = SendRequest::init().await;

        (
            State {
                receiver: receive_request,
            },
            send_request,
        )
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
