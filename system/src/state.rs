use tokio::sync::mpsc::{channel, Receiver, Sender};

pub use channel::Request;

mod channel;

pub struct State {
    request: Receiver<Request>,
}

impl State {
    pub async fn init() -> (State, Sender<Request>) {
        let (send_request, request) = channel(64);

        (State { request }, send_request)
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(request) = self.request.recv().await {
            match request {
                Request::Ok(()) => println!("received a request!"),
                Request::Shutdown => self.request.close(),
            }
        }

        Ok(())
    }
}
