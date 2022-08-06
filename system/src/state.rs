use tokio::sync::mpsc::{channel, Receiver, Sender};

pub use channel::Request;

mod channel;

pub struct State {
    receiver: Receiver<Request>,
}

impl State {
    pub async fn init() -> (State, Sender<Request>) {
        let (sender, receiver) = channel(64);

        (State { receiver }, sender)
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
