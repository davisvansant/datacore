use tokio::sync::broadcast::{channel, Receiver, Sender};

#[derive(Clone, Debug)]
pub struct FailCeremony {
    request: Sender<bool>,
}

impl FailCeremony {
    pub fn init() -> FailCeremony {
        let channel = channel(1);

        FailCeremony { request: channel.0 }
    }

    pub fn subscribe(&self) -> Receiver<bool> {
        self.request.subscribe()
    }

    pub fn error(&self) {
        let _ = self.request.send(true);
    }
}
