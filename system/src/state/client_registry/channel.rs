use tokio::sync::mpsc::{channel, Receiver, Sender};

pub type ReceiveRequest = Receiver<Request>;

#[derive(Debug)]
pub enum Request {
    Register,
    Read(String),
    Update(String, String),
    Remove(String),
    Shutdown,
}

pub struct ClientRegistryRequest {
    channel: Sender<Request>,
}

impl ClientRegistryRequest {
    pub async fn init() -> (ClientRegistryRequest, ReceiveRequest) {
        let (sender, receiver) = channel(64);

        (ClientRegistryRequest { channel: sender }, receiver)
    }

    pub async fn register(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.send(Request::Register).await?;

        Ok(())
    }

    pub async fn read(&self, client_id: String) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.send(Request::Read(client_id)).await?;

        Ok(())
    }

    pub async fn update(
        &self,
        client_id: String,
        client_metadata: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.channel
            .send(Request::Update(client_id, client_metadata))
            .await?;

        Ok(())
    }

    pub async fn remove(&self, client_id: String) -> Result<(), Box<dyn std::error::Error>> {
        self.channel.send(Request::Remove(client_id)).await?;

        Ok(())
    }
}
