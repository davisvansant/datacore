use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::relying_party::client::ceremony_data::CeremonyData;
use crate::relying_party::client::incoming_data::{IncomingData, IncomingDataTask};
use crate::relying_party::client::outgoing_data::{
    CeremonyStatus, ConnectedClient, OutgoingDataTask,
};

pub mod ceremony_data;
pub mod incoming_data;
pub mod outgoing_data;

#[derive(Debug, Deserialize, Serialize)]
pub struct WebAuthnData {
    pub message: String,
    pub contents: Vec<u8>,
    pub timestamp: String,
}

pub struct CeremonyIO {
    tasks: Vec<JoinHandle<()>>,
}

impl CeremonyIO {
    pub async fn init() -> (
        CeremonyIO,
        broadcast::Sender<IncomingData>,
        mpsc::Receiver<CeremonyStatus>,
        CeremonyData,
        ConnectedClient,
        mpsc::Sender<Vec<u8>>,
    ) {
        let connected_client = ConnectedClient::init().await;
        let connected_relying_party = broadcast::channel(1);
        let mut incoming = IncomingDataTask::init(connected_relying_party.0.to_owned()).await;
        let mut outgoing = OutgoingDataTask::init(connected_client.0.to_owned()).await;
        let ceremony_data =
            CeremonyData::init(connected_relying_party.0.to_owned(), outgoing.0.to_owned()).await;
        let incoming_task_error = connected_client.0.to_owned();
        let outgoing_task_error = connected_client.0.to_owned();

        let incoming_handle = tokio::spawn(async move {
            if let Err(error) = incoming.1.run().await {
                incoming_task_error.fail_ceremony(error).await;
            }
        });

        let outgoing_handle = tokio::spawn(async move {
            if let Err(error) = outgoing.1.run().await {
                outgoing_task_error.fail_ceremony(error).await;
            }
        });

        let tasks = vec![incoming_handle, outgoing_handle];

        (
            CeremonyIO { tasks },
            connected_relying_party.0,
            connected_client.1,
            ceremony_data,
            connected_client.0.to_owned(),
            incoming.0,
        )
    }

    pub async fn shutdown(&mut self) {
        for task in &self.tasks {
            task.abort();
        }

        self.tasks.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ceremony_io() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_ceremony_io = CeremonyIO::init().await;

        assert_eq!(test_ceremony_io.0.tasks.len(), 2);

        for test_task in &test_ceremony_io.0.tasks {
            assert!(!test_task.is_finished());
        }

        test_ceremony_io.0.shutdown().await;

        assert_eq!(test_ceremony_io.0.tasks.len(), 0);

        Ok(())
    }
}
