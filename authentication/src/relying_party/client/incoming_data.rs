use tokio::sync::{broadcast, mpsc};

use crate::api::public_key_credential::PublicKeyCredential;
use crate::relying_party::client::WebAuthnData;

#[derive(Clone, Debug)]
pub enum IncomingData {
    PublicKeyCredential(PublicKeyCredential),
}

pub struct IncomingDataTask {
    data: mpsc::Receiver<Vec<u8>>,
    relying_party: broadcast::Sender<IncomingData>,
}

impl IncomingDataTask {
    pub async fn init() -> (
        broadcast::Sender<IncomingData>,
        IncomingDataTask,
        mpsc::Sender<Vec<u8>>,
    ) {
        let (relying_party, _) = broadcast::channel(64);
        let (sender, receiver) = mpsc::channel(64);

        (
            relying_party.to_owned(),
            IncomingDataTask {
                data: receiver,
                relying_party,
            },
            sender,
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(data) = self.data.recv().await {
            let webauthndata: WebAuthnData = serde_json::from_slice(&data)?;

            match webauthndata.message.as_str() {
                "public_key_credential" => {
                    let public_key_credential: PublicKeyCredential =
                        serde_json::from_slice(&webauthndata.contents)?;

                    self.relying_party
                        .send(IncomingData::PublicKeyCredential(public_key_credential))?;
                }
                _ => panic!("not yet..."),
            }
        }

        Ok(())
    }
}
