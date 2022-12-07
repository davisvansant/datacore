use chrono::{offset::Utc, SecondsFormat};
use tokio::sync::{broadcast, mpsc};

use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::relying_party::client::WebAuthnData;

#[derive(Debug, Clone)]
pub enum OutgoingData {
    PublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptions),
    PublicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions),
}

pub struct OutgoingDataTask {
    data: mpsc::Receiver<OutgoingData>,
    client: broadcast::Sender<Vec<u8>>,
}

impl OutgoingDataTask {
    pub async fn init() -> (
        mpsc::Sender<OutgoingData>,
        OutgoingDataTask,
        broadcast::Sender<Vec<u8>>,
    ) {
        let (sender, data) = mpsc::channel(64);
        let (client, _) = broadcast::channel(64);

        (
            sender,
            OutgoingDataTask {
                data,
                client: client.to_owned(),
            },
            client,
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(data) = self.data.recv().await {
            match data {
                OutgoingData::PublicKeyCredentialCreationOptions(options) => {
                    let webauthndata = WebAuthnData {
                        message: String::from("public_key_credential_creation_options"),
                        contents: serde_json::to_vec(&options)?,
                        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    };

                    let json = serde_json::to_vec(&webauthndata)?;

                    self.client.send(json)?;
                }
                OutgoingData::PublicKeyCredentialRequestOptions(options) => {
                    let webauthndata = WebAuthnData {
                        message: String::from("public_key_credential_request_options"),
                        contents: serde_json::to_vec(&options)?,
                        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    };

                    let json = serde_json::to_vec(&webauthndata)?;

                    self.client.send(json)?;
                }
            }
        }

        Ok(())
    }
}
