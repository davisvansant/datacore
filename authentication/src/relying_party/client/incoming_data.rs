use tokio::sync::{broadcast, mpsc};

use crate::api::public_key_credential::PublicKeyCredential;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::relying_party::client::webauthn_data::WebAuthnData;

#[derive(Clone, Debug)]
pub enum IncomingData {
    PublicKeyCredential(PublicKeyCredential),
}

pub struct IncomingDataTask {
    relying_party: broadcast::Sender<IncomingData>,
    data: mpsc::Receiver<Vec<u8>>,
}

impl IncomingDataTask {
    pub async fn init(
        relying_party: broadcast::Sender<IncomingData>,
    ) -> (mpsc::Sender<Vec<u8>>, IncomingDataTask) {
        let channel = mpsc::channel(1);

        (
            channel.0,
            IncomingDataTask {
                relying_party,
                data: channel.1,
            },
        )
    }

    pub async fn run(&mut self) -> Result<(), AuthenticationError> {
        while let Some(data) = self.data.recv().await {
            let webauthndata = WebAuthnData::from_incoming_data(&data).await?;

            match webauthndata.message.as_str() {
                "public_key_credential" => {
                    match serde_json::from_slice(&webauthndata.contents) {
                        Ok(public_key_credential) => {
                            let _ = self
                                .relying_party
                                .send(IncomingData::PublicKeyCredential(public_key_credential));
                        }
                        Err(error) => {
                            println!("json serialization error -> {:?}", error);

                            let authentication_error = AuthenticationError {
                                error: AuthenticationErrorType::OperationError,
                            };

                            return Err(authentication_error);
                        }
                    };
                }
                _ => panic!("not yet..."),
            }
        }

        Ok(())
    }
}
