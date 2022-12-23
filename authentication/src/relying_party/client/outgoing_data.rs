use chrono::{offset::Utc, SecondsFormat};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::relying_party::client::WebAuthnData;

#[derive(Clone, Debug)]
pub enum OutgoingData {
    PublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptions),
    PublicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions),
}

#[derive(Clone, Debug)]
pub enum CeremonyStatus {
    Continue(Vec<u8>),
    Fail(AuthenticationError),
}

#[derive(Clone, Debug)]
pub struct ConnectedClient {
    status: Sender<CeremonyStatus>,
}

impl ConnectedClient {
    pub async fn init() -> (ConnectedClient, Receiver<CeremonyStatus>) {
        let channel = channel(1);

        (ConnectedClient { status: channel.0 }, channel.1)
    }

    pub async fn continue_ceremony(&self, data: Vec<u8>) {
        let _ = self.status.send(CeremonyStatus::Continue(data)).await;
    }

    pub async fn fail_ceremony(&self, error: AuthenticationError) {
        let _ = self.status.send(CeremonyStatus::Fail(error)).await;
    }
}

pub struct OutgoingDataTask {
    data: Receiver<OutgoingData>,
    connected_client: ConnectedClient,
}

impl OutgoingDataTask {
    pub async fn init(
        connected_client: ConnectedClient,
    ) -> (Sender<OutgoingData>, OutgoingDataTask) {
        let channel = channel(1);

        (
            channel.0,
            OutgoingDataTask {
                data: channel.1,
                connected_client,
            },
        )
    }

    pub async fn run(&mut self) -> Result<(), AuthenticationError> {
        while let Some(data) = self.data.recv().await {
            match data {
                OutgoingData::PublicKeyCredentialCreationOptions(options) => {
                    let webauthndata = match serde_json::to_vec(&options) {
                        Ok(contents) => WebAuthnData {
                            message: String::from("public_key_credential_creation_options"),
                            contents,
                            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                        },
                        Err(error) => {
                            println!("json serialization error -> {:?}", error);

                            let authentication_error = AuthenticationError {
                                error: AuthenticationErrorType::OperationError,
                            };

                            return Err(authentication_error);
                        }
                    };

                    match serde_json::to_vec(&webauthndata) {
                        Ok(json) => {
                            self.connected_client.continue_ceremony(json).await;
                        }
                        Err(error) => {
                            println!("json serialization error -> {:?}", error);

                            let authentication_error = AuthenticationError {
                                error: AuthenticationErrorType::OperationError,
                            };

                            return Err(authentication_error);
                        }
                    }
                }
                OutgoingData::PublicKeyCredentialRequestOptions(options) => {
                    let webauthndata = match serde_json::to_vec(&options) {
                        Ok(contents) => WebAuthnData {
                            message: String::from("public_key_credential_request_options"),
                            contents,
                            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                        },
                        Err(error) => {
                            println!("json serialization error -> {:?}", error);

                            let authentication_error = AuthenticationError {
                                error: AuthenticationErrorType::OperationError,
                            };

                            return Err(authentication_error);
                        }
                    };

                    match serde_json::to_vec(&webauthndata) {
                        Ok(json) => {
                            self.connected_client.continue_ceremony(json).await;
                        }
                        Err(error) => {
                            println!("json serialization error -> {:?}", error);

                            let authentication_error = AuthenticationError {
                                error: AuthenticationErrorType::OperationError,
                            };

                            return Err(authentication_error);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
