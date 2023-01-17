use std::borrow::Cow;

use axum::extract::ws::{close_code, CloseFrame, Message};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::credential_creation_options::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity,
};
use crate::error::{AuthenticationError, AuthenticationErrorType};

use crate::relying_party::protocol::communication::{FailCeremony, WebAuthnData};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum OutgoingData {
    PublicKeyCredentialUserEntity(PublicKeyCredentialUserEntity),
    PublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptions),
    PublicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions),
}

impl OutgoingData {
    pub async fn to_webauthn_data(&self) -> Result<Vec<u8>, AuthenticationError> {
        match self {
            OutgoingData::PublicKeyCredentialUserEntity(user_entity) => {
                let message = String::from("public_key_credential_user_entity");
                let contents = self.serialize(user_entity).await?;
                let webauthn_data = WebAuthnData::generate(message, contents).await?;

                Ok(webauthn_data)
            }
            OutgoingData::PublicKeyCredentialCreationOptions(options) => {
                let message = String::from("public_key_credential_creation_options");
                let contents = self.serialize(&options).await?;
                let webauthn_data = WebAuthnData::generate(message, contents).await?;

                Ok(webauthn_data)
            }
            OutgoingData::PublicKeyCredentialRequestOptions(options) => {
                let message = String::from("public_key_credential_request_options");
                let contents = self.serialize(&options).await?;
                let webauthn_data = WebAuthnData::generate(message, contents).await?;

                Ok(webauthn_data)
            }
        }
    }

    async fn serialize<T: ?Sized + Serialize>(
        &self,
        contents: &T,
    ) -> Result<Vec<u8>, AuthenticationError> {
        match serde_json::to_vec(contents) {
            Ok(json) => Ok(json),
            Err(error) => {
                println!("webauthn json serialization -> {:?}", error);

                let authentication_error = AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                };

                Err(authentication_error)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct RelyingPartyAgentChannel {
    request: mpsc::Sender<OutgoingData>,
}

impl RelyingPartyAgentChannel {
    pub async fn init(request: mpsc::Sender<OutgoingData>) -> RelyingPartyAgentChannel {
        RelyingPartyAgentChannel { request }
    }

    pub async fn user_account(
        &self,
        user_entity: PublicKeyCredentialUserEntity,
    ) -> Result<(), AuthenticationError> {
        match self
            .request
            .send(OutgoingData::PublicKeyCredentialUserEntity(user_entity))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("{:?}", error);

                Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            }
        }
    }

    pub async fn public_key_credential_creation_options(
        &self,
        options: PublicKeyCredentialCreationOptions,
    ) -> Result<(), AuthenticationError> {
        match self
            .request
            .send(OutgoingData::PublicKeyCredentialCreationOptions(options))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("{:?}", error);

                Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            }
        }
    }

    pub async fn public_key_credential_request_options(
        &self,
        options: PublicKeyCredentialRequestOptions,
    ) -> Result<(), AuthenticationError> {
        match self
            .request
            .send(OutgoingData::PublicKeyCredentialRequestOptions(options))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("{:?}", error);

                Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct RelyingPartyAgent {
    incoming_data: mpsc::Receiver<OutgoingData>,
    outgoing_data: mpsc::Sender<Message>,
    fail_ceremony: FailCeremony,
}

impl RelyingPartyAgent {
    pub async fn init(
        outgoing_data: mpsc::Sender<Message>,
        fail_ceremony: FailCeremony,
    ) -> (RelyingPartyAgentChannel, RelyingPartyAgent) {
        let channel = mpsc::channel(1);
        let relying_party_agent_channel = RelyingPartyAgentChannel::init(channel.0).await;

        (
            relying_party_agent_channel,
            RelyingPartyAgent {
                incoming_data: channel.1,
                outgoing_data,
                fail_ceremony,
            },
        )
    }

    pub async fn run(&mut self) {
        let mut error = self.fail_ceremony.subscribe();

        loop {
            tokio::select! {
                biased;

                _ = error.recv() => {
                    println!("shutting down relying party agent...");

                    self.incoming_data.close();

                    break;
                }

                Some(data) = self.incoming_data.recv() => {
                    match data.to_webauthn_data().await {
                        Ok(webauthn_data) => {
                            let _ = self.outgoing_data.send(Message::Binary(webauthn_data)).await;
                        }
                        Err(authentication_error) => {
                            let close_frame = CloseFrame {
                                code: close_code::ERROR,
                                reason: Cow::from(authentication_error.to_string()),
                            };

                            let _ = self.outgoing_data
                                .send(Message::Close(Some(close_frame)))
                                .await;

                            self.incoming_data.close();
                        }
                    }
                }
            }
        }
    }
}
