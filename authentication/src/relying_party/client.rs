use chrono::{offset::Utc, SecondsFormat};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;

use std::time::Duration;

use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, AuthenticatorResponse,
};
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::api::public_key_credential::PublicKeyCredential;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::relying_party::client::incoming_data::{IncomingData, IncomingDataTask};
use crate::relying_party::client::outgoing_data::{OutgoingData, OutgoingDataTask};

pub mod incoming_data;
pub mod outgoing_data;

#[derive(Debug, Deserialize, Serialize)]
pub struct WebAuthnData {
    pub message: String,
    pub contents: Vec<u8>,
    pub timestamp: String,
}

#[derive(Clone, Debug)]
pub struct ClientChannel {
    incoming_data: broadcast::Sender<IncomingData>,
    outgoing_data: mpsc::Sender<OutgoingData>,
}

impl ClientChannel {
    pub async fn init(
        incoming_data: broadcast::Sender<IncomingData>,
        outgoing_data: mpsc::Sender<OutgoingData>,
    ) -> ClientChannel {
        ClientChannel {
            incoming_data,
            outgoing_data,
        }
    }

    pub async fn credentials_create(
        &self,
        options: PublicKeyCredentialCreationOptions,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        let call_timeout = match options.timeout {
            Some(timeout) => Duration::from_millis(timeout),
            None => return Err(error),
        };

        match self
            .outgoing_data
            .send(OutgoingData::PublicKeyCredentialCreationOptions(options))
            .await
        {
            Ok(()) => {
                let mut incoming_data = self.incoming_data.subscribe();

                match timeout(call_timeout, incoming_data.recv()).await {
                    Ok(received_data) => {
                        if let Ok(IncomingData::PublicKeyCredential(credential)) = received_data {
                            Ok(credential)
                        } else {
                            Err(error)
                        }
                    }
                    Err(timeout_error) => {
                        println!("timeout reached! {:?}", timeout_error);

                        Err(error)
                    }
                }
            }
            Err(_) => Err(error),
        }
    }

    pub async fn credentials_get(
        &self,
        options: PublicKeyCredentialRequestOptions,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        let call_timeout = match options.timeout {
            Some(timeout) => Duration::from_millis(timeout),
            None => return Err(error),
        };

        match self
            .outgoing_data
            .send(OutgoingData::PublicKeyCredentialRequestOptions(options))
            .await
        {
            Ok(()) => {
                let mut incoming_data = self.incoming_data.subscribe();

                match timeout(call_timeout, incoming_data.recv()).await {
                    Ok(received_data) => {
                        if let Ok(IncomingData::PublicKeyCredential(credential)) = received_data {
                            Ok(credential)
                        } else {
                            Err(error)
                        }
                    }
                    Err(timeout_error) => {
                        println!("timeout reached! {:?}", timeout_error);

                        Err(error)
                    }
                }
            }
            Err(_) => Err(error),
        }
    }
}
