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
    message: String,
    contents: Vec<u8>,
    timestamp: String,
}

pub struct ClientChannel {
    incoming_data: broadcast::Sender<IncomingData>,
    outgoing_data: mpsc::Sender<OutgoingData>,
}

impl ClientChannel {
    pub async fn init() -> (IncomingDataTask, OutgoingDataTask, ClientChannel) {
        let (incoming_data, incoming_data_task, relying_party) = IncomingDataTask::init().await;
        let (outgoing_data, outgoing_data_task, connected_client) = OutgoingDataTask::init().await;

        let mut client = connected_client.subscribe();

        tokio::spawn(async move {
            if let Ok(outgoing_data) = client.recv().await {
                let webauthndata: WebAuthnData = serde_json::from_slice(&outgoing_data).unwrap();

                println!(
                    "send to client -> {:?}",
                    String::from_utf8(outgoing_data).unwrap(),
                );

                match webauthndata.message.as_str() {
                    "public_key_credential_creation_options" => {
                        let id = String::from("some_credential_id");
                        let client_data_json = Vec::with_capacity(0);
                        let attestation_object = Vec::with_capacity(0);
                        let response = AuthenticatorResponse::AuthenticatorAttestationResponse(
                            AuthenticatorAttestationResponse {
                                client_data_json,
                                attestation_object,
                            },
                        );
                        let credential = PublicKeyCredential::generate(id, response).await;
                        let webauthndata = WebAuthnData {
                            message: String::from("public_key_credential"),
                            contents: serde_json::to_vec(&credential).expect("json"),
                            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                        };
                        let json = serde_json::to_vec(&webauthndata).expect("json");

                        relying_party
                            .send(json)
                            .await
                            .expect("a good message to send");
                    }
                    "public_key_credential_request_options" => {
                        let id = String::from("some_key_id");
                        let client_data_json = Vec::with_capacity(0);
                        let authenticator_data = Vec::with_capacity(0);
                        let signature = Vec::with_capacity(0);
                        let user_handle = Vec::with_capacity(0);
                        let response = AuthenticatorResponse::AuthenticatorAssertionResponse(
                            AuthenticatorAssertionResponse {
                                client_data_json,
                                authenticator_data,
                                signature,
                                user_handle,
                            },
                        );
                        let credential = PublicKeyCredential::generate(id, response).await;
                        let webauthndata = WebAuthnData {
                            message: String::from("public_key_credential"),
                            contents: serde_json::to_vec(&credential).expect("json"),
                            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                        };
                        let json = serde_json::to_vec(&webauthndata).expect("json");

                        relying_party
                            .send(json)
                            .await
                            .expect("a good message to send");
                    }
                    _ => panic!("this is just for testing..."),
                }
            }
        });

        (
            incoming_data_task,
            outgoing_data_task,
            ClientChannel {
                incoming_data,
                outgoing_data,
            },
        )
    }

    pub async fn credentials_create(
        &self,
        options: PublicKeyCredentialCreationOptions,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        let call_timeout = Duration::from_millis(options.timeout);

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

        let call_timeout = Duration::from_millis(options.timeout);

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
