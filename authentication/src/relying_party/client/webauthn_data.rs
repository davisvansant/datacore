use chrono::{offset::Utc, SecondsFormat};
use serde::{Deserialize, Serialize};

use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::relying_party::client::outgoing_data::OutgoingData;

#[derive(Debug, Deserialize, Serialize)]
pub struct WebAuthnData {
    pub message: String,
    pub contents: Vec<u8>,
    pub timestamp: String,
}

impl WebAuthnData {
    pub async fn to_outgoing_data(data: OutgoingData) -> Result<Vec<u8>, AuthenticationError> {
        match data {
            OutgoingData::PublicKeyCredentialCreationOptions(options) => {
                match serde_json::to_vec(&options) {
                    Ok(contents) => {
                        let webauthndata = WebAuthnData {
                            message: String::from("public_key_credential_creation_options"),
                            contents,
                            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                        };

                        match serde_json::to_vec(&webauthndata) {
                            Ok(json) => Ok(json),
                            Err(error) => {
                                println!("json serialization error -> {:?}", error);

                                let authentication_error = AuthenticationError {
                                    error: AuthenticationErrorType::OperationError,
                                };

                                Err(authentication_error)
                            }
                        }
                    }
                    Err(error) => {
                        println!("json serialization error -> {:?}", error);

                        let authentication_error = AuthenticationError {
                            error: AuthenticationErrorType::OperationError,
                        };

                        Err(authentication_error)
                    }
                }
            }
            OutgoingData::PublicKeyCredentialRequestOptions(options) => {
                match serde_json::to_vec(&options) {
                    Ok(contents) => {
                        let webauthndata = WebAuthnData {
                            message: String::from("public_key_credential_request_options"),
                            contents,
                            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                        };

                        match serde_json::to_vec(&webauthndata) {
                            Ok(json) => Ok(json),
                            Err(error) => {
                                println!("json serialization error -> {:?}", error);

                                let authentication_error = AuthenticationError {
                                    error: AuthenticationErrorType::OperationError,
                                };

                                Err(authentication_error)
                            }
                        }
                    }
                    Err(error) => {
                        println!("json serialization error -> {:?}", error);

                        let authentication_error = AuthenticationError {
                            error: AuthenticationErrorType::OperationError,
                        };

                        Err(authentication_error)
                    }
                }
            }
        }
    }

    pub async fn from_incoming_data(data: &[u8]) -> Result<WebAuthnData, AuthenticationError> {
        match serde_json::from_slice(data) {
            Ok(webauthndata) => Ok(webauthndata),
            Err(error) => {
                println!("json deserialization error -> {:?}", error);

                let authentication_error = AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                };

                Err(authentication_error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
    use crate::api::credential_creation_options::{
        PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
    };

    #[tokio::test]
    async fn to_outgoing_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_entity = PublicKeyCredentialRpEntity {
            id: String::from("some_rp_entity_id"),
        };
        let test_user_entity = PublicKeyCredentialUserEntity::generate(
            String::from("some_user_name"),
            String::from("some_display_name"),
        )
        .await;

        let test_creation_options =
            PublicKeyCredentialCreationOptions::generate(test_rp_entity, test_user_entity).await;
        let test_outgoing_data =
            OutgoingData::PublicKeyCredentialCreationOptions(test_creation_options);

        assert!(WebAuthnData::to_outgoing_data(test_outgoing_data)
            .await
            .is_ok());

        let test_request_options =
            PublicKeyCredentialRequestOptions::generate(Some("test_rp_id")).await;

        let test_outgoing_data =
            OutgoingData::PublicKeyCredentialRequestOptions(test_request_options);

        assert!(WebAuthnData::to_outgoing_data(test_outgoing_data)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn from_incoming_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_incoming_data = r#"
            {
                "message": "public_key_credential",
                "contents": [0],
                "timestamp": "2018-01-26T18:30:09.453Z"
            }
        "#
        .as_bytes();

        assert!(WebAuthnData::from_incoming_data(test_incoming_data)
            .await
            .is_ok());

        Ok(())
    }
}
