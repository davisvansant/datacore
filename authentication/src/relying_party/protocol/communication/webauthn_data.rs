use chrono::{offset::Utc, SecondsFormat};
use serde::{Deserialize, Serialize};

use crate::error::{AuthenticationError, AuthenticationErrorType};

#[derive(Debug, Deserialize, Serialize)]
pub struct WebAuthnData {
    pub message: String,
    pub contents: Vec<u8>,
    pub timestamp: String,
}

impl WebAuthnData {
    pub async fn from_incoming_data(data: &[u8]) -> Result<WebAuthnData, AuthenticationError> {
        match serde_json::from_slice(data) {
            Ok(webauthndata) => Ok(webauthndata),
            Err(error) => {
                println!("webauthn json deserialization -> {:?}", error);

                let authentication_error = AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                };

                Err(authentication_error)
            }
        }
    }

    pub async fn generate(
        message: String,
        contents: Vec<u8>,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let webauthn_data = WebAuthnData {
            message,
            contents,
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        };

        match serde_json::to_vec(&webauthn_data) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
