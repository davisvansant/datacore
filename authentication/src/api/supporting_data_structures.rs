use serde::{Deserialize, Serialize};

use crate::api::credential_creation_options::Challenge;

#[derive(Serialize, Deserialize)]
pub struct CollectedClientData {
    pub r#type: String,
    pub challenge: Challenge,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,
    #[serde(rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
}

impl CollectedClientData {
    pub async fn generate() -> CollectedClientData {
        let r#type = String::from("some_type");
        let challenge = Challenge::generate().await;
        let origin = String::from("some_origin");
        let cross_origin = false;
        let token_binding = Some(TokenBinding::generate().await);

        CollectedClientData {
            r#type,
            challenge,
            origin,
            cross_origin,
            token_binding,
        }
    }
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenBinding {
    pub status: TokenBindingStatus,
    pub id: String,
}

impl TokenBinding {
    pub async fn generate() -> TokenBinding {
        let status = TokenBindingStatus::Present;
        let id = String::from("some_id");

        TokenBinding { status, id }
    }
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
pub enum TokenBindingStatus {
    Present,
    Supported,
}

#[derive(Clone, Eq, PartialEq)]
pub enum PublicKeyCredentialType {
    PublicKey,
}

pub struct PublicKeyCredentialDescriptor {
    pub r#type: PublicKeyCredentialType,
    pub id: Vec<u8>,
    pub transports: Option<Vec<String>>,
}

pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Internal,
}

pub type COSEAlgorithmIdentifier = i32;

pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collected_client_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_collected_client_data_json = b"
        { 
            \"type\": \"webauthn.create\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            \"origin\": \"some_test_origin\",
            \"crossOrigin\": true
        }";

        let test_collected_client_data: CollectedClientData =
            serde_json::from_slice(test_collected_client_data_json)?;

        assert_eq!(test_collected_client_data.r#type, "webauthn.create");
        assert_eq!(test_collected_client_data.challenge.0.len(), 16);
        assert_eq!(test_collected_client_data.origin, "some_test_origin");
        assert!(test_collected_client_data.cross_origin);

        Ok(())
    }
}
