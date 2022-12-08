use serde::{Deserialize, Serialize};

use crate::security::challenge::{base64_encode_challenge, generate_challenge};

#[derive(Serialize, Deserialize)]
pub struct CollectedClientData {
    pub r#type: String,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,
    #[serde(rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
}

impl CollectedClientData {
    pub async fn generate() -> CollectedClientData {
        let r#type = String::from("some_type");
        let challenge = base64_encode_challenge(&generate_challenge().await).await;
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyCredentialDescriptor {
    pub r#type: PublicKeyCredentialType,
    pub id: [u8; 16],
    pub transports: Option<Vec<String>>,
}

#[derive(Debug)]
pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Internal,
}

pub type COSEAlgorithmIdentifier = i32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UserVerificationRequirement {
    #[serde(rename = "required")]
    Required,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "discouraged")]
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
            \"challenge\": \"c29tZV90ZXN0X2NoYWxsZW5nZQ==\",
            \"origin\": \"some_test_origin\",
            \"crossOrigin\": true
        }";

        let test_collected_client_data: CollectedClientData =
            serde_json::from_slice(test_collected_client_data_json)?;

        assert_eq!(test_collected_client_data.r#type, "webauthn.create");
        assert_eq!(
            base64::decode(&test_collected_client_data.challenge)?,
            b"some_test_challenge",
        );
        assert_eq!(test_collected_client_data.origin, "some_test_origin");
        assert!(test_collected_client_data.cross_origin);

        Ok(())
    }
}
