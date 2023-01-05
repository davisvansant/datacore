use serde::{Deserialize, Serialize};

use crate::security::challenge::{base64_encode_challenge, generate_challenge};
use crate::security::uuid::CredentialId;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ClientDataType {
    #[serde(rename = "webauthn.create")]
    Create,
    #[serde(rename = "webauthn.get")]
    Get,
}

#[derive(Serialize, Deserialize)]
pub struct CollectedClientData {
    pub r#type: ClientDataType,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,
    #[serde(rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
}

impl CollectedClientData {
    pub async fn generate() -> CollectedClientData {
        let r#type = ClientDataType::Create;
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
    #[serde(rename = "present")]
    Present,
    #[serde(rename = "supported")]
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
    pub id: CredentialId,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AuthenticatorTransport {
    #[serde(rename = "usb")]
    Usb,
    #[serde(rename = "nfc")]
    Nfc,
    #[serde(rename = "ble")]
    Ble,
    #[serde(rename = "internal")]
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

        assert_eq!(test_collected_client_data.r#type, ClientDataType::Create);
        assert_eq!(
            base64::decode(&test_collected_client_data.challenge)?,
            b"some_test_challenge",
        );
        assert_eq!(test_collected_client_data.origin, "some_test_origin");
        assert!(test_collected_client_data.cross_origin);

        Ok(())
    }

    #[tokio::test]
    async fn token_binding() -> Result<(), Box<dyn std::error::Error>> {
        let test_token_binding = r#"
            { 
                "status": "present",
                "id": "some_id"
            }
        "#
        .as_bytes();

        assert!(serde_json::from_slice::<TokenBinding>(test_token_binding).is_ok());

        let test_token_binding = r#"
            { 
                "status": "supported",
                "id": "some_id"
            }
        "#
        .as_bytes();

        assert!(serde_json::from_slice::<TokenBinding>(test_token_binding).is_ok());

        let test_token_binding = r#"
            { 
                "status": "something_else",
                "id": "some_id"
            }
        "#
        .as_bytes();

        assert!(serde_json::from_slice::<TokenBinding>(test_token_binding).is_err());

        Ok(())
    }

    #[tokio::test]
    async fn public_key_credential_descriptor() -> Result<(), Box<dyn std::error::Error>> {
        let test_descriptor = r#"
            { 
                "type": "public-key",
                "id": [0]
            }
        "#
        .as_bytes();

        assert!(serde_json::from_slice::<PublicKeyCredentialDescriptor>(test_descriptor).is_ok());

        let test_descriptor = r#"
            { 
                "type": "public-key",
                "id": [0],
                "transports": [
                    "usb",
                    "nfc",
                    "ble",
                    "internal"
                ]
            }
        "#
        .as_bytes();

        assert!(serde_json::from_slice::<PublicKeyCredentialDescriptor>(test_descriptor).is_ok());

        let test_descriptor = r#"
            { 
                "type": "something_else",
                "id": "some_id"
            }
        "#
        .as_bytes();

        assert!(serde_json::from_slice::<PublicKeyCredentialDescriptor>(test_descriptor).is_err());

        let test_transport = r#""not_usb""#.as_bytes();

        assert!(serde_json::from_slice::<AuthenticatorTransport>(test_transport).is_err());

        let test_transport = r#""not_nfc""#.as_bytes();

        assert!(serde_json::from_slice::<AuthenticatorTransport>(test_transport).is_err());

        let test_transport = r#""not_ble""#.as_bytes();

        assert!(serde_json::from_slice::<AuthenticatorTransport>(test_transport).is_err());

        let test_transport = r#""not_internal""#.as_bytes();

        assert!(serde_json::from_slice::<AuthenticatorTransport>(test_transport).is_err());

        Ok(())
    }

    #[tokio::test]
    async fn user_verification_requirement() -> Result<(), Box<dyn std::error::Error>> {
        let test_requirement = r#""required""#.as_bytes();

        assert!(serde_json::from_slice::<UserVerificationRequirement>(test_requirement).is_ok());

        let test_requirement = r#""not_required""#.as_bytes();

        assert!(serde_json::from_slice::<UserVerificationRequirement>(test_requirement).is_err());

        let test_requirement = r#""preferred""#.as_bytes();

        assert!(serde_json::from_slice::<UserVerificationRequirement>(test_requirement).is_ok());

        let test_requirement = r#""not_preferred""#.as_bytes();

        assert!(serde_json::from_slice::<UserVerificationRequirement>(test_requirement).is_err());

        let test_requirement = r#""discouraged""#.as_bytes();

        assert!(serde_json::from_slice::<UserVerificationRequirement>(test_requirement).is_ok());

        let test_requirement = r#""not_discouraged""#.as_bytes();

        assert!(serde_json::from_slice::<UserVerificationRequirement>(test_requirement).is_err());

        Ok(())
    }
}
