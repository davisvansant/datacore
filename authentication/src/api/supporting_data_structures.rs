use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CollectedClientData {
    pub r#type: String,
    pub challenge: Vec<u8>,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,
    #[serde(rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
}

impl CollectedClientData {
    pub async fn generate() -> CollectedClientData {
        let r#type = String::from("some_type");
        let challenge = Vec::with_capacity(0);
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

#[derive(Deserialize, PartialEq, Serialize)]
pub struct TokenBinding {
    status: TokenBindingStatus,
    id: String,
}

impl TokenBinding {
    pub async fn generate() -> TokenBinding {
        let status = TokenBindingStatus::Present;
        let id = String::from("some_id");

        TokenBinding { status, id }
    }
}

#[derive(Deserialize, PartialEq, Serialize)]
pub enum TokenBindingStatus {
    Present,
    Supported,
}

pub enum PublicKeyCredentialType {
    PublicKey,
}

pub struct PublicKeyCredentialDescriptor {
    public_key_credential_type: String,
    pub id: Vec<u8>,
    transports: Option<Vec<String>>,
}

pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Internal,
}

pub type COSEAlgorithmIdentifier = u32;

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
            \"challenge\": [],
            \"origin\": \"some_test_origin\",
            \"crossOrigin\": true
        }";

        let test_collected_client_data: CollectedClientData =
            serde_json::from_slice(test_collected_client_data_json)?;

        assert_eq!(test_collected_client_data.r#type, "webauthn.create");
        assert_eq!(test_collected_client_data.challenge.len(), 0);
        assert_eq!(test_collected_client_data.origin, "some_test_origin");
        assert!(test_collected_client_data.cross_origin);

        Ok(())
    }
}
