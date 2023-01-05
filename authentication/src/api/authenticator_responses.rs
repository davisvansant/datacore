use serde::{Deserialize, Serialize};

use crate::security::uuid::UserHandle;

pub type ClientDataJSON = Vec<u8>;
pub type Signature = Vec<u8>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AuthenticatorResponse {
    AuthenticatorAttestationResponse(AuthenticatorAttestationResponse),
    AuthenticatorAssertionResponse(AuthenticatorAssertionResponse),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: ClientDataJSON,
    pub attestation_object: Vec<u8>,
}

impl AuthenticatorAttestationResponse {
    pub async fn generate(
        client_data_json: ClientDataJSON,
        attestation_object: Vec<u8>,
    ) -> AuthenticatorAttestationResponse {
        AuthenticatorAttestationResponse {
            client_data_json,
            attestation_object,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: ClientDataJSON,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: Vec<u8>,
    pub signature: Signature,
    #[serde(rename = "userHandle")]
    pub user_handle: UserHandle,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::credential_creation_options::PublicKeyCredentialUserEntity;
    use crate::authenticator::attestation::{COSEAlgorithm, COSEKey};
    use crate::authenticator::data::AuthenticatorData;

    #[tokio::test]
    async fn authenticator_attestation_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_collected_client_data_json = b"
        { 
            \"type\": \"webauthn.create\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            \"origin\": \"some_test_origin\",
            \"crossOrigin\": true
        }";
        let test_attestation_object = Vec::with_capacity(0);

        AuthenticatorAttestationResponse::generate(
            test_collected_client_data_json.to_vec(),
            test_attestation_object,
        )
        .await;

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_assertion_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_data_json = b"
        { 
            \"type\": \"webauthn.get\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            \"origin\": \"some_test_origin\",
            \"crossOrigin\": true
        }";
        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = true;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;

        let test_key_pair = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_signature = test_key_pair
            .1
            .sign(test_client_data_json.as_ref(), &test_authenticator_data)
            .await?;
        let test_name = String::from("some_test_name");
        let test_display_name = String::from("some_test_display_name");
        let test_user_entity =
            PublicKeyCredentialUserEntity::generate(test_name, test_display_name).await;

        let test_response =
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: test_client_data_json.to_vec(),
                authenticator_data: test_authenticator_data,
                signature: test_signature.to_vec(),
                user_handle: test_user_entity.id.to_vec(),
            });

        assert!(serde_json::to_vec(&test_response).is_ok());

        let test_response = r#"
            {
                "clientDataJSON": [0],
                "authenticatorData": [0],
                "signature": [0],
                "userHandle": [0]
            }
        "#
        .as_bytes();

        let test_assertion_response: AuthenticatorAssertionResponse =
            serde_json::from_slice(test_response)?;

        assert!(!test_assertion_response.client_data_json.is_empty());
        assert!(!test_assertion_response.authenticator_data.is_empty());
        assert!(!test_assertion_response.signature.is_empty());
        assert!(!test_assertion_response.user_handle.is_empty());

        Ok(())
    }
}
