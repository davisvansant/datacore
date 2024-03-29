use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use serde::{Deserialize, Serialize};

use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::AuthenticatorResponse;
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::api::supporting_data_structures::PublicKeyCredentialType;
use crate::security::uuid::CredentialId;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: CredentialId,
    pub response: AuthenticatorResponse,
    pub r#type: PublicKeyCredentialType,
}

impl PublicKeyCredential {
    pub async fn generate(
        raw_id: CredentialId,
        response: AuthenticatorResponse,
    ) -> PublicKeyCredential {
        let r#type = PublicKeyCredentialType::PublicKey;
        // let id = base64::encode(&raw_id);
        let id = STANDARD.encode(&raw_id);

        PublicKeyCredential {
            id,
            raw_id,
            response,
            r#type,
        }
    }
}

pub struct CredentialCreationOptions {
    pub public_key: PublicKeyCredentialCreationOptions,
}

pub struct CredentialRequestOptions {
    pub public_key: PublicKeyCredentialRequestOptions,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authenticator_responses::AuthenticatorAssertionResponse;
    use crate::api::credential_creation_options::PublicKeyCredentialUserEntity;
    use crate::authenticator::attestation::{COSEAlgorithm, COSEKey};
    use crate::authenticator::data::AuthenticatorData;

    #[tokio::test]
    async fn generate() -> Result<(), Box<dyn std::error::Error>> {
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
                authenticator_data: test_authenticator_data.to_owned(),
                signature: test_signature.to_vec(),
                user_handle: test_user_entity.id.to_vec(),
            });

        let test_credential_id = [0u8; 16].to_vec();

        let test_public_key_credential =
            PublicKeyCredential::generate(test_credential_id, test_response).await;

        // let test_base64_engine = general_purpose::
        assert_eq!(
            STANDARD.decode(test_public_key_credential.id.as_bytes())?,
            [0u8; 16],
        );
        assert_eq!(test_public_key_credential.raw_id, [0u8; 16]);
        assert_eq!(
            test_public_key_credential.response,
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: test_client_data_json.to_vec(),
                authenticator_data: test_authenticator_data,
                signature: test_signature.to_vec(),
                user_handle: test_user_entity.id.to_vec(),
            }),
        );
        assert_eq!(
            test_public_key_credential.r#type,
            PublicKeyCredentialType::PublicKey,
        );

        Ok(())
    }
}
