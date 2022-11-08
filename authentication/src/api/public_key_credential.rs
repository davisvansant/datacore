use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::AuthenticatorResponse;
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::api::supporting_data_structures::PublicKeyCredentialType;

#[derive(Debug)]
pub struct PublicKeyCredential {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: AuthenticatorResponse,
    pub r#type: PublicKeyCredentialType,
}

impl PublicKeyCredential {
    pub async fn generate(id: String, response: AuthenticatorResponse) -> PublicKeyCredential {
        let r#type = PublicKeyCredentialType::PublicKey;
        let raw_id = id.as_bytes().to_vec();

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
