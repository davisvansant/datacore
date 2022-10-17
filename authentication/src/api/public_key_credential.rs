use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::AuthenticatorResponse;
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;

pub struct PublicKeyCredential {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: AuthenticatorResponse,
    pub r#type: String,
}

impl PublicKeyCredential {
    pub async fn generate(
        r#type: String,
        id: String,
        raw_id: Vec<u8>,
        response: AuthenticatorResponse,
    ) -> PublicKeyCredential {
        PublicKeyCredential {
            id,
            raw_id,
            response,
            r#type,
        }
    }
}

pub struct CredentialCreationOptions {
    public_key: PublicKeyCredentialCreationOptions,
}

pub struct CredentialRequestOptions {
    public_key: PublicKeyCredentialRequestOptions,
}
