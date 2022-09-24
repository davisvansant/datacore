use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::{
    AuthenticatorAttestationResponse, AuthenticatorResponse,
};
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;

pub struct PublicKeyCredential {
    id: String,
    raw_id: Vec<u8>,
    pub response: AuthenticatorResponse,
    r#type: String,
}

impl PublicKeyCredential {
    pub async fn generate() -> PublicKeyCredential {
        let id = String::from("some_id");
        let raw_id = Vec::with_capacity(0);
        let response = AuthenticatorResponse::AuthenticatorAttestationResponse(
            AuthenticatorAttestationResponse::generate().await,
        );
        let r#type = String::from("some_type");

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
