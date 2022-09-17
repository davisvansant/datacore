use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::AuthenticatorResponse;
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;

pub struct PublicKeyCredential {
    id: String,
    raw_id: Vec<u8>,
    response: AuthenticatorResponse,
    r#type: String,
}

pub struct CredentialCreationOptions {
    public_key: PublicKeyCredentialCreationOptions,
}

pub struct CredentialRequestOptions {
    public_key: PublicKeyCredentialRequestOptions,
}
