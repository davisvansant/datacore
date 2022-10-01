use crate::authenticator::attestation::AttestationObject;
use crate::authenticator::data::AuthenticatorData;

pub type ClientDataJSON = Vec<u8>;
pub type Signature = Vec<u8>;
pub type UserHandle = Vec<u8>;

pub enum AuthenticatorResponse {
    AuthenticatorAttestationResponse(AuthenticatorAttestationResponse),
    AuthenticatorAssertionResponse(AuthenticatorAssertionResponse),
}

#[derive(Clone)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: ClientDataJSON,
    pub attestation_object: AttestationObject,
}

impl AuthenticatorAttestationResponse {
    pub async fn generate(
        attestation_object: AttestationObject,
    ) -> AuthenticatorAttestationResponse {
        let client_data_json = Vec::with_capacity(0);

        AuthenticatorAttestationResponse {
            client_data_json,
            attestation_object,
        }
    }
}

#[derive(Clone)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: ClientDataJSON,
    pub authenticator_data: AuthenticatorData,
    pub signature: Signature,
    pub user_handle: UserHandle,
}
