pub enum AuthenticatorResponse {
    AuthenticatorAttestationResponse(AuthenticatorAttestationResponse),
    AuthenticatorAssertionResponse(AuthenticatorAssertionResponse),
}

#[derive(Clone)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

impl AuthenticatorAttestationResponse {
    pub async fn generate() -> AuthenticatorAttestationResponse {
        let client_data_json = Vec::with_capacity(0);
        let attestation_object = Vec::with_capacity(0);

        AuthenticatorAttestationResponse {
            client_data_json,
            attestation_object,
        }
    }
}

#[derive(Clone)]
pub struct AuthenticatorAssertionResponse {
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}
