pub struct AuthenticatorResponse {
    client_data_json: Vec<u8>,
}

pub struct AuthenticatorAttestationResponse {
    client_data_json: Vec<u8>,
    attestation_object: Vec<u8>,
}

pub struct AuthenticatorAssertionResponse {
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    user_handle: Vec<u8>,
}
