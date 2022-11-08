pub type ClientDataJSON = Vec<u8>;
pub type Signature = Vec<u8>;
pub type UserHandle = Vec<u8>;

#[derive(Debug)]
pub enum AuthenticatorResponse {
    AuthenticatorAttestationResponse(AuthenticatorAttestationResponse),
    AuthenticatorAssertionResponse(AuthenticatorAssertionResponse),
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: ClientDataJSON,
    pub authenticator_data: Vec<u8>,
    pub signature: Signature,
    pub user_handle: UserHandle,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
