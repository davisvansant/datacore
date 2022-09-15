use crate::error::{AuthenticationError, AuthenticationErrorType};

pub struct AssertionSignature {
    authenticator_data: Vec<u8>,
    client_data_hash: Vec<u8>,
}

impl AssertionSignature {
    pub async fn generate(
        authenticator_data: Vec<u8>,
        client_data_hash: Vec<u8>,
    ) -> AssertionSignature {
        AssertionSignature {
            authenticator_data,
            client_data_hash,
        }
    }

    pub async fn sign(&self, private_key: Vec<u8>) -> Result<Vec<u8>, AuthenticationError> {
        Err(AuthenticationError {
            error: AuthenticationErrorType::UnknownError,
        })
    }
}
