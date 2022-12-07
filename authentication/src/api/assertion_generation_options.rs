use serde::{Deserialize, Serialize};

use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientInputs;
use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;
use crate::security::challenge::{base64_encode_challenge, generate_challenge};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: Vec<u8>,
    pub timeout: u64,
    pub rp_id: String,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub user_verification: String,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

impl PublicKeyCredentialRequestOptions {
    pub async fn generate() -> PublicKeyCredentialRequestOptions {
        let challenge = base64_encode_challenge(&generate_challenge().await)
            .await
            .as_bytes()
            .to_vec();
        let timeout = 0;
        let rp_id = String::from("some_rp_id");
        let allow_credentials = Vec::with_capacity(0);
        let user_verification = String::from("preferred");
        let extensions = None;

        PublicKeyCredentialRequestOptions {
            challenge,
            timeout,
            rp_id,
            allow_credentials,
            user_verification,
            extensions,
        }
    }
}
