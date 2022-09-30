use crate::api::credential_creation_options::Challenge;
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientInputs;
use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;

pub struct PublicKeyCredentialRequestOptions {
    pub challenge: Challenge,
    pub timeout: u32,
    pub rp_id: String,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub user_verification: String,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

impl PublicKeyCredentialRequestOptions {
    pub async fn generate() -> PublicKeyCredentialRequestOptions {
        let challenge = Challenge::generate().await;
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
