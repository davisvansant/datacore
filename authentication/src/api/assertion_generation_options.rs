use crate::api::extensions_inputs_and_outputs::AuthenticationExensionsClientInputs;
use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;

pub struct PublicKeyCredentialRequestOptions {
    challenge: Vec<u8>,
    timeout: u32,
    rp_id: String,
    allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    user_verification: String,
    extensions: Option<AuthenticationExensionsClientInputs>,
}
