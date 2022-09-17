use crate::api::credential_generation_parameters::PublicKeyCredentialParameters;
use crate::api::extensions_inputs_and_outputs::AuthenticationExensionsClientInputs;
use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;

pub struct PublicKeyCredentialCreationOptions {
    rp: PublicKeyCredentialRpEntity,
    user: PublicKeyCredentialUserEntity,
    challenge: Vec<u8>,
    public_key_credential_parameters: Vec<PublicKeyCredentialParameters>,
    timeout: u32,
    exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    authenticator_selection: AuthenticatorSelectionCriteria,
    attestation: Option<String>,
    extensions: AuthenticationExensionsClientInputs,
}

pub struct PublicKeyCredentialEntity {
    name: String,
}

pub struct PublicKeyCredentialRpEntity {
    id: String,
}

pub struct PublicKeyCredentialUserEntity {
    id: Vec<u8>,
    display_name: String,
}

pub struct AuthenticatorSelectionCriteria {
    authenticator_attachment: String,
    resident_key: String,
    require_resident_key: bool,
    user_verification: String,
}

pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

pub enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}
