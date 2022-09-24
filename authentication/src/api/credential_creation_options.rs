use crate::api::credential_generation_parameters::PublicKeyCredentialParameters;
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientInputs;
use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;

pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: Vec<u8>,
    pub public_key_credential_parameters: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    pub attestation: Option<String>,
    pub extensions: AuthenticationExtensionsClientInputs,
}

impl PublicKeyCredentialCreationOptions {
    pub async fn generate() -> PublicKeyCredentialCreationOptions {
        let rp = PublicKeyCredentialRpEntity {
            id: String::from("some_rp_entity"),
        };
        let user = PublicKeyCredentialUserEntity {
            id: Vec::with_capacity(0),
            display_name: String::from("some_display_name"),
        };
        let challenge = Vec::with_capacity(0);
        let public_key_credential_parameters = Vec::with_capacity(0);
        let timeout = 0;
        let exclude_credentials = Vec::with_capacity(0);
        let authenticator_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: String::from("some_attachment"),
            resident_key: String::from("some_resident_key"),
            require_resident_key: false,
            user_verification: String::from("some_user_verification"),
        };
        let attestation = None;
        let extensions = AuthenticationExtensionsClientInputs {};

        PublicKeyCredentialCreationOptions {
            rp,
            user,
            challenge,
            public_key_credential_parameters,
            timeout,
            exclude_credentials,
            authenticator_selection,
            attestation,
            extensions,
        }
    }
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
