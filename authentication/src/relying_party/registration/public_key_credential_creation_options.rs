pub struct PublicKeyCredentialRpEntity {
    id: String,
}

pub struct PublicKeyCredentialUserEntity {
    id: Vec<u8>,
    display_name: String,
}

pub struct PublicKeyCredentialParameters {
    public_key_credential_type: String,
    algorithm: i32,
}

pub struct PublicKeyCredentialDescriptor {
    public_key_credential_type: String,
    id: Vec<u8>,
    transports: Option<Vec<String>>,
}

pub struct AuthenticatorSelectionCriteria {
    authenticator_attachment: String,
    resident_key: String,
    require_resident_key: bool,
    user_verification: String,
}

pub struct AuthenticationExensionsClientInputs {}

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
