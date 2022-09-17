pub struct CollectedClientData {
    signature_confusion_attack_type: String,
    challenge: String,
    origin: String,
    cross_origin: bool,
    token_binding: Option<TokenBinding>,
}

pub struct TokenBinding {
    status: TokenBindingStatus,
    id: String,
}

pub enum TokenBindingStatus {
    Present,
    Supported,
}

pub enum PublicKeyCredentialType {
    PublicKey,
}

pub struct PublicKeyCredentialDescriptor {
    public_key_credential_type: String,
    id: Vec<u8>,
    transports: Option<Vec<String>>,
}

pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Internal,
}

pub type COSEAlgorithmIdentifier = u32;

pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}
