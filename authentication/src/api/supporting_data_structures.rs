pub struct CollectedClientData {
    pub r#type: String,
    pub challenge: Vec<u8>,
    pub origin: String,
    pub cross_origin: bool,
    pub token_binding: Option<TokenBinding>,
}

impl CollectedClientData {
    pub async fn generate() -> CollectedClientData {
        let r#type = String::from("some_type");
        let challenge = Vec::with_capacity(0);
        let origin = String::from("some_origin");
        let cross_origin = false;
        let token_binding = Some(TokenBinding::generate().await);

        CollectedClientData {
            r#type,
            challenge,
            origin,
            cross_origin,
            token_binding,
        }
    }
}

#[derive(PartialEq)]
pub struct TokenBinding {
    status: TokenBindingStatus,
    id: String,
}

impl TokenBinding {
    pub async fn generate() -> TokenBinding {
        let status = TokenBindingStatus::Present;
        let id = String::from("some_id");

        TokenBinding { status, id }
    }
}

#[derive(PartialEq)]
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
