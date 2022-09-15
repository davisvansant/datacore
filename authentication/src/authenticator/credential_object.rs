use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;

pub struct CredentialObject {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    user_handle: String,
    credential_source: PublicKeyCredentialSource,
    credential_id: String,
    credentials: String,
}

impl CredentialObject {
    pub async fn generate() -> CredentialObject {
        let public_key = Vec::with_capacity(0);
        let private_key = Vec::with_capacity(0);
        let user_handle = String::from("some_user_handle");
        let credential_source = PublicKeyCredentialSource::generate().await;
        let credential_id = String::from("some_credential_id");
        let credentials = String::from("some_credentials");

        CredentialObject {
            public_key,
            private_key,
            user_handle,
            credential_source,
            credential_id,
            credentials,
        }
    }
}
