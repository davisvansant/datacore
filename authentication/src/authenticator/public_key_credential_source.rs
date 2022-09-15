pub struct PublicKeyCredentialSource {
    pub public_key_credential_type: String,
    pub id: String,
    pub private_key: String,
    pub rpid: String,
    pub user_handle: String,
    pub other_ui: String,
}

impl PublicKeyCredentialSource {
    pub async fn generate() -> PublicKeyCredentialSource {
        let public_key_credential_type = String::from("build an enum here");
        let id = String::from("some_id");
        let private_key = String::from("some_private_key");
        let rpid = String::from("some_rpid");
        let user_handle = String::from("some_user_handle");
        let other_ui = String::from("some_other_ui");

        PublicKeyCredentialSource {
            public_key_credential_type,
            id,
            private_key,
            rpid,
            user_handle,
            other_ui,
        }
    }
}
