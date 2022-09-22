pub struct AuthenticatorData {
    pub rpidhash: String,
    pub flags: String,
    pub signcount: String,
    pub attestedcredentialdata: String,
    pub extensions: String,
}

impl AuthenticatorData {
    pub async fn generate() -> AuthenticatorData {
        let rpidhash = String::from("some_rpid_hash");
        let flags = String::from("some_flags");
        let signcount = String::from("some_sign_count");
        let attestedcredentialdata = String::from("some_attested_credential_data");
        let extensions = String::from("some_exentions");

        AuthenticatorData {
            rpidhash,
            flags,
            signcount,
            attestedcredentialdata,
            extensions,
        }
    }
}
