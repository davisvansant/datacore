use crate::authenticator::attestation::AttestedCredentialData;

pub struct AuthenticatorData {
    pub rpidhash: String,
    pub flags: String,
    pub signcount: String,
    pub attestedcredentialdata: AttestedCredentialData,
    pub extensions: String,
}

impl AuthenticatorData {
    pub async fn generate(attestedcredentialdata: AttestedCredentialData) -> AuthenticatorData {
        let rpidhash = String::from("some_rpid_hash");
        let flags = String::from("some_flags");
        let signcount = String::from("some_sign_count");
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
