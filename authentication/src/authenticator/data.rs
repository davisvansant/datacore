use serde::{Deserialize, Serialize};

use crate::authenticator::attestation::AttestedCredentialData;
use crate::security::sha2::generate_hash;

pub const UP: usize = 0;
pub const UV: usize = 2;
pub const AT: usize = 6;
pub const ED: usize = 7;
pub type RpIdHash = Vec<u8>;
pub type SignCount = u32;

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct AuthenticatorData {
    pub rp_id_hash: RpIdHash,
    pub flags: [u8; 8],
    pub signcount: SignCount,
    pub attestedcredentialdata: Option<AttestedCredentialData>,
    pub extensions: Option<String>,
}

impl AuthenticatorData {
    pub async fn generate(
        rp_id: &str,
        attestedcredentialdata: AttestedCredentialData,
    ) -> AuthenticatorData {
        let rp_id_hash = generate_hash(rp_id.as_bytes()).await;
        let flags = [0; 8];
        let signcount = 0;
        // let extensions = String::from("some_extensions");

        AuthenticatorData {
            rp_id_hash,
            flags,
            signcount,
            attestedcredentialdata: Some(attestedcredentialdata),
            extensions: None,
        }
    }

    pub async fn set_user_present(&mut self) {
        self.flags[UP] = 1
    }

    pub async fn set_user_not_present(&mut self) {
        self.flags[UP] = 0
    }

    pub async fn set_user_verifed(&mut self) {
        self.flags[UV] = 1
    }

    pub async fn set_user_not_verified(&mut self) {
        self.flags[UV] = 0
    }

    pub async fn set_attested_credential_data_included(&mut self) {
        self.flags[AT] = 1
    }

    pub async fn set_extension_data_included(&mut self) {
        self.flags[ED] = 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;
        let test_rp_hash = generate_hash(test_rp_id.as_bytes()).await;

        assert_eq!(test_authenticator_data.rp_id_hash, test_rp_hash);
        assert_eq!(test_authenticator_data.flags.len(), 8);
        assert_eq!(test_authenticator_data.signcount, 0);
        // assert_eq!(test_authenticator_data.extensions, "some_extensions");

        Ok(())
    }

    #[tokio::test]
    async fn flags_user_present() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;

        assert_eq!(UP, 0);
        assert_eq!(test_authenticator_data.flags[UP], 0);

        test_authenticator_data.set_user_present().await;

        assert_eq!(test_authenticator_data.flags[UP], 1);

        test_authenticator_data.set_user_not_present().await;

        assert_eq!(test_authenticator_data.flags[UP], 0);

        Ok(())
    }

    #[tokio::test]
    async fn flags_user_verified() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;

        assert_eq!(UV, 2);
        assert_eq!(test_authenticator_data.flags[UV], 0);

        test_authenticator_data.set_user_verifed().await;

        assert_eq!(test_authenticator_data.flags[UV], 1);

        test_authenticator_data.set_user_not_verified().await;

        assert_eq!(test_authenticator_data.flags[UV], 0);

        Ok(())
    }

    #[tokio::test]
    async fn flags_attested_credential_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;

        assert_eq!(AT, 6);
        assert_eq!(test_authenticator_data.flags[AT], 0);

        test_authenticator_data
            .set_attested_credential_data_included()
            .await;

        assert_eq!(test_authenticator_data.flags[AT], 1);

        Ok(())
    }

    #[tokio::test]
    async fn flags_extension_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;

        assert_eq!(ED, 7);
        assert_eq!(test_authenticator_data.flags[ED], 0);

        test_authenticator_data.set_extension_data_included().await;

        assert_eq!(test_authenticator_data.flags[ED], 1);

        Ok(())
    }
}
