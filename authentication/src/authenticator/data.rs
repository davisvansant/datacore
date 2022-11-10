use serde::{Deserialize, Serialize};

use crate::authenticator::attestation::AttestedCredentialData;
use crate::security::sha2::generate_hash;

pub const UP: u8 = 0;
pub const UV: u8 = 2;
pub const AT: u8 = 6;
pub const ED: u8 = 7;
pub type RpIdHash = Vec<u8>;
pub type SignCount = u32;

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct AuthenticatorData {
    pub rp_id_hash: RpIdHash,
    pub flags: u8,
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
        let flags = 0b0000_0000;
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
        self.flags |= 1 << UP
    }

    pub async fn set_user_not_present(&mut self) {
        self.flags &= !(1 << UP)
    }

    pub async fn set_user_verifed(&mut self) {
        self.flags |= 1 << UV
    }

    pub async fn set_user_not_verified(&mut self) {
        self.flags &= !(1 << UV)
    }

    pub async fn set_attested_credential_data_included(&mut self) {
        self.flags |= 1 << AT
    }

    pub async fn set_extension_data_included(&mut self) {
        self.flags |= 1 << ED
    }

    pub async fn user_present(&self) -> bool {
        (1 << UP & self.flags) > 0
    }

    pub async fn user_verified(&self) -> bool {
        (1 << UV & self.flags) > 0
    }

    pub async fn includes_attested_credential_data(&self) -> bool {
        (1 << AT & self.flags) > 0
    }

    pub async fn includes_extension_data(&self) -> bool {
        (1 << ED & self.flags) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;
        let test_rp_hash = generate_hash(test_rp_id.as_bytes()).await;

        assert_eq!(test_authenticator_data.rp_id_hash, test_rp_hash);
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert_eq!(test_authenticator_data.signcount, 0);

        test_authenticator_data.set_user_present().await;
        test_authenticator_data.set_user_verifed().await;
        test_authenticator_data
            .set_attested_credential_data_included()
            .await;
        test_authenticator_data.set_extension_data_included().await;

        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);

        Ok(())
    }

    #[tokio::test]
    async fn flags_user_present() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;

        assert_eq!(UP, 0);
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(!test_authenticator_data.user_present().await);

        test_authenticator_data.set_user_present().await;

        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(test_authenticator_data.user_present().await);

        test_authenticator_data.set_user_not_present().await;

        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(!test_authenticator_data.user_present().await);

        Ok(())
    }

    #[tokio::test]
    async fn flags_user_verified() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;

        assert_eq!(UV, 2);
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(!test_authenticator_data.user_verified().await);

        test_authenticator_data.set_user_verifed().await;
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(test_authenticator_data.user_verified().await);

        test_authenticator_data.set_user_not_verified().await;

        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(!test_authenticator_data.user_verified().await);

        Ok(())
    }

    #[tokio::test]
    async fn flags_attested_credential_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;

        assert_eq!(AT, 6);
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(
            !test_authenticator_data
                .includes_attested_credential_data()
                .await
        );

        test_authenticator_data
            .set_attested_credential_data_included()
            .await;

        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(
            test_authenticator_data
                .includes_attested_credential_data()
                .await
        );

        Ok(())
    }

    #[tokio::test]
    async fn flags_extension_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data).await;

        assert_eq!(ED, 7);
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(!test_authenticator_data.includes_extension_data().await);

        test_authenticator_data.set_extension_data_included().await;

        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(test_authenticator_data.includes_extension_data().await);

        Ok(())
    }
}
