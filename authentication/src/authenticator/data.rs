use sha2::{Digest, Sha256};

use crate::authenticator::attestation::AttestedCredentialData;

pub const UP: usize = 0;
pub const UV: usize = 2;
pub const AT: usize = 6;
pub const ED: usize = 7;
pub type RpIdHash = Vec<u8>;
pub type SignCount = u32;

#[derive(Clone)]
pub struct AuthenticatorData {
    pub rp_id_hash: RpIdHash,
    pub flags: [u8; 8],
    pub signcount: SignCount,
    pub attestedcredentialdata: AttestedCredentialData,
    pub extensions: String,
}

impl AuthenticatorData {
    pub async fn generate(
        rp_id: &str,
        attestedcredentialdata: AttestedCredentialData,
    ) -> AuthenticatorData {
        let rp_id_hash = hash(rp_id).await;
        let flags = [0; 8];
        let signcount = 0;
        let extensions = String::from("some_extensions");

        AuthenticatorData {
            rp_id_hash,
            flags,
            signcount,
            attestedcredentialdata,
            extensions,
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

async fn hash(rp_id: &str) -> RpIdHash {
    let mut sha256_hash = Sha256::new();

    sha256_hash.update(rp_id);
    let rp_id_hash = sha256_hash.finalize();

    rp_id_hash.to_vec()
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
        let test_rp_hash = super::hash(test_rp_id).await;

        assert_eq!(test_authenticator_data.rp_id_hash, test_rp_hash);
        assert_eq!(test_authenticator_data.flags.len(), 8);
        assert_eq!(test_authenticator_data.signcount, 0);
        assert_eq!(test_authenticator_data.extensions, "some_extensions");

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

    #[tokio::test]
    async fn hash() -> Result<(), Box<dyn std::error::Error>> {
        let test_empty_hash = super::hash("").await;
        let test_empty_hex =
            hex_literal::hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        assert_eq!(test_empty_hash, test_empty_hex);

        let test_hash = super::hash("test").await;
        let test_hash_error = super::hash("test.").await;
        let test_hex =
            hex_literal::hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");

        assert_eq!(test_hash, test_hex);
        assert_ne!(test_hash_error, test_hex);

        Ok(())
    }
}
