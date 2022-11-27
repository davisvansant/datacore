use serde::{Deserialize, Serialize};

use crate::authenticator::attestation::AttestedCredentialData;
use crate::security::sha2::generate_hash;

pub const UP: u8 = 0;
pub const UV: u8 = 2;
pub const AT: u8 = 6;
pub const ED: u8 = 7;
pub type RpIdHash = Vec<u8>;
pub type SignCount = [u8; 4];

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct AuthenticatorData {
    pub rp_id_hash: RpIdHash,
    pub flags: u8,
    pub signcount: SignCount,
    pub attested_credential_data: Option<Vec<u8>>,
    pub extensions: Option<String>,
}

impl AuthenticatorData {
    pub async fn generate(rp_id: &str, attested_credential_data: Vec<u8>) -> AuthenticatorData {
        let rp_id_hash = generate_hash(rp_id.as_bytes()).await;
        let flags = 0b0000_0000;
        let signcount = 0_u32.to_be_bytes();
        // let extensions = String::from("some_extensions");

        AuthenticatorData {
            rp_id_hash,
            flags,
            signcount,
            attested_credential_data: Some(attested_credential_data),
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

    pub async fn to_byte_array(&self) -> Vec<u8> {
        let mut authenticator_data: Vec<u8> = Vec::with_capacity(1000);

        for element in &self.rp_id_hash {
            authenticator_data.push(*element);
        }

        authenticator_data.push(self.flags);

        for element in self.signcount {
            authenticator_data.push(element);
        }

        if let Some(attested_credential_data) = &self.attested_credential_data {
            for element in attested_credential_data {
                authenticator_data.push(*element);
            }
        }

        authenticator_data.shrink_to_fit();
        authenticator_data
    }

    pub async fn from_byte_array(data: &[u8]) -> AuthenticatorData {
        if data.len() == 37 {
            let (rp_id_hash, remaining) = data.split_at(32);
            let (flags, sign_count_data) = remaining.split_at(1);

            let mut signcount: [u8; 4] = [0; 4];

            signcount.copy_from_slice(sign_count_data);

            AuthenticatorData {
                rp_id_hash: rp_id_hash.to_vec(),
                flags: flags[0],
                signcount,
                attested_credential_data: None,
                extensions: None,
            }
        } else {
            let (rp_id_hash, remaining) = data.split_at(32);
            let (flags, remaining) = remaining.split_at(1);
            let (sign_count_data, attested_credential_data) = remaining.split_at(4);

            let mut signcount: [u8; 4] = [0; 4];

            signcount.copy_from_slice(sign_count_data);

            AuthenticatorData {
                rp_id_hash: rp_id_hash.to_vec(),
                flags: flags[0],
                signcount,
                attested_credential_data: Some(attested_credential_data.to_vec()),
                extensions: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data_byte_array).await;
        let test_rp_hash = generate_hash(test_rp_id.as_bytes()).await;

        assert_eq!(test_authenticator_data.rp_id_hash, test_rp_hash);
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert_eq!(test_authenticator_data.signcount, [0; 4]);

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
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data_byte_array).await;

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
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data_byte_array).await;

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
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data_byte_array).await;

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
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data_byte_array).await;

        assert_eq!(ED, 7);
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(!test_authenticator_data.includes_extension_data().await);

        test_authenticator_data.set_extension_data_included().await;

        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(test_authenticator_data.includes_extension_data().await);

        Ok(())
    }

    #[tokio::test]
    async fn to_byte_array() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data_byte_array).await;

        let test_byte_array = test_authenticator_data.to_byte_array().await;

        for element in &test_byte_array {
            assert_eq!(std::mem::size_of_val(element), 1);
        }

        assert!(test_byte_array.len() >= 37);
        assert!(test_byte_array.capacity() >= 37);
        assert!(std::mem::size_of_val(&*test_byte_array) >= 37);

        test_authenticator_data
            .set_attested_credential_data_included()
            .await;
        test_authenticator_data.set_extension_data_included().await;
        test_authenticator_data.signcount = 1000_u32.to_be_bytes();

        let test_other_byte_array = test_authenticator_data.to_byte_array().await;

        for element in &test_other_byte_array {
            assert_eq!(std::mem::size_of_val(element), 1);
        }

        assert!(test_other_byte_array.len() >= 37);
        assert!(test_other_byte_array.capacity() >= 37);
        assert!(std::mem::size_of_val(&*test_other_byte_array) >= 37);

        Ok(())
    }

    #[tokio::test]
    async fn from_byte_array() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate(test_rp_id, test_attested_credential_data_byte_array).await;

        test_authenticator_data
            .set_attested_credential_data_included()
            .await;
        test_authenticator_data.set_extension_data_included().await;
        test_authenticator_data.signcount = 1000_u32.to_be_bytes();

        let test_byte_array = test_authenticator_data.to_byte_array().await;
        let test_from_byte_array = AuthenticatorData::from_byte_array(&test_byte_array).await;

        assert_eq!(
            test_from_byte_array.rp_id_hash,
            generate_hash(b"test_rp_id").await,
        );
        assert!(
            test_from_byte_array
                .includes_attested_credential_data()
                .await
        );
        assert!(test_from_byte_array.includes_extension_data().await);
        assert_eq!(test_from_byte_array.signcount, 1000_u32.to_be_bytes());
        // assert!(test_from_byte_array.attestedcredentialdata.is_none());
        assert!(test_from_byte_array.attested_credential_data.is_some());
        assert!(test_from_byte_array.extensions.is_none());

        Ok(())
    }
}
