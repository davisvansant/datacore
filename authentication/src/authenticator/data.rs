use serde::{Deserialize, Serialize};

use crate::authenticator::attestation::AttestedCredentialData;
use crate::error::{AuthenticationError, AuthenticationErrorType};
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
    pub sign_count: SignCount,
    pub attested_credential_data: Option<Vec<u8>>,
    pub extensions: Option<Vec<u8>>,
}

impl AuthenticatorData {
    pub async fn generate(
        rp_id: &str,
        user_present: bool,
        user_verified: bool,
        sign_count: SignCount,
        attested_credential_data: Option<Vec<u8>>,
        extensions: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let rp_id_hash = generate_hash(rp_id.as_bytes()).await;
        let flags = 0b0000_0000;

        let mut authenticator_data = AuthenticatorData {
            rp_id_hash,
            flags,
            sign_count,
            attested_credential_data,
            extensions,
        };

        if user_present {
            authenticator_data.set_user_present().await;
        }

        if user_verified {
            authenticator_data.set_user_verifed().await;
        }

        if authenticator_data.attested_credential_data.is_some() {
            authenticator_data
                .set_attested_credential_data_included()
                .await;
        }

        if authenticator_data.extensions.is_some() {
            authenticator_data.set_extension_data_included().await;
        }

        let mut authenticator_data_byte_array: Vec<u8> = Vec::with_capacity(1000);

        for element in &authenticator_data.rp_id_hash {
            authenticator_data_byte_array.push(*element);
        }

        authenticator_data_byte_array.push(authenticator_data.flags);

        for element in authenticator_data.sign_count {
            authenticator_data_byte_array.push(element);
        }

        if let Some(attested_credential_data) = &authenticator_data.attested_credential_data {
            for element in attested_credential_data {
                authenticator_data_byte_array.push(*element);
            }
        }

        if let Some(extensions) = &authenticator_data.extensions {
            for element in extensions {
                authenticator_data_byte_array.push(*element);
            }
        }

        authenticator_data_byte_array.shrink_to_fit();
        authenticator_data_byte_array
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

    pub async fn from_byte_array(data: &[u8]) -> AuthenticatorData {
        if data.len() == 37 {
            let (rp_id_hash, remaining) = data.split_at(32);
            let (flags, sign_count_data) = remaining.split_at(1);

            let mut sign_count: [u8; 4] = [0; 4];

            sign_count.copy_from_slice(sign_count_data);

            AuthenticatorData {
                rp_id_hash: rp_id_hash.to_vec(),
                flags: flags[0],
                sign_count,
                attested_credential_data: None,
                extensions: None,
            }
        } else {
            let (rp_id_hash, remaining) = data.split_at(32);
            let (flags, remaining) = remaining.split_at(1);
            let (sign_count_data, attested_credential_data) = remaining.split_at(4);

            let mut sign_count: [u8; 4] = [0; 4];

            sign_count.copy_from_slice(sign_count_data);

            AuthenticatorData {
                rp_id_hash: rp_id_hash.to_vec(),
                flags: flags[0],
                sign_count,
                attested_credential_data: Some(attested_credential_data.to_vec()),
                extensions: None,
            }
        }
    }

    pub async fn attested_credential_data(
        data: &[u8],
    ) -> Result<AttestedCredentialData, AuthenticationError> {
        if data.len() == 37 {
            Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })
        } else {
            let (rp_id_hash, remaining) = data.split_at(32);
            let (flags, remaining) = remaining.split_at(1);
            let (sign_count_data, attested_credential_data) = remaining.split_at(4);

            let mut sign_count: [u8; 4] = [0; 4];

            sign_count.copy_from_slice(sign_count_data);

            let authenticator_data = AuthenticatorData {
                rp_id_hash: rp_id_hash.to_vec(),
                flags: flags[0],
                sign_count,
                attested_credential_data: Some(attested_credential_data.to_vec()),
                extensions: None,
            };

            let data = match authenticator_data.attested_credential_data {
                Some(data) => data,
                None => {
                    return Err(AuthenticationError {
                        error: AuthenticationErrorType::OperationError,
                    });
                }
            };

            let attested_credential_data = AttestedCredentialData::from_byte_array(&data).await;

            Ok(attested_credential_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::attestation::{AttestedCredentialData, COSEAlgorithm, COSEKey};

    #[tokio::test]
    async fn generate() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = true;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;

        for element in &test_authenticator_data {
            assert_eq!(std::mem::size_of_val(element), 1);
        }

        assert_eq!(test_authenticator_data.len(), 37);
        assert_eq!(test_authenticator_data.capacity(), 37);
        assert_eq!(std::mem::size_of_val(&*test_authenticator_data), 37);

        Ok(())
    }

    #[tokio::test]
    async fn flags_user_present() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_authenticator_data = AuthenticatorData {
            rp_id_hash: generate_hash(b"test_rp_id").await,
            flags: 0b0000_0000,
            sign_count: [0u8; 4],
            attested_credential_data: None,
            extensions: None,
        };

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
        let mut test_authenticator_data = AuthenticatorData {
            rp_id_hash: generate_hash(b"test_rp_id").await,
            flags: 0b0000_0000,
            sign_count: [0u8; 4],
            attested_credential_data: None,
            extensions: None,
        };

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
        let mut test_authenticator_data = AuthenticatorData {
            rp_id_hash: generate_hash(b"test_rp_id").await,
            flags: 0b0000_0000,
            sign_count: [0u8; 4],
            attested_credential_data: None,
            extensions: None,
        };

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
        let mut test_authenticator_data = AuthenticatorData {
            rp_id_hash: generate_hash(b"test_rp_id").await,
            flags: 0b0000_0000,
            sign_count: [0u8; 4],
            attested_credential_data: None,
            extensions: None,
        };

        assert_eq!(ED, 7);
        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(!test_authenticator_data.includes_extension_data().await);

        test_authenticator_data.set_extension_data_included().await;

        assert_eq!(std::mem::size_of_val(&test_authenticator_data.flags), 1);
        assert!(test_authenticator_data.includes_extension_data().await);

        Ok(())
    }

    #[tokio::test]
    async fn from_byte_array() -> Result<(), Box<dyn std::error::Error>> {
        let test_credential_id = [0u8; 16];
        let test_keypair = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_attested_credential_data =
            AttestedCredentialData::generate(test_credential_id, test_keypair.0).await?;
        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = true;
        let test_sign_count = 1000_u32.to_be_bytes();
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            Some(test_attested_credential_data),
            None,
        )
        .await;
        let test_from_byte_array =
            AuthenticatorData::from_byte_array(&test_authenticator_data).await;

        assert_eq!(
            test_from_byte_array.rp_id_hash,
            generate_hash(b"test_rp_id").await,
        );
        assert!(
            test_from_byte_array
                .includes_attested_credential_data()
                .await
        );
        assert!(!test_from_byte_array.includes_extension_data().await);
        assert_eq!(test_from_byte_array.sign_count, 1000_u32.to_be_bytes());
        assert!(test_from_byte_array.attested_credential_data.is_some());
        assert!(test_from_byte_array.extensions.is_none());

        Ok(())
    }
}
