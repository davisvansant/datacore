use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use uuid::{Bytes, Uuid};

use crate::api::credential_generation_parameters::PublicKeyCredentialParameters;
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientInputs;
use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;

pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: Challenge,
    pub public_key_credential_parameters: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    pub attestation: Option<String>,
    pub extensions: AuthenticationExtensionsClientInputs,
}

impl PublicKeyCredentialCreationOptions {
    pub async fn generate(
        user: PublicKeyCredentialUserEntity,
    ) -> PublicKeyCredentialCreationOptions {
        let rp = PublicKeyCredentialRpEntity {
            id: String::from("some_rp_entity"),
        };
        let challenge = Challenge::generate().await;
        let public_key_credential_parameters = Vec::with_capacity(0);
        let timeout = 0;
        let exclude_credentials = Vec::with_capacity(0);
        let authenticator_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: String::from("some_attachment"),
            resident_key: String::from("some_resident_key"),
            require_resident_key: false,
            user_verification: String::from("some_user_verification"),
        };
        let attestation = None;
        let extensions = AuthenticationExtensionsClientInputs {};

        PublicKeyCredentialCreationOptions {
            rp,
            user,
            challenge,
            public_key_credential_parameters,
            timeout,
            exclude_credentials,
            authenticator_selection,
            attestation,
            extensions,
        }
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub struct Challenge(pub [u8; 16]);

impl Challenge {
    pub async fn generate() -> Challenge {
        let mut rng = thread_rng();

        Challenge(rng.gen())
    }
}

pub struct PublicKeyCredentialEntity {
    pub name: String,
}

pub struct PublicKeyCredentialRpEntity {
    pub id: String,
}

#[derive(Eq, Hash, PartialEq)]
pub struct PublicKeyCredentialUserEntity {
    pub name: String,
    pub id: Bytes,
    pub display_name: String,
}

impl PublicKeyCredentialUserEntity {
    pub async fn generate(name: String, display_name: String) -> PublicKeyCredentialUserEntity {
        let id = Uuid::new_v4().into_bytes();

        PublicKeyCredentialUserEntity {
            name,
            id,
            display_name,
        }
    }
}

pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: String,
    pub resident_key: String,
    pub require_resident_key: bool,
    pub user_verification: String,
}

pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

pub enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn challenge() -> Result<(), Box<dyn std::error::Error>> {
        let test_challenge = Challenge::generate().await;

        assert_eq!(test_challenge.0.len(), 16);

        Ok(())
    }

    #[tokio::test]
    async fn public_key_credential_user_entity() -> Result<(), Box<dyn std::error::Error>> {
        let test_name = String::from("some_name");
        let test_display_name = String::from("some_display_name");
        let test_public_key_credential_user_entity =
            PublicKeyCredentialUserEntity::generate(test_name, test_display_name).await;

        assert_eq!(test_public_key_credential_user_entity.name, "some_name");
        assert_eq!(test_public_key_credential_user_entity.id.len(), 16);
        assert_eq!(
            test_public_key_credential_user_entity.display_name,
            "some_display_name",
        );

        Ok(())
    }
}
