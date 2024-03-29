use crate::api::credential_creation_options::{
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};
use crate::api::credential_generation_parameters::PublicKeyCredentialParameters;
use crate::api::supporting_data_structures::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialType,
};
use crate::authenticator::attestation::{
    AttestationObject, AttestationStatementFormat, AttestedCredentialData, COSEAlgorithm, COSEKey,
};
use crate::authenticator::data::AuthenticatorData;
use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::authenticator::store::CredentialsChannel;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::uuid::CredentialId;

use uuid::Uuid;

pub struct AuthenticatorMakeCrendential {
    hash: Vec<u8>,
    rp_entity: PublicKeyCredentialRpEntity,
    user_entity: PublicKeyCredentialUserEntity,
    require_resident_key: bool,
    require_user_presence: bool,
    require_user_verification: bool,
    cred_types_and_pub_key_apis: Vec<PublicKeyCredentialParameters>,
    exclude_credential_descriptor_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    enterprise_attestation_possible: bool,
    extensions: String,
}

impl AuthenticatorMakeCrendential {
    pub async fn collect_parameters(
        hash: Vec<u8>,
        rp_entity: PublicKeyCredentialRpEntity,
        user_entity: PublicKeyCredentialUserEntity,
        require_resident_key: bool,
        require_user_presence: bool,
        require_user_verification: bool,
        cred_types_and_pub_key_apis: Vec<PublicKeyCredentialParameters>,
        exclude_credential_descriptor_list: Option<Vec<PublicKeyCredentialDescriptor>>,
        enterprise_attestation_possible: bool,
        extensions: String,
    ) -> AuthenticatorMakeCrendential {
        AuthenticatorMakeCrendential {
            hash,
            rp_entity,
            user_entity,
            require_resident_key,
            require_user_presence,
            require_user_verification,
            cred_types_and_pub_key_apis,
            exclude_credential_descriptor_list,
            enterprise_attestation_possible,
            extensions,
        }
    }

    pub async fn check_parameters(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn check_supported_combinations(&self) -> Result<(), AuthenticationError> {
        let mut supported_combinations = Vec::with_capacity(5);
        let eddsa = PublicKeyCredentialParameters {
            r#type: PublicKeyCredentialType::PublicKey,
            alg: -8,
        };

        supported_combinations.push(eddsa);

        let mut matched = Vec::with_capacity(1);

        for public_key_credential_parameter in &self.cred_types_and_pub_key_apis {
            for supported in &supported_combinations {
                match public_key_credential_parameter == supported {
                    true => {
                        matched.push(1);

                        break;
                    }
                    false => continue,
                }
            }
        }

        if !matched.is_empty() {
            Ok(())
        } else {
            Err(AuthenticationError {
                error: AuthenticationErrorType::NotSupportedError,
            })
        }
    }

    pub async fn authorize_disclosure(
        &self,
        store: &CredentialsChannel,
    ) -> Result<(), AuthenticationError> {
        if let Some(descriptor_list) = &self.exclude_credential_descriptor_list {
            for descriptor in descriptor_list {
                match store
                    .lookup(self.rp_entity.id.to_owned(), descriptor.id.to_owned())
                    .await
                {
                    Ok(credential) => {
                        match credential.rpid == self.rp_entity.id
                            && credential.r#type == descriptor.r#type
                        {
                            true => {
                                println!("consent to create new credential");

                                return Err(AuthenticationError {
                                    error: AuthenticationErrorType::NotAllowedError,
                                });
                            }
                            false => continue,
                        }
                    }
                    Err(_) => continue,
                }
            }
        } else {
            return Ok(());
        }

        Ok(())
    }

    pub async fn require_resident_key(&self) -> Result<(), AuthenticationError> {
        let client_side_credential_storage_modality = true;

        match self.require_resident_key {
            true => match client_side_credential_storage_modality {
                true => Ok(()),
                false => Err(AuthenticationError {
                    error: AuthenticationErrorType::ConstraintError,
                }),
            },
            false => Ok(()),
        }
    }

    pub async fn require_user_verification(&self) -> Result<(), AuthenticationError> {
        let user_verification = true;

        match self.require_user_verification {
            true => match user_verification {
                true => Ok(()),
                false => Err(AuthenticationError {
                    error: AuthenticationErrorType::ConstraintError,
                }),
            },
            false => Ok(()),
        }
    }

    pub async fn collect_authorization_gesture(&self) -> Result<(), AuthenticationError> {
        match self.require_user_verification {
            true => println!("user verification"),
            false => {}
        }

        match self.require_user_presence {
            true => println!("test user presence"),
            false => {}
        }

        Ok(())
    }

    pub async fn generate_new_credential_object(
        &self,
        store: &CredentialsChannel,
    ) -> Result<(CredentialId, COSEKey), AuthenticationError> {
        let algorithm = COSEAlgorithm::from(self.cred_types_and_pub_key_apis[0].alg).await;
        let keypair = COSEKey::generate(algorithm).await;
        let credential_id = Uuid::new_v4().simple().into_uuid().into_bytes();
        let credential = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: credential_id.to_vec(),
            private_key: keypair.1,
            rpid: self.rp_entity.id.to_owned(),
            user_handle: self.user_entity.id.to_owned(),
            other_ui: String::from("some_other_ui"),
        };

        store
            .set(
                self.rp_entity.id.to_owned(),
                self.user_entity.id.to_owned(),
                credential,
            )
            .await?;

        Ok((credential_id.to_vec(), keypair.0))
    }

    pub async fn process_extensions(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn signature_counter(
        &self,
        store: &CredentialsChannel,
        // credential_id: [u8; 16],
        credential_id: &CredentialId,
    ) -> Result<(), AuthenticationError> {
        store.signature_counter(credential_id.to_owned()).await?;

        Ok(())
    }

    pub async fn attested_credential_data(
        &self,
        // credential_id: [u8; 16],
        credential_id: &CredentialId,
        public_key: COSEKey,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let attested_credential_data =
            AttestedCredentialData::generate(credential_id, public_key).await?;

        Ok(attested_credential_data)
    }

    pub async fn authenticator_data(
        &self,
        attested_credential_data: Vec<u8>,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let authenticator_data = AuthenticatorData::generate(
            &self.rp_entity.id,
            self.require_user_presence,
            self.require_user_verification,
            [0; 4],
            Some(attested_credential_data),
            None,
        )
        .await;

        Ok(authenticator_data)
    }

    pub async fn create_attestation_object(
        &self,
        authenticator_data: Vec<u8>,
        store: &CredentialsChannel,
    ) -> Result<(), AuthenticationError> {
        let credential_source = store
            .lookup(self.rp_entity.id.to_owned(), self.user_entity.id.to_owned())
            .await?;
        let attestation_format = AttestationStatementFormat::Packed;
        let attestation_object = AttestationObject::generate(
            attestation_format,
            authenticator_data,
            &self.hash,
            credential_source.private_key,
        )
        .await?;

        println!("send this to the client -> {:?}", attestation_object);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::store::Credentials;

    #[tokio::test]
    async fn check_supported_combinations() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_make_credential = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: false,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_make_credential
            .check_supported_combinations()
            .await
            .is_ok());

        test_make_credential.cred_types_and_pub_key_apis.clear();
        test_make_credential
            .cred_types_and_pub_key_apis
            .push(PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -7,
            });

        assert!(test_make_credential
            .check_supported_combinations()
            .await
            .is_err());

        test_make_credential.cred_types_and_pub_key_apis.clear();
        test_make_credential
            .cred_types_and_pub_key_apis
            .push(PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -6,
            });
        test_make_credential
            .cred_types_and_pub_key_apis
            .push(PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -7,
            });
        test_make_credential
            .cred_types_and_pub_key_apis
            .push(PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            });

        assert!(test_make_credential
            .check_supported_combinations()
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authorize_disclosure() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let test_algorithm = COSEAlgorithm::EdDSA;
        let test_new_credential = COSEKey::generate(test_algorithm).await;
        let test_credential_id = b"cred_identifier_";
        let test_credential = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: test_credential_id.to_vec(),
            private_key: test_new_credential.1,
            rpid: String::from("some_relying_party_id"),
            user_handle: [0; 16].to_vec(),
            other_ui: String::from("some_other_ui"),
        };

        test_credentials_store
            .0
            .set(
                String::from("some_relying_party_id"),
                b"cred_identifier_".to_vec(),
                test_credential,
            )
            .await?;

        let mut test_make_credential = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: false,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_make_credential
            .authorize_disclosure(&test_credentials_store.0)
            .await
            .is_ok());

        test_make_credential.exclude_credential_descriptor_list =
            Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"cred_identifier_".to_vec(),
                transports: None,
            }]);

        assert!(test_make_credential
            .authorize_disclosure(&test_credentials_store.0)
            .await
            .is_ok());

        test_make_credential.rp_entity.id = String::from("some_relying_party_id");

        assert!(test_make_credential
            .authorize_disclosure(&test_credentials_store.0)
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn require_resident_key() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_make_credential = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: true,
            require_user_presence: false,
            require_user_verification: false,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_make_credential.require_resident_key().await.is_ok());

        test_make_credential.require_resident_key = false;

        assert!(test_make_credential.require_resident_key().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn require_user_verification() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_make_credential = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: true,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_make_credential
            .require_user_verification()
            .await
            .is_ok());

        test_make_credential.require_user_verification = false;

        assert!(test_make_credential
            .require_user_verification()
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn collect_authorization_gesture() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: true,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_ok.collect_authorization_gesture().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn generate_new_credential_object() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials_store = Credentials::init().await;
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: true,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        assert!(test_ok
            .generate_new_credential_object(&test_credentials_store.0)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials_store = Credentials::init().await;
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: true,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        // let test_credential_id: [u8; 16] = [0; 16].to_vec();
        let test_credential_id = [0u8; 16].to_vec();

        assert!(test_ok
            .signature_counter(&test_credentials_store.0, &test_credential_id)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn attested_credential_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: true,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let (test_credential_id, test_public_key) = test_ok
            .generate_new_credential_object(&test_credentials_store.0)
            .await?;

        assert!(test_ok
            .attested_credential_data(&test_credential_id, test_public_key)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: true,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let (test_credential_id, test_public_key) = test_ok
            .generate_new_credential_object(&test_credentials_store.0)
            .await?;
        let test_attested_credential_data = test_ok
            .attested_credential_data(&test_credential_id, test_public_key)
            .await?;

        assert!(test_ok
            .authenticator_data(test_attested_credential_data)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn create_attestation_object() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                name: String::from("some_rp_name"),
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16].to_vec(),
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: true,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let (test_credential_id, test_public_key) = test_ok
            .generate_new_credential_object(&test_credentials_store.0)
            .await?;
        let test_attested_credential_data = test_ok
            .attested_credential_data(&test_credential_id, test_public_key)
            .await?;
        let test_authenticator_data = test_ok
            .authenticator_data(test_attested_credential_data)
            .await?;

        assert!(test_ok
            .create_attestation_object(test_authenticator_data, &test_credentials_store.0)
            .await
            .is_ok());

        Ok(())
    }
}
