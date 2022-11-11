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
use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::collections::HashMap;

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

    pub async fn authorize_disclosure(&self) -> Result<(), AuthenticationError> {
        let mut credentials = HashMap::with_capacity(1);
        let test_credential_id = String::from("some_credential_id").as_bytes().to_vec();
        let internal_credential_for_testing = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: b"cred_identifier_".to_owned(),
            private_key: Vec::with_capacity(0),
            rpid: String::from("some_relying_party_id"),
            user_handle: [0; 16],
            other_ui: String::from("some_other_ui"),
        };

        credentials.insert(test_credential_id, internal_credential_for_testing);

        if let Some(descriptor_list) = &self.exclude_credential_descriptor_list {
            for descriptor in descriptor_list {
                match credentials.get(&descriptor.id) {
                    Some(credential) => {
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
                    None => continue,
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

    pub async fn generate_new_credential_object(&self) -> Result<(), AuthenticationError> {
        let algorithm = COSEAlgorithm::from(self.cred_types_and_pub_key_apis[0].alg).await;
        let new_credential = COSEKey::generate(algorithm).await;
        let credential_id = [0; 16];
        let credential = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: credential_id,
            private_key: new_credential.1.to_bytes().to_vec(),
            rpid: self.rp_entity.id.to_owned(),
            user_handle: self.user_entity.id,
            other_ui: String::from("some_other_ui"),
        };
        let mut credentials = HashMap::with_capacity(1);

        credentials.insert(credential_id, credential);

        Ok(())
    }

    pub async fn process_extensions(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn signature_counter(&self) -> Result<(), AuthenticationError> {
        let mut signature_counter = HashMap::with_capacity(1);
        let credential_id = [0; 16];

        signature_counter.insert(credential_id, 0);

        Ok(())
    }

    pub async fn attested_credential_data(
        &self,
    ) -> Result<AttestedCredentialData, AuthenticationError> {
        let aaguid = [0; 128].to_vec();
        let credential_id = [0; 16];
        let public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;

        let attested_credential_data = AttestedCredentialData {
            aaguid,
            credential_id_length: credential_id.len().to_be_bytes(),
            credential_id: credential_id.to_vec(),
            credential_public_key: public_key.0,
        };

        Ok(attested_credential_data)
    }

    pub async fn authenticator_data(
        &self,
        attested_credential_data: AttestedCredentialData,
    ) -> Result<AuthenticatorData, AuthenticationError> {
        let authenticator_data =
            AuthenticatorData::generate(&self.rp_entity.id, attested_credential_data).await;

        Ok(authenticator_data)
    }

    pub async fn create_attestation_object(
        &self,
        authenticator_data: AuthenticatorData,
    ) -> Result<AttestationObject, AuthenticationError> {
        let attestation_format = AttestationStatementFormat::Packed;
        let attestation_object =
            AttestationObject::generate(attestation_format, authenticator_data, &self.hash).await?;

        Ok(attestation_object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_supported_combinations() -> Result<(), Box<dyn std::error::Error>> {
        let test_supported = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_supported.check_supported_combinations().await.is_ok());

        let test_unsupported = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: false,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -7,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_unsupported
            .check_supported_combinations()
            .await
            .is_err());

        let test_supported_unsupported = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),

                id: [0; 16],
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: false,
            cred_types_and_pub_key_apis: vec![
                PublicKeyCredentialParameters {
                    r#type: PublicKeyCredentialType::PublicKey,
                    alg: -6,
                },
                PublicKeyCredentialParameters {
                    r#type: PublicKeyCredentialType::PublicKey,
                    alg: -7,
                },
                PublicKeyCredentialParameters {
                    r#type: PublicKeyCredentialType::PublicKey,
                    alg: -8,
                },
            ],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_supported_unsupported
            .check_supported_combinations()
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authorize_disclosure() -> Result<(), Box<dyn std::error::Error>> {
        let test_none = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_none.authorize_disclosure().await.is_ok());

        let test_some_unmatched = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: false,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"some_id".to_vec(),
                transports: None,
            }]),
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_some_unmatched.authorize_disclosure().await.is_ok());

        let test_some_matched = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_relying_party_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: false,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            }],
            exclude_credential_descriptor_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"some_credential_id".to_vec(),
                transports: None,
            }]),
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_some_matched.authorize_disclosure().await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn require_resident_key() -> Result<(), Box<dyn std::error::Error>> {
        let test_true = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_true.require_resident_key().await.is_ok());

        let test_false = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_false.require_resident_key().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn require_user_verification() -> Result<(), Box<dyn std::error::Error>> {
        let test_true = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_true.require_user_verification().await.is_ok());

        let test_false = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_false.require_user_verification().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn collect_authorization_gesture() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_ok.generate_new_credential_object().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_ok.signature_counter().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn attested_credential_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        assert!(test_ok.attested_credential_data().await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorMakeCrendential {
            hash: Vec::with_capacity(0),
            rp_entity: PublicKeyCredentialRpEntity {
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        let test_attested_credential_data = test_ok.attested_credential_data().await.unwrap();

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
                id: String::from("some_id"),
            },
            user_entity: PublicKeyCredentialUserEntity {
                name: String::from("some_name"),
                display_name: String::from("some_display_name"),
                id: [0; 16],
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

        let test_attested_credential_data = test_ok.attested_credential_data().await.unwrap();
        let test_authenticator_data = test_ok
            .authenticator_data(test_attested_credential_data)
            .await
            .unwrap();

        assert!(test_ok
            .create_attestation_object(test_authenticator_data)
            .await
            .is_ok());

        Ok(())
    }
}
