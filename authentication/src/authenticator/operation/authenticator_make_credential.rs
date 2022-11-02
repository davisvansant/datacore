use crate::api::credential_creation_options::{
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};
use crate::api::credential_generation_parameters::PublicKeyCredentialParameters;
use crate::api::supporting_data_structures::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialType,
};
use crate::authenticator::attestation::{
    AttestationObject, AttestationStatementFormat, AttestedCredentialData,
};
// use crate::authenticator::credential_object::CredentialObject;
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
            algorithm: -8,
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
            id: String::from("some_credential_id"),
            private_key: String::from("some_private_key"),
            rpid: String::from("some_relying_party_id"),
            user_handle: String::from("some_user_handle"),
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

    pub async fn process_extensions(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn signature_counter(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn attested_credential_data(
        &self,
    ) -> Result<AttestedCredentialData, AuthenticationError> {
        let attested_credential_data = AttestedCredentialData::generate().await;

        Ok(attested_credential_data)
    }

    pub async fn authenticator_data(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn create_attestation_object(
        &self,
        attested_credential_data: AttestedCredentialData,
    ) -> Result<AttestationObject, AuthenticationError> {
        // let _ = CredentialObject::generate().await;

        let attestation_format = AttestationStatementFormat::Packed;
        let authenticator_data =
            AuthenticatorData::generate(&self.rp_entity.id, attested_credential_data).await;
        let hash = Vec::with_capacity(0);

        let attestation_object =
            AttestationObject::generate(attestation_format, authenticator_data, hash).await;

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
                // id: String::from("some_id"),
                id: [0; 16],
            },
            require_resident_key: false,
            require_user_presence: false,
            require_user_verification: false,
            cred_types_and_pub_key_apis: vec![PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                algorithm: -8,
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
                algorithm: -7,
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
                    algorithm: -6,
                },
                PublicKeyCredentialParameters {
                    r#type: PublicKeyCredentialType::PublicKey,
                    algorithm: -7,
                },
                PublicKeyCredentialParameters {
                    r#type: PublicKeyCredentialType::PublicKey,
                    algorithm: -8,
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
                algorithm: -8,
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
                algorithm: -8,
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
                algorithm: -8,
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
                algorithm: -8,
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
                algorithm: -8,
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
                algorithm: -8,
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
                algorithm: -8,
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
                algorithm: -8,
            }],
            exclude_credential_descriptor_list: None,
            enterprise_attestation_possible: false,
            extensions: String::from("some_extensions"),
        };

        assert!(test_ok.collect_authorization_gesture().await.is_ok());

        Ok(())
    }
}
