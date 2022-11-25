use crate::api::authenticator_responses::AuthenticatorAssertionResponse;
use crate::api::supporting_data_structures::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialType,
};
use crate::authenticator::data::AuthenticatorData;
use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::authenticator::store::CredentialsChannel;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::sha2::generate_hash;

pub struct AuthenticatorGetAssertion {
    rpid: String,
    hash: Vec<u8>,
    allow_descriptor_credential_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    require_user_presence: bool,
    require_user_verification: bool,
    extensions: Vec<String>,
}

impl AuthenticatorGetAssertion {
    pub async fn collect_parameters(
        rpid: String,
        hash: Vec<u8>,
        allow_descriptor_credential_list: Option<Vec<PublicKeyCredentialDescriptor>>,
        require_user_presence: bool,
        require_user_verification: bool,
        extensions: Vec<String>,
    ) -> AuthenticatorGetAssertion {
        AuthenticatorGetAssertion {
            rpid,
            hash,
            allow_descriptor_credential_list,
            require_user_presence,
            require_user_verification,
            extensions,
        }
    }

    pub async fn check_parameters(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn credential_options(
        &self,
        store: &CredentialsChannel,
    ) -> Result<Vec<PublicKeyCredentialSource>, AuthenticationError> {
        let mut credential_options = match &self.allow_descriptor_credential_list {
            Some(allow_descriptor_credential_list) => {
                Vec::with_capacity(allow_descriptor_credential_list.len())
            }
            None => Vec::with_capacity(0),
        };

        match &self.allow_descriptor_credential_list {
            Some(allow_descriptor_credential_list) => {
                for descriptor in allow_descriptor_credential_list {
                    match store.lookup(self.rpid.to_owned(), descriptor.id).await {
                        Ok(credential_source) => credential_options.push(credential_source),
                        Err(_) => continue,
                    }
                }
            }
            None => {
                let credentials_store = store.values().await?;

                for credential_source in credentials_store {
                    credential_options.push(credential_source)
                }
            }
        }

        credential_options.retain(|credential_option| credential_option.rpid == self.rpid);

        match &credential_options.is_empty() {
            true => Err(AuthenticationError {
                error: AuthenticationErrorType::NotAllowedError,
            }),
            false => Ok(credential_options),
        }
    }

    pub async fn collect_authorization_gesture(
        &self,
        credential_options: Vec<PublicKeyCredentialSource>,
    ) -> Result<PublicKeyCredentialSource, AuthenticationError> {
        let selected_credential = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: b"cred_identifier_".to_owned(),
            private_key: Vec::with_capacity(0),
            rpid: String::from("some_relying_party_id"),
            user_handle: [0; 16],
            other_ui: String::from("some_other_ui"),
        };

        Ok(selected_credential)
    }

    pub async fn process_extensions(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn increment_signature_counter(
        &self,
        store: &CredentialsChannel,
        selected_credential: &PublicKeyCredentialSource,
    ) -> Result<(), AuthenticationError> {
        store.increment(selected_credential.id).await?;

        Ok(())
    }

    pub async fn authenticator_data(
        &self,
        store: &CredentialsChannel,
        selected_credential: &PublicKeyCredentialSource,
    ) -> Result<AuthenticatorData, AuthenticationError> {
        let rp_id_hash = generate_hash(self.rpid.as_bytes()).await;
        let signcount = store.counter(selected_credential.id).await?;
        let mut authenticator_data = AuthenticatorData {
            rp_id_hash,
            flags: 0b0000_0000,
            signcount: signcount.to_be_bytes(),
            attestedcredentialdata: None,
            extensions: None,
        };

        if self.require_user_presence {
            authenticator_data.set_user_present().await;
        }

        if self.require_user_verification {
            authenticator_data.set_user_verifed().await;
        }

        Ok(authenticator_data)
    }

    pub async fn assertion_signature(
        &self,
        authenticator_data: &AuthenticatorData,
        selected_credential: &PublicKeyCredentialSource,
    ) -> Result<AuthenticatorAssertionResponse, AuthenticationError> {
        let mut authenticator_data_byte_array = Vec::with_capacity(500);
        let mut sign = Vec::with_capacity(500);

        let serialized_authenticator_data_rp_id_hash =
            match bincode::serialize(&authenticator_data.rp_id_hash) {
                Ok(rp_id_hash) => rp_id_hash,
                Err(error) => {
                    println!("error with serialization -> {:?}", error);

                    return Err(AuthenticationError {
                        error: AuthenticationErrorType::UnknownError,
                    });
                }
            };

        let serialized_authenticator_data_flags =
            match bincode::serialize(&authenticator_data.flags) {
                Ok(flags) => flags,
                Err(error) => {
                    println!("error with serialization -> {:?}", error);

                    return Err(AuthenticationError {
                        error: AuthenticationErrorType::UnknownError,
                    });
                }
            };

        let serialized_authenticator_data_sign_count =
            match bincode::serialize(&authenticator_data.signcount) {
                Ok(sign_count) => sign_count,
                Err(error) => {
                    println!("error with serialization -> {:?}", error);

                    return Err(AuthenticationError {
                        error: AuthenticationErrorType::UnknownError,
                    });
                }
            };

        for element in serialized_authenticator_data_rp_id_hash {
            authenticator_data_byte_array.push(element);
        }

        for element in serialized_authenticator_data_flags {
            authenticator_data_byte_array.push(element);
        }

        for element in serialized_authenticator_data_sign_count {
            authenticator_data_byte_array.push(element);
        }

        for element in &authenticator_data_byte_array {
            sign.push(*element);
        }

        for element in &self.hash {
            sign.push(*element);
        }

        sign.shrink_to_fit();

        let assertion_response = AuthenticatorAssertionResponse {
            client_data_json: self.hash.to_owned(),
            authenticator_data: authenticator_data_byte_array,
            signature: sign,
            user_handle: selected_credential.user_handle.to_vec(),
        };

        Ok(assertion_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::attestation::{COSEAlgorithm, COSEKey};
    use crate::authenticator::store::Credentials;

    #[tokio::test]
    async fn credential_options() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let test_algorithm = COSEAlgorithm::EdDSA;
        let test_new_credential = COSEKey::generate(test_algorithm).await;
        let test_credential_id = *b"cred_identifier_";
        let test_credential = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: test_credential_id,
            private_key: test_new_credential.1.to_bytes().to_vec(),
            rpid: String::from("some_relying_party_id"),
            user_handle: [0; 16],
            other_ui: String::from("some_other_ui"),
        };

        test_credentials_store
            .0
            .set(
                String::from("some_relying_party_id"),
                *b"cred_identifier_",
                test_credential,
            )
            .await?;

        let mut test_get_assertion = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: *b"cred_identifier_",
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        assert!(test_get_assertion
            .credential_options(&test_credentials_store.0)
            .await
            .is_ok());

        test_get_assertion.rpid = String::from("some_rp_id");

        assert!(test_get_assertion
            .credential_options(&test_credentials_store.0)
            .await
            .is_err());

        test_get_assertion.rpid = String::from("some_relying_party_id");
        test_get_assertion.allow_descriptor_credential_list = None;

        assert!(test_get_assertion
            .credential_options(&test_credentials_store.0)
            .await
            .is_ok());

        test_get_assertion.rpid = String::from("some_rp_id");

        assert!(test_get_assertion
            .credential_options(&test_credentials_store.0)
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn collect_authorization_gesture() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let test_algorithm = COSEAlgorithm::EdDSA;
        let test_new_credential = COSEKey::generate(test_algorithm).await;
        let test_credential_id = *b"cred_identifier_";
        let test_credential = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: test_credential_id,
            private_key: test_new_credential.1.to_bytes().to_vec(),
            rpid: String::from("some_relying_party_id"),
            user_handle: [0; 16],
            other_ui: String::from("some_other_ui"),
        };

        test_credentials_store
            .0
            .set(
                String::from("some_relying_party_id"),
                *b"cred_identifier_",
                test_credential,
            )
            .await?;

        let test_ok = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: *b"cred_identifier_",
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        let test_credential_options = test_ok
            .credential_options(&test_credentials_store.0)
            .await?;

        assert!(test_ok
            .collect_authorization_gesture(test_credential_options)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn increment_signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let test_algorithm = COSEAlgorithm::EdDSA;
        let test_new_credential = COSEKey::generate(test_algorithm).await;
        let test_credential_id = *b"cred_identifier_";
        let test_credential = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: test_credential_id,
            private_key: test_new_credential.1.to_bytes().to_vec(),
            rpid: String::from("some_relying_party_id"),
            user_handle: [0; 16],
            other_ui: String::from("some_other_ui"),
        };

        test_credentials_store
            .0
            .set(
                String::from("some_relying_party_id"),
                *b"cred_identifier_",
                test_credential,
            )
            .await?;

        let test_ok = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: *b"cred_identifier_",
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        let test_credential_options = test_ok
            .credential_options(&test_credentials_store.0)
            .await?;
        let test_selected_credentaial = test_ok
            .collect_authorization_gesture(test_credential_options)
            .await?;

        assert!(test_ok
            .increment_signature_counter(&test_credentials_store.0, &test_selected_credentaial)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_data() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let mut test_get_assertion = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: *b"cred_identifier_",
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        let mut test_selected_credential = PublicKeyCredentialSource::generate().await;

        test_selected_credential.id = *b"cred_identifier_";

        test_credentials_store
            .0
            .signature_counter(*b"cred_identifier_")
            .await?;

        let test_authenticator_data = test_get_assertion
            .authenticator_data(&test_credentials_store.0, &test_selected_credential)
            .await?;

        assert_eq!(
            test_authenticator_data.rp_id_hash,
            generate_hash(b"some_relying_party_id").await,
        );
        assert!(!test_authenticator_data.user_present().await);
        assert!(!test_authenticator_data.user_verified().await);
        // assert_eq!(test_authenticator_data.signcount, 0);
        assert_eq!(test_authenticator_data.signcount, [0; 4]);
        assert!(test_authenticator_data.attestedcredentialdata.is_none());
        assert!(test_authenticator_data.extensions.is_none());

        test_get_assertion.rpid = String::from("some_other_rp_id");
        test_get_assertion.require_user_presence = true;
        test_get_assertion.require_user_verification = true;

        let test_authenticator_data = test_get_assertion
            .authenticator_data(&test_credentials_store.0, &test_selected_credential)
            .await?;

        assert_eq!(
            test_authenticator_data.rp_id_hash,
            generate_hash(b"some_other_rp_id").await,
        );
        assert!(test_authenticator_data.user_present().await);
        assert!(test_authenticator_data.user_verified().await);
        // assert_eq!(test_authenticator_data.signcount, 0);
        assert_eq!(test_authenticator_data.signcount, [0; 4]);
        assert!(test_authenticator_data.attestedcredentialdata.is_none());
        assert!(test_authenticator_data.extensions.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn assertion_signature() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials_store = Credentials::init().await;

        tokio::spawn(async move {
            test_credentials_store.1.run().await.unwrap();
        });

        let test_algorithm = COSEAlgorithm::EdDSA;
        let test_new_credential = COSEKey::generate(test_algorithm).await;
        let test_credential_id = *b"cred_identifier_";
        let test_credential = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: test_credential_id,
            private_key: test_new_credential.1.to_bytes().to_vec(),
            rpid: String::from("some_relying_party_id"),
            user_handle: [0; 16],
            other_ui: String::from("some_other_ui"),
        };

        test_credentials_store
            .0
            .set(
                String::from("some_relying_party_id"),
                *b"cred_identifier_",
                test_credential,
            )
            .await?;

        let test_ok = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: b"some_test_client_data".to_vec(),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: *b"cred_identifier_",
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        let test_credential_options = test_ok
            .credential_options(&test_credentials_store.0)
            .await?;
        let test_selected_credentaial = test_ok
            .collect_authorization_gesture(test_credential_options)
            .await?;
        let mut test_selected_credential = PublicKeyCredentialSource::generate().await;

        test_selected_credential.id = *b"cred_identifier_";

        test_credentials_store
            .0
            .signature_counter(*b"cred_identifier_")
            .await?;

        let test_authenticator_data = test_ok
            .authenticator_data(&test_credentials_store.0, &test_selected_credential)
            .await
            .unwrap();
        let test_assertion_signature = test_ok
            .assertion_signature(&test_authenticator_data, &test_selected_credentaial)
            .await?;

        assert_eq!(test_assertion_signature.client_data_json.len(), 21);
        assert_eq!(test_assertion_signature.authenticator_data.len(), 45);
        assert_eq!(test_assertion_signature.signature.len(), 66);
        assert_eq!(test_assertion_signature.user_handle.len(), 16);

        Ok(())
    }
}
