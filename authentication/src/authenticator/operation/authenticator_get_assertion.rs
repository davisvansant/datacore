use crate::api::authenticator_responses::AuthenticatorAssertionResponse;
use crate::api::supporting_data_structures::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialType,
};
use crate::authenticator::data::AuthenticatorData;
use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::sha2::generate_hash;

use std::collections::HashMap;

// pub type CredentialOptions = Vec<PublicKeyCredentialSource>;

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
    ) -> Result<Vec<PublicKeyCredentialSource>, AuthenticationError> {
        let mut credential_options = match &self.allow_descriptor_credential_list {
            Some(allow_descriptor_credential_list) => {
                Vec::with_capacity(allow_descriptor_credential_list.len())
            }
            None => Vec::with_capacity(0),
        };

        let mut credentials = HashMap::with_capacity(1);
        let test_credential_id = b"cred_identifier_".to_vec();
        let internal_credential_for_testing = PublicKeyCredentialSource {
            r#type: PublicKeyCredentialType::PublicKey,
            id: b"cred_identifier_".to_owned(),
            private_key: Vec::with_capacity(0),
            rpid: String::from("some_relying_party_id"),
            user_handle: [0; 16],
            other_ui: String::from("some_other_ui"),
        };

        credentials.insert(test_credential_id, internal_credential_for_testing);

        match &self.allow_descriptor_credential_list {
            Some(allow_descriptor_credential_list) => {
                for descriptor in allow_descriptor_credential_list {
                    match credentials.get(&descriptor.id) {
                        Some(credential_source) => {
                            credential_options.push(credential_source.to_owned());
                        }
                        None => continue,
                    }
                }
            }
            None => {
                for credential_source in credentials.values() {
                    credential_options.push(credential_source.to_owned())
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
        selected_credential: &PublicKeyCredentialSource,
    ) -> Result<(), AuthenticationError> {
        let mut signature_counter = HashMap::with_capacity(1);
        let initial_value = 0_u32.to_be_bytes();

        signature_counter.insert(selected_credential.id, initial_value);

        if let Some(sign_count) = signature_counter.get_mut(&selected_credential.id) {
            let mut value = u32::from_be_bytes(*sign_count);

            value += 1;

            *sign_count = value.to_be_bytes();
        }

        Ok(())
    }

    pub async fn authenticator_data(&self) -> Result<AuthenticatorData, AuthenticationError> {
        let rp_id_hash = generate_hash(self.rpid.as_bytes()).await;
        let mut authenticator_data = AuthenticatorData {
            rp_id_hash,
            // flags: [0; 8],
            flags: 0b0000_0000,
            signcount: 0,
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

        // for element in serialized_authenticator_data_rp_id_hash {
        //     sign.push(element);
        // }

        // for element in serialized_authenticator_data_flags {
        //     sign.push(element);
        // }

        // for element in serialized_authenticator_data_sign_count {
        //     sign.push(element);
        // }
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
    // use crate::authenticator::data::{UP, UV};

    #[tokio::test]
    async fn credential_options() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"cred_identifier_".to_vec(),
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        assert!(test_ok.credential_options().await.is_ok());

        let test_err = AuthenticatorGetAssertion {
            rpid: String::from("some_rp_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"cred_identifier_".to_vec(),
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        assert!(test_err.credential_options().await.is_err());

        let test_none_rp_ok = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: None,
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        assert!(test_none_rp_ok.credential_options().await.is_ok());

        let test_none_rp_error = AuthenticatorGetAssertion {
            rpid: String::from("some_rp_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: None,
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        assert!(test_none_rp_error.credential_options().await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn collect_authorization_gesture() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"cred_identifier_".to_vec(),
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        let test_credential_options = test_ok.credential_options().await.unwrap();

        assert!(test_ok
            .collect_authorization_gesture(test_credential_options)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn increment_signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"cred_identifier_".to_vec(),
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        let test_credential_options = test_ok.credential_options().await.unwrap();
        let test_selected_credentaial = test_ok
            .collect_authorization_gesture(test_credential_options)
            .await
            .unwrap();

        assert!(test_ok
            .increment_signature_counter(&test_selected_credentaial)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_false = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"cred_identifier_".to_vec(),
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        let test_authenticator_data = test_false.authenticator_data().await.unwrap();

        assert_eq!(
            test_authenticator_data.rp_id_hash,
            generate_hash(b"some_relying_party_id").await,
        );
        // assert_eq!(test_authenticator_data.flags[UP], 0);
        // assert_eq!(test_authenticator_data.flags[UV], 0);
        assert!(!test_authenticator_data.user_present().await);
        assert!(!test_authenticator_data.user_verified().await);
        assert_eq!(test_authenticator_data.signcount, 0);
        assert!(test_authenticator_data.attestedcredentialdata.is_none());
        assert!(test_authenticator_data.extensions.is_none());

        let test_true = AuthenticatorGetAssertion {
            rpid: String::from("some_other_rp_id"),
            hash: Vec::with_capacity(0),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"cred_identifier_".to_vec(),
                transports: None,
            }]),
            require_user_presence: true,
            require_user_verification: true,
            extensions: vec![String::from("some_extension")],
        };

        let test_authenticator_data = test_true.authenticator_data().await.unwrap();

        assert_eq!(
            test_authenticator_data.rp_id_hash,
            generate_hash(b"some_other_rp_id").await,
        );
        // assert_eq!(test_authenticator_data.flags[UP], 1);
        // assert_eq!(test_authenticator_data.flags[UV], 1);
        assert!(test_authenticator_data.user_present().await);
        assert!(test_authenticator_data.user_verified().await);
        assert_eq!(test_authenticator_data.signcount, 0);
        assert!(test_authenticator_data.attestedcredentialdata.is_none());
        assert!(test_authenticator_data.extensions.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn assertion_signature() -> Result<(), Box<dyn std::error::Error>> {
        let test_ok = AuthenticatorGetAssertion {
            rpid: String::from("some_relying_party_id"),
            hash: b"some_test_client_data".to_vec(),
            allow_descriptor_credential_list: Some(vec![PublicKeyCredentialDescriptor {
                r#type: PublicKeyCredentialType::PublicKey,
                id: b"cred_identifier_".to_vec(),
                transports: None,
            }]),
            require_user_presence: false,
            require_user_verification: false,
            extensions: vec![String::from("some_extension")],
        };

        let test_credential_options = test_ok.credential_options().await.unwrap();
        let test_selected_credentaial = test_ok
            .collect_authorization_gesture(test_credential_options)
            .await
            .unwrap();
        let test_authenticator_data = test_ok.authenticator_data().await.unwrap();
        let test_assertion_signature = test_ok
            .assertion_signature(&test_authenticator_data, &test_selected_credentaial)
            .await
            .unwrap();

        assert_eq!(test_assertion_signature.client_data_json.len(), 21);
        assert_eq!(test_assertion_signature.authenticator_data.len(), 45);
        assert_eq!(test_assertion_signature.signature.len(), 66);
        assert_eq!(test_assertion_signature.user_handle.len(), 16);

        Ok(())
    }
}
