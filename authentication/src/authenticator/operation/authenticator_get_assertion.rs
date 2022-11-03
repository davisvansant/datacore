use crate::api::supporting_data_structures::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialType,
};
use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::error::{AuthenticationError, AuthenticationErrorType};

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

    pub async fn authenticator_data(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn assertion_signature(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
