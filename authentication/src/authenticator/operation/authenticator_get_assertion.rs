use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;
use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::error::{AuthenticationError, AuthenticationErrorType};

pub type CredentialOptions = Vec<PublicKeyCredentialSource>;

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

    pub async fn credential_options(&self) -> Result<CredentialOptions, AuthenticationError> {
        let mut credential_options = match &self.allow_descriptor_credential_list {
            Some(allow_descriptor_credential_list) => {
                Vec::with_capacity(allow_descriptor_credential_list.len())
            }
            None => Vec::with_capacity(0),
        };

        match &self.allow_descriptor_credential_list {
            Some(allow_descriptor_credential_list) => {
                for _credential_source in allow_descriptor_credential_list {
                    let placeholder_credential_source = PublicKeyCredentialSource::generate().await;

                    credential_options.push(placeholder_credential_source);
                }
            }
            None => {
                // lookup exsisting credential sources and add to
                let placeholder_credential_source = PublicKeyCredentialSource::generate().await;

                credential_options.push(placeholder_credential_source);
            }
        }

        credential_options.retain(|credential_option| credential_option.id == self.rpid.as_bytes());

        match &credential_options.is_empty() {
            true => Err(AuthenticationError {
                error: AuthenticationErrorType::NotAllowedError,
            }),
            false => Ok(credential_options),
        }
    }

    pub async fn collect_authorization_gesture(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn process_extensions(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn increment_signature_counter(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn authenticator_data(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn assertion_signature(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }
}
