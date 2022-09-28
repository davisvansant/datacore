use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::{
    AuthenticatorAssertionResponse, AuthenticatorResponse, ClientDataJSON, Signature,
};
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientOutputs;
use crate::api::public_key_credential::PublicKeyCredential;
use crate::api::supporting_data_structures::CollectedClientData;
use crate::authenticator::data::AuthenticatorData;
use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::collections::HashMap;

pub struct AuthenticationCeremony {}

impl AuthenticationCeremony {
    pub async fn public_key_credential_request_options(
        &self,
    ) -> Result<PublicKeyCredentialRequestOptions, AuthenticationError> {
        let public_key_credential_request_options =
            PublicKeyCredentialRequestOptions::generate().await;

        Ok(public_key_credential_request_options)
    }

    pub async fn call_credentials_get(
        &self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let credential = PublicKeyCredential::generate().await;

        Ok(credential)
    }

    pub async fn authenticator_assertion_response(
        &self,
        credential: &PublicKeyCredential,
    ) -> Result<AuthenticatorAssertionResponse, AuthenticationError> {
        match &credential.response {
            AuthenticatorResponse::AuthenticatorAttestationResponse(_) => {
                Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            }
            AuthenticatorResponse::AuthenticatorAssertionResponse(response) => {
                Ok(response.to_owned())
            }
        }
    }

    pub async fn client_extension_results(
        &self,
        _credential: &PublicKeyCredential,
    ) -> Result<AuthenticationExtensionsClientOutputs, AuthenticationError> {
        Ok(AuthenticationExtensionsClientOutputs {})
    }

    pub async fn verify_credential_id(
        &self,
        options: &PublicKeyCredentialRequestOptions,
        credential: &PublicKeyCredential,
    ) -> Result<(), AuthenticationError> {
        if !options.allow_credentials.is_empty() {
            for acceptable_credential in &options.allow_credentials {
                match acceptable_credential.id == credential.id.as_bytes() {
                    true => continue,
                    false => {
                        return Err(AuthenticationError {
                            error: AuthenticationErrorType::OperationError,
                        });
                    }
                };
            }
        }

        Ok(())
    }

    pub async fn identify_user_and_verify(
        &self,
        credential: &PublicKeyCredential,
        authenticator_assertion_response: &AuthenticatorAssertionResponse,
    ) -> Result<(), AuthenticationError> {
        match credential.id.as_bytes() == authenticator_assertion_response.user_handle {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn credential_public_key(
        &self,
        credential: &PublicKeyCredential,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let mut some_credentials_map = HashMap::with_capacity(1);

        struct Account {
            key: Vec<u8>,
            counter: u32,
            transports: Vec<String>,
        }

        let id = String::from("some_id");

        let account = Account {
            key: Vec::with_capacity(0),
            counter: 0,
            transports: Vec::with_capacity(0),
        };

        some_credentials_map.insert(id, account);

        match some_credentials_map.get(&credential.id) {
            Some(credential) => Ok(credential.key.to_owned()),
            None => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn response_values(
        &self,
        response: AuthenticatorAssertionResponse,
    ) -> Result<(ClientDataJSON, AuthenticatorData, Signature), AuthenticationError> {
        let client_data = response.client_data_json;
        let authenticator_data = response.authenticator_data;
        let signature = response.signature;

        Ok((client_data, authenticator_data, signature))
    }

    pub async fn client_data(
        &self,
        client_data_json: ClientDataJSON,
    ) -> Result<CollectedClientData, AuthenticationError> {
        let collected_client_data = CollectedClientData::generate().await;

        Ok(collected_client_data)
    }
}
