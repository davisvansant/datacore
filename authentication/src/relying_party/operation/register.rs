use crate::api::authenticator_responses::{
    AuthenticatorAttestationResponse, AuthenticatorResponse,
};
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientOutputs;
use crate::api::public_key_credential::PublicKeyCredential;
use crate::api::supporting_data_structures::{CollectedClientData, TokenBinding};
use crate::error::{AuthenticationError, AuthenticationErrorType};

pub struct Register {}

impl Register {
    pub async fn public_key_credential_creation_options(
        &self,
    ) -> Result<PublicKeyCredentialCreationOptions, AuthenticationError> {
        let public_key_credential_creation_options =
            PublicKeyCredentialCreationOptions::generate().await;

        Ok(public_key_credential_creation_options)
    }

    pub async fn call_credentials_create(
        &self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let credential = PublicKeyCredential::generate().await;

        Ok(credential)
    }

    pub async fn authenticator_attestation_response(
        &self,
        credential: &PublicKeyCredential,
    ) -> Result<AuthenticatorAttestationResponse, AuthenticationError> {
        match &credential.response {
            AuthenticatorResponse::AuthenticatorAttestationResponse(response) => {
                Ok(response.to_owned())
            }
            AuthenticatorResponse::AuthenticatorAssertionResponse(_) => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn client_extension_results(
        &self,
        _credential: &PublicKeyCredential,
    ) -> Result<AuthenticationExtensionsClientOutputs, AuthenticationError> {
        Ok(AuthenticationExtensionsClientOutputs {})
    }

    pub async fn json(
        &self,
        response: AuthenticatorAttestationResponse,
    ) -> Result<Vec<u8>, AuthenticationError> {
        Ok(response.client_data_json)
    }

    pub async fn client_data(
        &self,
        json: Vec<u8>,
    ) -> Result<CollectedClientData, AuthenticationError> {
        let client_data = CollectedClientData::generate().await;

        Ok(client_data)
    }

    pub async fn verify_type(
        &self,
        client_data: &CollectedClientData,
    ) -> Result<(), AuthenticationError> {
        match client_data.r#type == "webauthn.create" {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_challenge(
        &self,
        client_data: &CollectedClientData,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<(), AuthenticationError> {
        match client_data.challenge == options.challenge {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_origin(
        &self,
        client_data: &CollectedClientData,
        rp_id: &str,
    ) -> Result<(), AuthenticationError> {
        match client_data.origin == rp_id {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_token_binding(
        &self,
        client_data: &CollectedClientData,
        connection_token_binding: &TokenBinding,
    ) -> Result<(), AuthenticationError> {
        if let Some(client_data_token_binding) = &client_data.token_binding {
            match client_data_token_binding == connection_token_binding {
                true => Ok(()),
                false => Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                }),
            }
        } else {
            Ok(())
        }
    }
}
