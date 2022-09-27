use crate::api::authenticator_responses::{
    AuthenticatorAttestationResponse, AuthenticatorResponse,
};
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientOutputs;
use crate::api::public_key_credential::PublicKeyCredential;
use crate::api::supporting_data_structures::{CollectedClientData, TokenBinding};
use crate::authenticator::attestation::{
    AttestationStatement, AttestationStatementFormat, AttestationStatementFormatIdentifier,
};
use crate::authenticator::data::{AuthenticatorData, ED, UP, UV};
use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::collections::HashMap;

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

    pub async fn verify_user_present(
        &self,
        authenticator_data: &AuthenticatorData,
    ) -> Result<(), AuthenticationError> {
        match authenticator_data.flags[UP] == 1 {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_user_verification(
        &self,
        authenticator_data: &AuthenticatorData,
    ) -> Result<(), AuthenticationError> {
        match authenticator_data.flags[UV] == 1 {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_algorithm(
        &self,
        authenticator_data: &AuthenticatorData,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<(), AuthenticationError> {
        todo!()
    }

    pub async fn verify_extension_outputs(
        &self,
        client_extension_results: &AuthenticationExtensionsClientOutputs,
        authenticator_data: &AuthenticatorData,
    ) -> Result<(), AuthenticationError> {
        if authenticator_data.flags[ED] == 1 {
            todo!()
        } else {
            Ok(())
        }
    }

    pub async fn determine_attestation_statement_format(
        &self,
        fmt: &AttestationStatementFormatIdentifier,
    ) -> Result<AttestationStatementFormat, AuthenticationError> {
        let attestation_statement_format = fmt.attestation_statement_format().await?;

        Ok(attestation_statement_format)
    }

    pub async fn verify_attestation_statement(
        &self,
        attestation_statement_format: &AttestationStatementFormat,
        attestation_statement: &AttestationStatement,
        authenticator_data: &AuthenticatorData,
        hash: &[u8],
    ) -> Result<(), AuthenticationError> {
        attestation_statement_format
            .verification_procedure(attestation_statement, authenticator_data, hash)
            .await?;

        Ok(())
    }

    pub async fn check_credential_id(
        &self,
        authenticator_data: &AuthenticatorData,
    ) -> Result<(), AuthenticationError> {
        match authenticator_data.attestedcredentialdata.credential_id == b"some_credential_id" {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn register(
        &self,
        options: PublicKeyCredentialCreationOptions,
        authenticator_data: AuthenticatorData,
    ) -> Result<(), AuthenticationError> {
        let mut some_credentials_map = HashMap::with_capacity(1);

        struct Account {
            key: Vec<u8>,
            counter: u32,
            transports: Vec<String>,
        }

        let account = Account {
            key: authenticator_data
                .attestedcredentialdata
                .credential_public_key,
            counter: authenticator_data.signcount,
            transports: Vec::with_capacity(0),
        };

        some_credentials_map.insert(options.user, account);

        Ok(())
    }
}
