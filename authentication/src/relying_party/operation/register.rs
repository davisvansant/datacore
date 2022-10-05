use ciborium::de::from_reader;

use crate::api::authenticator_responses::{
    AuthenticatorAttestationResponse, AuthenticatorResponse,
};
use crate::api::credential_creation_options::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity,
};
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientOutputs;
use crate::api::public_key_credential::PublicKeyCredential;
use crate::api::supporting_data_structures::{CollectedClientData, TokenBinding};
use crate::authenticator::attestation::{
    AttestationObject, AttestationStatement, AttestationStatementFormat,
    AttestationStatementFormatIdentifier, AttestedCredentialData,
};
use crate::authenticator::data::{AuthenticatorData, ED, UP, UV};
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::sha2::generate_hash;

use std::collections::HashMap;

pub struct Register {}

impl Register {
    pub async fn public_key_credential_creation_options(
        &self,
    ) -> Result<PublicKeyCredentialCreationOptions, AuthenticationError> {
        let user = String::from("some_user");
        let display_name = String::from("some_display_name");
        let user_entity = PublicKeyCredentialUserEntity::generate(user, display_name).await;
        let public_key_credential_creation_options =
            PublicKeyCredentialCreationOptions::generate(user_entity).await;

        Ok(public_key_credential_creation_options)
    }

    pub async fn call_credentials_create(
        &self,
        _options: &PublicKeyCredentialCreationOptions,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let r#type = String::from("public-key");
        let id = String::from("some_credential_id");
        let raw_id = Vec::with_capacity(0);
        let client_data_json = Vec::with_capacity(0);
        let attestation_object = Vec::with_capacity(0);
        let response = AuthenticatorResponse::AuthenticatorAttestationResponse(
            AuthenticatorAttestationResponse {
                client_data_json,
                attestation_object,
            },
        );
        let r#type = String::from("public-key");
        let credential = PublicKeyCredential::generate(r#type, id, raw_id, response).await;

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
        response: &AuthenticatorAttestationResponse,
    ) -> Result<Vec<u8>, AuthenticationError> {
        Ok(response.client_data_json.to_owned())
    }

    pub async fn client_data(
        &self,
        json: Vec<u8>,
    ) -> Result<CollectedClientData, AuthenticationError> {
        match serde_json::from_slice(&json) {
            Ok(client_data) => Ok(client_data),
            Err(_) => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
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

    pub async fn perform_decoding(
        &self,
        authenticator_attestation_response: AuthenticatorAttestationResponse,
    ) -> Result<
        (
            AttestationStatementFormat,
            AuthenticatorData,
            AttestationStatement,
        ),
        AuthenticationError,
    > {
        let attestation_object: AttestationObject = match from_reader(
            authenticator_attestation_response
                .attestation_object
                .as_slice(),
        ) {
            Ok(attestation_object) => attestation_object,
            Err(_) => {
                return Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            }
        };

        let attestation_statement_format = attestation_object
            .fmt
            .attestation_statement_format()
            .await?;
        let authenticator_data = attestation_object.authData;
        let attestation_statement = attestation_object.attStmt;

        Ok((
            attestation_statement_format,
            authenticator_data,
            attestation_statement,
        ))
    }

    pub async fn verify_rp_id_hash(
        &self,
        authenticator_data: &AuthenticatorData,
        rp_id: &str,
    ) -> Result<(), AuthenticationError> {
        let rp_id_hash = generate_hash(rp_id.as_bytes()).await;

        match authenticator_data.rp_id_hash == rp_id_hash {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::attestation::PackedAttestationStatementSyntax;
    use ciborium::cbor;

    #[tokio::test]
    async fn perform_decoding() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data).await;
        let test_attestation_statement =
            AttestationStatement::Packed(PackedAttestationStatementSyntax::build().await);

        let test_client_data_json = Vec::with_capacity(0);
        let test_attestation_object_cbor = cbor!({
            "authData" => test_authenticator_data,
            "fmt" => "packed",
            "attStmt" => test_attestation_statement,
        })?;

        let mut test_attestation_object = Vec::with_capacity(0);
        ciborium::ser::into_writer(&test_attestation_object_cbor, &mut test_attestation_object)?;

        let test_authenticator_attestation_response = AuthenticatorAttestationResponse {
            client_data_json: test_client_data_json,
            attestation_object: test_attestation_object,
        };

        let test_registration = Register {};
        let test_perform_decoding = test_registration
            .perform_decoding(test_authenticator_attestation_response)
            .await
            .unwrap();

        assert_eq!(test_perform_decoding.0, AttestationStatementFormat::Packed);
        assert_eq!(test_perform_decoding.1.flags[UP], 0);
        assert_eq!(test_perform_decoding.1.signcount, 0);

        match test_perform_decoding.2 {
            AttestationStatement::Packed(test_packed_attestation_statement) => {
                assert_eq!(test_packed_attestation_statement.alg, 3);
            }
        }

        Ok(())
    }
}
