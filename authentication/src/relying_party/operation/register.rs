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
        json: &[u8],
    ) -> Result<CollectedClientData, AuthenticationError> {
        match serde_json::from_slice(json) {
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

    pub async fn hash(
        &self,
        response: &AuthenticatorAttestationResponse,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let hash = generate_hash(&response.client_data_json).await;

        Ok(hash)
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
        Ok(())
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
    use crate::api::authenticator_responses::AuthenticatorAssertionResponse;
    use crate::api::credential_creation_options::Challenge;
    use crate::api::supporting_data_structures::TokenBindingStatus;
    use crate::authenticator::attestation::PackedAttestationStatementSyntax;
    use ciborium::cbor;

    #[tokio::test]
    async fn public_key_credential_creation_options() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_public_key_credential_creation_options = test_registration
            .public_key_credential_creation_options()
            .await?;

        assert_eq!(
            test_public_key_credential_creation_options.rp.id,
            "some_rp_entity",
        );
        assert_eq!(
            test_public_key_credential_creation_options.user.name,
            "some_user",
        );
        assert_eq!(
            test_public_key_credential_creation_options
                .public_key_credential_parameters
                .len(),
            0,
        );
        assert_eq!(test_public_key_credential_creation_options.timeout, 0);
        assert_eq!(
            test_public_key_credential_creation_options
                .exclude_credentials
                .len(),
            0,
        );
        assert_eq!(
            test_public_key_credential_creation_options
                .authenticator_selection
                .authenticator_attachment,
            "some_attachment",
        );
        assert!(test_public_key_credential_creation_options
            .attestation
            .is_none());

        Ok(())
    }

    #[tokio::test]
    async fn call_credentials_create() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_public_key_credential_creation_options = test_registration
            .public_key_credential_creation_options()
            .await?;
        let test_public_key_credential = test_registration
            .call_credentials_create(&test_public_key_credential_creation_options)
            .await?;

        assert_eq!(test_public_key_credential.r#type, "public-key");
        assert_eq!(test_public_key_credential.id, "some_credential_id");

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_attestation_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_public_key_credential_assertion = PublicKeyCredential {
            id: String::from("test_id"),
            raw_id: Vec::with_capacity(0),
            response: AuthenticatorResponse::AuthenticatorAssertionResponse(
                AuthenticatorAssertionResponse {
                    client_data_json: Vec::with_capacity(0),
                    authenticator_data: Vec::with_capacity(0),
                    signature: Vec::with_capacity(0),
                    user_handle: Vec::with_capacity(0),
                },
            ),
            r#type: String::from("test_type"),
        };
        let test_authenticator_attestation_response_err = test_registration
            .authenticator_attestation_response(&test_public_key_credential_assertion)
            .await;

        assert!(test_authenticator_attestation_response_err.is_err());

        let test_public_key_credential_attestation = PublicKeyCredential {
            id: String::from("test_id"),
            raw_id: Vec::with_capacity(0),
            response: AuthenticatorResponse::AuthenticatorAttestationResponse(
                AuthenticatorAttestationResponse {
                    client_data_json: Vec::with_capacity(0),
                    attestation_object: Vec::with_capacity(0),
                },
            ),
            r#type: String::from("test_type"),
        };
        let test_authenticator_attestation_response_ok = test_registration
            .authenticator_attestation_response(&test_public_key_credential_attestation)
            .await;

        assert!(test_authenticator_attestation_response_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn client_extension_results() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_public_key_credential_creation_options = test_registration
            .public_key_credential_creation_options()
            .await?;
        let test_public_key_credential = test_registration
            .call_credentials_create(&test_public_key_credential_creation_options)
            .await?;

        assert!(test_registration
            .client_extension_results(&test_public_key_credential)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn json() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_response = AuthenticatorAttestationResponse {
            client_data_json: Vec::with_capacity(0),
            attestation_object: Vec::with_capacity(0),
        };

        let test_json = test_registration.json(&test_response).await?;

        assert!(test_json.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn client_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_invalid_json = b"
        { 
            \"crossorigin\": true,
            \"type\": \"webauthn.create\",
            \"origin\": \"some_test_origin\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
        }";

        let test_client_data_error = test_registration.client_data(test_invalid_json).await;

        assert!(test_client_data_error.is_err());

        let test_valid_json = b"
        { 
            \"crossOrigin\": true,
            \"type\": \"webauthn.create\",
            \"origin\": \"some_test_origin\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        }";
        let test_client_data_ok = test_registration.client_data(test_valid_json).await;

        assert!(test_client_data_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_type() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_invalid_client_data_type = CollectedClientData {
            r#type: String::from("webauthn.not_create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        let test_verify_type_error = test_registration
            .verify_type(&test_invalid_client_data_type)
            .await;

        assert!(test_verify_type_error.is_err());

        let test_valid_client_data_type = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        let test_verify_type_ok = test_registration
            .verify_type(&test_valid_client_data_type)
            .await;

        assert!(test_verify_type_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_public_key_credential_creation_options = test_registration
            .public_key_credential_creation_options()
            .await?;

        let test_invalid_client_data_challenge = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        let test_verify_challenge_error = test_registration
            .verify_challenge(
                &test_invalid_client_data_challenge,
                &test_public_key_credential_creation_options,
            )
            .await;

        assert!(test_verify_challenge_error.is_err());

        let test_valid_client_data_challenge = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: test_public_key_credential_creation_options
                .challenge
                .to_owned(),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        let test_verify_challenge_ok = test_registration
            .verify_challenge(
                &test_valid_client_data_challenge,
                &test_public_key_credential_creation_options,
            )
            .await;

        assert!(test_verify_challenge_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_origin() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_invalid_client_data_origin = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        let test_verify_origin_error = test_registration
            .verify_origin(&test_invalid_client_data_origin, "some_test_rp_origin")
            .await;

        assert!(test_verify_origin_error.is_err());

        let test_valid_client_data_origin = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        let test_verify_origin_ok = test_registration
            .verify_origin(&test_valid_client_data_origin, "some_test_origin")
            .await;

        assert!(test_verify_origin_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_token_binding() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_token_binding = TokenBinding {
            status: TokenBindingStatus::Present,
            id: String::from("some_token_binding_id"),
        };
        let test_client_data_token_binding_none = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };
        let test_verify_token_binding_none = test_registration
            .verify_token_binding(&test_client_data_token_binding_none, &test_token_binding)
            .await;

        assert!(test_verify_token_binding_none.is_ok());

        let test_invalid_client_data_token_binding = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: Some(TokenBinding {
                status: TokenBindingStatus::Supported,
                id: String::from("some_token_binding_id"),
            }),
        };
        let test_verify_token_binding_error = test_registration
            .verify_token_binding(&test_invalid_client_data_token_binding, &test_token_binding)
            .await;

        assert!(test_verify_token_binding_error.is_err());

        let test_valid_client_data_token_binding = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: Some(TokenBinding {
                status: TokenBindingStatus::Present,
                id: String::from("some_token_binding_id"),
            }),
        };
        let test_verify_token_binding_ok = test_registration
            .verify_token_binding(&test_valid_client_data_token_binding, &test_token_binding)
            .await;

        assert!(test_verify_token_binding_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn hash() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration = Register {};
        let test_response = AuthenticatorAttestationResponse {
            client_data_json: b"some_test_data_to_hash".to_vec(),
            attestation_object: Vec::with_capacity(0),
        };

        assert!(test_registration.hash(&test_response).await.is_ok());

        Ok(())
    }

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

    #[tokio::test]
    async fn verify_rp_id_hash() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data).await;
        let test_registration = Register {};

        assert!(test_registration
            .verify_rp_id_hash(&test_authenticator_data, "test_rp_identity")
            .await
            .is_err());
        assert!(test_registration
            .verify_rp_id_hash(&test_authenticator_data, "test_rp_id")
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_user_present() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data).await;
        let test_registration = Register {};

        assert!(test_registration
            .verify_user_present(&test_authenticator_data)
            .await
            .is_err());

        test_authenticator_data.set_user_present().await;

        assert!(test_registration
            .verify_user_present(&test_authenticator_data)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_user_verification() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data).await;
        let test_registration = Register {};

        assert!(test_registration
            .verify_user_verification(&test_authenticator_data)
            .await
            .is_err());

        test_authenticator_data.set_user_verifed().await;

        assert!(test_registration
            .verify_user_verification(&test_authenticator_data)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_algorithm() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data).await;
        let test_registration = Register {};
        let test_public_key_credential_creation_options = test_registration
            .public_key_credential_creation_options()
            .await?;

        assert!(test_registration
            .verify_algorithm(
                &test_authenticator_data,
                &test_public_key_credential_creation_options
            )
            .await
            .is_ok());

        Ok(())
    }
}
