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
    AttestationStatementFormatIdentifier, AttestationType, AttestationVerificationProcedureOutput,
    AttestedCredentialData, PackedAttestationStatementSyntax,
};
use crate::authenticator::data::AuthenticatorData;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::relying_party::store::{StoreChannel, UserAccount};
use crate::security::sha2::generate_hash;

pub struct RegistrationCeremony {}

impl RegistrationCeremony {
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
        let id = String::from("some_credential_id");
        let client_data_json = Vec::with_capacity(0);
        let attestation_object = Vec::with_capacity(0);
        let response = AuthenticatorResponse::AuthenticatorAttestationResponse(
            AuthenticatorAttestationResponse {
                client_data_json,
                attestation_object,
            },
        );
        let credential = PublicKeyCredential::generate(id, response).await;

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
            AttestationStatementFormatIdentifier,
            Vec<u8>,
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

        let attestation_statement_format_identifier = attestation_object.format;
        let authenticator_data = attestation_object.authenticator_data;
        let attestation_statement = attestation_object.attestation_statement;

        Ok((
            attestation_statement_format_identifier,
            authenticator_data,
            attestation_statement,
        ))
    }

    pub async fn verify_rp_id_hash(
        &self,
        authenticator_data: &[u8],
        rp_id: &str,
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;
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
        authenticator_data: &[u8],
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;

        match authenticator_data.user_present().await {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_user_verification(
        &self,
        authenticator_data: &[u8],
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;

        match authenticator_data.user_verified().await {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_algorithm(
        &self,
        authenticator_data: &[u8],
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;
        let mut algorithm_match = Vec::with_capacity(1);
        let public_key_alg = match &authenticator_data.attested_credential_data {
            Some(data) => {
                let attested_credential_data = AttestedCredentialData::from_byte_array(data).await;

                attested_credential_data
                    .credential_public_key
                    .algorithm()
                    .await
            }
            None => {
                return Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            }
        };

        for public_key_credential_parameters in &options.public_key_credential_parameters {
            match public_key_alg == public_key_credential_parameters.alg {
                true => {
                    algorithm_match.push(1);

                    break;
                }
                false => continue,
            }
        }

        match !algorithm_match.is_empty() {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_extension_outputs(
        &self,
        _client_extension_results: &AuthenticationExtensionsClientOutputs,
        authenticator_data: &[u8],
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;

        if authenticator_data.includes_extension_data().await {
            todo!()
        } else {
            Ok(())
        }
    }

    pub async fn determine_attestation_statement_format(
        &self,
        fmt: &AttestationStatementFormatIdentifier,
    ) -> Result<AttestationStatementFormat, AuthenticationError> {
        let attestation_statement_format = fmt.try_into()?;

        Ok(attestation_statement_format)
    }

    pub async fn verify_attestation_statement(
        &self,
        attestation_statement_format: &AttestationStatementFormat,
        attestation_statement: &AttestationStatement,
        authenticator_data: &[u8],
        hash: &[u8],
    ) -> Result<AttestationVerificationProcedureOutput, AuthenticationError> {
        match attestation_statement_format {
            AttestationStatementFormat::Packed => {
                let output = PackedAttestationStatementSyntax::verification_procedure(
                    attestation_statement.packed().await,
                    authenticator_data,
                    hash,
                )
                .await?;

                Ok(output)
            }
        }
    }

    pub async fn assess_attestation_trustworthiness(
        &self,
        verification_output: AttestationVerificationProcedureOutput,
    ) -> Result<(), AuthenticationError> {
        match verification_output.attestation_type {
            AttestationType::None => {}
            AttestationType::SelfAttestation => {}
            _ => {}
        }

        Ok(())
    }

    pub async fn check_credential_id(
        &self,
        store: &StoreChannel,
        authenticator_data: &[u8],
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;

        if let Some(data) = &authenticator_data.attested_credential_data {
            let attested_credential_data = AttestedCredentialData::from_byte_array(data).await;

            store
                .check(attested_credential_data.credential_id.to_vec())
                .await?;

            Ok(())
        } else {
            Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })
        }
    }

    pub async fn register(
        &self,
        store: &StoreChannel,
        options: PublicKeyCredentialCreationOptions,
        authenticator_data: &[u8],
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;
        let public_key = if let Some(data) = authenticator_data.attested_credential_data {
            let attested_credential_data = AttestedCredentialData::from_byte_array(&data).await;

            attested_credential_data.credential_public_key
        } else {
            return Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            });
        };
        let signature_counter = authenticator_data.signcount;
        let new_account = UserAccount {
            public_key,
            signature_counter: u32::from_be_bytes(signature_counter),
            transports: None,
        };

        store
            .register(options.user.id.to_vec(), new_account)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authenticator_responses::AuthenticatorAssertionResponse;
    use crate::api::credential_creation_options::Challenge;
    use crate::api::credential_generation_parameters::PublicKeyCredentialParameters;
    use crate::api::supporting_data_structures::{PublicKeyCredentialType, TokenBindingStatus};
    use crate::authenticator::attestation::{
        AttestedCredentialData, COSEAlgorithm, COSEKey, PackedAttestationStatementSyntax,
    };
    use crate::relying_party::Store;
    use ciborium::cbor;

    #[tokio::test]
    async fn public_key_credential_creation_options() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};

        assert!(test_registration_ceremony
            .public_key_credential_creation_options()
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn call_credentials_create() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_public_key_credential_creation_options = test_registration_ceremony
            .public_key_credential_creation_options()
            .await?;

        assert!(test_registration_ceremony
            .call_credentials_create(&test_public_key_credential_creation_options)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_attestation_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_public_key_credential_assertion = PublicKeyCredential::generate(
            String::from("test_id"),
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: Vec::with_capacity(0),
                authenticator_data: Vec::with_capacity(0),
                signature: Vec::with_capacity(0),
                user_handle: Vec::with_capacity(0),
            }),
        )
        .await;

        assert!(test_registration_ceremony
            .authenticator_attestation_response(&test_public_key_credential_assertion)
            .await
            .is_err());

        let test_public_key_credential_attestation = PublicKeyCredential::generate(
            String::from("test_id"),
            AuthenticatorResponse::AuthenticatorAttestationResponse(
                AuthenticatorAttestationResponse {
                    client_data_json: Vec::with_capacity(0),
                    attestation_object: Vec::with_capacity(0),
                },
            ),
        )
        .await;

        assert!(test_registration_ceremony
            .authenticator_attestation_response(&test_public_key_credential_attestation)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn client_extension_results() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_public_key_credential_creation_options = test_registration_ceremony
            .public_key_credential_creation_options()
            .await?;
        let test_public_key_credential = test_registration_ceremony
            .call_credentials_create(&test_public_key_credential_creation_options)
            .await?;

        assert!(test_registration_ceremony
            .client_extension_results(&test_public_key_credential)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn json() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_response = AuthenticatorAttestationResponse {
            client_data_json: Vec::with_capacity(0),
            attestation_object: Vec::with_capacity(0),
        };

        let test_json = test_registration_ceremony.json(&test_response).await?;

        assert!(test_json.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn client_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_invalid_json = b"
        { 
            \"crossorigin\": true,
            \"type\": \"webauthn.create\",
            \"origin\": \"some_test_origin\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
        }";

        assert!(test_registration_ceremony
            .client_data(test_invalid_json)
            .await
            .is_err());

        let test_valid_json = b"
        { 
            \"crossOrigin\": true,
            \"type\": \"webauthn.create\",
            \"origin\": \"some_test_origin\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        }";

        assert!(test_registration_ceremony
            .client_data(test_valid_json)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_type() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let mut test_client_data = CollectedClientData {
            r#type: String::from("webauthn.not_create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        assert!(test_registration_ceremony
            .verify_type(&test_client_data)
            .await
            .is_err());

        test_client_data.r#type = String::from("webauthn.create");

        assert!(test_registration_ceremony
            .verify_type(&test_client_data)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_public_key_credential_creation_options = test_registration_ceremony
            .public_key_credential_creation_options()
            .await?;

        let mut test_client_data = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        assert!(test_registration_ceremony
            .verify_challenge(
                &test_client_data,
                &test_public_key_credential_creation_options
            )
            .await
            .is_err());

        test_client_data.challenge = test_public_key_credential_creation_options
            .challenge
            .to_owned();

        assert!(test_registration_ceremony
            .verify_challenge(
                &test_client_data,
                &test_public_key_credential_creation_options,
            )
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_origin() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let mut test_client_data = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        assert!(test_registration_ceremony
            .verify_origin(&test_client_data, "some_test_rp_origin")
            .await
            .is_err());

        test_client_data.origin = String::from("some_test_origin");

        assert!(test_registration_ceremony
            .verify_origin(&test_client_data, "some_test_origin")
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_token_binding() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_token_binding = TokenBinding {
            status: TokenBindingStatus::Present,
            id: String::from("some_token_binding_id"),
        };

        let mut test_client_data = CollectedClientData {
            r#type: String::from("webauthn.create"),
            challenge: Challenge([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        assert!(test_registration_ceremony
            .verify_token_binding(&test_client_data, &test_token_binding)
            .await
            .is_ok());

        test_client_data.token_binding = Some(TokenBinding {
            status: TokenBindingStatus::Supported,
            id: String::from("some_token_binding_id"),
        });

        assert!(test_registration_ceremony
            .verify_token_binding(&test_client_data, &test_token_binding)
            .await
            .is_err());

        test_client_data.token_binding = Some(TokenBinding {
            status: TokenBindingStatus::Present,
            id: String::from("some_token_binding_id"),
        });

        assert!(test_registration_ceremony
            .verify_token_binding(&test_client_data, &test_token_binding)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn hash() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_response = AuthenticatorAttestationResponse {
            client_data_json: b"some_test_data_to_hash".to_vec(),
            attestation_object: Vec::with_capacity(0),
        };

        assert!(test_registration_ceremony
            .hash(&test_response)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn perform_decoding() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data_byte_array)
                .await;
        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;
        let test_attestation_statement =
            AttestationStatement::Packed(PackedAttestationStatementSyntax::generate().await);

        let test_client_data_json = Vec::with_capacity(0);
        let test_attestation_object_cbor = cbor!({
            "authData" => test_authenticator_data_byte_array,
            "fmt" => "packed",
            "attStmt" => test_attestation_statement,
        })?;

        let mut test_attestation_object = Vec::with_capacity(0);
        ciborium::ser::into_writer(&test_attestation_object_cbor, &mut test_attestation_object)?;

        let test_authenticator_attestation_response = AuthenticatorAttestationResponse {
            client_data_json: test_client_data_json,
            attestation_object: test_attestation_object,
        };

        let test_registration_ceremony = RegistrationCeremony {};
        assert!(test_registration_ceremony
            .perform_decoding(test_authenticator_attestation_response)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_rp_id_hash() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data_byte_array)
                .await;
        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;
        let test_registration_ceremony = RegistrationCeremony {};

        assert!(test_registration_ceremony
            .verify_rp_id_hash(&test_authenticator_data_byte_array, "test_rp_identity")
            .await
            .is_err());
        assert!(test_registration_ceremony
            .verify_rp_id_hash(&test_authenticator_data_byte_array, "test_rp_id")
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_user_present() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data_byte_array)
                .await;
        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;
        let test_registration_ceremony = RegistrationCeremony {};

        assert!(test_registration_ceremony
            .verify_user_present(&test_authenticator_data_byte_array)
            .await
            .is_err());

        test_authenticator_data.set_user_present().await;

        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;

        assert!(test_registration_ceremony
            .verify_user_present(&test_authenticator_data_byte_array)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_user_verification() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data_byte_array)
                .await;
        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;
        let test_registration_ceremony = RegistrationCeremony {};

        assert!(test_registration_ceremony
            .verify_user_verification(&test_authenticator_data_byte_array)
            .await
            .is_err());

        test_authenticator_data.set_user_verifed().await;

        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;

        assert!(test_registration_ceremony
            .verify_user_verification(&test_authenticator_data_byte_array)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_algorithm() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data_byte_array)
                .await;
        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;
        let test_registration_ceremony = RegistrationCeremony {};
        let mut test_public_key_credential_creation_options = test_registration_ceremony
            .public_key_credential_creation_options()
            .await?;

        assert!(test_registration_ceremony
            .verify_algorithm(
                &test_authenticator_data_byte_array,
                &test_public_key_credential_creation_options
            )
            .await
            .is_err());

        test_public_key_credential_creation_options
            .public_key_credential_parameters
            .push(PublicKeyCredentialParameters {
                r#type: PublicKeyCredentialType::PublicKey,
                alg: -8,
            });

        assert!(test_registration_ceremony
            .verify_algorithm(
                &test_authenticator_data_byte_array,
                &test_public_key_credential_creation_options
            )
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn determine_attestation_statement_format() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};

        assert!(test_registration_ceremony
            .determine_attestation_statement_format(&String::from("something_else"))
            .await
            .is_err());

        assert!(test_registration_ceremony
            .determine_attestation_statement_format(&String::from("packed"))
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_attestation_statement() -> Result<(), Box<dyn std::error::Error>> {
        let test_attestation_statement_format = AttestationStatementFormat::Packed;
        let test_attestation_statement =
            AttestationStatement::Packed(PackedAttestationStatementSyntax::generate().await);
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data_byte_array)
                .await;
        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;
        let test_hash = Vec::with_capacity(0);
        let test_registration_ceremony = RegistrationCeremony {};

        assert!(test_registration_ceremony
            .verify_attestation_statement(
                &test_attestation_statement_format,
                &test_attestation_statement,
                &test_authenticator_data_byte_array,
                &test_hash,
            )
            .await
            .is_ok());

        let test_cose_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_credential_id = [0; 16];
        let test_credential_id_length = test_credential_id.len() as u16;
        let test_credential_id_length_bytes = test_credential_id_length.to_be_bytes();
        let test_another_credential_data = AttestedCredentialData {
            aaguid: [0; 16],
            credential_id_length: test_credential_id_length_bytes,
            credential_id: test_credential_id,
            credential_public_key: test_cose_key.0,
        };
        let test_another_credential_data_byte_array =
            test_another_credential_data.to_byte_array().await;
        let test_another_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_another_credential_data_byte_array)
                .await;
        let test_another_authenticator_data_byte_array =
            test_another_authenticator_data.to_byte_array().await;
        let test_signature = test_cose_key
            .1
            .sign(&test_another_authenticator_data_byte_array, &test_hash)
            .await?;
        let test_packed_attestation_statement_syntax_none =
            AttestationStatement::Packed(PackedAttestationStatementSyntax {
                alg: -8,
                // sig: test_signature.to_bytes().to_vec(),
                sig: test_signature.to_vec(),
                x5c: None,
            });

        assert!(test_registration_ceremony
            .verify_attestation_statement(
                &test_attestation_statement_format,
                &test_packed_attestation_statement_syntax_none,
                &test_another_authenticator_data_byte_array,
                &test_hash,
            )
            .await
            .is_ok());

        let test_packed_attestation_statement_syntax_none_alg =
            AttestationStatement::Packed(PackedAttestationStatementSyntax {
                alg: -7,
                sig: [0; 64].to_vec(),
                x5c: None,
            });

        assert!(test_registration_ceremony
            .verify_attestation_statement(
                &test_attestation_statement_format,
                &test_packed_attestation_statement_syntax_none_alg,
                &test_authenticator_data_byte_array,
                &test_hash,
            )
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn assess_attestation_trustworthiness() -> Result<(), Box<dyn std::error::Error>> {
        let test_registration_ceremony = RegistrationCeremony {};
        let test_attestation_verification_output = AttestationVerificationProcedureOutput {
            attestation_type: AttestationType::SelfAttestation,
            x5c: None,
        };

        assert!(test_registration_ceremony
            .assess_attestation_trustworthiness(test_attestation_verification_output)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn check_credential_id() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let mut test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data_byte_array)
                .await;
        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;
        let test_registration_ceremony = RegistrationCeremony {};
        let mut test_store = Store::init().await;

        tokio::spawn(async move {
            if let Err(error) = test_store.1.run().await {
                println!("test store error -> {:?}", error);
            }
        });

        test_store
            .0
            .register(
                [0; 16].to_vec(),
                UserAccount {
                    public_key: COSEKey::generate(COSEAlgorithm::EdDSA).await.0,
                    signature_counter: 0,
                    transports: None,
                },
            )
            .await?;

        assert!(test_registration_ceremony
            .check_credential_id(&test_store.0, &test_authenticator_data_byte_array)
            .await
            .is_err());

        test_attested_credential_data.credential_id = [1; 16];
        let test_byte_array = test_attested_credential_data.to_byte_array().await;
        test_authenticator_data.attested_credential_data = Some(test_byte_array);

        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;

        assert!(test_registration_ceremony
            .check_credential_id(&test_store.0, &test_authenticator_data_byte_array)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn register() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_attested_credential_data_byte_array =
            test_attested_credential_data.to_byte_array().await;
        let test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data_byte_array)
                .await;
        let test_authenticator_data_byte_array = test_authenticator_data.to_byte_array().await;
        let test_registration_ceremony = RegistrationCeremony {};
        let test_options = test_registration_ceremony
            .public_key_credential_creation_options()
            .await?;
        let mut test_store = Store::init().await;

        tokio::spawn(async move {
            if let Err(error) = test_store.1.run().await {
                println!("test store error -> {:?}", error);
            }
        });

        assert!(test_registration_ceremony
            .register(
                &test_store.0,
                test_options,
                &test_authenticator_data_byte_array,
            )
            .await
            .is_ok());

        Ok(())
    }
}
