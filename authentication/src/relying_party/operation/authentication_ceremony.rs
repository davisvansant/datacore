use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::{
    AuthenticatorAssertionResponse, AuthenticatorResponse, ClientDataJSON, Signature,
};
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientOutputs;
use crate::api::public_key_credential::PublicKeyCredential;
use crate::api::supporting_data_structures::{CollectedClientData, TokenBinding};
use crate::authenticator::attestation::AttestedCredentialData;
use crate::authenticator::data::{AuthenticatorData, UP, UV};
use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::sha2::generate_hash;

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
        let r#type = String::from("public-key");
        let id = String::from("some_key_id");
        let raw_id = Vec::with_capacity(0);
        let client_data_json = Vec::with_capacity(0);
        let authenticator_data = Vec::with_capacity(0);
        let signature = Vec::with_capacity(0);
        let user_handle = Vec::with_capacity(0);
        let response =
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json,
                authenticator_data,
                signature,
                user_handle,
            });
        let credential = PublicKeyCredential::generate(r#type, id, raw_id, response).await;

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
            let mut identified_credential = Vec::with_capacity(1);

            for acceptable_credential in &options.allow_credentials {
                match acceptable_credential.id == credential.id.as_bytes() {
                    true => {
                        identified_credential.push(1);

                        break;
                    }
                    false => continue,
                }
            }

            match !identified_credential.is_empty() {
                true => Ok(()),
                false => Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                }),
            }
        } else {
            Ok(())
        }
    }

    pub async fn identify_user_and_verify(
        &self,
        authenticator_assertion_response: &AuthenticatorAssertionResponse,
    ) -> Result<(), AuthenticationError> {
        let mut credentials = HashMap::with_capacity(1);
        let credential_id = String::from("some_id").into_bytes();
        let public_key_credential_source = PublicKeyCredentialSource::generate().await;

        credentials.insert(credential_id, public_key_credential_source);

        if let Some(credential_source) =
            credentials.get(&authenticator_assertion_response.user_handle)
        {
            match credential_source.id.as_bytes() == &authenticator_assertion_response.user_handle {
                true => Ok(()),
                false => Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                }),
            }
        } else {
            Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })
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
        let rp_id = "some_rp_id";
        let attested_credential_data = AttestedCredentialData::generate().await;
        let authenticator_data = AuthenticatorData::generate(rp_id, attested_credential_data).await;
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

    pub async fn verify_client_data_type(
        &self,
        client_data: &CollectedClientData,
    ) -> Result<(), AuthenticationError> {
        match client_data.r#type == "webauthn.get" {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_client_data_challenge(
        &self,
        client_data: &CollectedClientData,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<(), AuthenticationError> {
        match client_data.challenge == options.challenge {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_client_data_origin(
        &self,
        client_data: &CollectedClientData,
        rp_origin: &str,
    ) -> Result<(), AuthenticationError> {
        match client_data.origin == rp_origin {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_client_data_token_binding(
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

    pub async fn hash(
        &self,
        _client_data: &CollectedClientData,
    ) -> Result<Vec<u8>, AuthenticationError> {
        Ok(Vec::with_capacity(0))
    }

    pub async fn verifiy_signature(
        &self,
        credential_public_key: &[u8],
        signature: &Signature,
        authenticator_data: &AuthenticatorData,
        hash: &[u8],
    ) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn stored_sign_count(
        &self,
        credential: &PublicKeyCredential,
        authenticator_data: &AuthenticatorData,
    ) -> Result<(), AuthenticationError> {
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

        if let Some(account) = some_credentials_map.get_mut(&credential.id) {
            let stored_sign_count = account.counter;

            match authenticator_data.signcount <= stored_sign_count {
                true => Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                }),
                false => {
                    account.counter = authenticator_data.signcount;

                    Ok(())
                }
            }
        } else {
            Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authenticator_responses::AuthenticatorAttestationResponse;
    use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;

    #[tokio::test]
    async fn public_key_credential_request_options() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};

        assert!(test_authentication_ceremony
            .public_key_credential_request_options()
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn call_credentials_get() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_public_key_credential_request_options = test_authentication_ceremony
            .public_key_credential_request_options()
            .await?;

        assert!(test_authentication_ceremony
            .call_credentials_get(&test_public_key_credential_request_options)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_assertion_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
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

        assert!(test_authentication_ceremony
            .authenticator_assertion_response(&test_public_key_credential_assertion)
            .await
            .is_ok());

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

        assert!(test_authentication_ceremony
            .authenticator_assertion_response(&test_public_key_credential_attestation)
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn client_extension_results() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_public_key_credential = PublicKeyCredential {
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

        assert!(test_authentication_ceremony
            .client_extension_results(&test_public_key_credential)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_credential_id() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let mut test_public_key_credential_request_options = test_authentication_ceremony
            .public_key_credential_request_options()
            .await?;
        let test_public_key_credential = PublicKeyCredential {
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

        assert!(test_authentication_ceremony
            .verify_credential_id(
                &test_public_key_credential_request_options,
                &test_public_key_credential,
            )
            .await
            .is_ok());

        test_public_key_credential_request_options
            .allow_credentials
            .push(PublicKeyCredentialDescriptor {
                r#type: String::from("public-key"),
                id: Vec::from(String::from("some_other_test_id")),
                transports: Some(vec![String::from("internal")]),
            });

        assert!(test_authentication_ceremony
            .verify_credential_id(
                &test_public_key_credential_request_options,
                &test_public_key_credential,
            )
            .await
            .is_err());

        test_public_key_credential_request_options
            .allow_credentials
            .push(PublicKeyCredentialDescriptor {
                r#type: String::from("public-key"),
                id: Vec::from(String::from("test_id")),
                transports: Some(vec![String::from("internal")]),
            });

        assert!(test_authentication_ceremony
            .verify_credential_id(
                &test_public_key_credential_request_options,
                &test_public_key_credential,
            )
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn identify_user_and_verify() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let mut test_authenticator_assertion_response = AuthenticatorAssertionResponse {
            client_data_json: Vec::with_capacity(0),
            authenticator_data: Vec::with_capacity(0),
            signature: Vec::with_capacity(0),
            user_handle: Vec::with_capacity(0),
        };

        assert!(test_authentication_ceremony
            .identify_user_and_verify(&test_authenticator_assertion_response)
            .await
            .is_err());

        test_authenticator_assertion_response.user_handle = b"some_other_id".to_vec();

        assert!(test_authentication_ceremony
            .identify_user_and_verify(&test_authenticator_assertion_response)
            .await
            .is_err());

        test_authenticator_assertion_response.user_handle = b"some_id".to_vec();

        assert!(test_authentication_ceremony
            .identify_user_and_verify(&test_authenticator_assertion_response)
            .await
            .is_ok());

        Ok(())
    }
}
