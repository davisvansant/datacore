use serde_json::from_slice;

use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::{
    AuthenticatorAssertionResponse, AuthenticatorResponse, ClientDataJSON, Signature,
};
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientOutputs;
use crate::api::public_key_credential::PublicKeyCredential;
use crate::api::supporting_data_structures::{ClientDataType, CollectedClientData, TokenBinding};
use crate::authenticator::attestation::COSEKey;
use crate::authenticator::data::AuthenticatorData;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::sha2::{generate_hash, Hash};

use crate::relying_party::store::CredentialPublicKeyChannel;
use crate::relying_party::store::SignatureCounterChannel;
use crate::relying_party::store::UserAccountChannel;

use crate::relying_party::protocol::communication::ClientAgent;

pub struct AuthenticationCeremony {}

impl AuthenticationCeremony {
    pub async fn public_key_credential_request_options(
        &self,
        rp_id: &str,
    ) -> Result<PublicKeyCredentialRequestOptions, AuthenticationError> {
        let public_key_credential_request_options =
            PublicKeyCredentialRequestOptions::generate(Some(rp_id)).await;

        Ok(public_key_credential_request_options)
    }

    pub async fn call_credentials_get(
        &self,
        options: &PublicKeyCredentialRequestOptions,
        client: &ClientAgent,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let credential = client.credentials_get(options.to_owned()).await?;

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
        match &options.allow_credentials {
            Some(allow_credentials) => {
                if !allow_credentials.is_empty() {
                    let mut identified_credential = Vec::with_capacity(1);

                    for acceptable_credential in allow_credentials {
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
            None => Ok(()),
        }
    }

    pub async fn identify_user_and_verify(
        &self,
        store: &UserAccountChannel,
        credential: &PublicKeyCredential,
        authenticator_assertion_response: &AuthenticatorAssertionResponse,
    ) -> Result<(), AuthenticationError> {
        store
            .verify(
                credential.raw_id.to_owned(),
                authenticator_assertion_response.user_handle.to_owned(),
            )
            .await?;

        Ok(())
    }

    pub async fn credential_public_key(
        &self,
        store: &CredentialPublicKeyChannel,
        credential: &PublicKeyCredential,
    ) -> Result<COSEKey, AuthenticationError> {
        let credential = store.lookup(credential.raw_id.to_vec()).await?;

        Ok(credential)
    }

    pub async fn response_values(
        &self,
        response: AuthenticatorAssertionResponse,
    ) -> Result<(ClientDataJSON, Vec<u8>, Signature), AuthenticationError> {
        let client_data = response.client_data_json;
        let authenticator_data = response.authenticator_data;
        let signature = response.signature;

        Ok((client_data, authenticator_data, signature))
    }

    pub async fn client_data(
        &self,
        client_data_json: &ClientDataJSON,
    ) -> Result<CollectedClientData, AuthenticationError> {
        match from_slice(client_data_json) {
            Ok(collected_client_data) => Ok(collected_client_data),
            Err(_) => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    pub async fn verify_client_data_type(
        &self,
        client_data: &CollectedClientData,
    ) -> Result<(), AuthenticationError> {
        match client_data.r#type == ClientDataType::Get {
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
        match client_data.challenge.as_bytes() == options.challenge {
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

    pub async fn verify_client_extension_results(
        &self,
        _client_extension_results: &AuthenticationExtensionsClientOutputs,
        authenticator_data: &[u8],
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;

        if authenticator_data.includes_extension_data().await {
            todo!();
        } else {
            Ok(())
        }
    }

    pub async fn hash(
        &self,
        client_data_json: &ClientDataJSON,
    ) -> Result<Hash, AuthenticationError> {
        let client_data_hash = generate_hash(client_data_json).await;

        Ok(client_data_hash)
    }

    pub async fn verify_signature(
        &self,
        credential_public_key: &COSEKey,
        signature: &Signature,
        authenticator_data: &[u8],
        hash: &[u8],
    ) -> Result<(), AuthenticationError> {
        credential_public_key
            .verify(signature, authenticator_data, hash)
            .await?;

        Ok(())
    }

    pub async fn stored_sign_count(
        &self,
        store: &SignatureCounterChannel,
        credential: &PublicKeyCredential,
        authenticator_data: &[u8],
    ) -> Result<(), AuthenticationError> {
        let authenticator_data = AuthenticatorData::from_byte_array(authenticator_data).await;

        store
            .initialize(
                credential.raw_id.to_owned(),
                u32::from_be_bytes(authenticator_data.sign_count),
            )
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authenticator_responses::AuthenticatorAttestationResponse;
    use crate::api::credential_creation_options::PublicKeyCredentialUserEntity;
    use crate::api::supporting_data_structures::{
        AuthenticatorTransport, PublicKeyCredentialDescriptor, PublicKeyCredentialType,
        TokenBinding, TokenBindingStatus,
    };
    use crate::authenticator::attestation::COSEAlgorithm;
    use crate::relying_party::protocol::communication::{
        AuthenticatorAgent, FailCeremony, RelyingPartyAgent, WebAuthnData,
    };
    use crate::relying_party::store::CredentialPublicKey;
    use crate::relying_party::store::SignatureCounter;
    use crate::relying_party::store::UserAccount;
    use axum::extract::ws::Message;
    use chrono::{offset::Utc, SecondsFormat};
    use tokio::sync::mpsc::channel;

    #[tokio::test]
    async fn public_key_credential_request_options() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};

        assert!(test_authentication_ceremony
            .public_key_credential_request_options("test_rp_id")
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn call_credentials_get() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_public_key_credential_request_options = test_authentication_ceremony
            .public_key_credential_request_options("test_rp_id")
            .await?;

        let (test_outgoing_message, mut test_outgoing_messages) = channel::<Message>(1);
        let test_fail_ceremony = FailCeremony::init();
        let mut test_relying_party_agent = RelyingPartyAgent::init(
            test_outgoing_message.to_owned(),
            test_fail_ceremony.to_owned(),
        )
        .await;
        let test_client_agent = ClientAgent::init(test_relying_party_agent.0.to_owned()).await;
        let mut test_authenticator_agent =
            AuthenticatorAgent::init(test_client_agent.0, test_fail_ceremony.to_owned()).await;

        tokio::spawn(async move {
            test_authenticator_agent.1.run().await;
        });

        tokio::spawn(async move {
            test_relying_party_agent.1.run().await;
        });

        tokio::spawn(async move {
            if let Some(Message::Binary(test_data)) = test_outgoing_messages.recv().await {
                let test_webauthndata: WebAuthnData = serde_json::from_slice(&test_data).unwrap();

                match test_webauthndata.message.as_str() {
                    "public_key_credential_request_options" => {
                        let id = [0u8; 16].to_vec();
                        let client_data_json = Vec::with_capacity(0);
                        let authenticator_data = Vec::with_capacity(0);
                        let signature = Vec::with_capacity(0);
                        let user_handle = Vec::with_capacity(0);
                        let response = AuthenticatorResponse::AuthenticatorAssertionResponse(
                            AuthenticatorAssertionResponse {
                                client_data_json,
                                authenticator_data,
                                signature,
                                user_handle,
                            },
                        );
                        let credential = PublicKeyCredential::generate(id, response).await;
                        let webauthndata = WebAuthnData {
                            message: String::from("public_key_credential"),
                            contents: serde_json::to_vec(&credential).expect("json"),
                            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                        };
                        let json = serde_json::to_vec(&webauthndata).expect("json");

                        test_authenticator_agent.0.translate(json).await;
                    }
                    _ => panic!("this is just for testing..."),
                }
            }
        });

        assert!(test_authentication_ceremony
            .call_credentials_get(
                &test_public_key_credential_request_options,
                &test_client_agent.1,
            )
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authenticator_assertion_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_public_key_credential_assertion = PublicKeyCredential::generate(
            [0u8; 16].to_vec(),
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: Vec::with_capacity(0),
                authenticator_data: Vec::with_capacity(0),
                signature: Vec::with_capacity(0),
                user_handle: Vec::with_capacity(0),
            }),
        )
        .await;

        assert!(test_authentication_ceremony
            .authenticator_assertion_response(&test_public_key_credential_assertion)
            .await
            .is_ok());

        let test_public_key_credential_attestation = PublicKeyCredential::generate(
            [0u8; 16].to_vec(),
            AuthenticatorResponse::AuthenticatorAttestationResponse(
                AuthenticatorAttestationResponse {
                    client_data_json: Vec::with_capacity(0),
                    attestation_object: Vec::with_capacity(0),
                },
            ),
        )
        .await;

        assert!(test_authentication_ceremony
            .authenticator_assertion_response(&test_public_key_credential_attestation)
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn client_extension_results() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_public_key_credential = PublicKeyCredential::generate(
            [0u8; 16].to_vec(),
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: Vec::with_capacity(0),
                authenticator_data: Vec::with_capacity(0),
                signature: Vec::with_capacity(0),
                user_handle: Vec::with_capacity(0),
            }),
        )
        .await;

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
            .public_key_credential_request_options("test_rp_id")
            .await?;
        let mut test_public_key_credential = PublicKeyCredential::generate(
            [0u8; 16].to_vec(),
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: Vec::with_capacity(0),
                authenticator_data: Vec::with_capacity(0),
                signature: Vec::with_capacity(0),
                user_handle: Vec::with_capacity(0),
            }),
        )
        .await;

        assert!(test_authentication_ceremony
            .verify_credential_id(
                &test_public_key_credential_request_options,
                &test_public_key_credential,
            )
            .await
            .is_ok());

        test_public_key_credential_request_options
            .allow_credentials
            .as_mut()
            .map_or_else(
                || {},
                |credentials| {
                    credentials.push(PublicKeyCredentialDescriptor {
                        r#type: PublicKeyCredentialType::PublicKey,
                        id: [1; 16].to_vec(),
                        transports: Some(vec![AuthenticatorTransport::Internal]),
                    })
                },
            );

        assert!(test_authentication_ceremony
            .verify_credential_id(
                &test_public_key_credential_request_options,
                &test_public_key_credential,
            )
            .await
            .is_err());

        test_public_key_credential.id = String::from_utf8([2; 16].to_vec())?;

        test_public_key_credential_request_options
            .allow_credentials
            .as_mut()
            .map_or_else(
                || {},
                |credentials| {
                    credentials.push(PublicKeyCredentialDescriptor {
                        r#type: PublicKeyCredentialType::PublicKey,
                        id: [2; 16].to_vec(),
                        transports: Some(vec![AuthenticatorTransport::Internal]),
                    })
                },
            );

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

        let test_id = [0u8; 16].to_vec();
        let test_client_data_json = Vec::with_capacity(0);
        let test_authenticator_data = Vec::with_capacity(0);
        let test_signature = Vec::with_capacity(0);
        let test_user_handle = b"some_test_id".to_vec();
        let test_response =
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: test_client_data_json,
                authenticator_data: test_authenticator_data,
                signature: test_signature,
                user_handle: test_user_handle,
            });
        let mut test_public_key_credential =
            PublicKeyCredential::generate(test_id, test_response).await;

        let test_response = test_authentication_ceremony
            .authenticator_assertion_response(&test_public_key_credential)
            .await?;

        let mut test_user_account = UserAccount::init().await;

        tokio::spawn(async move {
            test_user_account.1.run().await;
        });

        assert!(test_authentication_ceremony
            .identify_user_and_verify(
                &test_user_account.0,
                &test_public_key_credential,
                &test_response,
            )
            .await
            .is_err());

        test_public_key_credential.raw_id = b"some_other_id".to_vec();

        test_user_account
            .0
            .register(
                b"some_other_id".to_vec(),
                PublicKeyCredentialUserEntity {
                    name: String::from("some_test_name"),
                    id: b"some_test_id".to_vec(),
                    display_name: String::from("some_display_name"),
                },
            )
            .await?;

        assert!(test_authentication_ceremony
            .identify_user_and_verify(
                &test_user_account.0,
                &test_public_key_credential,
                &test_response,
            )
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn credential_public_key() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};

        let test_id = [0u8; 16].to_vec();
        let test_client_data_json = Vec::with_capacity(0);
        let test_authenticator_data = Vec::with_capacity(0);
        let test_signature = Vec::with_capacity(0);
        let test_user_handle = b"some_test_id".to_vec();
        let test_response =
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: test_client_data_json,
                authenticator_data: test_authenticator_data,
                signature: test_signature,
                user_handle: test_user_handle,
            });
        let mut test_public_key_credential =
            PublicKeyCredential::generate(test_id, test_response).await;

        let mut test_credential_public_key = CredentialPublicKey::init().await;

        tokio::spawn(async move {
            test_credential_public_key.1.run().await;
        });

        test_credential_public_key
            .0
            .register(
                b"some_id".to_vec(),
                COSEKey::generate(COSEAlgorithm::EdDSA).await.0,
            )
            .await?;

        assert!(test_authentication_ceremony
            .credential_public_key(&test_credential_public_key.0, &test_public_key_credential)
            .await
            .is_err());

        test_public_key_credential.raw_id = b"some_id".to_vec();

        assert!(test_authentication_ceremony
            .credential_public_key(&test_credential_public_key.0, &test_public_key_credential)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn response_values() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};

        let test_client_data_json = Vec::with_capacity(0);
        let test_authenticator_data = Vec::with_capacity(0);
        let test_signature = Vec::with_capacity(0);
        let test_user_handle = b"some_test_id".to_vec();
        let test_authenticator_assertion_response = AuthenticatorAssertionResponse {
            client_data_json: test_client_data_json,
            authenticator_data: test_authenticator_data,
            signature: test_signature,
            user_handle: test_user_handle,
        };

        assert!(test_authentication_ceremony
            .response_values(test_authenticator_assertion_response)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn client_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};

        let test_invalid_json = b"
        { 
            \"typ\": \"webauthn.get\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            \"origin\": \"some_test_origin\",
            \"cross_rigin\": false
        }";

        assert!(test_authentication_ceremony
            .client_data(&test_invalid_json.to_vec())
            .await
            .is_err());

        let test_valid_json = b"
        { 
            \"type\": \"webauthn.get\",
            \"challenge\": \"c29tZV90ZXN0X2NoYWxsZW5nZQ==\",
            \"origin\": \"some_test_origin\",
            \"crossOrigin\": true
        }";

        assert!(test_authentication_ceremony
            .client_data(&test_valid_json.to_vec())
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_client_data_type() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let mut test_client_data = CollectedClientData {
            r#type: ClientDataType::Create,
            challenge: String::from("c29tZV90ZXN0X2NoYWxsZW5nZQ=="),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        assert!(test_authentication_ceremony
            .verify_client_data_type(&test_client_data)
            .await
            .is_err());

        test_client_data.r#type = ClientDataType::Get;

        assert!(test_authentication_ceremony
            .verify_client_data_type(&test_client_data)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_client_data_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_public_key_credential_request_options = test_authentication_ceremony
            .public_key_credential_request_options("test_rp_id")
            .await?;
        let mut test_client_data = CollectedClientData {
            r#type: ClientDataType::Get,
            challenge: String::from("c29tZV90ZXN0X2NoYWxsZW5nZQ=="),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        assert!(test_authentication_ceremony
            .verify_client_data_challenge(
                &test_client_data,
                &test_public_key_credential_request_options,
            )
            .await
            .is_err());

        test_client_data.challenge = String::from_utf8(
            test_public_key_credential_request_options
                .challenge
                .to_owned(),
        )?;

        assert!(test_authentication_ceremony
            .verify_client_data_challenge(
                &test_client_data,
                &test_public_key_credential_request_options,
            )
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_client_data_origin() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_client_data = CollectedClientData {
            r#type: ClientDataType::Get,
            challenge: String::from("c29tZV90ZXN0X2NoYWxsZW5nZQ=="),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };

        assert!(test_authentication_ceremony
            .verify_client_data_origin(&test_client_data, "not_some_test_origin")
            .await
            .is_err());

        assert!(test_authentication_ceremony
            .verify_client_data_origin(&test_client_data, "some_test_origin")
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_client_data_token_binding() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let mut test_client_data = CollectedClientData {
            r#type: ClientDataType::Get,
            challenge: String::from("c29tZV90ZXN0X2NoYWxsZW5nZQ=="),
            origin: String::from("some_test_origin"),
            cross_origin: false,
            token_binding: None,
        };
        let test_token_binding = TokenBinding {
            status: TokenBindingStatus::Present,
            id: String::from("some_token_binding_id"),
        };

        assert!(test_authentication_ceremony
            .verify_client_data_token_binding(&test_client_data, &test_token_binding)
            .await
            .is_ok());

        test_client_data.token_binding = Some(TokenBinding {
            status: TokenBindingStatus::Supported,
            id: String::from("some_token_binding_id"),
        });

        assert!(test_authentication_ceremony
            .verify_client_data_token_binding(&test_client_data, &test_token_binding)
            .await
            .is_err());

        test_client_data.token_binding = Some(TokenBinding {
            status: TokenBindingStatus::Present,
            id: String::from("some_other_token_binding_id"),
        });

        assert!(test_authentication_ceremony
            .verify_client_data_token_binding(&test_client_data, &test_token_binding)
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn verify_rp_id_hash() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = true;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;

        assert!(test_authentication_ceremony
            .verify_rp_id_hash(&test_authenticator_data, "test_other_rp_id")
            .await
            .is_err());
        assert!(test_authentication_ceremony
            .verify_rp_id_hash(&test_authenticator_data, "test_rp_id")
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_user_present() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_rp_id = "test_rp_id";
        let test_user_present = false;
        let test_user_verified = true;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;

        assert!(test_authentication_ceremony
            .verify_user_present(&test_authenticator_data)
            .await
            .is_err());

        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = true;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;

        assert!(test_authentication_ceremony
            .verify_user_present(&test_authenticator_data)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_user_verification() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = false;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;

        assert!(test_authentication_ceremony
            .verify_user_verification(&test_authenticator_data)
            .await
            .is_err());

        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = true;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;

        assert!(test_authentication_ceremony
            .verify_user_verification(&test_authenticator_data)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn hash() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_collected_client_data = b"
        { 
            \"type\": \"webauthn.get\",
            \"challenge\": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            \"origin\": \"some_test_origin\",
            \"crossOrigin\": true
        }";

        assert!(test_authentication_ceremony
            .hash(&test_collected_client_data.to_vec())
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify_signature() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};
        let test_keypair = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = true;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;
        let test_hash = b"test_client_data".to_vec();
        let test_signature = test_keypair
            .1
            .sign(&test_authenticator_data, &test_hash)
            .await?;

        assert!(test_authentication_ceremony
            .verify_signature(
                &test_keypair.0,
                &test_signature.to_vec(),
                &test_authenticator_data,
                &test_hash,
            )
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn stored_sign_count() -> Result<(), Box<dyn std::error::Error>> {
        let test_authentication_ceremony = AuthenticationCeremony {};

        let test_id = [0u8; 16].to_vec();
        let test_client_data_json = Vec::with_capacity(0);
        let test_authenticator_data = Vec::with_capacity(0);
        let test_signature = Vec::with_capacity(0);
        let test_user_handle = b"some_test_id".to_vec();
        let test_response =
            AuthenticatorResponse::AuthenticatorAssertionResponse(AuthenticatorAssertionResponse {
                client_data_json: test_client_data_json,
                authenticator_data: test_authenticator_data,
                signature: test_signature,
                user_handle: test_user_handle,
            });
        let test_public_key_credential =
            PublicKeyCredential::generate(test_id, test_response).await;

        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = false;
        let test_sign_count = 1_u32.to_be_bytes();
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            None,
            None,
        )
        .await;

        let mut test_signature_counter = SignatureCounter::init().await;

        tokio::spawn(async move {
            test_signature_counter.1.run().await;
        });

        test_signature_counter
            .0
            .initialize([0u8; 16].to_vec(), 0)
            .await?;

        assert!(test_authentication_ceremony
            .stored_sign_count(
                &test_signature_counter.0,
                &test_public_key_credential,
                &test_authenticator_data,
            )
            .await
            .is_ok());

        Ok(())
    }
}
