use axum::http::StatusCode;
use tokio::sync::{mpsc, oneshot};

use crate::api::supporting_data_structures::TokenBinding;
use crate::error::AuthenticationError;
use crate::relying_party::client::ceremony_data::CeremonyData;
use crate::relying_party::client::outgoing_data::ConnectedClient;
use crate::relying_party::operation::{AuthenticationCeremony, RegistrationCeremony};
use crate::relying_party::session::{Active, Available, SessionInfo};
use crate::security::uuid::SessionId;

use crate::relying_party::store::{CredentialPublicKey, CredentialPublicKeyChannel};
use crate::relying_party::store::{SignatureCounter, SignatureCounterChannel};
use crate::relying_party::store::{UserAccount, UserAccountChannel};

pub mod client;
pub mod operation;
pub mod protocol;
pub mod store;

mod session;

#[derive(Debug)]
pub enum Operation {
    Allocate,
    Consume(SessionId),
    RegistrationCeremony((SessionId, CeremonyData, ConnectedClient)),
    AuthenticationCeremony((SessionId, CeremonyData, ConnectedClient)),
}

#[derive(Debug)]
pub enum Response {
    SessionInfo(SessionInfo),
    Error,
}

#[derive(Clone)]
pub struct RelyingPartyOperation {
    run: mpsc::Sender<(Operation, oneshot::Sender<Response>)>,
}

impl RelyingPartyOperation {
    pub async fn init() -> (
        RelyingPartyOperation,
        mpsc::Receiver<(Operation, oneshot::Sender<Response>)>,
    ) {
        let (run, operation) = mpsc::channel(100);

        (RelyingPartyOperation { run }, operation)
    }

    pub async fn allocate(&self) -> Result<SessionInfo, StatusCode> {
        let (request, response) = oneshot::channel();
        match self.run.send((Operation::Allocate, request)).await {
            Ok(()) => {
                if let Ok(Response::SessionInfo(session_info)) = response.await {
                    Ok(session_info)
                } else {
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
            Err(error) => {
                println!("allocate request -> {:?}", error);

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    pub async fn consume(&self, id: SessionId) -> Result<SessionInfo, StatusCode> {
        let (request, response) = oneshot::channel();
        match self.run.send((Operation::Consume(id), request)).await {
            Ok(()) => match response.await {
                Ok(Response::SessionInfo(session_info)) => Ok(session_info),
                Ok(Response::Error) => Err(StatusCode::BAD_REQUEST),
                Err(error) => {
                    println!("consume response -> {:?}", error);

                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            },
            Err(error) => {
                println!("consume request -> {:?}", error);

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    pub async fn registration_ceremony(
        &self,
        session_id: SessionId,
        ceremony_data: CeremonyData,
        connected_client: ConnectedClient,
    ) -> Result<(), StatusCode> {
        let (_request, _response) = oneshot::channel();

        match self
            .run
            .send((
                Operation::RegistrationCeremony((session_id, ceremony_data, connected_client)),
                _request,
            ))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!(
                    "relying party operation | registration ceremony -> {:?}",
                    error,
                );

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    pub async fn authentication_ceremony(
        &self,
        session_id: SessionId,
        ceremony_data: CeremonyData,
        connected_client: ConnectedClient,
    ) -> Result<(), StatusCode> {
        let (_request, _response) = oneshot::channel();

        match self
            .run
            .send((
                Operation::AuthenticationCeremony((session_id, ceremony_data, connected_client)),
                _request,
            ))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!(
                    "relying party operation | authentication ceremony -> {:?}",
                    error,
                );

                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

pub struct RelyingParty {
    identifier: String,
    operation: mpsc::Receiver<(Operation, oneshot::Sender<Response>)>,
}

impl RelyingParty {
    pub async fn init() -> (RelyingPartyOperation, RelyingParty) {
        let identifier = String::from("some_identifier");
        let relying_party_operation = RelyingPartyOperation::init().await;

        (
            relying_party_operation.0.to_owned(),
            RelyingParty {
                identifier,
                operation: relying_party_operation.1,
            },
        )
    }

    pub async fn run(&mut self) -> Result<(), StatusCode> {
        let mut active = Active::init().await;
        let mut available = Available::init().await;
        let mut credential_public_key = CredentialPublicKey::init().await;
        let mut signature_counter = SignatureCounter::init().await;
        let mut user_account = UserAccount::init().await;

        tokio::spawn(async move {
            active.1.run().await;
        });

        tokio::spawn(async move {
            available.1.run().await;
        });

        tokio::spawn(async move {
            credential_public_key.1.run().await;
        });

        tokio::spawn(async move {
            signature_counter.1.run().await;
        });

        tokio::spawn(async move {
            user_account.1.run().await;
        });

        while let Some((operation, response)) = self.operation.recv().await {
            match operation {
                Operation::Allocate => {
                    let session_info = available.0.allocate().await?;
                    let _ = response.send(Response::SessionInfo(session_info));
                }
                Operation::Consume(id) => match available.0.consume(id).await {
                    Ok(session_info) => {
                        let _ = response.send(Response::SessionInfo(session_info));
                    }
                    Err(_) => {
                        let _ = response.send(Response::Error);
                    }
                },
                Operation::RegistrationCeremony((session_id, ceremony_data, connected_client)) => {
                    let identifier = self.identifier.to_owned();
                    let credential_public_key = credential_public_key.0.to_owned();
                    let signature_counter = signature_counter.0.to_owned();
                    let user_account = user_account.0.to_owned();

                    let task_id = session_id.to_owned();
                    let task = active.0.to_owned();

                    let handle = tokio::spawn(async move {
                        if let Err(error) = RelyingParty::register_new_credential(
                            &identifier,
                            ceremony_data,
                            credential_public_key,
                            signature_counter,
                            user_account,
                        )
                        .await
                        {
                            println!("ceremony error -> {:?}", error);

                            let _ = task.abort(task_id).await;
                            connected_client.fail_ceremony(error).await;
                        }
                    });

                    active.0.insert(session_id, handle).await?;
                }
                Operation::AuthenticationCeremony((
                    session_id,
                    ceremony_data,
                    connected_client,
                )) => {
                    let identifier = self.identifier.to_owned();
                    let credential_public_key = credential_public_key.0.to_owned();
                    let signature_counter = signature_counter.0.to_owned();
                    let user_account = user_account.0.to_owned();

                    let task_id = session_id.to_owned();
                    let task = active.0.to_owned();

                    let handle = tokio::spawn(async move {
                        if let Err(error) = RelyingParty::verify_authentication_assertion(
                            &identifier,
                            ceremony_data,
                            credential_public_key,
                            signature_counter,
                            user_account,
                        )
                        .await
                        {
                            println!("ceremony error -> {:?}", error);

                            let _ = task.abort(task_id).await;
                            connected_client.fail_ceremony(error).await;
                        }
                    });

                    active.0.insert(session_id, handle).await?;
                }
            }
        }
        Ok(())
    }

    async fn register_new_credential(
        identifier: &str,
        client: CeremonyData,
        credential_public_key: CredentialPublicKeyChannel,
        signature_counter: SignatureCounterChannel,
        user_account: UserAccountChannel,
    ) -> Result<(), AuthenticationError> {
        let operation = RegistrationCeremony {};
        let options = operation
            .public_key_credential_creation_options(identifier)
            .await?;
        let credential = operation.call_credentials_create(&options, &client).await?;
        let response = operation
            .authenticator_attestation_response(&credential)
            .await?;
        let client_extension_results = operation.client_extension_results(&credential).await?;
        let json_text = operation.json(&response).await?;
        let client_data = operation.client_data(&json_text).await?;

        let connection_token_binding = TokenBinding::generate().await;

        operation.verify_type(&client_data).await?;
        operation.verify_challenge(&client_data, &options).await?;
        operation.verify_origin(&client_data, identifier).await?;
        operation
            .verify_token_binding(&client_data, &connection_token_binding)
            .await?;

        let hash = operation.hash(&response).await?;
        let (fmt, authenticator_data, attestation_statement) =
            operation.perform_decoding(response).await?;

        operation
            .verify_rp_id_hash(&authenticator_data, identifier)
            .await?;
        operation.verify_user_present(&authenticator_data).await?;
        operation
            .verify_user_verification(&authenticator_data)
            .await?;
        operation
            .verify_algorithm(&authenticator_data, &options)
            .await?;
        operation
            .verify_extension_outputs(&client_extension_results, &authenticator_data)
            .await?;
        operation
            .determine_attestation_statement_format(&fmt)
            .await?;

        let attestation_statement_format = operation
            .determine_attestation_statement_format(&fmt)
            .await?;
        let attestation_statement_output = operation
            .verify_attestation_statement(
                &attestation_statement_format,
                &attestation_statement,
                &authenticator_data,
                &hash,
            )
            .await?;

        operation
            .assess_attestation_trustworthiness(attestation_statement_output)
            .await?;

        operation
            .check_credential_id(&user_account, &authenticator_data)
            .await?;

        operation
            .register(
                &credential_public_key,
                &signature_counter,
                &user_account,
                options,
                &authenticator_data,
            )
            .await?;

        Ok(())
    }

    pub async fn verify_authentication_assertion(
        identifier: &str,
        client: CeremonyData,
        credential_public_key: CredentialPublicKeyChannel,
        signature_counter: SignatureCounterChannel,
        user_account: UserAccountChannel,
    ) -> Result<(), AuthenticationError> {
        let operation = AuthenticationCeremony {};
        let options = operation
            .public_key_credential_request_options(identifier)
            .await?;
        let credential = operation.call_credentials_get(&options, &client).await?;
        let response = operation
            .authenticator_assertion_response(&credential)
            .await?;
        let client_extension_results = operation.client_extension_results(&credential).await?;

        operation
            .verify_credential_id(&options, &credential)
            .await?;

        operation
            .identify_user_and_verify(&user_account, &credential, &response)
            .await?;

        let credential_public_key = operation
            .credential_public_key(&credential_public_key, &credential)
            .await?;

        let (client_data_json, authenticator_data, signature) =
            operation.response_values(response).await?;
        let client_data = operation.client_data(&client_data_json).await?;

        let token_binding = TokenBinding::generate().await;

        operation.verify_client_data_type(&client_data).await?;
        operation
            .verify_client_data_challenge(&client_data, &options)
            .await?;
        operation
            .verify_client_data_origin(&client_data, identifier)
            .await?;
        operation
            .verify_client_data_token_binding(&client_data, &token_binding)
            .await?;
        operation
            .verify_rp_id_hash(&authenticator_data, identifier)
            .await?;
        operation.verify_user_present(&authenticator_data).await?;
        operation
            .verify_user_verification(&authenticator_data)
            .await?;
        operation
            .verify_client_extension_results(&client_extension_results, &authenticator_data)
            .await?;

        let hash = operation.hash(&client_data_json).await?;

        operation
            .verify_signature(
                &credential_public_key,
                &signature,
                &authenticator_data,
                &hash,
            )
            .await?;

        operation
            .stored_sign_count(&signature_counter, &credential, &authenticator_data)
            .await?;

        Ok(())
    }
}
