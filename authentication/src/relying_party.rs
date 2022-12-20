use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, Duration};

use crate::security::session_token::{generate_session_token, SessionToken};
use crate::security::uuid::{generate_session_id, SessionId};

use std::collections::HashMap;

use crate::api::supporting_data_structures::TokenBinding;
use crate::error::AuthenticationError;
use crate::relying_party::client::ClientChannel;
use crate::relying_party::operation::{AuthenticationCeremony, RegistrationCeremony};
use crate::relying_party::store::{Store, StoreChannel};

pub mod client;
pub mod operation;
pub mod protocol;
pub mod store;

#[derive(Debug, Deserialize, Serialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub token: SessionToken,
}

impl SessionInfo {
    pub async fn generate() -> SessionInfo {
        SessionInfo {
            id: generate_session_id().await,
            token: generate_session_token().await,
        }
    }
}

#[derive(Debug)]
pub enum Operation {
    Allocate,
    Consume(SessionId),
    RegistrationCeremony(ClientChannel),
    AuthenticationCeremony(ClientChannel),
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
        client_channel: ClientChannel,
    ) -> Result<(), StatusCode> {
        let (_request, _response) = oneshot::channel();

        match self
            .run
            .send((Operation::RegistrationCeremony(client_channel), _request))
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
        client_channel: ClientChannel,
    ) -> Result<(), StatusCode> {
        let (_request, _response) = oneshot::channel();

        match self
            .run
            .send((Operation::AuthenticationCeremony(client_channel), _request))
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
    available_session: HashMap<SessionId, SessionToken>,
    store: StoreChannel,
    session_timeout: RelyingPartyOperation,
    operation: mpsc::Receiver<(Operation, oneshot::Sender<Response>)>,
}

impl RelyingParty {
    pub async fn init() -> (RelyingPartyOperation, RelyingParty) {
        let identifier = String::from("some_identifier");
        let available_session = HashMap::with_capacity(100);
        let (channel, mut store) = Store::init().await;
        let relying_party_operation = RelyingPartyOperation::init().await;

        tokio::spawn(async move {
            if let Err(error) = store.run().await {
                println!("store error -> {:?}", error);
            }
        });

        (
            relying_party_operation.0.to_owned(),
            RelyingParty {
                identifier,
                available_session,
                store: channel,
                session_timeout: relying_party_operation.0,
                operation: relying_party_operation.1,
            },
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some((operation, response)) = self.operation.recv().await {
            match operation {
                Operation::Allocate => {
                    let session_info = self.allocate().await;
                    let _ = response.send(Response::SessionInfo(session_info));
                }
                Operation::Consume(id) => match self.consume(id).await {
                    Some(session_info) => {
                        let _ = response.send(Response::SessionInfo(session_info));
                    }
                    None => {
                        let _ = response.send(Response::Error);
                    }
                },
                Operation::RegistrationCeremony(client_channel) => {
                    let identifier = self.identifier.to_owned();
                    let store = self.store.to_owned();

                    tokio::spawn(async move {
                        let operation = RegistrationCeremony {};

                        if let Err(error) = RelyingParty::register_new_credential(
                            operation,
                            &identifier,
                            client_channel,
                            store,
                        )
                        .await
                        {
                            println!("ceremony error -> {:?}", error);
                        }
                    });
                }
                Operation::AuthenticationCeremony(client_channel) => {
                    let identifier = self.identifier.to_owned();
                    let store = self.store.to_owned();

                    tokio::spawn(async move {
                        let operation = AuthenticationCeremony {};

                        if let Err(error) = RelyingParty::verify_authentication_assertion(
                            operation,
                            &identifier,
                            client_channel,
                            store,
                        )
                        .await
                        {
                            println!("ceremony error -> {:?}", error);
                        }
                    });
                }
            }
        }
        Ok(())
    }

    async fn allocate(&mut self) -> SessionInfo {
        let session_info = SessionInfo::generate().await;

        self.available_session
            .insert(session_info.id, session_info.token);

        let session_timeout = self.session_timeout.to_owned();
        let id = session_info.id.to_owned();

        tokio::spawn(async move {
            sleep(Duration::from_millis(30000)).await;

            if let Err(error) = session_timeout.consume(id).await {
                println!("timeout error -> {:?}", error);
            }
        });

        session_info
    }

    async fn consume(&mut self, id: SessionId) -> Option<SessionInfo> {
        self.available_session
            .remove_entry(&id)
            .map(|(id, token)| SessionInfo { id, token })
    }

    async fn register_new_credential(
        operation: RegistrationCeremony,
        identifier: &str,
        client: ClientChannel,
        store: StoreChannel,
    ) -> Result<(), AuthenticationError> {
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
            .check_credential_id(&store, &authenticator_data)
            .await?;
        operation
            .register(&store, options, &authenticator_data)
            .await?;

        Ok(())
    }

    pub async fn verify_authentication_assertion(
        operation: AuthenticationCeremony,
        identifier: &str,
        client: ClientChannel,
        store: StoreChannel,
    ) -> Result<(), AuthenticationError> {
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
            .identify_user_and_verify(&store, &response)
            .await?;

        let credential_public_key = operation.credential_public_key(&store, &credential).await?;
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
            .stored_sign_count(&store, &credential, &authenticator_data)
            .await?;

        Ok(())
    }
}
