use tokio::sync::mpsc;

use crate::api::supporting_data_structures::TokenBinding;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::relying_party::operation::{AuthenticationCeremony, RegistrationCeremony};
use crate::relying_party::protocol::communication::{ClientAgent, FailCeremony};
use crate::relying_party::store::{CredentialPublicKey, CredentialPublicKeyChannel};
use crate::relying_party::store::{SignatureCounter, SignatureCounterChannel};
use crate::relying_party::store::{UserAccount, UserAccountChannel};

pub mod operation;
pub mod protocol;
pub mod store;

#[derive(Debug)]
pub enum Ceremony {
    Registration(ClientAgent, FailCeremony),
    Authentication(ClientAgent, FailCeremony),
}

#[derive(Debug)]
pub enum Operation {
    Initiate(Ceremony),
}

#[derive(Clone)]
pub struct RelyingPartyOperation {
    run: mpsc::Sender<Operation>,
}

impl RelyingPartyOperation {
    pub async fn init() -> (RelyingPartyOperation, mpsc::Receiver<Operation>) {
        let (run, operation) = mpsc::channel(100);

        (RelyingPartyOperation { run }, operation)
    }

    pub async fn initiate(&self, ceremony: Ceremony) -> Result<(), AuthenticationError> {
        if let Err(error) = self.run.send(Operation::Initiate(ceremony)).await {
            println!("relying party operation | initiate ceremony -> {:?}", error);

            Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })
        } else {
            Ok(())
        }
    }
}

pub struct RelyingParty {
    identifier: String,
    operation: mpsc::Receiver<Operation>,
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

    pub async fn run(&mut self) {
        let mut credential_public_key = CredentialPublicKey::init().await;
        let mut signature_counter = SignatureCounter::init().await;
        let mut user_account = UserAccount::init().await;

        tokio::spawn(async move {
            credential_public_key.1.run().await;
        });

        tokio::spawn(async move {
            signature_counter.1.run().await;
        });

        tokio::spawn(async move {
            user_account.1.run().await;
        });

        while let Some(Operation::Initiate(ceremony)) = self.operation.recv().await {
            let identifier = self.identifier.to_owned();
            let credential_public_key = credential_public_key.0.to_owned();
            let signature_counter = signature_counter.0.to_owned();
            let user_account = user_account.0.to_owned();

            match ceremony {
                Ceremony::Registration(client_agent, fail_ceremony) => {
                    tokio::spawn(async move {
                        let mut error = fail_ceremony.subscribe();

                        loop {
                            tokio::select! {
                                biased;

                                _ = error.recv() => {
                                    println!("registration ceremony failed");

                                    break;
                                }

                                Err(error) = RelyingParty::register_new_credential(
                                    &identifier,
                                    client_agent,
                                    credential_public_key,
                                    signature_counter,
                                    user_account,
                                ) =>
                                {
                                    println!("ceremony error -> {:?}", error);

                                    fail_ceremony.error();

                                    break;
                                }
                            }
                        }
                    });
                }
                Ceremony::Authentication(client_agent, fail_ceremony) => {
                    tokio::spawn(async move {
                        let mut error = fail_ceremony.subscribe();

                        loop {
                            tokio::select! {
                                biased;

                                _ = error.recv() => {
                                    println!("registration ceremony failed");

                                    break;
                                }

                                Err(error) = RelyingParty::register_new_credential(
                                    &identifier,
                                    client_agent,
                                    credential_public_key,
                                    signature_counter,
                                    user_account,
                                ) =>
                                {
                                    println!("ceremony error -> {:?}", error);

                                    fail_ceremony.error();

                                    break;
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    async fn register_new_credential(
        identifier: &str,
        client: ClientAgent,
        credential_public_key: CredentialPublicKeyChannel,
        signature_counter: SignatureCounterChannel,
        user_account: UserAccountChannel,
    ) -> Result<(), AuthenticationError> {
        let operation = RegistrationCeremony {};
        let options = operation
            .public_key_credential_creation_options(identifier, &client)
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
        client: ClientAgent,
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
