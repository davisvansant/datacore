use tokio::sync::broadcast;
use tokio::time::timeout;

use std::time::Duration;

use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::credential_creation_options::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity,
};
use crate::api::public_key_credential::PublicKeyCredential;
use crate::error::{AuthenticationError, AuthenticationErrorType};

use crate::relying_party::protocol::communication::{IncomingData, RelyingPartyAgentChannel};

#[derive(Debug)]
pub struct ClientAgent {
    authenticator_agent: broadcast::Sender<IncomingData>,
    relying_party_agent: RelyingPartyAgentChannel,
}

impl ClientAgent {
    pub async fn init(
        relying_party_agent: RelyingPartyAgentChannel,
    ) -> (broadcast::Sender<IncomingData>, ClientAgent) {
        let authenticator_agent = broadcast::channel(1);

        (
            authenticator_agent.0.to_owned(),
            ClientAgent {
                authenticator_agent: authenticator_agent.0,
                relying_party_agent,
            },
        )
    }

    pub async fn user_account(&self) -> Result<PublicKeyCredentialUserEntity, AuthenticationError> {
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        let call_timeout = Duration::from_millis(150000);
        let initial_name = String::from("initial_name");
        let initial_display_name = String::from("initial_display_name");
        let user_entity =
            PublicKeyCredentialUserEntity::generate(initial_name, initial_display_name).await;
        let expected_id = user_entity.id.to_owned();

        self.relying_party_agent.user_account(user_entity).await?;

        let mut incoming_data = self.authenticator_agent.subscribe();

        match timeout(call_timeout, incoming_data.recv()).await {
            Ok(received_data) => {
                if let Ok(IncomingData::PublicKeyCredentialUserEntity(
                    public_key_credential_user_entity,
                )) = received_data
                {
                    match public_key_credential_user_entity.id == expected_id {
                        true => Ok(public_key_credential_user_entity),
                        false => Err(error),
                    }
                } else {
                    Err(error)
                }
            }
            Err(timeout_error) => {
                println!("ceremony data | credentials create -> {:?}", timeout_error);

                Err(error)
            }
        }
    }

    pub async fn credentials_create(
        &self,
        options: PublicKeyCredentialCreationOptions,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        let call_timeout = match options.timeout {
            Some(timeout) => Duration::from_millis(timeout),
            None => return Err(error),
        };

        self.relying_party_agent
            .public_key_credential_creation_options(options)
            .await?;

        let mut incoming_data = self.authenticator_agent.subscribe();

        match timeout(call_timeout, incoming_data.recv()).await {
            Ok(received_data) => {
                if let Ok(IncomingData::PublicKeyCredential(credential)) = received_data {
                    Ok(credential)
                } else {
                    Err(error)
                }
            }
            Err(timeout_error) => {
                println!("ceremony data | credentials create -> {:?}", timeout_error);

                Err(error)
            }
        }
    }

    pub async fn credentials_get(
        &self,
        options: PublicKeyCredentialRequestOptions,
    ) -> Result<PublicKeyCredential, AuthenticationError> {
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        let call_timeout = match options.timeout {
            Some(timeout) => Duration::from_millis(timeout),
            None => return Err(error),
        };

        self.relying_party_agent
            .public_key_credential_request_options(options)
            .await?;

        let mut incoming_data = self.authenticator_agent.subscribe();

        match timeout(call_timeout, incoming_data.recv()).await {
            Ok(received_data) => {
                if let Ok(IncomingData::PublicKeyCredential(credential)) = received_data {
                    Ok(credential)
                } else {
                    Err(error)
                }
            }
            Err(timeout_error) => {
                println!("timeout reached! {:?}", timeout_error);

                Err(error)
            }
        }
    }
}
