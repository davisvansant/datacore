use tokio::sync::{broadcast, mpsc};

use crate::api::credential_creation_options::PublicKeyCredentialUserEntity;
use crate::api::public_key_credential::PublicKeyCredential;

use crate::error::AuthenticationError;

use crate::relying_party::protocol::communication::{FailCeremony, WebAuthnData};

#[derive(Clone)]
pub enum IncomingData {
    PublicKeyCredentialUserEntity(PublicKeyCredentialUserEntity),
    PublicKeyCredential(PublicKeyCredential),
    Error(AuthenticationError),
}

pub struct AuthenticatorAgentChannel {
    request: mpsc::Sender<Vec<u8>>,
}

impl AuthenticatorAgentChannel {
    pub async fn init(request: mpsc::Sender<Vec<u8>>) -> AuthenticatorAgentChannel {
        AuthenticatorAgentChannel { request }
    }

    pub async fn translate(&self, data: Vec<u8>) {
        let _ = self.request.send(data).await;
    }
}

pub struct AuthenticatorAgent {
    incoming_data: mpsc::Receiver<Vec<u8>>,
    outgoing_data: broadcast::Sender<IncomingData>,
    fail_ceremony: FailCeremony,
}

impl AuthenticatorAgent {
    pub async fn init(
        outgoing_data: broadcast::Sender<IncomingData>,
        fail_ceremony: FailCeremony,
    ) -> (AuthenticatorAgentChannel, AuthenticatorAgent) {
        let channel = mpsc::channel(1);
        let authenticator_agent_channel = AuthenticatorAgentChannel::init(channel.0).await;

        (
            authenticator_agent_channel,
            AuthenticatorAgent {
                incoming_data: channel.1,
                outgoing_data,
                fail_ceremony,
            },
        )
    }

    pub async fn run(&mut self) {
        let mut error = self.fail_ceremony.subscribe();

        loop {
            tokio::select! {
                biased;

                _ = error.recv() => {
                    println!("shutting down authenticator agent...");

                    self.incoming_data.close();

                    break;
                }
                Some(data) = self.incoming_data.recv() => {
                    match WebAuthnData::from_incoming_data(&data).await {
                        Ok(webauthn_data) => match webauthn_data.message.as_str() {
                            "public_key_credential" => {
                                match serde_json::from_slice(&webauthn_data.contents) {
                                    Ok(public_key_credential) => {
                                        let _ = self.outgoing_data.send(IncomingData::PublicKeyCredential(public_key_credential));
                                    }
                                    Err(error) => {
                                        println!("json serialization error -> {:?}", error);

                                        self.fail_ceremony.error();
                                        self.incoming_data.close();
                                    }
                                }
                            }
                            "public_key_credential_user_entity" => {
                                match serde_json::from_slice(&webauthn_data.contents) {
                                    Ok(public_key_credential_user_entity) => {
                                        let _ = self.outgoing_data.send(IncomingData::PublicKeyCredentialUserEntity(public_key_credential_user_entity));
                                    }
                                    Err(error) => {
                                        println!("json serialization error -> {:?}", error);

                                        self.fail_ceremony.error();
                                        self.incoming_data.close();
                                    }
                                }
                            }
                            _ => {
                                self.fail_ceremony.error();
                                self.incoming_data.close();
                            }
                        }
                        Err(error) => {
                            self.fail_ceremony.error();
                        }
                    }
                }
            }
        }
    }
}
