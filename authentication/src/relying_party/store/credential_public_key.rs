use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

use crate::authenticator::attestation::COSEKey;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::uuid::CredentialId;

#[derive(Debug)]
pub enum Request {
    Register((CredentialId, COSEKey)),
    Lookup(CredentialId),
}

#[derive(Debug)]
pub enum Response {
    PublicKey(COSEKey),
    FailCeremony(bool),
}

#[derive(Clone)]
pub struct CredentialPublicKeyChannel {
    sender: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl CredentialPublicKeyChannel {
    pub async fn init() -> (
        CredentialPublicKeyChannel,
        mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
    ) {
        let (sender, receiver) = mpsc::channel(50);

        (CredentialPublicKeyChannel { sender }, receiver)
    }

    pub async fn register(
        &self,
        credential_id: CredentialId,
        public_key: COSEKey,
    ) -> Result<(), AuthenticationError> {
        let (request, response) = oneshot::channel();
        let operation_error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .sender
            .send((Request::Register((credential_id, public_key)), request))
            .await
        {
            Ok(()) => match response.await {
                Ok(Response::FailCeremony(fail_ceremony)) => match fail_ceremony {
                    true => Err(operation_error),
                    false => Ok(()),
                },
                Ok(Response::PublicKey(_)) => Err(operation_error),
                Err(error) => {
                    println!("credential public key channel | register -> {:?}", error);

                    Err(operation_error)
                }
            },
            Err(error) => {
                println!("credential public key channel | register -> {:?}", error);

                Err(operation_error)
            }
        }
    }

    pub async fn lookup(
        &self,
        credential_id: CredentialId,
    ) -> Result<COSEKey, AuthenticationError> {
        let (request, response) = oneshot::channel();
        let operation_error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .sender
            .send((Request::Lookup(credential_id), request))
            .await
        {
            Ok(()) => match response.await {
                Ok(Response::PublicKey(public_key)) => Ok(public_key),
                Ok(Response::FailCeremony(_)) => Err(operation_error),
                Err(error) => {
                    println!("credential public key channel | lookup -> {:?}", error);

                    Err(operation_error)
                }
            },
            Err(error) => {
                println!("credential public key channel | lookup -> {:?}", error);

                Err(operation_error)
            }
        }
    }
}

pub struct CredentialPublicKey {
    registration: HashMap<CredentialId, COSEKey>,
    receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl CredentialPublicKey {
    pub async fn init() -> (CredentialPublicKeyChannel, CredentialPublicKey) {
        let registration = HashMap::with_capacity(50);
        let (credential_public_key_channel, receiver) = CredentialPublicKeyChannel::init().await;

        (
            credential_public_key_channel,
            CredentialPublicKey {
                registration,
                receiver,
            },
        )
    }

    pub async fn run(&mut self) {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                Request::Register((credential_id, public_key)) => {
                    match self.register(credential_id, public_key).await {
                        true => {
                            let _ = response.send(Response::FailCeremony(true));
                        }
                        false => {
                            let _ = response.send(Response::FailCeremony(false));
                        }
                    }
                }
                Request::Lookup(credential_id) => match self.lookup(credential_id).await {
                    Some(public_key) => {
                        let _ = response.send(Response::PublicKey(public_key));
                    }
                    None => {
                        let _ = response.send(Response::FailCeremony(true));
                    }
                },
            }
        }
    }

    async fn register(&mut self, credential_id: CredentialId, public_key: COSEKey) -> bool {
        self.registration.insert(credential_id, public_key);

        false
    }

    async fn lookup(&self, credential_id: CredentialId) -> Option<COSEKey> {
        self.registration
            .get(&credential_id)
            .map(|public_key| public_key.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::attestation::COSEAlgorithm;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_credential_public_key = CredentialPublicKey::init().await;

        assert!(test_credential_public_key.0.sender.capacity() >= 50);
        assert!(test_credential_public_key.1.registration.capacity() >= 50);

        Ok(())
    }

    #[tokio::test]
    async fn register() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credential_public_key = CredentialPublicKey::init().await;

        assert!(test_credential_public_key.1.registration.is_empty());

        let test_credential_id = [0u8; 16].to_vec();
        let test_keypair = COSEKey::generate(COSEAlgorithm::EdDSA).await;

        test_credential_public_key
            .1
            .register(test_credential_id, test_keypair.0)
            .await;

        assert!(!test_credential_public_key.1.registration.is_empty());

        test_credential_public_key.1.registration.clear();

        assert!(test_credential_public_key.1.registration.is_empty());

        let test_run = tokio::spawn(async move {
            test_credential_public_key.1.run().await;

            assert!(!test_credential_public_key.1.registration.is_empty());
        });

        let test_credential_id = [0u8; 16].to_vec();
        let test_keypair = COSEKey::generate(COSEAlgorithm::EdDSA).await;

        assert!(test_credential_public_key
            .0
            .register(test_credential_id, test_keypair.0)
            .await
            .is_ok());

        drop(test_credential_public_key.0);

        assert!(test_run.await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn lookup() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credential_public_key = CredentialPublicKey::init().await;

        let test_credential_id = [0u8; 16].to_vec();
        let test_keypair = COSEKey::generate(COSEAlgorithm::EdDSA).await;

        test_credential_public_key
            .1
            .register(test_credential_id, test_keypair.0)
            .await;

        assert!(test_credential_public_key
            .1
            .lookup([0u8; 16].to_vec())
            .await
            .is_some());
        assert!(test_credential_public_key
            .1
            .lookup([1u8; 16].to_vec())
            .await
            .is_none());

        let test_run = tokio::spawn(async move {
            test_credential_public_key.1.run().await;
        });

        assert!(test_credential_public_key
            .0
            .lookup([0u8; 16].to_vec())
            .await
            .is_ok());
        assert!(test_credential_public_key
            .0
            .lookup([1u8; 16].to_vec())
            .await
            .is_err());

        drop(test_credential_public_key.0);

        assert!(test_run.await.is_ok());

        Ok(())
    }
}
