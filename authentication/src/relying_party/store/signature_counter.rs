use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::uuid::CredentialId;

#[derive(Debug)]
pub enum Request {
    Initialize((CredentialId, u32)),
    Update((CredentialId, u32)),
}

#[derive(Debug)]
pub enum Response {
    FailCeremony(bool),
}

#[derive(Clone)]
pub struct SignatureCounterChannel {
    sender: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl SignatureCounterChannel {
    pub async fn init() -> (
        SignatureCounterChannel,
        mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
    ) {
        let (sender, receiver) = mpsc::channel(64);

        (SignatureCounterChannel { sender }, receiver)
    }

    pub async fn initialize(
        &self,
        credential_id: CredentialId,
        sign_count: u32,
    ) -> Result<(), AuthenticationError> {
        let (_request, _response) = oneshot::channel();
        let operation_error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .sender
            .send((Request::Initialize((credential_id, sign_count)), _request))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("signature counter channel | initialize -> {:?}", error);

                Err(operation_error)
            }
        }
    }

    pub async fn update(
        &self,
        credential_id: CredentialId,
        sign_count: u32,
    ) -> Result<(), AuthenticationError> {
        let (request, response) = oneshot::channel();
        let operation_error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .sender
            .send((Request::Update((credential_id, sign_count)), request))
            .await
        {
            Ok(()) => match response.await {
                Ok(Response::FailCeremony(fail_ceremony)) => match fail_ceremony {
                    true => Err(operation_error),
                    false => Ok(()),
                },
                Err(error) => {
                    println!("signature counter channel | update -> {:?}", error);

                    Err(operation_error)
                }
            },
            Err(error) => {
                println!("signature counter channel | update -> {:?}", error);

                Err(operation_error)
            }
        }
    }
}

pub struct SignatureCounter {
    stored_value: HashMap<CredentialId, u32>,
    receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl SignatureCounter {
    pub async fn init() -> (SignatureCounterChannel, SignatureCounter) {
        let stored_value = HashMap::with_capacity(50);
        let (signature_counter_channel, receiver) = SignatureCounterChannel::init().await;

        (
            signature_counter_channel,
            SignatureCounter {
                stored_value,
                receiver,
            },
        )
    }

    pub async fn run(&mut self) {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                Request::Initialize((credential_id, sign_count)) => {
                    self.initialize(credential_id, sign_count).await;
                }
                Request::Update((credential_id, sign_count)) => {
                    match self.update(credential_id, sign_count).await {
                        true => {
                            let _ = response.send(Response::FailCeremony(true));
                        }
                        false => {
                            let _ = response.send(Response::FailCeremony(false));
                        }
                    }
                }
            }
        }
    }

    async fn initialize(&mut self, credential_id: CredentialId, sign_count: u32) {
        self.stored_value.insert(credential_id, sign_count);
    }

    async fn update(&mut self, credential_id: CredentialId, sign_count: u32) -> bool {
        if let Some(stored_sign_count) = self.stored_value.get_mut(&credential_id) {
            if sign_count > *stored_sign_count {
                *stored_sign_count = sign_count;

                false
            } else {
                true
            }
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_signature_counter = SignatureCounter::init().await;

        assert!(test_signature_counter.0.sender.capacity() >= 50);
        assert!(test_signature_counter.1.stored_value.capacity() >= 50);

        Ok(())
    }

    #[tokio::test]
    async fn initialize() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_signature_counter = SignatureCounter::init().await;

        assert!(test_signature_counter.1.stored_value.is_empty());

        test_signature_counter
            .1
            .initialize([0u8; 16].to_vec(), 1)
            .await;

        assert!(!test_signature_counter.1.stored_value.is_empty());

        test_signature_counter.1.stored_value.clear();

        assert!(test_signature_counter.1.stored_value.is_empty());

        let test_run = tokio::spawn(async move {
            test_signature_counter.1.run().await;

            assert!(!test_signature_counter.1.stored_value.is_empty());
        });

        assert!(test_signature_counter
            .0
            .initialize([0u8; 16].to_vec(), 1)
            .await
            .is_ok());

        drop(test_signature_counter.0);

        assert!(test_run.await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn update() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_signature_counter = SignatureCounter::init().await;

        test_signature_counter
            .1
            .initialize([0u8; 16].to_vec(), 1)
            .await;

        // tests here are "opposite" => true == fail ceremony, false == continue ceremony
        assert!(test_signature_counter.1.update([0u8; 16].to_vec(), 0).await);
        assert!(test_signature_counter.1.update([0u8; 16].to_vec(), 1).await);
        assert!(!test_signature_counter.1.update([0u8; 16].to_vec(), 2).await);
        assert!(test_signature_counter.1.update([1u8; 16].to_vec(), 1).await);

        let test_run = tokio::spawn(async move {
            test_signature_counter.1.run().await;
        });

        assert!(test_signature_counter
            .0
            .update([0u8; 16].to_vec(), 1)
            .await
            .is_err());

        assert!(test_signature_counter
            .0
            .update([0u8; 16].to_vec(), 2)
            .await
            .is_err());

        assert!(test_signature_counter
            .0
            .update([0u8; 16].to_vec(), 3)
            .await
            .is_ok());

        assert!(test_signature_counter
            .0
            .update([1u8; 16].to_vec(), 1)
            .await
            .is_err());

        drop(test_signature_counter.0);

        assert!(test_run.await.is_ok());

        Ok(())
    }
}
