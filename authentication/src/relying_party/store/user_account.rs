use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

use crate::api::credential_creation_options::PublicKeyCredentialUserEntity;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use crate::security::uuid::{CredentialId, UserHandle};

#[derive(Debug)]
pub enum Request {
    Check(CredentialId),
    Register((CredentialId, PublicKeyCredentialUserEntity)),
    Verify((CredentialId, UserHandle)),
}

#[derive(Debug)]
pub enum Response {
    FailCeremony(bool),
}

#[derive(Clone)]
pub struct UserAccountChannel {
    sender: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl UserAccountChannel {
    pub async fn init() -> (
        UserAccountChannel,
        mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
    ) {
        let (sender, receiver) = mpsc::channel(64);

        (UserAccountChannel { sender }, receiver)
    }

    pub async fn check(&self, credential_id: CredentialId) -> Result<(), AuthenticationError> {
        let (request, response) = oneshot::channel();
        let operation_error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .sender
            .send((Request::Check(credential_id), request))
            .await
        {
            Ok(()) => match response.await {
                Ok(Response::FailCeremony(fail_ceremony)) => match fail_ceremony {
                    true => Err(operation_error),
                    false => Ok(()),
                },
                Err(error) => {
                    println!("user account channel | check -> {:?}", error);

                    Err(operation_error)
                }
            },
            Err(error) => {
                println!("user account channel | check -> {:?}", error);

                Err(operation_error)
            }
        }
    }

    pub async fn register(
        &self,
        credential_id: CredentialId,
        user_entity: PublicKeyCredentialUserEntity,
    ) -> Result<(), AuthenticationError> {
        let (request, response) = oneshot::channel();
        let operation_error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .sender
            .send((Request::Register((credential_id, user_entity)), request))
            .await
        {
            Ok(()) => match response.await {
                Ok(Response::FailCeremony(fail_ceremony)) => match fail_ceremony {
                    true => Err(operation_error),
                    false => Ok(()),
                },
                Err(error) => {
                    println!("user account channel | register -> {:?}", error);

                    Err(operation_error)
                }
            },
            Err(error) => {
                println!("user account channel | register -> {:?}", error);

                Err(operation_error)
            }
        }
    }

    pub async fn verify(
        &self,
        credential_id: CredentialId,
        user_handle: UserHandle,
    ) -> Result<(), AuthenticationError> {
        let (request, response) = oneshot::channel();
        let operation_error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .sender
            .send((Request::Verify((credential_id, user_handle)), request))
            .await
        {
            Ok(()) => match response.await {
                Ok(Response::FailCeremony(fail_ceremony)) => match fail_ceremony {
                    true => Err(operation_error),
                    false => Ok(()),
                },
                Err(error) => {
                    println!("user account channel | verify -> {:?}", error);

                    Err(operation_error)
                }
            },
            Err(error) => {
                println!("user account channel | verify -> {:?}", error);

                Err(operation_error)
            }
        }
    }
}

pub struct UserAccount {
    registration: HashMap<CredentialId, PublicKeyCredentialUserEntity>,
    receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl UserAccount {
    pub async fn init() -> (UserAccountChannel, UserAccount) {
        let registration = HashMap::with_capacity(50);
        let (user_account_channel, receiver) = UserAccountChannel::init().await;

        (
            user_account_channel,
            UserAccount {
                registration,
                receiver,
            },
        )
    }

    pub async fn run(&mut self) {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                Request::Check(credential_id) => match self.check(credential_id).await {
                    true => {
                        let _ = response.send(Response::FailCeremony(true));
                    }
                    false => {
                        let _ = response.send(Response::FailCeremony(false));
                    }
                },
                Request::Register((credential_id, user_entity)) => {
                    match self.register(credential_id, user_entity).await {
                        true => {
                            let _ = response.send(Response::FailCeremony(true));
                        }
                        false => {
                            let _ = response.send(Response::FailCeremony(false));
                        }
                    }
                }
                Request::Verify((credential_id, user_handle)) => {
                    match self.verify(credential_id, user_handle).await {
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

    async fn check(&self, credential_id: CredentialId) -> bool {
        self.registration.contains_key(&credential_id)
    }

    async fn register(
        &mut self,
        credential_id: CredentialId,
        user_entity: PublicKeyCredentialUserEntity,
    ) -> bool {
        self.registration.insert(credential_id, user_entity);

        false
    }

    async fn verify(&self, credential_id: CredentialId, user_handle: UserHandle) -> bool {
        match self.registration.get(&credential_id) {
            Some(registered_user_entity) => match registered_user_entity.id != user_handle {
                true => true,
                false => false,
            },
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_user_account = UserAccount::init().await;

        assert!(test_user_account.0.sender.capacity() >= 50);
        assert!(test_user_account.1.registration.capacity() >= 50);

        Ok(())
    }

    #[tokio::test]
    async fn check() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_user_account = UserAccount::init().await;

        assert!(test_user_account.1.registration.is_empty());

        let test_user_entity = PublicKeyCredentialUserEntity {
            name: String::from("some_test_name"),
            id: [0u8; 16].to_vec(),
            display_name: String::from("some_test_display_name"),
        };

        test_user_account
            .1
            .registration
            .insert([0u8; 16].to_vec(), test_user_entity);

        assert!(!test_user_account.1.registration.is_empty());
        assert!(!test_user_account.1.check([1u8; 16].to_vec()).await);
        assert!(test_user_account.1.check([0u8; 16].to_vec()).await);

        tokio::spawn(async move {
            test_user_account.1.run().await;
        });

        assert!(test_user_account.0.check([1u8; 16].to_vec()).await.is_ok());
        assert!(test_user_account.0.check([0u8; 16].to_vec()).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn register() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_user_account = UserAccount::init().await;

        assert!(test_user_account.1.registration.is_empty());

        let test_user_entity = PublicKeyCredentialUserEntity {
            name: String::from("some_test_name"),
            id: [0u8; 16].to_vec(),
            display_name: String::from("some_test_display_name"),
        };

        test_user_account
            .1
            .registration
            .insert([0u8; 16].to_vec(), test_user_entity.to_owned());

        assert!(!test_user_account.1.registration.is_empty());
        test_user_account.1.registration.clear();
        assert!(test_user_account.1.registration.is_empty());

        let test_run = tokio::spawn(async move {
            test_user_account.1.run().await;

            assert!(!test_user_account.1.registration.is_empty());
        });

        assert!(test_user_account
            .0
            .register([1u8; 16].to_vec(), test_user_entity)
            .await
            .is_ok());

        drop(test_user_account.0);

        assert!(test_run.await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn verify() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_user_account = UserAccount::init().await;

        let test_user_entity = PublicKeyCredentialUserEntity {
            name: String::from("some_test_name"),
            id: b"some_user_id".to_vec(),
            display_name: String::from("some_test_display_name"),
        };

        test_user_account
            .1
            .registration
            .insert([0u8; 16].to_vec(), test_user_entity.to_owned());

        assert!(
            test_user_account
                .1
                .verify([0u8; 16].to_vec(), b"some_other_user_id".to_vec())
                .await
        );
        assert!(
            test_user_account
                .1
                .verify([1u8; 16].to_vec(), b"some_user_id".to_vec())
                .await
        );
        assert!(
            !test_user_account
                .1
                .verify([0u8; 16].to_vec(), b"some_user_id".to_vec())
                .await
        );

        tokio::spawn(async move {
            test_user_account.1.run().await;
        });

        assert!(test_user_account
            .0
            .verify([0u8; 16].to_vec(), b"some_other_user_id".to_vec())
            .await
            .is_err());

        assert!(test_user_account
            .0
            .verify([1u8; 16].to_vec(), b"some_user_id".to_vec())
            .await
            .is_err());

        assert!(test_user_account
            .0
            .verify([0u8; 16].to_vec(), b"some_user_id".to_vec())
            .await
            .is_ok());

        Ok(())
    }
}
