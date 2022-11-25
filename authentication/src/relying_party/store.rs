use crate::api::supporting_data_structures::AuthenticatorTransport;
use crate::authenticator::attestation::COSEKey;
use crate::error::{AuthenticationError, AuthenticationErrorType};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub struct UserAccount {
    pub public_key: COSEKey,
    pub signature_counter: u32,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[derive(Debug)]
pub enum Request {
    Check(Vec<u8>),
    Register((Vec<u8>, UserAccount)),
    Identify(Vec<u8>),
    Lookup(Vec<u8>),
    SignCount((Vec<u8>, u32)),
}

#[derive(Debug)]
pub enum Response {
    PublicKey(COSEKey),
    FailCeremony(bool),
}

#[derive(Clone)]
pub struct StoreChannel {
    request: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl StoreChannel {
    pub async fn init() -> (
        StoreChannel,
        mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
    ) {
        let (request, receiver) = mpsc::channel::<(Request, oneshot::Sender<Response>)>(64);

        (StoreChannel { request }, receiver)
    }

    pub async fn check(&self, credential_id: Vec<u8>) -> Result<(), AuthenticationError> {
        let (request, response) = oneshot::channel();
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .request
            .send((Request::Check(credential_id), request))
            .await
        {
            Ok(()) => {
                if let Ok(Response::FailCeremony(fail_ceremony)) = response.await {
                    match fail_ceremony {
                        true => Err(error),
                        false => Ok(()),
                    }
                } else {
                    Err(error)
                }
            }
            Err(_) => Err(error),
        }
    }

    pub async fn register(
        &self,
        credential_id: Vec<u8>,
        user_account: UserAccount,
    ) -> Result<(), AuthenticationError> {
        let (_request, _response) = oneshot::channel();

        match self
            .request
            .send((Request::Register((credential_id, user_account)), _request))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("error sending register request to store -> {:?}", error);

                Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            }
        }
    }

    pub async fn identify(&self, credential_id: Vec<u8>) -> Result<(), AuthenticationError> {
        let (request, response) = oneshot::channel();
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .request
            .send((Request::Identify(credential_id), request))
            .await
        {
            Ok(()) => {
                if let Ok(Response::FailCeremony(fail_ceremony)) = response.await {
                    match fail_ceremony {
                        true => Err(error),
                        false => Ok(()),
                    }
                } else {
                    Err(error)
                }
            }
            Err(_) => Err(error),
        }
    }

    pub async fn lookup(&self, credential_id: Vec<u8>) -> Result<COSEKey, AuthenticationError> {
        let (request, response) = oneshot::channel();
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .request
            .send((Request::Lookup(credential_id), request))
            .await
        {
            Ok(()) => {
                if let Ok(Response::PublicKey(public_key)) = response.await {
                    Ok(public_key)
                } else {
                    Err(error)
                }
            }
            Err(_) => Err(error),
        }
    }

    pub async fn sign_count(
        &self,
        credential_id: Vec<u8>,
        authenticator_data_sign_count: u32,
    ) -> Result<(), AuthenticationError> {
        let (request, response) = oneshot::channel();
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        match self
            .request
            .send((
                Request::SignCount((credential_id, authenticator_data_sign_count)),
                request,
            ))
            .await
        {
            Ok(()) => {
                if let Ok(Response::FailCeremony(fail_ceremony)) = response.await {
                    match fail_ceremony {
                        true => Err(error),
                        false => Ok(()),
                    }
                } else {
                    Err(error)
                }
            }
            Err(_) => Err(error),
        }
    }
}

pub struct Store {
    credentials: HashMap<Vec<u8>, UserAccount>,
    request: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl Store {
    pub async fn init() -> (StoreChannel, Store) {
        let credentials = HashMap::with_capacity(50);
        let (channel, receiver) = StoreChannel::init().await;

        (
            channel,
            Store {
                credentials,
                request: receiver,
            },
        )
    }

    pub async fn run(&mut self) -> Result<(), AuthenticationError> {
        while let Some((request, response)) = self.request.recv().await {
            match request {
                Request::Check(credential_id) => match self.check(credential_id).await {
                    Ok(()) => _ = response.send(Response::FailCeremony(false)),
                    Err(_) => {
                        _ = response.send(Response::FailCeremony(true));
                    }
                },
                Request::Register((credential_id, user_account)) => {
                    self.register(credential_id, user_account).await?;
                }
                Request::Identify(credential_id) => match self.identify(credential_id).await {
                    Ok(()) => _ = response.send(Response::FailCeremony(false)),
                    Err(_) => _ = response.send(Response::FailCeremony(true)),
                },
                Request::Lookup(credential_id) => {
                    if let Ok(public_key) = self.lookup(credential_id).await {
                        _ = response.send(Response::PublicKey(public_key))
                    } else {
                        continue;
                    }
                }
                Request::SignCount((credential_id, authenticator_data_sign_count)) => {
                    if let Ok(()) = self
                        .sign_count(credential_id, authenticator_data_sign_count)
                        .await
                    {
                        _ = response.send(Response::FailCeremony(false))
                    } else {
                        _ = response.send(Response::FailCeremony(true));

                        continue;
                    }
                }
            }
        }

        Ok(())
    }

    async fn check(&self, credential_id: Vec<u8>) -> Result<(), AuthenticationError> {
        match self.credentials.contains_key(&credential_id) {
            true => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
            false => Ok(()),
        }
    }

    async fn register(
        &mut self,
        credential_id: Vec<u8>,
        user_account: UserAccount,
    ) -> Result<(), AuthenticationError> {
        self.credentials.insert(credential_id, user_account);

        Ok(())
    }

    async fn identify(&self, credential_id: Vec<u8>) -> Result<(), AuthenticationError> {
        match self.credentials.contains_key(&credential_id) {
            true => Ok(()),
            false => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    async fn lookup(&self, credential_id: Vec<u8>) -> Result<COSEKey, AuthenticationError> {
        match self.credentials.get(&credential_id) {
            Some(user_account) => {
                let public_key = user_account.public_key.to_owned();

                Ok(public_key)
            }
            None => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }

    async fn sign_count(
        &mut self,
        credential_id: Vec<u8>,
        authenticator_data_sign_count: u32,
    ) -> Result<(), AuthenticationError> {
        if let Some(stored) = self.credentials.get_mut(&credential_id) {
            if authenticator_data_sign_count > stored.signature_counter {
                stored.signature_counter = authenticator_data_sign_count;

                Ok(())
            } else {
                Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
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
    use crate::authenticator::attestation::COSEAlgorithm;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_store = Store::init().await;

        assert!(!test_store.0.request.is_closed());

        Ok(())
    }

    #[tokio::test]
    async fn channel_check() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();

        tokio::spawn(async move {
            test_store.1.run().await.unwrap();
        });

        assert!(test_store.0.check(test_credential_id).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn channel_register() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();
        let test_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_user_account = UserAccount {
            public_key: test_public_key.0,
            signature_counter: 0,
            transports: None,
        };

        tokio::spawn(async move {
            test_store.1.run().await.unwrap();
        });

        assert!(test_store
            .0
            .register(test_credential_id, test_user_account)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn channel_identify() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();

        tokio::spawn(async move {
            test_store.1.run().await.unwrap();
        });

        assert!(test_store
            .0
            .identify(test_credential_id.to_owned())
            .await
            .is_err());

        let test_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_user_account = UserAccount {
            public_key: test_public_key.0,
            signature_counter: 0,
            transports: None,
        };

        test_store
            .0
            .register(test_credential_id.to_owned(), test_user_account)
            .await?;

        assert!(test_store
            .0
            .identify(test_credential_id.to_owned())
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn channel_lookup() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();

        tokio::spawn(async move {
            test_store.1.run().await.unwrap();
        });

        assert!(test_store
            .0
            .lookup(test_credential_id.to_owned())
            .await
            .is_err());

        let test_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_user_account = UserAccount {
            public_key: test_public_key.0,
            signature_counter: 0,
            transports: None,
        };

        test_store
            .0
            .register(test_credential_id.to_owned(), test_user_account)
            .await?;

        assert!(test_store
            .0
            .lookup(test_credential_id.to_owned())
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn channel_sign_count() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();

        tokio::spawn(async move {
            test_store.1.run().await.unwrap();
        });

        let test_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_user_account = UserAccount {
            public_key: test_public_key.0,
            signature_counter: 0,
            transports: None,
        };

        test_store
            .0
            .register(test_credential_id.to_owned(), test_user_account)
            .await?;

        assert!(test_store
            .0
            .sign_count(test_credential_id.to_owned(), 0)
            .await
            .is_err());

        assert!(test_store
            .0
            .sign_count(test_credential_id.to_owned(), 1)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn check() -> Result<(), Box<dyn std::error::Error>> {
        let test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();

        assert!(test_store.1.check(test_credential_id).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn register() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();
        let test_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_user_account = UserAccount {
            public_key: test_public_key.0,
            signature_counter: 0,
            transports: None,
        };

        assert!(test_store
            .1
            .register(test_credential_id, test_user_account)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn identify() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();

        assert!(test_store
            .1
            .identify(test_credential_id.to_owned())
            .await
            .is_err());

        let test_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_user_account = UserAccount {
            public_key: test_public_key.0,
            signature_counter: 0,
            transports: None,
        };

        test_store
            .1
            .register(test_credential_id.to_owned(), test_user_account)
            .await?;

        assert!(test_store
            .1
            .identify(test_credential_id.to_owned())
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn lookup() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();

        assert!(test_store
            .1
            .lookup(test_credential_id.to_owned())
            .await
            .is_err());

        let test_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_user_account = UserAccount {
            public_key: test_public_key.0,
            signature_counter: 0,
            transports: None,
        };

        test_store
            .1
            .register(test_credential_id.to_owned(), test_user_account)
            .await?;

        assert!(test_store
            .1
            .lookup(test_credential_id.to_owned())
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn sign_count() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_store = Store::init().await;
        let test_credential_id = [0; 16].to_vec();

        assert!(test_store
            .1
            .sign_count(test_credential_id.to_owned(), 0)
            .await
            .is_err());

        assert!(test_store
            .1
            .sign_count(test_credential_id.to_owned(), 1)
            .await
            .is_err());

        let test_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_user_account = UserAccount {
            public_key: test_public_key.0,
            signature_counter: 0,
            transports: None,
        };

        test_store
            .1
            .register(test_credential_id.to_owned(), test_user_account)
            .await?;

        assert!(test_store
            .1
            .sign_count(test_credential_id.to_owned(), 0)
            .await
            .is_err());

        assert!(test_store
            .1
            .sign_count(test_credential_id.to_owned(), 1)
            .await
            .is_ok());

        Ok(())
    }
}
