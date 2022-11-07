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
    Register((Vec<u8>, UserAccount)),
    Lookup(Vec<u8>),
    SignCount((Vec<u8>, u32)),
}

#[derive(Debug)]
pub enum Response {
    PublicKey(COSEKey),
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

    pub async fn lookup(&self, credential_id: Vec<u8>) -> Result<COSEKey, AuthenticationError> {
        let (request, response) = oneshot::channel();
        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        if let Ok(()) = self
            .request
            .send((Request::Lookup(credential_id), request))
            .await
        {
            if let Ok(Response::PublicKey(public_key)) = response.await {
                Ok(public_key)
            } else {
                Err(error)
            }
        } else {
            Err(error)
        }
    }

    pub async fn sign_count(
        &self,
        credential_id: Vec<u8>,
        authenticator_data_sign_count: u32,
    ) -> Result<(), AuthenticationError> {
        let (_request, _response) = oneshot::channel();

        match self
            .request
            .send((
                Request::SignCount((credential_id, authenticator_data_sign_count)),
                _request,
            ))
            .await
        {
            Ok(()) => Ok(()),
            Err(_) => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }
}

pub struct Store {
    credentials: HashMap<Vec<u8>, UserAccount>,
    request: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

impl Store {
    pub async fn init() -> (Store, StoreChannel) {
        let credentials = HashMap::with_capacity(50);
        let (channel, receiver) = StoreChannel::init().await;

        (
            Store {
                credentials,
                request: receiver,
            },
            channel,
        )
    }

    pub async fn run(&mut self) -> Result<(), AuthenticationError> {
        while let Some((request, response)) = self.request.recv().await {
            match request {
                Request::Register((credential_id, user_account)) => {
                    self.register(credential_id, user_account).await?;
                }
                Request::Lookup(credential_id) => {
                    if let Ok(public_key) = self.lookup(credential_id).await {
                        _ = response.send(Response::PublicKey(public_key))
                    } else {
                        continue;
                    }
                }
                Request::SignCount((credential_id, authenticator_data_sign_count)) => {
                    self.sign_count(credential_id, authenticator_data_sign_count)
                        .await?;
                }
            }
        }

        Ok(())
    }

    async fn register(
        &mut self,
        credential_id: Vec<u8>,
        user_account: UserAccount,
    ) -> Result<(), AuthenticationError> {
        self.credentials.insert(credential_id, user_account);

        Ok(())
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
