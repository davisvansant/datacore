use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[derive(Debug)]
pub enum CredentialsRequest {
    Set((String, [u8; 16]), PublicKeyCredentialSource),
    SignatureCounter([u8; 16]),
    Increment([u8; 16]),
    Lookup((String, [u8; 16])),
    Counter([u8; 16]),
}

#[derive(Debug)]
pub enum CredentialsResponse {
    PublicKeyCredentialSource(PublicKeyCredentialSource),
    SignCount(u32),
    TerminateOperation,
}

pub struct CredentialsChannel {
    request: mpsc::Sender<(CredentialsRequest, oneshot::Sender<CredentialsResponse>)>,
    error: AuthenticationError,
}

impl CredentialsChannel {
    pub async fn init() -> (
        CredentialsChannel,
        mpsc::Receiver<(CredentialsRequest, oneshot::Sender<CredentialsResponse>)>,
    ) {
        let (sender, receiver) = mpsc::channel(64);

        let error = AuthenticationError {
            error: AuthenticationErrorType::OperationError,
        };

        (
            CredentialsChannel {
                request: sender,
                error,
            },
            receiver,
        )
    }

    pub async fn set(
        &self,
        rp_entity_id: String,
        user_handle: [u8; 16],
        credential_source: PublicKeyCredentialSource,
    ) -> Result<(), AuthenticationError> {
        let (_request, _response) = oneshot::channel();

        match self
            .request
            .send((
                CredentialsRequest::Set((rp_entity_id, user_handle), credential_source),
                _request,
            ))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("error sending register request to store -> {:?}", error);

                Err(self.error)
            }
        }
    }

    pub async fn signature_counter(
        &self,
        credential_id: [u8; 16],
    ) -> Result<(), AuthenticationError> {
        let (_request, _response) = oneshot::channel();

        match self
            .request
            .send((
                CredentialsRequest::SignatureCounter(credential_id),
                _request,
            ))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("error sending register request to store -> {:?}", error);

                Err(self.error)
            }
        }
    }

    pub async fn increment(&self, credential_id: [u8; 16]) -> Result<(), AuthenticationError> {
        let (_request, _response) = oneshot::channel();

        match self
            .request
            .send((CredentialsRequest::Increment(credential_id), _request))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("error sending register request to store -> {:?}", error);

                Err(self.error)
            }
        }
    }

    pub async fn lookup(
        &self,
        rp_entity_id: String,
        user_handle: [u8; 16],
    ) -> Result<PublicKeyCredentialSource, AuthenticationError> {
        let (request, response) = oneshot::channel();

        if let Ok(()) = self
            .request
            .send((
                CredentialsRequest::Lookup((rp_entity_id, user_handle)),
                request,
            ))
            .await
        {
            match response.await {
                Ok(CredentialsResponse::PublicKeyCredentialSource(credential_source)) => {
                    Ok(credential_source)
                }
                Ok(CredentialsResponse::TerminateOperation) => Err(self.error),
                Err(_) => Err(self.error),
                _ => Err(self.error),
            }
        } else {
            Err(self.error)
        }
    }

    pub async fn counter(&self, credential_id: [u8; 16]) -> Result<u32, AuthenticationError> {
        let (request, response) = oneshot::channel();

        if let Ok(()) = self
            .request
            .send((CredentialsRequest::Counter(credential_id), request))
            .await
        {
            if let Ok(CredentialsResponse::SignCount(value)) = response.await {
                Ok(value)
            } else {
                Err(self.error)
            }
        } else {
            Err(self.error)
        }
    }
}

pub struct Credentials {
    map: HashMap<(String, [u8; 16]), PublicKeyCredentialSource>,
    receiver: mpsc::Receiver<(CredentialsRequest, oneshot::Sender<CredentialsResponse>)>,
    signature_counter: HashMap<
        [u8; 16],
        mpsc::Sender<(
            SignatureCounterRequest,
            oneshot::Sender<SignatureCounterResponse>,
        )>,
    >,
    signature_counter_handles: Vec<JoinHandle<()>>,
}

impl Credentials {
    pub async fn init() -> (CredentialsChannel, Credentials) {
        let capacity = 50;
        let map = HashMap::with_capacity(capacity);
        let (credentials_channel, receiver) = CredentialsChannel::init().await;
        let signature_counter = HashMap::with_capacity(capacity);
        let signature_counter_handles = Vec::with_capacity(capacity);

        (
            credentials_channel,
            Credentials {
                map,
                receiver,
                signature_counter,
                signature_counter_handles,
            },
        )
    }

    pub async fn run(&mut self) -> Result<(), AuthenticationError> {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                CredentialsRequest::Set((rp_entity_id, user_handle), source) => {
                    self.set(rp_entity_id, user_handle, source).await?;
                }
                CredentialsRequest::SignatureCounter(credential_id) => {
                    self.signature_counter(credential_id).await?;
                }
                CredentialsRequest::Increment(credential_id) => {
                    self.increment(credential_id).await?;
                }
                CredentialsRequest::Lookup((rp_id, credential_id)) => {
                    match self.lookup(rp_id, credential_id).await {
                        Ok(credential_source) => {
                            _ = response.send(CredentialsResponse::PublicKeyCredentialSource(
                                credential_source,
                            ));
                        }
                        Err(_) => _ = response.send(CredentialsResponse::TerminateOperation),
                    }
                }
                CredentialsRequest::Counter(credential_id) => {
                    match self.counter(credential_id).await {
                        Ok(value) => _ = response.send(CredentialsResponse::SignCount(value)),
                        Err(_) => _ = response.send(CredentialsResponse::TerminateOperation),
                    }
                }
            }
        }

        Ok(())
    }

    async fn set(
        &mut self,
        rp_entity_id: String,
        user_handle: [u8; 16],
        source: PublicKeyCredentialSource,
    ) -> Result<(), AuthenticationError> {
        self.map.insert((rp_entity_id, user_handle), source);

        Ok(())
    }

    async fn signature_counter(
        &mut self,
        credential_id: [u8; 16],
    ) -> Result<(), AuthenticationError> {
        let mut signature_counter = SignatureCounter::init().await;

        let signature_counter_handle = tokio::spawn(async move {
            if let Err(error) = signature_counter.1.run().await {
                println!("signature counter error -> {:?}", error);
            }
        });

        self.signature_counter
            .insert(credential_id, signature_counter.0);

        self.signature_counter_handles
            .push(signature_counter_handle);

        Ok(())
    }

    async fn increment(&self, credential_id: [u8; 16]) -> Result<(), AuthenticationError> {
        if let Some(channel) = self.signature_counter.get(&credential_id) {
            let (_request, _response) = oneshot::channel();

            if let Err(error) = channel
                .send((SignatureCounterRequest::Increment, _request))
                .await
            {
                println!("signature channel error -> {:?}", error);
            }
        }

        Ok(())
    }

    async fn lookup(
        &self,
        rp_id: String,
        user_handle: [u8; 16],
    ) -> Result<PublicKeyCredentialSource, AuthenticationError> {
        if let Some(credential_source) = self.map.get(&(rp_id, user_handle)) {
            Ok(credential_source.to_owned())
        } else {
            Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })
        }
    }

    async fn counter(&self, credential_id: [u8; 16]) -> Result<u32, AuthenticationError> {
        if let Some(channel) = self.signature_counter.get(&credential_id) {
            let (request, response) = oneshot::channel();

            if channel
                .send((SignatureCounterRequest::Value, request))
                .await
                .is_err()
            {
                Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            } else {
                match response.await {
                    Ok(SignatureCounterResponse::Value(value)) => Ok(value),
                    Err(_) => Err(AuthenticationError {
                        error: AuthenticationErrorType::OperationError,
                    }),
                }
            }
        } else {
            Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })
        }
    }
}

#[derive(Debug)]
pub enum SignatureCounterRequest {
    Increment,
    Value,
}

#[derive(Debug)]
pub enum SignatureCounterResponse {
    Value(u32),
}

pub struct SignatureCounter {
    value: u32,
    receiver: mpsc::Receiver<(
        SignatureCounterRequest,
        oneshot::Sender<SignatureCounterResponse>,
    )>,
}

impl SignatureCounter {
    pub async fn init() -> (
        mpsc::Sender<(
            SignatureCounterRequest,
            oneshot::Sender<SignatureCounterResponse>,
        )>,
        SignatureCounter,
    ) {
        let value: u32 = 0;
        let (sender, receiver) = mpsc::channel(64);

        (sender, SignatureCounter { value, receiver })
    }

    pub async fn run(&mut self) -> Result<(), AuthenticationError> {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                SignatureCounterRequest::Increment => {
                    self.increment().await;
                }
                SignatureCounterRequest::Value => {
                    let value = self.value().await;

                    _ = response.send(SignatureCounterResponse::Value(value));
                }
            }
        }

        Ok(())
    }

    async fn increment(&mut self) {
        self.value += 1;
    }

    async fn value(&self) -> u32 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn credentials_channel_init() -> Result<(), Box<dyn std::error::Error>> {
        let test_credentials = Credentials::init().await;

        assert!(!test_credentials.0.request.is_closed());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_channel_set() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_rp_entity_id = String::from("some_rp_entity_id");
        let test_user_handle = [0; 16];
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        tokio::spawn(async move {
            test_credentials.1.run().await.unwrap();
        });

        assert!(test_credentials
            .0
            .set(test_rp_entity_id, test_user_handle, test_credential_source)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_channel_signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = [0; 16];

        tokio::spawn(async move {
            test_credentials.1.run().await.unwrap();
        });

        assert!(test_credentials
            .0
            .signature_counter(test_credential_id)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_channel_increment() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = [0; 16];

        tokio::spawn(async move {
            test_credentials.1.run().await.unwrap();
        });

        assert!(test_credentials
            .0
            .increment(test_credential_id)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_channel_lookup() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_rp_entity_id = String::from("some_rp_entity_id");
        let test_user_handle = [0; 16];
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        tokio::spawn(async move {
            test_credentials.1.run().await.unwrap();
        });

        assert!(test_credentials
            .0
            .lookup(test_rp_entity_id.to_owned(), test_user_handle)
            .await
            .is_err());

        test_credentials
            .0
            .set(
                test_rp_entity_id.to_owned(),
                test_user_handle,
                test_credential_source,
            )
            .await?;

        assert!(test_credentials
            .0
            .lookup(test_rp_entity_id.to_owned(), test_user_handle)
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_channel_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = [0; 16];

        tokio::spawn(async move {
            test_credentials.1.run().await.unwrap();
        });

        test_credentials
            .0
            .signature_counter(test_credential_id.to_owned())
            .await?;

        assert!(test_credentials
            .0
            .counter(test_credential_id.to_owned())
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_init() -> Result<(), Box<dyn std::error::Error>> {
        let test_credentials = Credentials::init().await;

        assert!(test_credentials.1.map.is_empty());
        assert!(test_credentials.1.signature_counter.is_empty());
        assert!(test_credentials.1.signature_counter_handles.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_set() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_rp_entity_id = String::from("some_rp_entity_id");
        let test_user_handle = [0; 16];
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        test_credentials
            .1
            .set(test_rp_entity_id, test_user_handle, test_credential_source)
            .await?;

        assert!(!test_credentials.1.map.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = [0; 16];

        test_credentials
            .1
            .signature_counter(test_credential_id)
            .await?;

        assert!(!test_credentials.1.signature_counter.is_empty());
        assert!(!test_credentials.1.signature_counter_handles.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_increment() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = [0; 16];

        test_credentials
            .1
            .signature_counter(test_credential_id)
            .await?;

        test_credentials.1.increment(test_credential_id).await?;

        Ok(())
    }

    #[tokio::test]
    async fn credentials_lookup() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_rp_entity_id = String::from("some_rp_entity_id");
        let test_user_handle = [0; 16];
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        test_credentials
            .1
            .set(
                test_rp_entity_id.to_owned(),
                test_user_handle,
                test_credential_source,
            )
            .await?;

        assert!(test_credentials
            .1
            .lookup(test_rp_entity_id.to_owned(), test_user_handle)
            .await
            .is_ok());
        assert!(test_credentials
            .1
            .lookup(test_rp_entity_id.to_owned(), [1; 16])
            .await
            .is_err());
        assert!(test_credentials
            .1
            .lookup(String::from("some_other_rp_entity_id"), test_user_handle)
            .await
            .is_err());
        assert!(test_credentials
            .1
            .lookup(String::from("some_rp"), [2; 16])
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = [0; 16];

        assert!(test_credentials
            .1
            .counter(test_credential_id)
            .await
            .is_err());

        test_credentials
            .1
            .signature_counter(test_credential_id)
            .await?;

        let test_value = test_credentials.1.counter(test_credential_id).await?;

        assert_eq!(test_value, 0);

        Ok(())
    }

    #[tokio::test]
    async fn signature_counter_init() -> Result<(), Box<dyn std::error::Error>> {
        let test_signature_counter = SignatureCounter::init().await;

        assert_eq!(test_signature_counter.1.value, 0);

        Ok(())
    }

    #[tokio::test]
    async fn signature_counter_increment() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_signature_counter = SignatureCounter::init().await;

        test_signature_counter.1.increment().await;

        assert_eq!(test_signature_counter.1.value, 1);

        Ok(())
    }

    #[tokio::test]
    async fn signature_counter_value() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_signature_counter = SignatureCounter::init().await;

        test_signature_counter.1.increment().await;
        test_signature_counter.1.increment().await;

        let test_value = test_signature_counter.1.value().await;

        assert_eq!(test_value, 2);

        Ok(())
    }
}
