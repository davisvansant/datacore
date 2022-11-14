use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[derive(Debug)]
pub enum CredentialsRequest {
    Set((String, String), PublicKeyCredentialSource),
    SignatureCounter(String),
    Increment(String),
    Lookup((String, String)),
}

#[derive(Debug)]
pub enum CredentialsResponse {
    PublicKeyCredentialSource(PublicKeyCredentialSource),
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
        credential_id: String,
        credential_source: PublicKeyCredentialSource,
    ) -> Result<(), AuthenticationError> {
        let (_request, _response) = oneshot::channel();

        match self
            .request
            .send((
                CredentialsRequest::Set((rp_entity_id, credential_id), credential_source),
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
        credential_id: String,
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

    pub async fn increment(&self, credential_id: String) -> Result<(), AuthenticationError> {
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
        credential_id: String,
    ) -> Result<PublicKeyCredentialSource, AuthenticationError> {
        let (request, response) = oneshot::channel();

        if let Ok(()) = self
            .request
            .send((
                CredentialsRequest::Lookup((rp_entity_id, credential_id)),
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
            }
        } else {
            Err(self.error)
        }
    }
}

pub struct Credentials {
    map: HashMap<(String, String), PublicKeyCredentialSource>,
    receiver: mpsc::Receiver<(CredentialsRequest, oneshot::Sender<CredentialsResponse>)>,
    signature_counter: HashMap<String, mpsc::Sender<SignatureCounterRequest>>,
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
                    self.signature_counter(&credential_id).await?;
                }
                CredentialsRequest::Increment(credential_id) => {
                    self.increment(&credential_id).await?;
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
            }
        }

        Ok(())
    }

    async fn set(
        &mut self,
        rp_entity_id: String,
        user_handle: String,
        source: PublicKeyCredentialSource,
    ) -> Result<(), AuthenticationError> {
        self.map.insert((rp_entity_id, user_handle), source);

        Ok(())
    }

    async fn signature_counter(&mut self, credential_id: &str) -> Result<(), AuthenticationError> {
        let mut signature_counter = SignatureCounter::init().await;

        let signature_counter_handle = tokio::spawn(async move {
            if let Err(error) = signature_counter.1.run().await {
                println!("signature counter error -> {:?}", error);
            }
        });

        self.signature_counter
            .insert(credential_id.to_owned(), signature_counter.0);

        self.signature_counter_handles
            .push(signature_counter_handle);

        Ok(())
    }

    async fn increment(&self, credential_id: &str) -> Result<(), AuthenticationError> {
        if let Some(channel) = self.signature_counter.get(credential_id) {
            if let Err(error) = channel.send(SignatureCounterRequest::Increment).await {
                println!("signature channel error -> {:?}", error);
            }
        }

        Ok(())
    }

    async fn lookup(
        &self,
        rp_id: String,
        credential_id: String,
    ) -> Result<PublicKeyCredentialSource, AuthenticationError> {
        if let Some(credential_source) = self.map.get(&(rp_id, credential_id)) {
            Ok(credential_source.to_owned())
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

pub struct SignatureCounter {
    value: u32,
    receiver: mpsc::Receiver<SignatureCounterRequest>,
}

impl SignatureCounter {
    pub async fn init() -> (mpsc::Sender<SignatureCounterRequest>, SignatureCounter) {
        let value: u32 = 0;
        let (sender, receiver) = mpsc::channel(64);

        (sender, SignatureCounter { value, receiver })
    }

    pub async fn run(&mut self) -> Result<(), AuthenticationError> {
        while let Some(request) = self.receiver.recv().await {
            match request {
                SignatureCounterRequest::Increment => {
                    self.increment().await;
                }
                SignatureCounterRequest::Value => {
                    let value = self.value().await;
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
    async fn signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let test_u32: u32 = 10;
        let test_be_bytes: [u8; 4] = 10_u32.to_be_bytes();

        assert_eq!(
            std::mem::size_of_val(&test_u32),
            std::mem::size_of_val(&test_be_bytes),
        );

        assert_eq!(std::mem::size_of_val(&test_u32), 4);
        assert_eq!(std::mem::size_of_val(&test_be_bytes), 4);

        Ok(())
    }

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
        let test_credential_id = String::from("some_credential_id");
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        tokio::spawn(async move {
            test_credentials.1.run().await.unwrap();
        });

        assert!(test_credentials
            .0
            .set(
                test_rp_entity_id,
                test_credential_id,
                test_credential_source,
            )
            .await
            .is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_channel_signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = String::from("some_credential_id");

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
        let test_credential_id = String::from("some_credential_id");

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
        let test_credential_id = String::from("some_credential_id");
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        tokio::spawn(async move {
            test_credentials.1.run().await.unwrap();
        });

        assert!(test_credentials
            .0
            .lookup(test_rp_entity_id.to_owned(), test_credential_id.to_owned())
            .await
            .is_err());

        test_credentials
            .0
            .set(
                test_rp_entity_id.to_owned(),
                test_credential_id.to_owned(),
                test_credential_source,
            )
            .await?;

        assert!(test_credentials
            .0
            .lookup(test_rp_entity_id.to_owned(), test_credential_id.to_owned())
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
        let test_credential_id = String::from("some_credential_id");
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        test_credentials
            .1
            .set(
                test_rp_entity_id,
                test_credential_id,
                test_credential_source,
            )
            .await?;

        assert!(!test_credentials.1.map.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = String::from("some_credential_id");

        test_credentials
            .1
            .signature_counter(&test_credential_id)
            .await?;

        assert!(!test_credentials.1.signature_counter.is_empty());
        assert!(!test_credentials.1.signature_counter_handles.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_increment() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = String::from("some_credential_id");

        test_credentials
            .1
            .signature_counter(&test_credential_id)
            .await?;

        test_credentials.1.increment(&test_credential_id).await?;

        Ok(())
    }

    #[tokio::test]
    async fn credentials_lookup() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_rp_entity_id = String::from("some_rp_entity_id");
        let test_credential_id = String::from("some_credential_id");
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        test_credentials
            .1
            .set(
                test_rp_entity_id.to_owned(),
                test_credential_id.to_owned(),
                test_credential_source,
            )
            .await?;

        assert!(test_credentials
            .1
            .lookup(test_rp_entity_id.to_owned(), test_credential_id.to_owned())
            .await
            .is_ok());
        assert!(test_credentials
            .1
            .lookup(
                test_rp_entity_id.to_owned(),
                String::from("some_other_credential_id"),
            )
            .await
            .is_err());
        assert!(test_credentials
            .1
            .lookup(
                String::from("some_other_rp_entity_id"),
                test_credential_id.to_owned(),
            )
            .await
            .is_err());
        assert!(test_credentials
            .1
            .lookup(String::from("some_rp"), String::from("some_credential"))
            .await
            .is_err());

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
