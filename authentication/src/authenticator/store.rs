use crate::authenticator::public_key_credential_source::PublicKeyCredentialSource;
use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub enum CredentialsRequest {
    Set((String, String), PublicKeyCredentialSource),
    SignatureCounter(String),
    Increment(String),
    Lookup((String, String)),
}

pub struct Credentials {
    map: HashMap<(String, String), PublicKeyCredentialSource>,
    receiver: mpsc::Receiver<CredentialsRequest>,
    signature_counter: HashMap<String, mpsc::Sender<SignatureCounterRequest>>,
    signature_counter_handles: Vec<JoinHandle<()>>,
}

impl Credentials {
    pub async fn init() -> Credentials {
        let capacity = 50;
        let map = HashMap::with_capacity(capacity);
        let (sender, receiver) = mpsc::channel(64);
        let signature_counter = HashMap::with_capacity(capacity);
        let signature_counter_handles = Vec::with_capacity(capacity);

        Credentials {
            map,
            receiver,
            signature_counter,
            signature_counter_handles,
        }
    }

    pub async fn run(&mut self) -> Result<(), AuthenticationError> {
        while let Some(request) = self.receiver.recv().await {
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
                    self.lookup(rp_id, credential_id).await?;
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
    async fn credentials_init() -> Result<(), Box<dyn std::error::Error>> {
        let test_credentials = Credentials::init().await;

        assert!(test_credentials.map.is_empty());
        assert!(test_credentials.signature_counter.is_empty());
        assert!(test_credentials.signature_counter_handles.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_set() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_rp_entity_id = String::from("some_rp_entity_id");
        let test_credential_id = String::from("some_credential_id");
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        test_credentials
            .set(
                test_rp_entity_id,
                test_credential_id,
                test_credential_source,
            )
            .await?;

        assert!(!test_credentials.map.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_signature_counter() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = String::from("some_credential_id");

        test_credentials
            .signature_counter(&test_credential_id)
            .await?;

        assert!(!test_credentials.signature_counter.is_empty());
        assert!(!test_credentials.signature_counter_handles.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn credentials_increment() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_credential_id = String::from("some_credential_id");

        test_credentials
            .signature_counter(&test_credential_id)
            .await?;

        test_credentials.increment(&test_credential_id).await?;

        Ok(())
    }

    #[tokio::test]
    async fn credentials_lookup() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_credentials = Credentials::init().await;
        let test_rp_entity_id = String::from("some_rp_entity_id");
        let test_credential_id = String::from("some_credential_id");
        let test_credential_source = PublicKeyCredentialSource::generate().await;

        test_credentials
            .set(
                test_rp_entity_id.to_owned(),
                test_credential_id.to_owned(),
                test_credential_source,
            )
            .await?;

        assert!(test_credentials
            .lookup(test_rp_entity_id.to_owned(), test_credential_id.to_owned())
            .await
            .is_ok());
        assert!(test_credentials
            .lookup(
                test_rp_entity_id.to_owned(),
                String::from("some_other_credential_id"),
            )
            .await
            .is_err());
        assert!(test_credentials
            .lookup(
                String::from("some_other_rp_entity_id"),
                test_credential_id.to_owned(),
            )
            .await
            .is_err());
        assert!(test_credentials
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
