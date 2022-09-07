use std::collections::HashMap;
use uuid::fmt::Simple;
use uuid::Uuid;

use crate::endpoint::client_registration::register::response::ClientInformation;

use channel::{ClientRegistryRequest, ReceiveRequest, Request, Response};

pub mod channel;

pub struct ClientRegistry {
    receiver: ReceiveRequest,
    registered: HashMap<String, String>,
}

impl ClientRegistry {
    pub async fn init() -> (ClientRegistry, ClientRegistryRequest) {
        let (send_request, receive_request) = ClientRegistryRequest::init().await;
        let registered = HashMap::with_capacity(50);

        (
            ClientRegistry {
                receiver: receive_request,
                registered,
            },
            send_request,
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some((request, response)) = self.receiver.recv().await {
            match request {
                Request::Register(client_metadata) => {
                    let client_information = self.add(client_metadata).await?;

                    let _ = response.send(Response::ClientInformation(client_information));
                }
                Request::Read(client_id) => {
                    let _client_metdata = self.read(&client_id).await?;
                }
                Request::Update(client_id, client_metadata) => {
                    self.update(client_id, client_metadata).await?;
                }
                Request::Remove(client_id) => self.remove(client_id).await?,
                Request::Shutdown => self.receiver.close(),
            }
        }

        Ok(())
    }

    async fn add(
        &mut self,
        client_metadata: String,
    ) -> Result<ClientInformation, Box<dyn std::error::Error>> {
        let client_id = issue_id().await;

        if self
            .registered
            .insert(client_id.to_string(), client_metadata)
            .is_none()
        {
            println!("registered new client!");
        }

        let client_information = ClientInformation {
            client_id: client_id.to_string(),
            client_secret: String::from("some_client_secret"),
            client_id_issued_at: String::from("some_client_id_issued_at"),
            client_secret_expires_at: String::from("some_client_secret_expires_at"),
        };

        Ok(client_information)
    }

    async fn read(&mut self, client_id: &str) -> Result<String, Box<dyn std::error::Error>> {
        match self.registered.get(client_id) {
            None => {
                let error = format!("could not find client id -> {:?}", client_id);

                Err(Box::from(error))
            }
            Some(client_id_value) => Ok(client_id_value.to_owned()),
        }
    }

    async fn update(
        &mut self,
        client_id: String,
        client_metadata: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.registered.contains_key(&client_id) {
            true => {
                if let Some(old_value) = self.registered.insert(client_id, client_metadata) {
                    println!("updated client! old value -> {:?}", &old_value);
                }

                Ok(())
            }
            false => {
                let error = String::from("client id not present!");

                Err(Box::from(error))
            }
        }
    }

    async fn remove(&mut self, client_id: String) -> Result<(), Box<dyn std::error::Error>> {
        match self.registered.remove(&client_id) {
            None => {
                let error = String::from("entry not found for removal");

                Err(Box::from(error))
            }
            Some(removed_value) => {
                println!("value removed! -> {:?}", removed_value);

                Ok(())
            }
        }
    }
}

async fn issue_id() -> Simple {
    Uuid::new_v4().simple()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let (test_client_registry, _) = ClientRegistry::init().await;

        assert!(test_client_registry.registered.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn add() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;

        assert_eq!(test_client_registry.registered.len(), 0);

        let test_client_metadata = String::from("test_client_metadata");

        test_client_registry.add(test_client_metadata).await?;

        assert_eq!(test_client_registry.registered.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn read() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;
        let test_value_error = test_client_registry.read("some_test_client_id").await;

        assert!(test_value_error.is_err());

        let test_client_metadata = String::from("test_client_metadata");
        let test_client_information = test_client_registry.add(test_client_metadata).await?;
        let test_value_ok = test_client_registry
            .read(&test_client_information.client_id)
            .await;

        assert!(test_value_ok.is_ok());
        assert_eq!(test_value_ok.unwrap(), "test_client_metadata");

        Ok(())
    }

    #[tokio::test]
    async fn update() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;
        let test_client_id = String::from("some_test_client_id");
        let test_client_metadata = String::from("test_client_metadata");
        let test_update_error = test_client_registry
            .update(test_client_id, test_client_metadata)
            .await;

        assert!(test_update_error.is_err());

        let test_initial_client_metadata = String::from("test_initial_client_metadata");
        let test_client_information = test_client_registry
            .add(test_initial_client_metadata)
            .await?;
        let test_client_metadata = String::from("some_new_test_client_metadata");
        let test_update_ok = test_client_registry
            .update(
                test_client_information.client_id.to_owned(),
                test_client_metadata,
            )
            .await;

        assert!(test_update_ok.is_ok());

        let test_updated_metadata_value = test_client_registry
            .read(&test_client_information.client_id)
            .await?;

        assert_eq!(test_updated_metadata_value, "some_new_test_client_metadata");

        Ok(())
    }

    #[tokio::test]
    async fn remove() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;
        let test_missing_client_id = String::from("some_test_client_id");
        let test_remove_error = test_client_registry.remove(test_missing_client_id).await;

        assert!(test_remove_error.is_err());

        let test_client_metadata = String::from("some_test_client_metadata");
        let test_valid_client_information = test_client_registry.add(test_client_metadata).await?;

        assert_eq!(test_client_registry.registered.len(), 1);

        let test_remove_ok = test_client_registry
            .remove(test_valid_client_information.client_id)
            .await;

        assert!(test_remove_ok.is_ok());
        assert_eq!(test_client_registry.registered.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn issue_id() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_id = super::issue_id().await;

        assert_eq!(
            test_client_id.as_uuid().get_version(),
            Some(uuid::Version::Random),
        );
        assert_eq!(test_client_id.to_string().len(), 32);

        Ok(())
    }
}
