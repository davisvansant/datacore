use std::collections::HashMap;

use channel::{ClientRegistryRequest, ReceiveRequest, Request};

pub mod channel;

pub struct ClientRegistry {
    receiver: ReceiveRequest,
    registered: HashMap<String, String>,
    unregistered: HashMap<String, String>,
}

impl ClientRegistry {
    pub async fn init() -> (ClientRegistry, ClientRegistryRequest) {
        let (send_request, receive_request) = ClientRegistryRequest::init().await;
        let capacity = 50;
        let registered = HashMap::with_capacity(capacity);
        let unregistered = HashMap::with_capacity(capacity);

        (
            ClientRegistry {
                receiver: receive_request,
                registered,
                unregistered,
            },
            send_request,
        )
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(request) = self.receiver.recv().await {
            match request {
                Request::Register => self.add().await?,
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

    async fn add(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let client_id = String::from("client_id");
        let client_metadata = String::from("client_metadata");

        if let None = self.registered.insert(client_id, client_metadata) {
            println!("registered new client!");
        }

        Ok(())
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

        test_client_registry.add().await?;

        assert_eq!(test_client_registry.registered.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn read() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;
        let test_value_error = test_client_registry.read("some_test_client_id").await;

        assert!(test_value_error.is_err());

        test_client_registry.add().await?;

        let test_value_ok = test_client_registry.read("client_id").await;

        assert!(test_value_ok.is_ok());
        assert_eq!(test_value_ok.unwrap(), "client_metadata");

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

        test_client_registry.add().await?;

        let test_client_id = String::from("client_id");
        let test_client_metadata = String::from("some_new_test_client_metadata");
        let test_update_ok = test_client_registry
            .update(test_client_id, test_client_metadata)
            .await;

        assert!(test_update_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn remove() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;
        let test_missing_client_id = String::from("some_test_client_id");
        let test_remove_error = test_client_registry.remove(test_missing_client_id).await;

        assert!(test_remove_error.is_err());

        test_client_registry.add().await?;

        assert_eq!(test_client_registry.registered.len(), 1);

        let test_valid_client_id = String::from("client_id");
        let test_remove_ok = test_client_registry.remove(test_valid_client_id).await;

        assert!(test_remove_ok.is_ok());

        assert_eq!(test_client_registry.registered.len(), 0);

        Ok(())
    }
}
