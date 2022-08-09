use std::collections::HashMap;

pub struct Clients {
    metadata: HashMap<String, String>,
}

impl Clients {
    pub async fn init() -> Clients {
        let metadata = HashMap::with_capacity(50);

        Clients { metadata }
    }

    pub async fn add(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let client_id = String::from("client_id");
        let client_metadata = String::from("client_metadata");

        if let None = self.metadata.insert(client_id, client_metadata) {
            println!("registered new client!");
        }

        Ok(())
    }

    pub async fn read(&mut self, client_id: &str) -> Result<String, Box<dyn std::error::Error>> {
        match self.metadata.get(client_id) {
            None => {
                let error = format!("could not find client id -> {:?}", client_id);

                Err(Box::from(error))
            }
            Some(client_id_value) => Ok(client_id_value.to_owned()),
        }
    }

    pub async fn update(
        &mut self,
        client_id: String,
        client_metadata: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.metadata.contains_key(&client_id) {
            true => {
                if let Some(old_value) = self.metadata.insert(client_id, client_metadata) {
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

    pub async fn remove(&mut self, client_id: String) -> Result<(), Box<dyn std::error::Error>> {
        match self.metadata.remove(&client_id) {
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
        let test_clients = Clients::init().await;

        assert!(test_clients.metadata.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn add() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_clients = Clients::init().await;

        assert_eq!(test_clients.metadata.len(), 0);

        test_clients.add().await?;

        assert_eq!(test_clients.metadata.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn read() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_clients = Clients::init().await;
        let test_value_error = test_clients.read("some_test_client_id").await;

        assert!(test_value_error.is_err());

        test_clients.add().await?;

        let test_value_ok = test_clients.read("client_id").await;

        assert!(test_value_ok.is_ok());
        assert_eq!(test_value_ok.unwrap(), "client_metadata");

        Ok(())
    }

    #[tokio::test]
    async fn update() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_clients = Clients::init().await;
        let test_client_id = String::from("some_test_client_id");
        let test_client_metadata = String::from("test_client_metadata");
        let test_update_error = test_clients
            .update(test_client_id, test_client_metadata)
            .await;

        assert!(test_update_error.is_err());

        test_clients.add().await?;

        let test_client_id = String::from("client_id");
        let test_client_metadata = String::from("some_new_test_client_metadata");
        let test_update_ok = test_clients
            .update(test_client_id, test_client_metadata)
            .await;

        assert!(test_update_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn remove() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_clients = Clients::init().await;
        let test_missing_client_id = String::from("some_test_client_id");
        let test_remove_error = test_clients.remove(test_missing_client_id).await;

        assert!(test_remove_error.is_err());

        test_clients.add().await?;

        assert_eq!(test_clients.metadata.len(), 1);

        let test_valid_client_id = String::from("client_id");
        let test_remove_ok = test_clients.remove(test_valid_client_id).await;

        assert!(test_remove_ok.is_ok());

        assert_eq!(test_clients.metadata.len(), 0);

        Ok(())
    }
}
