use std::collections::HashMap;

use crate::endpoint::client_registration::register::request::ClientMetadata;
use crate::endpoint::client_registration::register::response::ClientInformation;

use channel::{ClientRegistryRequest, ReceiveRequest, Request, Response};

pub mod channel;

pub struct ClientRegistry {
    receiver: ReceiveRequest,
    registered: HashMap<String, ClientMetadata>,
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
        client_metadata: ClientMetadata,
    ) -> Result<ClientInformation, Box<dyn std::error::Error>> {
        let client_information = ClientInformation::build().await;

        if self
            .registered
            .insert(client_information.client_id.to_owned(), client_metadata)
            .is_none()
        {
            println!("registered new client!");
        }

        Ok(client_information)
    }

    async fn read(&self, client_id: &str) -> Result<ClientMetadata, Box<dyn std::error::Error>> {
        match self.registered.get(client_id) {
            None => {
                let error = format!("could not find client id -> {:?}", client_id);

                Err(Box::from(error))
            }
            Some(client_metadata) => Ok(client_metadata.to_owned()),
        }
    }

    async fn update(
        &mut self,
        client_id: String,
        client_metadata: ClientMetadata,
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

        let test_client_metadata = ClientMetadata {
            redirect_uris: vec![
                String::from("some_test_uri_one"),
                String::from("some_test_uri_two"),
            ],
            token_endpoint_auth_method: String::from("some_test_token_endpoint_auth_method"),
            grant_types: String::from("some_test_grant_type"),
            response_types: vec![
                String::from("some_test_response_type_one"),
                String::from("some_test_response_type_two"),
            ],
            client_name: String::from("some_test_client_name"),
            client_uri: String::from("some_test_client_uri"),
            logo_uri: String::from("some_test_logo_uri"),
            scope: String::from("some_test_scope"),
            contacts: String::from("some_test_contacts"),
            tos_uri: String::from("some_test_tos_uri"),
            policy_uri: String::from("some_test_policy_uri"),
            jwks_uri: String::from("some_test_jwks_uri"),
            jwks: String::from("some_test_jwks"),
            software_id: String::from("some_test_software_id"),
            software_version: String::from("some_test_software_version"),
            software_statement: None,
        };

        test_client_registry.add(test_client_metadata).await?;

        assert_eq!(test_client_registry.registered.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn read() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;
        let test_value_error = test_client_registry.read("some_test_client_id").await;

        assert!(test_value_error.is_err());

        let test_client_metadata = ClientMetadata {
            redirect_uris: vec![
                String::from("some_test_uri_one"),
                String::from("some_test_uri_two"),
            ],
            token_endpoint_auth_method: String::from("some_test_token_endpoint_auth_method"),
            grant_types: String::from("some_test_grant_type"),
            response_types: vec![
                String::from("some_test_response_type_one"),
                String::from("some_test_response_type_two"),
            ],
            client_name: String::from("some_test_client_name"),
            client_uri: String::from("some_test_client_uri"),
            logo_uri: String::from("some_test_logo_uri"),
            scope: String::from("some_test_scope"),
            contacts: String::from("some_test_contacts"),
            tos_uri: String::from("some_test_tos_uri"),
            policy_uri: String::from("some_test_policy_uri"),
            jwks_uri: String::from("some_test_jwks_uri"),
            jwks: String::from("some_test_jwks"),
            software_id: String::from("some_test_software_id"),
            software_version: String::from("some_test_software_version"),
            software_statement: None,
        };
        let test_client_information = test_client_registry.add(test_client_metadata).await?;
        let test_value_ok = test_client_registry
            .read(&test_client_information.client_id)
            .await;

        assert!(test_value_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn update() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;
        let test_client_id = String::from("some_test_client_id");
        let test_client_metadata = ClientMetadata {
            redirect_uris: vec![
                String::from("some_test_uri_one"),
                String::from("some_test_uri_two"),
            ],
            token_endpoint_auth_method: String::from("some_test_token_endpoint_auth_method"),
            grant_types: String::from("some_test_grant_type"),
            response_types: vec![
                String::from("some_test_response_type_one"),
                String::from("some_test_response_type_two"),
            ],
            client_name: String::from("some_test_client_name"),
            client_uri: String::from("some_test_client_uri"),
            logo_uri: String::from("some_test_logo_uri"),
            scope: String::from("some_test_scope"),
            contacts: String::from("some_test_contacts"),
            tos_uri: String::from("some_test_tos_uri"),
            policy_uri: String::from("some_test_policy_uri"),
            jwks_uri: String::from("some_test_jwks_uri"),
            jwks: String::from("some_test_jwks"),
            software_id: String::from("some_test_software_id"),
            software_version: String::from("some_test_software_version"),
            software_statement: None,
        };
        let test_update_error = test_client_registry
            .update(test_client_id, test_client_metadata)
            .await;

        assert!(test_update_error.is_err());

        let test_initial_client_metadata = ClientMetadata {
            redirect_uris: vec![
                String::from("some_test_uri_one"),
                String::from("some_test_uri_two"),
            ],
            token_endpoint_auth_method: String::from("some_test_token_endpoint_auth_method"),
            grant_types: String::from("some_test_grant_type"),
            response_types: vec![
                String::from("some_test_response_type_one"),
                String::from("some_test_response_type_two"),
            ],
            client_name: String::from("some_test_client_name"),
            client_uri: String::from("some_test_client_uri"),
            logo_uri: String::from("some_test_logo_uri"),
            scope: String::from("some_test_scope"),
            contacts: String::from("some_test_contacts"),
            tos_uri: String::from("some_test_tos_uri"),
            policy_uri: String::from("some_test_policy_uri"),
            jwks_uri: String::from("some_test_jwks_uri"),
            jwks: String::from("some_test_jwks"),
            software_id: String::from("some_test_software_id"),
            software_version: String::from("some_test_software_version"),
            software_statement: None,
        };

        let test_client_information = test_client_registry
            .add(test_initial_client_metadata)
            .await?;

        let test_updated_client_metadata = ClientMetadata {
            redirect_uris: vec![
                String::from("some_test_uri_one"),
                String::from("some_test_uri_two"),
            ],
            token_endpoint_auth_method: String::from("some_test_token_endpoint_auth_method"),
            grant_types: String::from("some_test_grant_type"),
            response_types: vec![
                String::from("some_test_response_type_one"),
                String::from("some_test_response_type_two"),
            ],
            client_name: String::from("some_test_client_name"),
            client_uri: String::from("some_test_client_uri"),
            logo_uri: String::from("some_test_logo_uri"),
            scope: String::from("some_test_scope"),
            contacts: String::from("some_test_contacts"),
            tos_uri: String::from("some_test_tos_uri"),
            policy_uri: String::from("some_test_policy_uri"),
            jwks_uri: String::from("some_test_jwks_uri"),
            jwks: String::from("some_test_jwks"),
            software_id: String::from("some_test_software_id"),
            software_version: String::from("some_test_software_version"),
            software_statement: Some(String::from("some_test_software_statement")),
        };

        let test_update_ok = test_client_registry
            .update(
                test_client_information.client_id.to_owned(),
                test_updated_client_metadata,
            )
            .await;

        assert!(test_update_ok.is_ok());

        let test_updated_metadata_value = test_client_registry
            .read(&test_client_information.client_id)
            .await?;

        assert!(test_updated_metadata_value.software_statement.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn remove() -> Result<(), Box<dyn std::error::Error>> {
        let (mut test_client_registry, _) = ClientRegistry::init().await;
        let test_missing_client_id = String::from("some_test_client_id");
        let test_remove_error = test_client_registry.remove(test_missing_client_id).await;

        assert!(test_remove_error.is_err());

        let test_client_metadata = ClientMetadata {
            redirect_uris: vec![
                String::from("some_test_uri_one"),
                String::from("some_test_uri_two"),
            ],
            token_endpoint_auth_method: String::from("some_test_token_endpoint_auth_method"),
            grant_types: String::from("some_test_grant_type"),
            response_types: vec![
                String::from("some_test_response_type_one"),
                String::from("some_test_response_type_two"),
            ],
            client_name: String::from("some_test_client_name"),
            client_uri: String::from("some_test_client_uri"),
            logo_uri: String::from("some_test_logo_uri"),
            scope: String::from("some_test_scope"),
            contacts: String::from("some_test_contacts"),
            tos_uri: String::from("some_test_tos_uri"),
            policy_uri: String::from("some_test_policy_uri"),
            jwks_uri: String::from("some_test_jwks_uri"),
            jwks: String::from("some_test_jwks"),
            software_id: String::from("some_test_software_id"),
            software_version: String::from("some_test_software_version"),
            software_statement: None,
        };

        let test_valid_client_information = test_client_registry.add(test_client_metadata).await?;

        assert_eq!(test_client_registry.registered.len(), 1);

        let test_remove_ok = test_client_registry
            .remove(test_valid_client_information.client_id)
            .await;

        assert!(test_remove_ok.is_ok());
        assert_eq!(test_client_registry.registered.len(), 0);

        Ok(())
    }
}
