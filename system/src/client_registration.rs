use std::net::SocketAddr;

use axum::routing::post;
use axum::Router;
use axum::Server;

use crate::state::client_registry::channel::ClientRegistryRequest;

mod register;

pub struct ClientRegistration {
    socket_address: SocketAddr,
    client_registry_request: ClientRegistryRequest,
}

impl ClientRegistration {
    pub async fn init(
        socket_address: SocketAddr,
        client_registry_request: ClientRegistryRequest,
    ) -> ClientRegistration {
        ClientRegistration {
            socket_address,
            client_registry_request,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        Server::bind(&self.socket_address)
            .serve(self.router().await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self) -> Router {
        let client_registry_request = self.client_registry_request.to_owned();

        let client_registration_endpoint = Router::new().route(
            "/register",
            post(move |request| ClientRegistration::register(request, client_registry_request)),
        );

        Router::new().merge(client_registration_endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:7591")?;
        let test_client_registry_request = ClientRegistryRequest::init().await;
        let test_client_registration =
            ClientRegistration::init(test_socket_address, test_client_registry_request.0).await;

        assert_eq!(
            test_client_registration.socket_address.to_string(),
            "127.0.0.1:7591",
        );

        Ok(())
    }
}
