use std::net::SocketAddr;

use axum::routing::post;
use axum::Router;
use axum::Server;

mod register;

pub struct ClientRegistration {
    socket_address: SocketAddr,
}

impl ClientRegistration {
    pub async fn init(socket_address: SocketAddr) -> ClientRegistration {
        ClientRegistration { socket_address }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        Server::bind(&self.socket_address)
            .serve(self.router().await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self) -> Router {
        let client_registration_endpoint =
            Router::new().route("/register", post(ClientRegistration::register));

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
        let test_client_registration = ClientRegistration::init(test_socket_address).await;

        assert_eq!(
            test_client_registration.socket_address.to_string(),
            "127.0.0.1:7591",
        );

        Ok(())
    }
}
