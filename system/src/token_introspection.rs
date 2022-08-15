use std::net::SocketAddr;

use axum::routing::post;
use axum::Router;
use axum::Server;

mod introspect;

pub struct TokenIntrospection {
    socket_address: SocketAddr,
}

impl TokenIntrospection {
    pub async fn init(socket_address: SocketAddr) -> TokenIntrospection {
        TokenIntrospection { socket_address }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        Server::bind(&self.socket_address)
            .serve(self.router().await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self) -> Router {
        let token_introspection_endpoint = Router::new().route(
            "/introspect",
            post(move |request| TokenIntrospection::introspect(request)),
        );

        Router::new().merge(token_introspection_endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:7662")?;
        let test_token_introspection = TokenIntrospection::init(test_socket_address).await;

        assert_eq!(
            test_token_introspection.socket_address.to_string(),
            "127.0.0.1:7662",
        );

        Ok(())
    }
}
