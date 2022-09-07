use std::net::SocketAddr;

use axum::routing::post;
use axum::Router;
use axum::Server;

use crate::state::access_tokens::channel::AccessTokensRequest;

pub mod introspect;

pub struct TokenIntrospection {
    socket_address: SocketAddr,
    access_tokens_request: AccessTokensRequest,
}

impl TokenIntrospection {
    pub async fn init(
        socket_address: SocketAddr,
        access_tokens_request: AccessTokensRequest,
    ) -> TokenIntrospection {
        TokenIntrospection {
            socket_address,
            access_tokens_request,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        Server::bind(&self.socket_address)
            .serve(self.router().await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self) -> Router {
        let access_tokens_request = self.access_tokens_request.to_owned();
        let token_introspection_endpoint = Router::new().route(
            "/introspect",
            post(move |request| TokenIntrospection::introspect(request, access_tokens_request)),
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
        let test_access_tokens_request = AccessTokensRequest::init().await;
        let test_token_introspection =
            TokenIntrospection::init(test_socket_address, test_access_tokens_request.0).await;

        assert_eq!(
            test_token_introspection.socket_address.to_string(),
            "127.0.0.1:7662",
        );

        Ok(())
    }
}
