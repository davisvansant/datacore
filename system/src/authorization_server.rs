use std::net::SocketAddr;

use axum::routing::{get, post};
use axum::Router;
use axum::Server;

mod authorization;
mod token;
mod userinfo;

pub struct AuthorizationServer {
    socket_address: SocketAddr,
}

impl AuthorizationServer {
    pub async fn init(socket_address: SocketAddr) -> AuthorizationServer {
        AuthorizationServer { socket_address }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        Server::bind(&self.socket_address)
            .serve(self.router().await.into_make_service())
            .await?;

        Ok(())
    }

    async fn router(&self) -> Router {
        let authorization_endpoint = Router::new()
            .route("/authorize", get(AuthorizationServer::authorization))
            .route("/authorize", post(AuthorizationServer::authorization));

        let token_endpoint = Router::new()
            .route("/token", get(AuthorizationServer::token))
            .route("/token", post(AuthorizationServer::token));

        let userinfo_endpoint = Router::new()
            .route("/userinfo", get(AuthorizationServer::userinfo))
            .route("/userinfo", post(AuthorizationServer::userinfo));

        Router::new()
            .merge(authorization_endpoint)
            .merge(token_endpoint)
            .merge(userinfo_endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:6749")?;
        let test_authorization_server = AuthorizationServer::init(test_socket_address).await;

        assert_eq!(
            test_authorization_server.socket_address.to_string(),
            "127.0.0.1:6749",
        );

        Ok(())
    }
}
