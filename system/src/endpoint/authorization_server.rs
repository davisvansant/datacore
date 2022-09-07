use std::net::SocketAddr;

use axum::routing::{get, post};
use axum::Router;
use axum::Server;

use crate::state::access_tokens::channel::AccessTokensRequest;
use crate::state::authorization_codes::channel::AuthorizationCodesRequest;

mod authorization;
pub mod token;
mod userinfo;

pub struct AuthorizationServer {
    socket_address: SocketAddr,
    authorization_codes_request: AuthorizationCodesRequest,
    access_tokens_request: AccessTokensRequest,
}

impl AuthorizationServer {
    pub async fn init(
        socket_address: SocketAddr,
        authorization_codes_request: AuthorizationCodesRequest,
        access_tokens_request: AccessTokensRequest,
    ) -> AuthorizationServer {
        AuthorizationServer {
            socket_address,
            authorization_codes_request,
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
        let authorization_codes_request_get = self.authorization_codes_request.to_owned();
        let authorization_codes_request_post = self.authorization_codes_request.to_owned();

        let authorization_endpoint = Router::new()
            .route(
                "/authorize",
                get(move |query, request| {
                    AuthorizationServer::authorize(query, request, authorization_codes_request_get)
                }),
            )
            .route(
                "/authorize",
                post(move |query, request| {
                    AuthorizationServer::authorize(query, request, authorization_codes_request_post)
                }),
            );

        let access_tokens_request_get = self.access_tokens_request.to_owned();
        let access_tokens_request_post = self.access_tokens_request.to_owned();

        let token_endpoint = Router::new()
            .route(
                "/token",
                get(move |headers, query, request| {
                    AuthorizationServer::token(headers, query, request, access_tokens_request_get)
                }),
            )
            .route(
                "/token",
                post(move |headers, query, request| {
                    AuthorizationServer::token(headers, query, request, access_tokens_request_post)
                }),
            );

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
        let test_authorization_codes_request = AuthorizationCodesRequest::init().await;
        let test_access_tokens_request = AccessTokensRequest::init().await;
        let test_authorization_server = AuthorizationServer::init(
            test_socket_address,
            test_authorization_codes_request.0,
            test_access_tokens_request.0,
        )
        .await;

        assert_eq!(
            test_authorization_server.socket_address.to_string(),
            "127.0.0.1:6749",
        );

        Ok(())
    }
}
