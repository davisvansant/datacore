use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::request::Request;
use axum::http::StatusCode;
use axum::response::Response;

use crate::token_introspection::AccessTokensRequest;

use super::TokenIntrospection;

impl TokenIntrospection {
    pub async fn introspect(
        _request: Request<Body>,
        access_tokens_request: AccessTokensRequest,
    ) -> Result<Response<Body>, StatusCode> {
        let response = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::access_tokens::AccessTokens;
    use axum::routing::post;
    use axum::Router;
    use axum::Server;
    use hyper::{Body, Method};
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn introspect_post() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:7662")?;
        let mut test_access_tokens = AccessTokens::init().await;

        tokio::spawn(async move {
            test_access_tokens
                .0
                .run()
                .await
                .expect("test access tokens");
        });

        let test_endpoint = Router::new().route(
            "/introspect",
            post(move |test_request| {
                TokenIntrospection::introspect(test_request, test_access_tokens.1)
            }),
        );

        let test_server =
            Server::bind(&test_socket_address).serve(test_endpoint.into_make_service());

        tokio::spawn(async move {
            test_server.await.unwrap();
        });

        let test_uri = http::uri::Builder::new()
            .scheme("http")
            .authority("127.0.0.1:7662")
            .path_and_query("/introspect")
            .build()
            .unwrap();

        let test_request = http::request::Builder::new()
            .uri(test_uri)
            .header(CONTENT_TYPE, "application/json")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        let test_client = hyper::client::Client::new();
        let test_response = test_client.request(test_request).await;

        assert!(test_response.is_ok());
        assert_eq!(test_response.as_ref().unwrap().status(), StatusCode::OK);

        assert!(test_response
            .as_ref()
            .unwrap()
            .headers()
            .contains_key(CONTENT_TYPE));
        assert_eq!(
            test_response
                .as_ref()
                .unwrap()
                .headers()
                .get(CONTENT_TYPE)
                .unwrap(),
            "application/json",
        );

        Ok(())
    }
}
