use axum::body::Body;
use axum::http::header::{HeaderMap, CONTENT_TYPE};
use axum::http::request::Request;
use axum::http::StatusCode;
use axum::response::Response;
use hyper::body::{to_bytes, Bytes};

use crate::authorization_server::token::error::{AccessTokenError, AccessTokenErrorCode};
use crate::token_introspection::AccessTokensRequest;

use super::TokenIntrospection;

use request::IntrospectionRequest;

mod request;

impl TokenIntrospection {
    pub async fn introspect(
        request: Request<Body>,
        access_tokens_request: AccessTokensRequest,
    ) -> Result<Response<Body>, AccessTokenError> {
        check_content_type(request.headers()).await?;

        let request_body = request.into_body();
        let bytes = bytes(request_body).await?;
        let introspection_request = IntrospectionRequest::init(&bytes).await?;
        let response = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();

        Ok(response)
    }
}

async fn check_content_type(headers: &HeaderMap) -> Result<(), AccessTokenError> {
    match headers.get(CONTENT_TYPE) {
        None => {
            let access_token_error = AccessTokenError {
                error: AccessTokenErrorCode::InvalidRequest,
                error_description: Some(String::from("Missing Header: Content-Type")),
                error_uri: None,
            };

            Err(access_token_error)
        }
        Some(application_x_www_form_urlencoded) => {
            match application_x_www_form_urlencoded == "application/x-www-form-urlencoded" {
                true => {
                    println!("valid header!");

                    Ok(())
                }
                false => {
                    let access_token_error = AccessTokenError {
                        error: AccessTokenErrorCode::InvalidRequest,
                        error_description: Some(String::from("Header: Content-Type is invalid!")),
                        error_uri: None,
                    };

                    Err(access_token_error)
                }
            }
        }
    }
}

async fn bytes(body: Body) -> Result<Bytes, AccessTokenError> {
    match to_bytes(body).await {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            let access_token_error = AccessTokenError {
                error: AccessTokenErrorCode::InvalidRequest,
                error_description: Some(error.to_string()),
                error_uri: None,
            };

            Err(access_token_error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::access_tokens::AccessTokens;
    use axum::http::header::HeaderValue;
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
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .method(Method::POST)
            .body(Body::from(Bytes::from("token=some_access_token")))
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

    #[tokio::test]
    async fn check_content_type() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_introspection_request_headers_ok = HeaderMap::with_capacity(1);

        test_introspection_request_headers_ok.insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/x-www-form-urlencoded").unwrap(),
        );

        assert!(
            super::check_content_type(&test_introspection_request_headers_ok)
                .await
                .is_ok()
        );

        let mut test_introspection_request_headers_invalid = HeaderMap::with_capacity(1);

        test_introspection_request_headers_invalid.insert(
            CONTENT_TYPE,
            HeaderValue::from_str("applicationx-www-form-urlencoded").unwrap(),
        );

        assert!(
            super::check_content_type(&test_introspection_request_headers_invalid)
                .await
                .is_err()
        );

        let test_introspection_request_headers_missing = HeaderMap::with_capacity(1);

        assert!(
            super::check_content_type(&test_introspection_request_headers_missing)
                .await
                .is_err()
        );

        Ok(())
    }
}
