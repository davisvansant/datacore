use axum::body::Body;
// use axum::extract::Query;
use axum::http::header::{HeaderMap, CONTENT_TYPE, LOCATION};
use axum::http::request::Request;
use axum::http::StatusCode;
use axum::response::Response;

use super::AuthorizationServer;

use error::{AuthorizationError, AuthorizationErrorCode};
use request::{AuthorizationRequest, AuthorizationResponseType};
use response::AuthorizationResponse;

mod error;
mod request;
mod response;

impl AuthorizationServer {
    pub(crate) async fn authorization(
        request: Request<Body>,
    ) -> Result<Response<Body>, AuthorizationError> {
        AuthorizationServer::check_content_type(request.headers()).await?;

        let authorization_response = AuthorizationResponse {
            code: String::from("some_code"),
            state: None,
        };

        let redirect_url = authorization_response.url().await;

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(LOCATION, redirect_url)
            .status(302)
            .body(Body::empty())
            .unwrap();

        Ok(response)
    }

    async fn check_content_type(headers: &HeaderMap) -> Result<(), AuthorizationError> {
        match headers.get(CONTENT_TYPE) {
            None => {
                let authorization_error = AuthorizationError {
                    error: AuthorizationErrorCode::InvalidRequest,
                    error_description: Some(String::from("Missing Header: Content-Type")),
                    error_uri: None,
                };

                return Err(authorization_error);
            }
            Some(application_x_www_form_urlencoded) => {
                match application_x_www_form_urlencoded == "application/x-www-form-urlencoded" {
                    true => println!("valid header!"),
                    false => {
                        let authorization_error = AuthorizationError {
                            error: AuthorizationErrorCode::InvalidRequest,
                            error_description: Some(String::from(
                                "Header: Content-Type is invalid!",
                            )),
                            error_uri: None,
                        };

                        return Err(authorization_error);
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::Router;
    use axum::Server;
    use hyper::{Body, Method};
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn authorize_get() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:6749")?;
        let test_endpoint =
            Router::new().route("/authorize", get(AuthorizationServer::authorization));

        let test_server =
            Server::bind(&test_socket_address).serve(test_endpoint.into_make_service());

        tokio::spawn(async move {
            test_server.await.unwrap();
        });

        let test_uri = http::uri::Builder::new()
            .scheme("http")
            .authority("127.0.0.1:6749")
            .path_and_query("/authorize?response_type=code&client_id=some_client_id")
            .build()
            .unwrap();
        let test_request = http::request::Builder::new()
            .uri(test_uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let test_client = hyper::client::Client::new();
        let test_response = test_client.request(test_request).await;

        assert!(test_response.is_ok());
        assert_eq!(test_response.as_ref().unwrap().status(), StatusCode::FOUND);
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
            "application/x-www-form-urlencoded",
        );
        assert!(test_response
            .as_ref()
            .unwrap()
            .headers()
            .contains_key(LOCATION));
        assert_eq!(
            test_response
                .as_ref()
                .unwrap()
                .headers()
                .get(LOCATION)
                .unwrap(),
            "code=some_code",
        );
        assert!(hyper::body::to_bytes(test_response.unwrap().body_mut())
            .await?
            .is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn check_content_type() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_request_ok = http::request::Builder::new()
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let test_check_content_type_ok =
            AuthorizationServer::check_content_type(test_authorization_request_ok.headers()).await;

        assert!(test_check_content_type_ok.is_ok());

        let test_authorization_request_invalid = http::request::Builder::new()
            .header(CONTENT_TYPE, "applicationx-www-form-urlencoded")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let test_check_content_type_invalid =
            AuthorizationServer::check_content_type(test_authorization_request_invalid.headers())
                .await;

        assert!(test_check_content_type_invalid.is_err());

        let test_authorization_request_missing = http::request::Builder::new()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let test_check_content_type_missing =
            AuthorizationServer::check_content_type(test_authorization_request_missing.headers())
                .await;

        assert!(test_check_content_type_missing.is_err());

        Ok(())
    }
}
