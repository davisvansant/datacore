use axum::body::Body;
use axum::extract::Query;
use axum::http::header::{HeaderMap, CONTENT_TYPE, LOCATION};
use axum::http::request::Request;
use axum::http::uri::Uri;
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
        query: Query<AuthorizationRequest>,
        request: Request<Body>,
    ) -> Result<Response<Body>, AuthorizationError> {
        AuthorizationServer::check_content_type(request.headers()).await?;
        AuthorizationServer::check_response_type(request.uri()).await?;
        AuthorizationServer::check_client_id(request.uri()).await?;
        AuthorizationServer::check_scope(query.scope.as_ref()).await?;
        AuthorizationServer::authorize_client(&query.client_id).await?;

        let authorization_response = match &query.state {
            None => AuthorizationResponse {
                code: String::from("some_code"),
                state: None,
            },
            Some(state) => AuthorizationResponse {
                code: String::from("some_code"),
                state: Some(state.to_owned()),
            },
        };

        let redirect_url = authorization_response.url().await;

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(LOCATION, redirect_url)
            .status(StatusCode::FOUND)
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

    async fn check_response_type(uri: &Uri) -> Result<(), AuthorizationError> {
        match uri.query() {
            None => {
                let authorization_error = AuthorizationError {
                    error: AuthorizationErrorCode::InvalidRequest,
                    error_description: Some(String::from("Missing URI query")),
                    error_uri: None,
                };

                return Err(authorization_error);
            }
            Some(query) => match query.contains("response_type=code") {
                true => println!("valid response type!"),
                false => {
                    let authorization_error = AuthorizationError {
                        error: AuthorizationErrorCode::UnsupportedResponseType,
                        error_description: None,
                        error_uri: None,
                    };

                    return Err(authorization_error);
                }
            },
        }

        Ok(())
    }

    async fn check_client_id(uri: &Uri) -> Result<(), AuthorizationError> {
        match uri.query() {
            None => {
                let authorization_error = AuthorizationError {
                    error: AuthorizationErrorCode::InvalidRequest,
                    error_description: Some(String::from("Missing URI query")),
                    error_uri: None,
                };

                return Err(authorization_error);
            }
            Some(query) => match query.contains("client_id=") {
                true => println!("request contains client_id"),
                false => {
                    let authorization_error = AuthorizationError {
                        error: AuthorizationErrorCode::InvalidRequest,
                        error_description: Some(String::from("client ID is missing!")),
                        error_uri: None,
                    };

                    return Err(authorization_error);
                }
            },
        }

        Ok(())
    }

    async fn check_scope(query_scope: Option<&String>) -> Result<(), AuthorizationError> {
        if let Some(access_token_scope) = query_scope {
            match access_token_scope.is_empty() {
                true => {
                    let authorization_error = AuthorizationError {
                        error: AuthorizationErrorCode::InvalidScope,
                        error_description: None,
                        error_uri: None,
                    };

                    return Err(authorization_error);
                }
                false => println!("verify -> {:?}", &access_token_scope),
            }
        }

        Ok(())
    }

    async fn authorize_client(id: &str) -> Result<(), AuthorizationError> {
        match id.is_ascii() {
            true => println!("we need better way to authorize this client..."),
            false => {
                let authorization_error = AuthorizationError {
                    error: AuthorizationErrorCode::AccessDenied,
                    error_description: None,
                    error_uri: None,
                };

                return Err(authorization_error);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
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

    #[tokio::test]
    async fn check_response_type() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/authorize?response_type=code")
            .build()
            .unwrap();

        let test_check_response_type_ok =
            AuthorizationServer::check_response_type(&test_uri_ok).await;

        assert!(test_check_response_type_ok.is_ok());

        let test_uri_invalid = http::uri::Builder::new()
            .path_and_query("/authorize?response_type=something_else")
            .build()
            .unwrap();

        let test_check_response_type_invalid =
            AuthorizationServer::check_response_type(&test_uri_invalid).await;

        assert!(test_check_response_type_invalid.is_err());

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/authorize?missing")
            .build()
            .unwrap();

        let test_check_response_type_missing =
            AuthorizationServer::check_response_type(&test_uri_missing).await;

        assert!(test_check_response_type_missing.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_client_id() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/authorize?client_id=some_client_id")
            .build()
            .unwrap();

        let test_check_client_id_ok = AuthorizationServer::check_client_id(&test_uri_ok).await;

        assert!(test_check_client_id_ok.is_ok());

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/authorize?missing")
            .build()
            .unwrap();

        let test_check_client_id_missing =
            AuthorizationServer::check_client_id(&test_uri_missing).await;

        assert!(test_check_client_id_missing.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_scope() -> Result<(), Box<dyn std::error::Error>> {
        let test_scope_some = Some(String::from("scope=some_test_scope"));
        let test_scope_ok = AuthorizationServer::check_scope(test_scope_some.as_ref()).await;

        assert!(test_scope_ok.is_ok());

        let test_scope_some_empty = Some(String::from(""));
        let test_scope_empty_error =
            AuthorizationServer::check_scope(test_scope_some_empty.as_ref()).await;

        assert!(test_scope_empty_error.is_err());

        let test_scope_none = None;
        let test_scope_none_ok = AuthorizationServer::check_scope(test_scope_none).await;

        assert!(test_scope_none_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn authorize_client() -> Result<(), Box<dyn std::error::Error>> {
        let test_ascii_id = "@30kmcunQlkm0";
        let test_ascii_id_ok = AuthorizationServer::authorize_client(test_ascii_id).await;

        assert!(test_ascii_id_ok.is_ok());

        let test_non_ascii_id = "❤Τêστ⊗";
        let test_non_ascii_id_error =
            AuthorizationServer::authorize_client(test_non_ascii_id).await;

        assert!(test_non_ascii_id_error.is_err());

        Ok(())
    }
}
