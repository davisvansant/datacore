use axum::body::Body;
use axum::extract::Query;
use axum::http::header::{HeaderMap, CONTENT_TYPE, LOCATION};
use axum::http::request::Request;
use axum::http::uri::{Builder, Uri};
use axum::http::StatusCode;
use axum::response::Response;

use super::AuthorizationServer;

use error::{AuthorizationError, AuthorizationErrorCode};
use request::AuthorizationRequest;
use response::AuthorizationResponse;

mod error;
mod request;
mod response;

impl AuthorizationServer {
    pub(crate) async fn authorize(
        query: Query<AuthorizationRequest>,
        request: Request<Body>,
    ) -> Result<Response<Body>, AuthorizationError> {
        println!("request query -> {:?}", query.response_type);
        println!("request query -> {:?}", query.client_id);
        println!("request query -> {:?}", query.redirect_uri);
        println!("request query -> {:?}", query.scope);
        println!("request query -> {:?}", query.state);

        check_content_type(request.headers()).await?;
        check_response_type(request.uri()).await?;

        let client_id = check_client_id(request.uri()).await?;
        let request_redirect_uri = check_redirect_uri(request.uri()).await?;

        check_scope(request.uri()).await?;

        let state_request = check_state(request.uri()).await?;

        authorize(&client_id).await?;

        let authorization_response = match state_request {
            None => AuthorizationResponse {
                code: String::from("some_code"),
                state: None,
            },
            Some(state) => AuthorizationResponse {
                code: String::from("some_code"),
                state: Some(state),
            },
        };

        let redirect_query = authorization_response.query().await;
        let response_redirect_uri = build_uri(&redirect_query).await?;
        let response = match request_redirect_uri {
            None => {
                // obtain redirect uri via registered client
                grant_access(response_redirect_uri).await?
            }
            Some(_uri) => grant_access(response_redirect_uri).await?,
        };

        Ok(response)
    }
}

async fn check_content_type(headers: &HeaderMap) -> Result<(), AuthorizationError> {
    match headers.get(CONTENT_TYPE) {
        None => {
            let authorization_error = AuthorizationError {
                error: AuthorizationErrorCode::InvalidRequest,
                error_description: Some(String::from("Missing Header: Content-Type")),
                error_uri: None,
            };

            Err(authorization_error)
        }
        Some(application_x_www_form_urlencoded) => {
            match application_x_www_form_urlencoded == "application/x-www-form-urlencoded" {
                true => {
                    println!("valid header!");

                    Ok(())
                }
                false => {
                    let authorization_error = AuthorizationError {
                        error: AuthorizationErrorCode::InvalidRequest,
                        error_description: Some(String::from("Header: Content-Type is invalid!")),
                        error_uri: None,
                    };

                    Err(authorization_error)
                }
            }
        }
    }
}

async fn check_response_type(uri: &Uri) -> Result<(), AuthorizationError> {
    let authorization_error_invalid_request = AuthorizationError {
        error: AuthorizationErrorCode::InvalidRequest,
        error_description: Some(String::from("missing query parameter")),
        error_uri: None,
    };

    let authorization_error_unsupported_response_type = AuthorizationError {
        error: AuthorizationErrorCode::UnsupportedResponseType,
        error_description: Some(String::from("expected response_type=code")),
        error_uri: None,
    };

    match uri.query() {
        None => Err(authorization_error_invalid_request),
        Some(query) => {
            match query
                .split('&')
                .find(|parameter| parameter.starts_with("response_type=code"))
            {
                Some(response_type_parameter) => {
                    println!("query contains {:?}", &response_type_parameter);

                    Ok(())
                }
                None => Err(authorization_error_unsupported_response_type),
            }
        }
    }
}

async fn check_client_id(uri: &Uri) -> Result<String, AuthorizationError> {
    let authorization_error = AuthorizationError {
        error: AuthorizationErrorCode::InvalidRequest,
        error_description: Some(String::from("missing client ID query parameter")),
        error_uri: None,
    };

    match uri.query() {
        None => Err(authorization_error),
        Some(query) => {
            match query
                .split('&')
                .find(|parameter| parameter.starts_with("client_id="))
            {
                Some(client_id_parameter) => {
                    println!("query contains {:?}", &client_id_parameter);

                    match client_id_parameter.strip_prefix("client_id=") {
                        None => Err(authorization_error),
                        Some(client_id) => Ok(client_id.to_owned()),
                    }
                }
                None => Err(authorization_error),
            }
        }
    }
}

async fn check_redirect_uri(uri: &Uri) -> Result<Option<String>, AuthorizationError> {
    let authorization_error = AuthorizationError {
        error: AuthorizationErrorCode::InvalidRequest,
        error_description: None,
        error_uri: None,
    };

    match uri.query() {
        None => Err(authorization_error),
        Some(query) => {
            match query
                .split('&')
                .find(|parameter| parameter.starts_with("redirect_uri="))
            {
                Some(redirect_uri_parameter) => {
                    println!("query contains {:?}", &redirect_uri_parameter);

                    match redirect_uri_parameter.strip_prefix("redirect_uri=") {
                        None => Err(authorization_error),
                        Some(redirect_uri) => {
                            println!("redirect uri paramenter value -> {:?}", &redirect_uri);

                            Ok(Some(redirect_uri.to_owned()))
                        }
                    }
                }
                None => Ok(None),
            }
        }
    }
}

async fn check_scope(uri: &Uri) -> Result<(), AuthorizationError> {
    let authorization_error = AuthorizationError {
        error: AuthorizationErrorCode::InvalidScope,
        error_description: None,
        error_uri: None,
    };

    match uri.query() {
        None => Err(authorization_error),
        Some(query) => {
            match query
                .split('&')
                .find(|parameter| parameter.starts_with("scope="))
            {
                Some(scope_parameter) => {
                    println!("query contains {:?}", &scope_parameter);

                    match scope_parameter.strip_prefix("scope=") {
                        None => Err(authorization_error),
                        Some(scope) => {
                            println!("scope paramenter value -> {:?}", &scope);

                            Ok(())
                        }
                    }
                }
                None => Ok(()),
            }
        }
    }
}

async fn check_state(uri: &Uri) -> Result<Option<String>, AuthorizationError> {
    let authorization_error = AuthorizationError {
        error: AuthorizationErrorCode::InvalidRequest,
        error_description: None,
        error_uri: None,
    };

    match uri.query() {
        None => Err(authorization_error),
        Some(query) => {
            match query
                .split('&')
                .find(|parameter| parameter.starts_with("state="))
            {
                Some(state_parameter) => {
                    println!("query contains {:?}", &state_parameter);

                    match state_parameter.strip_prefix("state=") {
                        None => Err(authorization_error),
                        Some(state) => {
                            println!("state paramenter value -> {:?}", &state);

                            Ok(Some(state.to_owned()))
                        }
                    }
                }
                None => Ok(None),
            }
        }
    }
}

async fn authorize(id: &str) -> Result<(), AuthorizationError> {
    match id.is_ascii() {
        true => {
            println!("we need better way to authorize this client...");

            Ok(())
        }
        false => {
            let authorization_error = AuthorizationError {
                error: AuthorizationErrorCode::AccessDenied,
                error_description: None,
                error_uri: None,
            };

            Err(authorization_error)
        }
    }
}

async fn build_uri(query: &str) -> Result<Uri, AuthorizationError> {
    let mut path_and_query = String::with_capacity(100);
    let path = "/some_redirect_path?";

    path_and_query.push_str(path);
    path_and_query.push_str(query);
    path_and_query.shrink_to_fit();

    match Builder::new()
        .scheme("https")
        .authority("some_url")
        .path_and_query(&path_and_query)
        .build()
    {
        Ok(uri) => Ok(uri),
        Err(error) => {
            let authorization_error = AuthorizationError {
                error: AuthorizationErrorCode::ServerError,
                error_description: Some(error.to_string()),
                error_uri: None,
            };

            Err(authorization_error)
        }
    }
}

async fn grant_access(redirect_uri: Uri) -> Result<Response<Body>, AuthorizationError> {
    match Response::builder()
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(LOCATION, redirect_uri.to_string().as_str())
        .status(StatusCode::FOUND)
        .body(Body::empty())
    {
        Ok(authorization_response) => Ok(authorization_response),
        Err(error) => {
            let authorization_error = AuthorizationError {
                error: AuthorizationErrorCode::ServerError,
                error_description: Some(error.to_string()),
                error_uri: None,
            };

            Err(authorization_error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use axum::Server;
    use hyper::body::to_bytes;
    use hyper::{Body, Method};
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn authorize_get() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:6749")?;
        let test_endpoint = Router::new().route("/authorize", get(AuthorizationServer::authorize));

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
            "https://some_url/some_redirect_path?code=some_code",
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
            super::check_content_type(test_authorization_request_ok.headers()).await;

        assert!(test_check_content_type_ok.is_ok());

        let test_authorization_request_invalid = http::request::Builder::new()
            .header(CONTENT_TYPE, "applicationx-www-form-urlencoded")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let test_check_content_type_invalid =
            super::check_content_type(test_authorization_request_invalid.headers()).await;

        assert!(test_check_content_type_invalid.is_err());

        let test_authorization_request_missing = http::request::Builder::new()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let test_check_content_type_missing =
            super::check_content_type(test_authorization_request_missing.headers()).await;

        assert!(test_check_content_type_missing.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_response_type() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/authorize?response_type=code")
            .build()
            .unwrap();

        let test_check_response_type_ok = super::check_response_type(&test_uri_ok).await;

        assert!(test_check_response_type_ok.is_ok());

        let test_uri_invalid = http::uri::Builder::new()
            .path_and_query("/authorize?response_type=something_else")
            .build()
            .unwrap();

        let test_check_response_type_invalid = super::check_response_type(&test_uri_invalid).await;

        assert!(test_check_response_type_invalid.is_err());

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/authorize?another_response_type=code")
            .build()
            .unwrap();

        let test_check_response_type_missing = super::check_response_type(&test_uri_missing).await;

        assert!(test_check_response_type_missing.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_client_id() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/authorize?client_id=some_client_id")
            .build()
            .unwrap();

        let test_check_client_id_ok = super::check_client_id(&test_uri_ok).await;

        assert!(test_check_client_id_ok.is_ok());
        assert_eq!(test_check_client_id_ok.unwrap(), "some_client_id");

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/authorize?missing_client_id=some_test_client_id")
            .build()
            .unwrap();

        let test_check_client_id_missing = super::check_client_id(&test_uri_missing).await;

        assert!(test_check_client_id_missing.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_redirect_uri() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/authorize?redirect_uri=some_test_redirect_uri")
            .build()
            .unwrap();

        let test_redirect_uri_ok = super::check_redirect_uri(&test_uri_ok).await;

        assert!(test_redirect_uri_ok.is_ok());
        assert!(test_redirect_uri_ok.as_ref().unwrap().is_some());
        assert_eq!(
            test_redirect_uri_ok.unwrap().unwrap(),
            "some_test_redirect_uri",
        );

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/authorize?another_redirect_uri=some_test_redirect_uri")
            .build()
            .unwrap();

        let test_redirect_uri_missing_ok = super::check_redirect_uri(&test_uri_missing).await;

        assert!(test_redirect_uri_missing_ok.is_ok());
        assert!(test_redirect_uri_missing_ok.unwrap().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn check_scope() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/authorize?scope=some_test_scope")
            .build()
            .unwrap();
        let test_scope_ok = super::check_scope(&test_uri_ok).await;

        assert!(test_scope_ok.is_ok());

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/authorize?another_scope=some_test_scope")
            .build()
            .unwrap();
        let test_scope_missing_ok = super::check_scope(&test_uri_missing).await;

        assert!(test_scope_missing_ok.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn check_state() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/authorize?state=some_test_state")
            .build()
            .unwrap();

        let test_state_ok = super::check_state(&test_uri_ok).await;

        assert!(test_state_ok.is_ok());
        assert!(test_state_ok.as_ref().unwrap().is_some());
        assert_eq!(test_state_ok.unwrap().unwrap(), "some_test_state");

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/authorize?another_state=some_test_state")
            .build()
            .unwrap();

        let test_state_missing_ok_none = super::check_state(&test_uri_missing).await;

        assert!(test_state_missing_ok_none.is_ok());
        assert!(test_state_missing_ok_none.unwrap().is_none());

        Ok(())
    }

    #[tokio::test]
    async fn authorize() -> Result<(), Box<dyn std::error::Error>> {
        let test_ascii_id = "@30kmcunQlkm0";
        let test_ascii_id_ok = super::authorize(test_ascii_id).await;

        assert!(test_ascii_id_ok.is_ok());

        let test_non_ascii_id = "❤Τêστ⊗";
        let test_non_ascii_id_error = super::authorize(test_non_ascii_id).await;

        assert!(test_non_ascii_id_error.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn build_uri() -> Result<(), Box<dyn std::error::Error>> {
        let test_query = "some_test_query=some_test_value";
        let test_uri = super::build_uri(test_query).await.unwrap();

        assert_eq!(
            test_uri,
            "https://some_url/some_redirect_path?some_test_query=some_test_value",
        );

        Ok(())
    }

    #[tokio::test]
    async fn grant_access() -> Result<(), Box<dyn std::error::Error>> {
        let test_redirect_url = Uri::from_static("some_test_redirect_url");
        let test_response = super::grant_access(test_redirect_url)
            .await
            .expect("test_response");

        assert!(test_response.headers().contains_key(CONTENT_TYPE));
        assert!(test_response.headers().contains_key(LOCATION));
        assert_eq!(
            test_response.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(
            test_response.headers().get(LOCATION).unwrap(),
            "some_test_redirect_url",
        );
        assert_eq!(test_response.status(), StatusCode::FOUND);

        let test_body_bytes = to_bytes(&mut test_response.into_body()).await?;

        assert!(test_body_bytes.is_empty());

        Ok(())
    }
}
