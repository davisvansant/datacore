use axum::body::Body;
use axum::extract::Query;
use axum::http::header::{HeaderMap, CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use axum::http::request::Request;
use axum::http::uri::Uri;
use axum::http::StatusCode;
use axum::response::Response;

use super::AuthorizationServer;

use error::{AccessTokenError, AccessTokenErrorCode};
use request::{AccessTokenGrantType, AccessTokenRequest};
use response::{AccessTokenResponse, AccessTokenType};

mod error;
mod request;
mod response;

impl AuthorizationServer {
    pub(crate) async fn token(
        headers: HeaderMap,
        query: Query<AccessTokenRequest>,
        request: Request<Body>,
    ) -> Result<Response<Body>, AccessTokenError> {
        // for (key, value) in headers.iter() {
        //     println!("header key {:?}", key);
        //     println!("header value {:?}", value);
        // }

        // println!("grant type = {:?}", query.grant_type);
        // println!("code = {:?}", query.code);
        // println!("redirect uri = {:?}", query.redirect_uri);
        // println!("client id = {:?}", query.client_id);
        AuthorizationServer::check_grant_type(request.uri()).await?;
        AuthorizationServer::check_code(request.uri()).await?;
        check_client_id(request.uri()).await?;

        let access_token_response = AccessTokenResponse {
            access_token: String::from("some_access_token"),
            token_type: AccessTokenType::Bearer,
            expires_in: 3600,
        };

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .header(CACHE_CONTROL, "no-store")
            .header(PRAGMA, "no-cache")
            .status(StatusCode::OK)
            .body(Body::from(
                serde_json::to_string(&access_token_response).unwrap(),
            ))
            .unwrap();

        Ok(response)
    }

    async fn check_grant_type(uri: &Uri) -> Result<(), AccessTokenError> {
        match uri.query() {
            None => {
                let access_token_error = AccessTokenError {
                    error: AccessTokenErrorCode::InvalidRequest,
                    error_description: Some(String::from("missing grant_type=")),
                    error_uri: None,
                };

                return Err(access_token_error);
            }
            Some(query) => match query.contains("grant_type=authorization_code") {
                true => println!("valid response type!"),
                false => {
                    let access_token_error = AccessTokenError {
                        error: AccessTokenErrorCode::InvalidGrant,
                        error_description: Some(String::from(
                            "missing grant_type=authorization_code",
                        )),
                        error_uri: None,
                    };

                    return Err(access_token_error);
                }
            },
        }

        Ok(())
    }

    async fn check_code(uri: &Uri) -> Result<(), AccessTokenError> {
        match uri.query() {
            None => {
                let access_token_error = AccessTokenError {
                    error: AccessTokenErrorCode::InvalidRequest,
                    error_description: Some(String::from("missing code=")),
                    error_uri: None,
                };

                return Err(access_token_error);
            }
            Some(query) => {
                match query
                    .split('&')
                    .find(|parameter| parameter.starts_with("code="))
                {
                    Some(code) => println!("query contains {:?}", &code),
                    None => {
                        let access_token_error = AccessTokenError {
                            error: AccessTokenErrorCode::InvalidClient,
                            error_description: None,
                            error_uri: None,
                        };

                        return Err(access_token_error);
                    }
                }
            }
        }

        Ok(())
    }
}

async fn check_client_id(uri: &Uri) -> Result<(), AccessTokenError> {
    let access_token_error = AccessTokenError {
        error: AccessTokenErrorCode::InvalidRequest,
        error_description: Some(String::from("missing client_id")),
        error_uri: None,
    };

    match uri.query() {
        None => return Err(access_token_error),
        Some(query) => {
            match query
                .split('&')
                .find(|parameter| parameter.starts_with("client_id="))
            {
                Some(client_id) => println!("query contains {:?}", &client_id),
                None => return Err(access_token_error),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::Router;
    use axum::Server;
    use hyper::{Body, Method};
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn token_post() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:6749")?;
        let test_endpoint = Router::new().route("/token", post(AuthorizationServer::token));

        let test_server =
            Server::bind(&test_socket_address).serve(test_endpoint.into_make_service());

        tokio::spawn(async move {
            test_server.await.unwrap();
        });

        let test_uri = http::uri::Builder::new()
            .scheme("http")
            .authority("127.0.0.1:6749")
            .path_and_query("/token?grant_type=authorization_code&code=some_authorization_code&client_id=some_test_client_id")
            .build()
            .unwrap();
        let test_request = http::request::Builder::new()
            .uri(test_uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
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

        assert!(test_response
            .as_ref()
            .unwrap()
            .headers()
            .contains_key(CACHE_CONTROL));
        assert_eq!(
            test_response
                .as_ref()
                .unwrap()
                .headers()
                .get(CACHE_CONTROL)
                .unwrap(),
            "no-store",
        );

        assert!(test_response
            .as_ref()
            .unwrap()
            .headers()
            .contains_key(PRAGMA));
        assert_eq!(
            test_response
                .as_ref()
                .unwrap()
                .headers()
                .get(PRAGMA)
                .unwrap(),
            "no-cache",
        );

        let test_response_body = hyper::body::to_bytes(test_response.unwrap().body_mut()).await?;
        let test_response_json: AccessTokenResponse = serde_json::from_slice(&test_response_body)?;

        assert_eq!(test_response_json.access_token, "some_access_token");
        assert_eq!(test_response_json.token_type, AccessTokenType::Bearer);
        assert_eq!(test_response_json.expires_in, 3600);

        Ok(())
    }

    #[tokio::test]
    async fn check_grant_type() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/token?grant_type=authorization_code")
            .build()
            .unwrap();

        let test_check_grant_type_ok = AuthorizationServer::check_grant_type(&test_uri_ok).await;

        assert!(test_check_grant_type_ok.is_ok());

        let test_uri_invalid = http::uri::Builder::new()
            .path_and_query("/token?grant_type=something_else")
            .build()
            .unwrap();

        let test_check_grant_type_invalid =
            AuthorizationServer::check_grant_type(&test_uri_invalid).await;

        assert!(test_check_grant_type_invalid.is_err());

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/token?missing_grant_type")
            .build()
            .unwrap();

        let test_check_grant_type_missing =
            AuthorizationServer::check_grant_type(&test_uri_missing).await;

        assert!(test_check_grant_type_missing.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_code() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/token?grant_type=authorization_code&code=some_test_code")
            .build()
            .unwrap();

        let test_check_code_ok = AuthorizationServer::check_code(&test_uri_ok).await;

        assert!(test_check_code_ok.is_ok());

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/token?grant_type=authorization_code&other_code=some_test_code")
            .build()
            .unwrap();

        let test_check_code_missing = AuthorizationServer::check_code(&test_uri_missing).await;

        assert!(test_check_code_missing.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_client_id() -> Result<(), Box<dyn std::error::Error>> {
        let test_uri_ok = http::uri::Builder::new()
            .path_and_query("/token?grant_type=authorization_code&code=some_test_code&client_id=some_test_client_id")
            .build()
            .unwrap();

        let test_check_client_id_ok = super::check_client_id(&test_uri_ok).await;

        assert!(test_check_client_id_ok.is_ok());

        let test_uri_missing = http::uri::Builder::new()
            .path_and_query("/token?grant_type=authorization_code&other_code=some_test_code&some_other_client_id=some_test_client_id")
            .build()
            .unwrap();

        let test_check_client_id_missing = super::check_client_id(&test_uri_missing).await;

        assert!(test_check_client_id_missing.is_err());

        Ok(())
    }
}
