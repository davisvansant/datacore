use axum::body::Body;
use axum::http::header::{HeaderMap, CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use axum::http::request::Request;
use axum::http::StatusCode;
use axum::response::Response;
use hyper::body::{to_bytes, Bytes};

use super::ClientRegistration;

use error::{ClientRegistrationError, ClientRegistrationErrorCode};
use request::ClientMetadata;
use response::ClientInformation;

mod error;
mod request;
mod response;

impl ClientRegistration {
    pub(crate) async fn register(
        request: Request<Body>,
    ) -> Result<Response<Body>, ClientRegistrationError> {
        ClientRegistration::check_content_type(request.headers()).await?;
        let bytes = ClientRegistration::bytes(request.into_body()).await?;
        let client_metadata = ClientRegistration::client_metadata(&bytes).await?;

        println!("client metadata -> {:?}", &client_metadata);

        ClientRegistration::check_redirect_uri(&client_metadata).await?;
        ClientRegistration::check_valid_software_statement(&client_metadata).await?;
        ClientRegistration::check_approved_software_statement(&client_metadata).await?;

        let client_information = ClientInformation {
            client_id: String::from("some_client_id"),
            client_secret: String::from("some_client_secret"),
            client_id_issued_at: String::from("some_client_id_issued_at"),
            client_secret_expires_at: String::from("some_client_secret_expires_at"),
        };

        let json = serde_json::to_vec(&client_information).expect("json");

        let response = ClientRegistration::success(json).await?;

        Ok(response)
    }

    async fn check_content_type(headers: &HeaderMap) -> Result<(), ClientRegistrationError> {
        match headers.get(CONTENT_TYPE) {
            None => {
                let client_registration_error = ClientRegistrationError {
                    error: ClientRegistrationErrorCode::InvalidClientMetadata,
                    error_description: String::from("Request is not valid JSON!"),
                };

                return Err(client_registration_error);
            }
            Some(application_json) => println!("valid request! -> {:?}", application_json),
        }

        Ok(())
    }

    async fn check_redirect_uri(
        client_metadata: &ClientMetadata,
    ) -> Result<(), ClientRegistrationError> {
        for uri in &client_metadata.redirect_uris {
            match uri.is_empty() {
                true => {
                    let client_registration_error = ClientRegistrationError {
                        error: ClientRegistrationErrorCode::InvalidRedirectUri,
                        error_description: String::from("URI is empty!"),
                    };

                    return Err(client_registration_error);
                }
                false => println!("valid uri!"),
            }
        }

        Ok(())
    }

    async fn check_valid_software_statement(
        client_metadata: &ClientMetadata,
    ) -> Result<(), ClientRegistrationError> {
        if let Some(software_statement) = &client_metadata.software_statement {
            match software_statement.is_empty() {
                true => {
                    let client_registration_error = ClientRegistrationError {
                        error: ClientRegistrationErrorCode::InvalidSoftwareStatement,
                        error_description: String::from("software statement is invalid!"),
                    };

                    return Err(client_registration_error);
                }
                false => println!("valid software statement!"),
            }
        }

        Ok(())
    }

    async fn check_approved_software_statement(
        client_metadata: &ClientMetadata,
    ) -> Result<(), ClientRegistrationError> {
        if let Some(software_statement) = &client_metadata.software_statement {
            match software_statement.is_empty() {
                true => {
                    let client_registration_error = ClientRegistrationError {
                        error: ClientRegistrationErrorCode::UnapprovedSoftwareStatement,
                        error_description: String::from("software statement is unapproved!"),
                    };

                    return Err(client_registration_error);
                }
                false => println!("approved software statement!"),
            }
        }

        Ok(())
    }

    async fn bytes(body: Body) -> Result<Bytes, ClientRegistrationError> {
        match to_bytes(body).await {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                let client_registration_error = ClientRegistrationError {
                    error: ClientRegistrationErrorCode::InvalidClientMetadata,
                    error_description: error.to_string(),
                };

                Err(client_registration_error)
            }
        }
    }

    async fn client_metadata(bytes: &[u8]) -> Result<ClientMetadata, ClientRegistrationError> {
        match serde_json::from_slice(bytes) {
            Ok(client_metadata) => Ok(client_metadata),
            Err(error) => {
                let client_registration_error = ClientRegistrationError {
                    error: ClientRegistrationErrorCode::InvalidClientMetadata,
                    error_description: error.to_string(),
                };

                Err(client_registration_error)
            }
        }
    }

    async fn success(json: Vec<u8>) -> Result<Response<Body>, ClientRegistrationError> {
        let response = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .header(CACHE_CONTROL, "no-store")
            .header(PRAGMA, "no-cache")
            .status(StatusCode::CREATED)
            .body(Body::from(json));

        match response {
            Ok(client_registration_response) => Ok(client_registration_response),
            Err(error) => {
                let client_registration_error = ClientRegistrationError {
                    error: ClientRegistrationErrorCode::InvalidClientMetadata,
                    error_description: error.to_string(),
                };

                Err(client_registration_error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::Router;
    use axum::Server;
    use hyper::{Body, Method};
    use serde_json::to_vec;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn register_post() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:7591")?;
        let test_endpoint = Router::new().route("/register", post(ClientRegistration::register));

        let test_server =
            Server::bind(&test_socket_address).serve(test_endpoint.into_make_service());

        tokio::spawn(async move {
            test_server.await.unwrap();
        });

        let test_uri = http::uri::Builder::new()
            .scheme("http")
            .authority("127.0.0.1:7591")
            .path_and_query("/register")
            .build()
            .unwrap();

        let test_client_metadata = ClientMetadata {
            redirect_uris: vec![
                String::from("some_test_uri_one"),
                String::from("some_test_uri_two"),
            ],
            token_endpoint_auth_method: String::from("some_test_token_endpoint_auth_method"),
            grant_types: String::from("some_test_grant_type"),
            response_types: vec![
                String::from("some_test_response_type_one"),
                String::from("some_test_response_type_two"),
            ],
            client_name: String::from("some_test_client_name"),
            client_uri: String::from("some_test_client_uri"),
            logo_uri: String::from("some_test_logo_uri"),
            scope: String::from("some_test_scope"),
            contacts: String::from("some_test_contacts"),
            tos_uri: String::from("some_test_tos_uri"),
            policy_uri: String::from("some_test_policy_uri"),
            jwks_uri: String::from("some_test_jwks_uri"),
            jwks: String::from("some_test_jwks"),
            software_id: String::from("some_test_software_id"),
            software_version: String::from("some_test_software_version"),
            software_statement: None,
        };

        let test_json = to_vec(&test_client_metadata)?;

        let test_request = http::request::Builder::new()
            .uri(test_uri)
            .header(CONTENT_TYPE, "application/json")
            .method(Method::POST)
            .body(Body::from(test_json))
            .unwrap();

        let test_client = hyper::client::Client::new();
        let test_response = test_client.request(test_request).await;

        assert!(test_response.is_ok());
        assert_eq!(
            test_response.as_ref().unwrap().status(),
            StatusCode::CREATED,
        );

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

        Ok(())
    }
}
