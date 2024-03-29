use axum::body::Body;
use axum::http::header::{HeaderMap, CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use axum::http::request::Request;
use axum::http::StatusCode;
use axum::response::Response;
use hyper::body::{to_bytes, Bytes};
use serde_json::to_vec;

use super::ClientRegistration;

use error::{ClientRegistrationError, ClientRegistrationErrorCode};
use request::ClientMetadata;
use response::ClientInformation;

use crate::state::client_registry::channel::ClientRegistryRequest;

pub mod error;
pub mod request;
pub mod response;

impl ClientRegistration {
    pub(crate) async fn register(
        request: Request<Body>,
        client_registry_request: ClientRegistryRequest,
    ) -> Result<Response<Body>, ClientRegistrationError> {
        check_content_type(request.headers()).await?;

        let bytes = bytes(request.into_body()).await?;
        let client_metadata = client_metadata(&bytes).await?;

        println!("client metadata -> {:?}", &client_metadata);

        check_redirect_uri(&client_metadata).await?;
        check_valid_software_statement(&client_metadata).await?;
        check_approved_software_statement(&client_metadata).await?;

        let client_information = client_registry_request.register(client_metadata).await?;
        let json = json(client_information).await?;
        let response = success(json).await?;

        Ok(response)
    }
}

async fn check_content_type(headers: &HeaderMap) -> Result<(), ClientRegistrationError> {
    match headers.get(CONTENT_TYPE) {
        None => {
            let client_registration_error = ClientRegistrationError {
                error: ClientRegistrationErrorCode::InvalidClientMetadata,
                error_description: String::from("Request is not valid JSON!"),
            };

            Err(client_registration_error)
        }
        Some(application_json) => {
            println!("valid request! -> {:?}", application_json);

            Ok(())
        }
    }
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

async fn json(client_information: ClientInformation) -> Result<Vec<u8>, ClientRegistrationError> {
    match to_vec(&client_information) {
        Ok(json) => Ok(json),
        Err(error) => {
            println!("json serialization -> {:?}", error);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::client_registry::ClientRegistry;
    use axum::routing::post;
    use axum::Router;
    use axum::Server;
    use hyper::{Body, Method};
    use serde_json::{json, to_vec};
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn register_post() -> Result<(), Box<dyn std::error::Error>> {
        let test_socket_address = SocketAddr::from_str("127.0.0.1:7591")?;
        let mut test_client_registry = ClientRegistry::init().await;

        tokio::spawn(async move {
            test_client_registry
                .0
                .run()
                .await
                .expect("test client registry");
        });

        let test_endpoint = Router::new().route(
            "/register",
            post(move |test_request| {
                ClientRegistration::register(test_request, test_client_registry.1)
            }),
        );

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

        let test_response_body = hyper::body::to_bytes(test_response.unwrap().body_mut()).await?;
        let test_response_json: ClientInformation = serde_json::from_slice(&test_response_body)?;

        assert_eq!(test_response_json.client_id.len(), 32);
        assert_eq!(test_response_json.client_secret, "some_client_secret");
        assert_eq!(
            test_response_json.client_id_issued_at,
            "some_client_id_issued_at",
        );
        assert_eq!(
            test_response_json.client_secret_expires_at,
            "some_client_secret_expires_at",
        );

        Ok(())
    }

    #[tokio::test]
    async fn check_content_type() -> Result<(), Box<dyn std::error::Error>> {
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
        let test_request_ok = http::request::Builder::new()
            .header(CONTENT_TYPE, "application/json")
            .method(Method::POST)
            .body(Body::from(test_json))
            .unwrap();

        let test_check_content_type_ok = super::check_content_type(test_request_ok.headers()).await;

        assert!(test_check_content_type_ok.is_ok());

        let test_request_error = http::request::Builder::new()
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        let test_check_content_type_error =
            super::check_content_type(test_request_error.headers()).await;

        assert!(test_check_content_type_error.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_redirect_uri() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_metadata_ok = ClientMetadata {
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

        let test_check_redirect_uri_ok = super::check_redirect_uri(&test_client_metadata_ok).await;

        assert!(test_check_redirect_uri_ok.is_ok());

        let test_client_metadata_error = ClientMetadata {
            redirect_uris: vec![String::from("some_test_uri_one"), String::from("")],
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

        let test_check_redirect_uri_error =
            super::check_redirect_uri(&test_client_metadata_error).await;

        assert!(test_check_redirect_uri_error.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_valid_software_statement() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_metadata_ok = ClientMetadata {
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
            software_statement: Some(String::from("some_test_software_statement")),
        };

        let test_check_valid_software_statement_ok =
            super::check_valid_software_statement(&test_client_metadata_ok).await;

        assert!(test_check_valid_software_statement_ok.is_ok());

        let test_client_metadata_error = ClientMetadata {
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
            software_statement: Some(String::from("")),
        };

        let test_check_valid_software_statement_error =
            super::check_valid_software_statement(&test_client_metadata_error).await;

        assert!(test_check_valid_software_statement_error.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn check_approved_software_statement() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_metadata_ok = ClientMetadata {
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
            software_statement: Some(String::from("some_test_software_statement")),
        };

        let test_check_approved_software_statement_ok =
            super::check_approved_software_statement(&test_client_metadata_ok).await;

        assert!(test_check_approved_software_statement_ok.is_ok());

        let test_client_metadata_error = ClientMetadata {
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
            software_statement: Some(String::from("")),
        };

        let test_check_approved_software_statement_error =
            super::check_approved_software_statement(&test_client_metadata_error).await;

        assert!(test_check_approved_software_statement_error.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn bytes() -> Result<(), Box<dyn std::error::Error>> {
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
        let test_body = Body::from(test_json);
        let test_bytes = super::bytes(test_body).await;

        assert!(test_bytes.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn client_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let test_valid_json = json!({
            "redirect_uris": [
                "some_test_uri_one",
                "some_test_uri_two",
            ],
            "token_endpoint_auth_method": "some_test_token_endpoint_auth_method",
            "grant_types": "some_test_grant_type",
            "response_types": [
                "some_test_response_type_one",
                "some_test_response_type_two",
            ],
            "client_name": "some_test_client_name",
            "client_uri": "some_test_client_uri",
            "logo_uri": "some_test_logo_uri",
            "scope": "some_test_scope",
            "contacts": "some_test_contacts",
            "tos_uri": "some_test_tos_uri",
            "policy_uri": "some_test_policy_uri",
            "jwks_uri": "some_test_jwks_uri",
            "jwks": "some_test_jwks",
            "software_id": "some_test_software_id",
            "software_version": "some_test_software_version",
        });

        let test_valid_bytes = to_vec(&test_valid_json)?;
        let test_client_metadata_ok = super::client_metadata(&test_valid_bytes).await;

        assert!(test_client_metadata_ok.is_ok());

        let test_invalid_json = json!({
            "some_json": "that_will_fail",
        });

        let test_invalid_bytes = to_vec(&test_invalid_json)?;
        let test_client_metadata_error = super::client_metadata(&test_invalid_bytes).await;

        assert!(test_client_metadata_error.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn success() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_information = ClientInformation {
            client_id: String::from("some_test_client_id"),
            client_secret: String::from("some_test_client_secret"),
            client_id_issued_at: String::from("some_test_client_id_issued_at"),
            client_secret_expires_at: String::from("some_test_client_secret_expires_at"),
        };

        let test_json = to_vec(&test_client_information)?;
        let test_response = super::success(test_json).await.unwrap();

        assert!(test_response.headers().contains_key(CONTENT_TYPE));
        assert!(test_response.headers().contains_key(CACHE_CONTROL));
        assert!(test_response.headers().contains_key(PRAGMA));
        assert_eq!(
            test_response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json",
        );
        assert_eq!(
            test_response.headers().get(CACHE_CONTROL).unwrap(),
            "no-store",
        );
        assert_eq!(test_response.headers().get(PRAGMA).unwrap(), "no-cache");
        assert_eq!(test_response.status(), StatusCode::CREATED);

        let test_body_bytes = to_bytes(&mut test_response.into_body()).await?;
        let test_client_information_response: ClientInformation =
            serde_json::from_slice(&test_body_bytes)?;

        assert_eq!(
            test_client_information_response.client_id,
            "some_test_client_id",
        );
        assert_eq!(
            test_client_information_response.client_secret,
            "some_test_client_secret",
        );
        assert_eq!(
            test_client_information_response.client_id_issued_at,
            "some_test_client_id_issued_at",
        );
        assert_eq!(
            test_client_information_response.client_secret_expires_at,
            "some_test_client_secret_expires_at",
        );

        Ok(())
    }
}
