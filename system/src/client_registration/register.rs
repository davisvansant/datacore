use axum::body::Body;
use axum::http::header::{HeaderMap, CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use axum::http::request::Request;
use axum::http::StatusCode;
use axum::response::Response;
use hyper::body::to_bytes;

use super::ClientRegistration;

use error::ClientRegistrationErrorCode;
use request::ClientMetadata;
use response::ClientInformation;

mod error;
mod request;
mod response;

impl ClientRegistration {
    pub(crate) async fn register(request: Request<Body>) -> Result<Response<Body>, StatusCode> {
        let request_headers = request.headers();

        match request_headers.get(CONTENT_TYPE) {
            None => println!("send error response"),
            Some(application_json) => println!("valid request! -> {:?}", application_json),
        };

        let request_body = request.into_body();

        let request_body_bytes = to_bytes(request_body).await.unwrap();

        let client_information: ClientMetadata =
            serde_json::from_slice(&request_body_bytes).unwrap();

        println!("client information request -> {:?}", client_information);

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .header(CACHE_CONTROL, "no-store")
            .header(PRAGMA, "no-cache")
            .status(200)
            .body(Body::empty())
            .unwrap();

        Ok(response)
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
        };

        let test_json = to_vec(&test_client_metadata)?;

        let test_request = http::request::Builder::new()
            .uri(test_uri)
            .header(CONTENT_TYPE, "application/json")
            .method(Method::POST)
            // .body(Body::empty())
            .body(Body::from(test_json))
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

        Ok(())
    }
}
