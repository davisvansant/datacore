use axum::body::Body;
use axum::http::header::{HeaderMap, CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use axum::http::request::Request;
use axum::http::StatusCode;
use axum::response::Response;

use super::ClientRegistration;

use request::ClientMetadata;
use response::ClientInformation;

mod request;
mod response;

impl ClientRegistration {
    pub(crate) async fn register(_request: Request<Body>) -> Result<Response<Body>, StatusCode> {
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
