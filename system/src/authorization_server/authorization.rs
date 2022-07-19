use axum::body::Body;
use axum::extract::Query;
use axum::http::header::{HeaderMap, CONTENT_TYPE, LOCATION};
use axum::http::StatusCode;
use axum::response::Response;

use super::AuthorizationServer;

use request::{AuthorizationRequest, AuthorizationResponseType};
use response::AuthorizationResponse;

mod error;
mod request;
mod response;

impl AuthorizationServer {
    pub(crate) async fn authorization(
        headers: HeaderMap,
        query: Query<AuthorizationRequest>,
    ) -> Result<Response<Body>, StatusCode> {
        for (key, value) in headers.iter() {
            println!("header key - {:?}", key);
            println!("header value - {:?}", value);
        }

        println!("response type = {:?}", query.response_type);
        println!("client_id = {:?}", query.client_id);
        println!("redirect_uri = {:?}", query.redirect_uri);
        println!("scope = {:?}", query.scope);
        println!("state = {:?}", query.state);

        let json_response = AuthorizationResponse {
            code: String::from("some_code"),
            state: None,
        };

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(LOCATION, "some_redirect_url")
            .status(302)
            .body(Body::from(serde_json::to_string(&json_response).unwrap()))
            .unwrap();

        Ok(response)
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
            "some_redirect_url",
        );

        Ok(())
    }
}
