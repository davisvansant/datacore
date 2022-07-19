use axum::body::Body;
use axum::extract::Query;
use axum::http::header::{HeaderMap, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::Response;

use super::AuthorizationServer;

use request::AccessTokenRequest;
use response::{AccessTokenResponse, AccessTokenType};

mod error;
mod request;
mod response;

impl AuthorizationServer {
    pub(crate) async fn token(
        headers: HeaderMap,
        query: Query<AccessTokenRequest>,
    ) -> Result<Response<Body>, StatusCode> {
        for (key, value) in headers.iter() {
            println!("header key {:?}", key);
            println!("header value {:?}", value);
        }

        println!("grant type = {:?}", query.grant_type);
        println!("code = {:?}", query.code);
        println!("redirect uri = {:?}", query.redirect_uri);
        println!("client id = {:?}", query.client_id);

        let access_token_response = AccessTokenResponse {
            access_token: String::from("some_access_token"),
            token_type: AccessTokenType::Bearer,
            expires_in: 3600,
        };

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .status(200)
            .body(Body::from(
                serde_json::to_string(&access_token_response).unwrap(),
            ))
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
            .path_and_query("/token?grant_type=authorization_code&code=some_authorization_code")
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
        // assert!(test_response
        //     .as_ref()
        //     .unwrap()
        //     .headers()
        //     .contains_key(LOCATION));
        // assert_eq!(
        //     test_response
        //         .as_ref()
        //         .unwrap()
        //         .headers()
        //         .get(LOCATION)
        //         .unwrap(),
        //     "code=some_code",
        // );
        // assert!(hyper::body::to_bytes(test_response.unwrap().body_mut())
        //     .await?
        //     .is_empty());
        let test_response_body = hyper::body::to_bytes(test_response.unwrap().body_mut()).await?;
        let test_response_json: AccessTokenResponse = serde_json::from_slice(&test_response_body)?;

        assert_eq!(test_response_json.access_token, "some_access_token");
        assert_eq!(test_response_json.token_type, AccessTokenType::Bearer);
        assert_eq!(test_response_json.expires_in, 3600);

        Ok(())
    }
}
