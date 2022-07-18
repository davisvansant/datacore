use axum::body::Body;
use axum::extract::Query;
use axum::http::header::{HeaderMap, CONTENT_TYPE, LOCATION};
use axum::http::StatusCode;
use axum::response::Response;

use super::AuthorizationServer;

use request::AuthorizationRequest;
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
