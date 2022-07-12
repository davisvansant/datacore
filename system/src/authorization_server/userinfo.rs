use axum::body::Body;
use axum::http::header::{HeaderMap, AUTHORIZATION};
use axum::http::StatusCode;
use axum::response::Response as HttpResponse;
use serde::{Deserialize, Serialize};

use super::AuthorizationServer;

#[derive(Deserialize)]
pub(crate) struct Request {}

#[derive(Serialize)]
pub(crate) struct Response {
    sub: String,
    name: String,
    given_name: String,
    family_name: String,
    preferred_username: String,
    email: String,
    picture: String,
}

impl AuthorizationServer {
    pub(crate) async fn userinfo(
        headers: HeaderMap,
        // query: Query<Request>,
    ) -> Result<HttpResponse<Body>, StatusCode> {
        for (key, value) in headers.iter() {
            println!("header key - {:?}", key);
            println!("header value - {:?}", value);
        }

        match headers.contains_key(AUTHORIZATION) {
            true => {
                let json_response = Response {
                    sub: String::from("some_sub"),
                    name: String::from("some_name"),
                    given_name: String::from("some_given_name"),
                    family_name: String::from("some_family_name"),
                    preferred_username: String::from("some_preferred_username"),
                    email: String::from("some_email"),
                    picture: String::from("some_picture"),
                };

                let response = HttpResponse::builder()
                    .status(200)
                    .body(Body::from(serde_json::to_string(&json_response).unwrap()))
                    .unwrap();

                Ok(response)
            }
            false => Err(StatusCode::UNAUTHORIZED),
        }
    }
}
