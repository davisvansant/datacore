use axum::body::Body;
use axum::extract::Query;
use axum::http::header::{HeaderMap, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::Response;

use super::AuthorizationServer;

use request::AccessTokenRequest;
use response::{AccessTokenResponse, AccessTokenType};

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
