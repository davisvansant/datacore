use axum::body::Body;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::Response as HttpResponse;
use serde::{Deserialize, Serialize};

use super::AuthorizationServer;

#[derive(Deserialize)]
pub(crate) struct AccessTokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
}

#[derive(Serialize)]
pub(crate) struct AccessTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u16,
}

impl AuthorizationServer {
    pub(crate) async fn token(
        request: Query<AccessTokenRequest>,
    ) -> Result<HttpResponse<Body>, StatusCode> {
        println!("grant type = {:?}", request.grant_type);
        println!("code = {:?}", request.code);
        println!("redirect uri = {:?}", request.redirect_uri);
        println!("client id = {:?}", request.client_id);

        let access_token_response = AccessTokenResponse {
            access_token: String::from("some_access_token"),
            token_type: String::from("some_token_type"),
            expires_in: 3600,
        };

        let response = HttpResponse::builder()
            .status(200)
            .body(Body::from(
                serde_json::to_string(&access_token_response).unwrap(),
            ))
            .unwrap();

        Ok(response)
    }
}
