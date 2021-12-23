use axum::body::Body;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::Response as HttpResponse;
use serde::{Deserialize, Serialize};

use super::AuthorizationServer;

#[derive(Deserialize)]
pub(crate) struct Request {
    response_type: String,
    client_id: String,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct Response {
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

impl AuthorizationServer {
    pub(crate) async fn authorization(
        request: Query<Request>,
    ) -> Result<HttpResponse<Body>, StatusCode> {
        println!("response type = {:?}", request.response_type);
        println!("client_id = {:?}", request.client_id);
        println!("redirect_uri = {:?}", request.redirect_uri);
        println!("scope = {:?}", request.scope);
        println!("state = {:?}", request.state);

        let json_response = Response {
            code: String::from("some_code"),
            state: None,
        };

        let response = HttpResponse::builder()
            .status(200)
            .body(Body::from(serde_json::to_string(&json_response).unwrap()))
            .unwrap();

        Ok(response)
    }
}