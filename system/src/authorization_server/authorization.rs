use axum::body::Body;
use axum::extract::Query;
use axum::http::header::HeaderMap;
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
    pub(crate) async fn authentication(
        headers: HeaderMap,
        query: Query<Request>,
    ) -> Result<HttpResponse<Body>, StatusCode> {
        for (key, value) in headers.iter() {
            println!("header key - {:?}", key);
            println!("header value - {:?}", value);
        }

        println!("response type = {:?}", query.response_type);
        println!("client_id = {:?}", query.client_id);
        println!("redirect_uri = {:?}", query.redirect_uri);
        println!("scope = {:?}", query.scope);
        println!("state = {:?}", query.state);

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
