use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use axum::http::status::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessTokenError {
    pub error: AccessTokenErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl IntoResponse for AccessTokenError {
    fn into_response(self) -> Response {
        let json = serde_json::to_vec(&self).expect("access token error json");

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .header(CACHE_CONTROL, "no-store")
            .header(PRAGMA, "no-cache")
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(json))
            .expect("access token error response");

        response.into_response()
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::to_bytes;
    use serde_json::{from_slice, json, to_value};

    #[tokio::test]
    async fn access_token_error() -> Result<(), Box<dyn std::error::Error>> {
        let test_access_token_error = AccessTokenError {
            error: AccessTokenErrorCode::InvalidRequest,
            error_description: None,
            error_uri: None,
        };

        let test_json = json!({
            "error": "invalid_request",
        });

        let test_error_json = serde_json::to_value(test_access_token_error)?;

        assert_eq!(test_error_json, test_json);

        Ok(())
    }

    #[tokio::test]
    async fn access_token_error_into_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_access_token_error = AccessTokenError {
            error: AccessTokenErrorCode::InvalidRequest,
            error_description: None,
            error_uri: None,
        };

        let test_response = test_access_token_error.into_response();

        assert!(test_response.headers().contains_key(CONTENT_TYPE));
        assert!(test_response.headers().contains_key(CACHE_CONTROL));
        assert!(test_response.headers().contains_key(PRAGMA));
        assert_eq!(
            test_response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json",
        );
        assert_eq!(
            test_response.headers().get(CACHE_CONTROL).unwrap(),
            "no-store",
        );
        assert_eq!(test_response.headers().get(PRAGMA).unwrap(), "no-cache");
        assert_eq!(test_response.status(), StatusCode::BAD_REQUEST);

        let test_body_bytes = to_bytes(&mut test_response.into_body()).await?;
        let test_access_token_error: AccessTokenError = from_slice(&test_body_bytes)?;

        assert_eq!(
            test_access_token_error.error,
            AccessTokenErrorCode::InvalidRequest
        );

        Ok(())
    }

    #[tokio::test]
    async fn access_token_error_code() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            to_value(&AccessTokenErrorCode::InvalidRequest)?,
            "invalid_request",
        );
        assert_eq!(
            to_value(&AccessTokenErrorCode::InvalidClient)?,
            "invalid_client",
        );
        assert_eq!(
            to_value(&AccessTokenErrorCode::InvalidGrant)?,
            "invalid_grant",
        );
        assert_eq!(
            to_value(&AccessTokenErrorCode::UnauthorizedClient)?,
            "unauthorized_client",
        );
        assert_eq!(
            to_value(&AccessTokenErrorCode::UnsupportedGrantType)?,
            "unsupported_grant_type",
        );
        assert_eq!(
            to_value(&AccessTokenErrorCode::InvalidScope)?,
            "invalid_scope",
        );

        Ok(())
    }
}
