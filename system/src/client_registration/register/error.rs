use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use axum::http::status::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientRegistrationError {
    pub error: ClientRegistrationErrorCode,
    pub error_description: String,
}

impl IntoResponse for ClientRegistrationError {
    fn into_response(self) -> Response {
        let json = serde_json::to_vec(&self).expect("client registration error json");

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .header(CACHE_CONTROL, "no-store")
            .header(PRAGMA, "no-cache")
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(json))
            .expect("client registration error response");

        response.into_response()
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientRegistrationErrorCode {
    InvalidRedirectUri,
    InvalidClientMetadata,
    InvalidSoftwareStatement,
    UnapprovedSoftwareStatement,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::to_bytes;
    use serde_json::{from_slice, json, to_value};

    #[tokio::test]
    async fn client_registration_error() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_registration_error = ClientRegistrationError {
            error: ClientRegistrationErrorCode::InvalidRedirectUri,
            error_description: String::from("some_test_error_description"),
        };

        let test_json = json!({
            "error": "invalid_redirect_uri",
            "error_description": "some_test_error_description",
        });

        let test_error_json = serde_json::to_value(test_client_registration_error)?;

        assert_eq!(test_error_json, test_json);

        Ok(())
    }

    #[tokio::test]
    async fn client_registration_error_into_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_registration_error = ClientRegistrationError {
            error: ClientRegistrationErrorCode::InvalidRedirectUri,
            error_description: String::from("some_test_error_description"),
        };

        let test_response = test_client_registration_error.into_response();

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
        let test_client_registration_error: ClientRegistrationError = from_slice(&test_body_bytes)?;

        assert_eq!(
            test_client_registration_error.error,
            ClientRegistrationErrorCode::InvalidRedirectUri,
        );
        assert_eq!(
            test_client_registration_error.error_description,
            "some_test_error_description",
        );

        Ok(())
    }

    #[tokio::test]
    async fn client_registration_error_code() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            to_value(&ClientRegistrationErrorCode::InvalidRedirectUri)?,
            "invalid_redirect_uri",
        );
        assert_eq!(
            to_value(&ClientRegistrationErrorCode::InvalidClientMetadata)?,
            "invalid_client_metadata",
        );
        assert_eq!(
            to_value(&ClientRegistrationErrorCode::InvalidSoftwareStatement)?,
            "invalid_software_statement",
        );
        assert_eq!(
            to_value(&ClientRegistrationErrorCode::UnapprovedSoftwareStatement)?,
            "unapproved_software_statement",
        );

        Ok(())
    }
}
