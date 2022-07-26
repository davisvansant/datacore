use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Serialize)]
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
            .status(400)
            .body(Body::from(json))
            .expect("client registration error response");

        response.into_response()
    }
}

#[derive(Serialize)]
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
    use serde_json::to_value;

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
