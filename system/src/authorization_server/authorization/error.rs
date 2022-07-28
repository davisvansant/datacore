// use serde::Serialize;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::status::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::to_value;

#[derive(Serialize)]
pub struct AuthorizationError {
    pub error: AuthorizationErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl IntoResponse for AuthorizationError {
    fn into_response(self) -> Response {
        let mut location_value = String::with_capacity(100);
        let authorization_error = to_value(self).expect("authorization error as json value");

        if let Some(error) = authorization_error["error"].as_str() {
            location_value.push_str("error=");
            location_value.push_str(error);
        }

        if let Some(error_description) = authorization_error["error_description"].as_str() {
            location_value.push_str("&");
            location_value.push_str("error_description=");
            location_value.push_str(error_description);
        }

        if let Some(error_uri) = authorization_error["error_uri"].as_str() {
            location_value.push_str("&");
            location_value.push_str("error_uri=");
            location_value.push_str(error_uri);
        }

        location_value.shrink_to_fit();

        let response = Response::builder()
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(LOCATION, location_value)
            .status(StatusCode::FOUND)
            .body(Body::empty())
            .expect("access token error response");

        response.into_response()
    }
}

// #[derive(Serialize)]
// #[serde(rename_all = "snake_case")]
// pub enum AuthorizationErrorCode {
//     InteractionRequired,
//     LoginRequired,
//     AccountSelectionRequired,
//     ConsentRequired,
//     InvalidRequestUri,
//     InvalidRequestObject,
//     RequestNotSupported,
//     RequestUriNotSupported,
//     RegistrationNotSupported,
// }
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorCode {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::to_bytes;
    use serde_json::to_value;

    #[tokio::test]
    async fn authorization_error_into_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_error = AuthorizationError {
            error: AuthorizationErrorCode::InvalidRequest,
            error_description: None,
            error_uri: None,
        };

        let test_response = test_authorization_error.into_response();

        assert!(test_response.headers().contains_key(CONTENT_TYPE));
        assert!(test_response.headers().contains_key(LOCATION));
        assert_eq!(
            test_response.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(
            test_response.headers().get(LOCATION).unwrap(),
            "error=invalid_request",
        );
        assert_eq!(test_response.status(), StatusCode::FOUND);

        let test_body_bytes = to_bytes(&mut test_response.into_body()).await?;

        assert!(test_body_bytes.is_empty());

        let test_authorization_error_description = AuthorizationError {
            error: AuthorizationErrorCode::InvalidRequest,
            error_description: Some(String::from("some_test_error_description")),
            error_uri: None,
        };

        let test_response = test_authorization_error_description.into_response();

        assert!(test_response.headers().contains_key(CONTENT_TYPE));
        assert!(test_response.headers().contains_key(LOCATION));
        assert_eq!(
            test_response.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(
            test_response.headers().get(LOCATION).unwrap(),
            "error=invalid_request&error_description=some_test_error_description",
        );
        assert_eq!(test_response.status(), StatusCode::FOUND);

        let test_body_bytes = to_bytes(&mut test_response.into_body()).await?;

        assert!(test_body_bytes.is_empty());

        // Ok(())

        let test_authorization_error_uri = AuthorizationError {
            error: AuthorizationErrorCode::InvalidRequest,
            error_description: None,
            error_uri: Some(String::from("some_test_error_uri")),
        };

        let test_response = test_authorization_error_uri.into_response();

        assert!(test_response.headers().contains_key(CONTENT_TYPE));
        assert!(test_response.headers().contains_key(LOCATION));
        assert_eq!(
            test_response.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(
            test_response.headers().get(LOCATION).unwrap(),
            "error=invalid_request&error_uri=some_test_error_uri",
        );
        assert_eq!(test_response.status(), StatusCode::FOUND);

        let test_body_bytes = to_bytes(&mut test_response.into_body()).await?;

        assert!(test_body_bytes.is_empty());

        let test_authorization_error_description_and_uri = AuthorizationError {
            error: AuthorizationErrorCode::InvalidRequest,
            error_description: Some(String::from("some_test_error_description")),
            error_uri: Some(String::from("some_test_error_uri")),
        };

        let test_response = test_authorization_error_description_and_uri.into_response();

        assert!(test_response.headers().contains_key(CONTENT_TYPE));
        assert!(test_response.headers().contains_key(LOCATION));
        assert_eq!(
            test_response.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded",
        );
        assert_eq!(
            test_response.headers().get(LOCATION).unwrap(),
            "error=invalid_request&error_description=some_test_error_description&error_uri=some_test_error_uri",
        );
        assert_eq!(test_response.status(), StatusCode::FOUND);

        let test_body_bytes = to_bytes(&mut test_response.into_body()).await?;

        assert!(test_body_bytes.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn authorization_error_code() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            to_value(&AuthorizationErrorCode::InvalidRequest)?,
            "invalid_request",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::UnauthorizedClient)?,
            "unauthorized_client",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::AccessDenied)?,
            "access_denied",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::UnsupportedResponseType)?,
            "unsupported_response_type",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::InvalidScope)?,
            "invalid_scope",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::ServerError)?,
            "server_error",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::TemporarilyUnavailable)?,
            "temporarily_unavailable",
        );

        Ok(())
    }

    // #[tokio::test]
    // async fn authorization_error_code() -> Result<(), Box<dyn std::error::Error>> {
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::InteractionRequired)?,
    //         "interaction_required",
    //     );
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::LoginRequired)?,
    //         "login_required",
    //     );
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::AccountSelectionRequired)?,
    //         "account_selection_required",
    //     );
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::ConsentRequired)?,
    //         "consent_required",
    //     );
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::InvalidRequestUri)?,
    //         "invalid_request_uri",
    //     );
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::InvalidRequestObject)?,
    //         "invalid_request_object",
    //     );
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::RequestNotSupported)?,
    //         "request_not_supported",
    //     );
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::RequestUriNotSupported)?,
    //         "request_uri_not_supported",
    //     );
    //     assert_eq!(
    //         to_value(&AuthorizationErrorCode::RegistrationNotSupported)?,
    //         "registration_not_supported",
    //     );

    //     Ok(())
    // }
}
