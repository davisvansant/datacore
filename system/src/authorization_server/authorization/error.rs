use serde::Serialize;

#[derive(Serialize)]
pub enum AuthorizationErrorCode {
    #[serde(rename = "interaction_required")]
    InteractionRequired,
    #[serde(rename = "login_required")]
    LoginRequired,
    #[serde(rename = "account_selection_required")]
    AccountSelectionRequired,
    #[serde(rename = "consent_required")]
    ConsentRequired,
    #[serde(rename = "invalid_request_uri")]
    InvalidRequestUri,
    #[serde(rename = "invalid_request_object")]
    InvalidRequestObject,
    #[serde(rename = "request_not_supported")]
    RequestNotSupported,
    #[serde(rename = "request_uri_not_supported")]
    RequestUriNotSupported,
    #[serde(rename = "registration_not_supported")]
    RegistrationNotSupported,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_value;

    #[tokio::test]
    async fn authorization_error_code() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            to_value(&AuthorizationErrorCode::InteractionRequired)?,
            "interaction_required",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::LoginRequired)?,
            "login_required",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::AccountSelectionRequired)?,
            "account_selection_required",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::ConsentRequired)?,
            "consent_required",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::InvalidRequestUri)?,
            "invalid_request_uri",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::InvalidRequestObject)?,
            "invalid_request_object",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::RequestNotSupported)?,
            "request_not_supported",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::RequestUriNotSupported)?,
            "request_uri_not_supported",
        );
        assert_eq!(
            to_value(&AuthorizationErrorCode::RegistrationNotSupported)?,
            "registration_not_supported",
        );

        Ok(())
    }
}
