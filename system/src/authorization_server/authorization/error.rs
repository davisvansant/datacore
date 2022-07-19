use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorCode {
    InteractionRequired,
    LoginRequired,
    AccountSelectionRequired,
    ConsentRequired,
    InvalidRequestUri,
    InvalidRequestObject,
    RequestNotSupported,
    RequestUriNotSupported,
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
