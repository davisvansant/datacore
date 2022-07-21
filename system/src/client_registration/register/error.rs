use serde::Serialize;

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
