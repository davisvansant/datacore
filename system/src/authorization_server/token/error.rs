use serde::Serialize;

#[derive(Serialize)]
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
    use serde_json::to_value;

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
