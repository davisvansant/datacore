use serde::Deserialize;

#[derive(Deserialize)]
pub struct AccessTokenRequest {
    pub grant_type: AccessTokenGrantType,
    pub code: String,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenGrantType {
    AuthorizationCode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_value, json};

    #[tokio::test]
    async fn access_token_request() -> Result<(), Box<dyn std::error::Error>> {
        let test_json = json!({
            "grant_type": "authorization_code",
            "code": "some_authorization_code",
        });

        let test_access_token_request: AccessTokenRequest = from_value(test_json)?;

        assert_eq!(
            test_access_token_request.grant_type,
            AccessTokenGrantType::AuthorizationCode,
        );
        assert_eq!(test_access_token_request.code, "some_authorization_code");

        Ok(())
    }
}
