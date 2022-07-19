use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: AccessTokenType,
    pub expires_in: u16,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum AccessTokenType {
    Bearer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_value;

    #[tokio::test]
    async fn access_token_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_response = AccessTokenResponse {
            access_token: String::from("some_access_token"),
            token_type: AccessTokenType::Bearer,
            expires_in: 3600,
        };

        let test_json = to_value(&test_authorization_response)?;

        assert_eq!(test_json["access_token"], "some_access_token");
        assert_eq!(test_json["token_type"], "Bearer");
        assert_eq!(test_json["expires_in"], 3600);

        Ok(())
    }
}
