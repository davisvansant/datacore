use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizationRequest {
    pub response_type: AuthorizationResponseType,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationResponseType {
    Code,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_value, json};

    #[tokio::test]
    async fn authorization_request() -> Result<(), Box<dyn std::error::Error>> {
        let test_json = json!({
            "response_type": "code",
            "client_id": "some_client_id",
        });

        let test_authorization_request: AuthorizationRequest = from_value(test_json)?;

        assert_eq!(
            test_authorization_request.response_type,
            AuthorizationResponseType::Code,
        );
        assert_eq!(test_authorization_request.client_id, "some_client_id");

        Ok(())
    }
}
