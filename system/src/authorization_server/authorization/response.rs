use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct AuthorizationResponse {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_value;

    #[tokio::test]
    async fn authorization_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_response = AuthorizationResponse {
            code: String::from("some_test_code"),
            state: None,
        };

        let test_json = to_value(&test_authorization_response)?;

        assert_eq!(test_json["code"], "some_test_code");

        Ok(())
    }
}
