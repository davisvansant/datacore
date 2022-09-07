use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct AuthorizationResponse {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl AuthorizationResponse {
    pub async fn query(&self) -> String {
        let mut query = String::with_capacity(100);

        if self.state.is_some() {
            query.push_str("code=");
            query.push_str(self.code.as_str());
            query.push('&');
            query.push_str("state=");
            query.push_str(self.state.as_ref().unwrap().as_str());
        } else {
            query.push_str("code=");
            query.push_str(self.code.as_str());
        }

        query.shrink_to_fit();

        query
    }
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
    #[tokio::test]
    async fn authorization_response_query() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_response = AuthorizationResponse {
            code: String::from("some_test_code"),
            state: None,
        };

        assert_eq!(
            test_authorization_response.query().await,
            "code=some_test_code",
        );

        let test_authorization_response_state = AuthorizationResponse {
            code: String::from("some_test_code"),
            state: Some(String::from("some_test_state")),
        };

        assert_eq!(
            test_authorization_response_state.query().await,
            "code=some_test_code&state=some_test_state",
        );

        Ok(())
    }
}
