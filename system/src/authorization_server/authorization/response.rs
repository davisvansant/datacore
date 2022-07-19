use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct AuthorizationResponse {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl AuthorizationResponse {
    pub async fn url(&self) -> String {
        let mut url = String::with_capacity(100);

        if self.state.is_some() {
            url.push_str("code=");
            url.push_str(self.code.as_str());
            url.push('&');
            url.push_str("state=");
            url.push_str(self.state.as_ref().unwrap().as_str());
        } else {
            url.push_str("code=");
            url.push_str(self.code.as_str());
        }

        url.shrink_to_fit();

        url
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
    async fn authorization_response_url() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_response = AuthorizationResponse {
            code: String::from("some_test_code"),
            state: None,
        };

        assert_eq!(
            test_authorization_response.url().await,
            "code=some_test_code",
        );

        let test_authorization_response_state = AuthorizationResponse {
            code: String::from("some_test_code"),
            state: Some(String::from("some_test_state")),
        };

        assert_eq!(
            test_authorization_response_state.url().await,
            "code=some_test_code&state=some_test_state",
        );

        Ok(())
    }
}
