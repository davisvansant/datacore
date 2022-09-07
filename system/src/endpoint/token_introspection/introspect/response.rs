use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value};

    #[tokio::test]
    async fn introspection_response() -> Result<(), Box<dyn std::error::Error>> {
        let test_introspection_response_none = IntrospectionResponse {
            active: true,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        };

        let test_json_none = to_value(&test_introspection_response_none)?;
        let test_expected_json_none = json!({
            "active": true,
        });

        assert_eq!(test_json_none, test_expected_json_none);

        let test_introspection_response_some = IntrospectionResponse {
            active: true,
            scope: Some(String::from("test_scope")),
            client_id: Some(String::from("test_client_id")),
            username: Some(String::from("test_username")),
            token_type: Some(String::from("test_token_type")),
            exp: Some(String::from("test_exp")),
            iat: Some(String::from("test_iat")),
            nbf: Some(String::from("test_nbf")),
            sub: Some(String::from("test_sub")),
            aud: Some(String::from("test_aud")),
            iss: Some(String::from("test_iss")),
            jti: Some(String::from("test_jti")),
        };

        let test_json_some = to_value(&test_introspection_response_some)?;
        let test_expected_json_some = json!({
            "active": true,
            "scope": "test_scope",
            "client_id": "test_client_id",
            "username": "test_username",
            "token_type": "test_token_type",
            "exp": "test_exp",
            "iat": "test_iat",
            "nbf": "test_nbf",
            "sub": "test_sub",
            "aud": "test_aud",
            "iss": "test_iss",
            "jti": "test_jti",
        });

        assert_eq!(test_json_some, test_expected_json_some);

        Ok(())
    }
}
