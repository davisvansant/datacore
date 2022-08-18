use crate::authorization_server::token::error::{AccessTokenError, AccessTokenErrorCode};

pub struct IntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

impl IntrospectionRequest {
    pub async fn init(bytes: &[u8]) -> Result<IntrospectionRequest, AccessTokenError> {
        let body_parameters = match std::str::from_utf8(bytes) {
            Ok(body_parameters) => body_parameters,
            Err(error) => {
                let access_token_error = AccessTokenError {
                    error: AccessTokenErrorCode::InvalidRequest,
                    error_description: Some(error.to_string()),
                    error_uri: None,
                };

                return Err(access_token_error);
            }
        };

        let token = match body_parameters
            .split('&')
            .find(|key| key.starts_with("token="))
        {
            None => {
                let access_token_error = AccessTokenError {
                    error: AccessTokenErrorCode::InvalidRequest,
                    error_description: None,
                    error_uri: None,
                };

                return Err(access_token_error);
            }
            Some(token_key_value) => match token_key_value.strip_prefix("token=") {
                None => {
                    let access_token_error = AccessTokenError {
                        error: AccessTokenErrorCode::InvalidRequest,
                        error_description: None,
                        error_uri: None,
                    };

                    return Err(access_token_error);
                }
                Some(token_value) => token_value.to_owned(),
            },
        };

        let token_type_hint = body_parameters
            .split('&')
            .find(|key| key.starts_with("token_type_hint="))
            .map(|token_type_hint| {
                token_type_hint
                    .strip_prefix("token_type_hint=")
                    .expect("token type hint value")
                    .to_owned()
            });

        Ok(IntrospectionRequest {
            token,
            token_type_hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn introspection_request() -> Result<(), AccessTokenError> {
        let test_string_none = b"token=some_test_token";
        let test_introspection_request_none = IntrospectionRequest::init(test_string_none).await?;

        assert_eq!(test_introspection_request_none.token, "some_test_token");
        assert!(test_introspection_request_none.token_type_hint.is_none());

        let test_string_some = b"token=some_test_token&token_type_hint=some_test_token_type_hint";
        let test_introspection_request_some = IntrospectionRequest::init(test_string_some).await?;

        assert_eq!(test_introspection_request_some.token, "some_test_token");
        assert_eq!(
            test_introspection_request_some.token_type_hint.unwrap(),
            "some_test_token_type_hint",
        );

        let test_string_token_error = b"another_token=some_test_token";
        let test_introspection_request_token_error =
            IntrospectionRequest::init(test_string_token_error).await;

        assert!(test_introspection_request_token_error.is_err());

        let test_string_token_missing = b"token_type_hint=some_test_token_type_hint";
        let test_introspection_request_token_missing_error =
            IntrospectionRequest::init(test_string_token_missing).await;

        assert!(test_introspection_request_token_missing_error.is_err());

        let test_string_hint_error =
            b"token=some_test_token&invalid_token_type_hint=some_test_token_type_hint";
        let test_introspection_request_hint_error =
            IntrospectionRequest::init(test_string_hint_error).await?;

        assert!(test_introspection_request_hint_error
            .token_type_hint
            .is_none());

        Ok(())
    }
}
