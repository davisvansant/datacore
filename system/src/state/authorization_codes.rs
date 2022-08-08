use std::collections::HashMap;

pub struct AuthorizationCodes {
    issued: HashMap<String, String>,
    expired: HashMap<String, String>,
}

impl AuthorizationCodes {
    pub async fn init() -> AuthorizationCodes {
        let capacity = 50;
        let issued = HashMap::with_capacity(capacity);
        let expired = HashMap::with_capacity(capacity);

        AuthorizationCodes { issued, expired }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_authorization_codes = AuthorizationCodes::init().await;

        assert!(test_authorization_codes.issued.is_empty());
        assert!(test_authorization_codes.expired.is_empty());

        Ok(())
    }
}
