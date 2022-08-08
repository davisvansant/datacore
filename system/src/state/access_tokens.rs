use std::collections::HashMap;

pub struct AccessTokens {
    issued: HashMap<String, String>,
    expired: HashMap<String, String>,
}

impl AccessTokens {
    pub async fn init() -> AccessTokens {
        let capacity = 50;
        let issued = HashMap::with_capacity(capacity);
        let expired = HashMap::with_capacity(capacity);

        AccessTokens { issued, expired }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_access_tokens = AccessTokens::init().await;

        assert!(test_access_tokens.issued.is_empty());
        assert!(test_access_tokens.expired.is_empty());

        Ok(())
    }
}
