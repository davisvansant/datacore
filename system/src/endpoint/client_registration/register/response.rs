use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientInformation {
    pub client_id: String,
    pub client_secret: String,
    pub client_id_issued_at: String,
    pub client_secret_expires_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_value;

    #[tokio::test]
    async fn client_information() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_information = ClientInformation {
            client_id: String::from("some_test_client_id"),
            client_secret: String::from("some_test_client_secret"),
            client_id_issued_at: String::from("some_test_client_id_issued_at"),
            client_secret_expires_at: String::from("some_test_client_secret_expires_at"),
        };

        let test_json = to_value(&test_client_information)?;

        assert_eq!(test_json["client_id"], "some_test_client_id");
        assert_eq!(test_json["client_secret"], "some_test_client_secret");
        assert_eq!(
            test_json["client_id_issued_at"],
            "some_test_client_id_issued_at",
        );
        assert_eq!(
            test_json["client_secret_expires_at"],
            "some_test_client_secret_expires_at",
        );

        Ok(())
    }
}
