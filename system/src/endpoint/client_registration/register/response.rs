use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientInformation {
    pub client_id: String,
    pub client_secret: String,
    pub client_id_issued_at: String,
    pub client_secret_expires_at: String,
}

impl ClientInformation {
    pub async fn build() -> ClientInformation {
        let client_id = Uuid::new_v4().simple();

        ClientInformation {
            client_id: client_id.to_string(),
            client_secret: String::from("some_client_secret"),
            client_id_issued_at: String::from("some_client_id_issued_at"),
            client_secret_expires_at: String::from("some_client_secret_expires_at"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_value;
    use std::str::FromStr;

    #[tokio::test]
    async fn client_information() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_information = ClientInformation {
            client_id: String::from("some_test_client_id"),
            client_secret: String::from("some_test_client_secret"),
            client_id_issued_at: String::from("some_test_client_id_issued_at"),
            client_secret_expires_at: String::from("some_test_client_secret_expires_at"),
        };

        let test_json = to_value(test_client_information)?;

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

    #[tokio::test]
    async fn build() -> Result<(), Box<dyn std::error::Error>> {
        let test_client_information = ClientInformation::build().await;
        let test_client_id = Uuid::from_str(&test_client_information.client_id)?;

        assert_eq!(test_client_id.get_version(), Some(uuid::Version::Random));
        assert_eq!(test_client_id.simple().to_string().len(), 32);

        Ok(())
    }
}
