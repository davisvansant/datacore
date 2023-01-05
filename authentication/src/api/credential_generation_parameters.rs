use serde::{Deserialize, Serialize};

use crate::api::supporting_data_structures::{COSEAlgorithmIdentifier, PublicKeyCredentialType};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKeyCredentialParameters {
    pub r#type: PublicKeyCredentialType,
    pub alg: COSEAlgorithmIdentifier,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn to_json() -> Result<(), Box<dyn std::error::Error>> {
        let test_parameters = PublicKeyCredentialParameters {
            r#type: PublicKeyCredentialType::PublicKey,
            alg: -8,
        };

        assert!(serde_json::to_string(&test_parameters).is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn from_json() -> Result<(), Box<dyn std::error::Error>> {
        let test_json = r#"
            {
                "type": "public-key",
                "alg": -8
            }
        "#
        .as_bytes();

        let test_parameters: PublicKeyCredentialParameters = serde_json::from_slice(test_json)?;

        assert_eq!(test_parameters.r#type, PublicKeyCredentialType::PublicKey);
        assert_eq!(test_parameters.alg, -8);

        let test_json = r#"
            {
                "type": "publickey",
                "alg": "-8"
            }
        "#
        .as_bytes();

        assert!(serde_json::from_slice::<PublicKeyCredentialParameters>(test_json).is_err());

        Ok(())
    }
}
