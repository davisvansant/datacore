use serde::{Deserialize, Serialize};

use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientInputs;
use crate::api::supporting_data_structures::{
    PublicKeyCredentialDescriptor, UserVerificationRequirement,
};
use crate::security::challenge::{base64_encode_challenge, generate_challenge};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

impl PublicKeyCredentialRequestOptions {
    pub async fn generate(rp_id: Option<&str>) -> PublicKeyCredentialRequestOptions {
        let challenge = base64_encode_challenge(&generate_challenge().await)
            .await
            .as_bytes()
            .to_vec();
        let timeout = 300000;

        PublicKeyCredentialRequestOptions {
            challenge,
            timeout: Some(timeout),
            rp_id: rp_id.map_or_else(|| None, |rp_id| Some(rp_id.to_string())),
            allow_credentials: Some(Vec::with_capacity(5)),
            user_verification: Some(UserVerificationRequirement::Preferred),
            extensions: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn public_key_credential_request_options() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_request_options =
            PublicKeyCredentialRequestOptions::generate(Some("test_rp_id")).await;

        assert!(test_request_options.challenge.len() >= 16);
        assert_eq!(test_request_options.timeout, Some(300000));
        assert_eq!(test_request_options.rp_id, Some(String::from("test_rp_id")));
        assert_eq!(
            test_request_options
                .allow_credentials
                .as_ref()
                .map(|credentials| credentials.len()),
            Some(0),
        );
        assert_eq!(
            test_request_options.user_verification,
            Some(UserVerificationRequirement::Preferred),
        );
        assert!(test_request_options.extensions.is_none());

        test_request_options.challenge = [0; 16].to_vec();

        let test_request_options_json = r#"{"challenge":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"timeout":300000,"rp_id":"test_rp_id","allow_credentials":[],"user_verification":"preferred"}"#;
        let test_assertion_json = serde_json::to_string(&test_request_options)?;

        assert_eq!(test_request_options_json, test_assertion_json);

        Ok(())
    }
}
