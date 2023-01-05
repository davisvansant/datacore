use serde::{Deserialize, Serialize};

use crate::api::credential_generation_parameters::PublicKeyCredentialParameters;
use crate::api::extensions_inputs_and_outputs::AuthenticationExtensionsClientInputs;
use crate::api::supporting_data_structures::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialType, UserVerificationRequirement,
};
use crate::security::challenge::{base64_encode_challenge, generate_challenge};
use crate::security::uuid::{generate_user_handle, UserHandle};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: Vec<u8>,
    pub public_key_credential_parameters: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

impl PublicKeyCredentialCreationOptions {
    pub async fn generate(
        rp: PublicKeyCredentialRpEntity,
        user: PublicKeyCredentialUserEntity,
    ) -> PublicKeyCredentialCreationOptions {
        let challenge = base64_encode_challenge(&generate_challenge().await)
            .await
            .as_bytes()
            .to_vec();

        let mut public_key_credential_parameters = Vec::with_capacity(3);
        let eddsa = PublicKeyCredentialParameters {
            r#type: PublicKeyCredentialType::PublicKey,
            alg: -8,
        };
        let es256 = PublicKeyCredentialParameters {
            r#type: PublicKeyCredentialType::PublicKey,
            alg: -7,
        };

        public_key_credential_parameters.push(eddsa);
        public_key_credential_parameters.push(es256);

        let authenticator_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: AuthenticatorAttachment::CrossPlatform,
            resident_key: ResidentKeyRequirement::Preferred,
            require_resident_key: false,
            user_verification: UserVerificationRequirement::Preferred,
        };

        PublicKeyCredentialCreationOptions {
            rp,
            user,
            challenge,
            public_key_credential_parameters,
            timeout: Some(300000),
            exclude_credentials: None,
            authenticator_selection: Some(authenticator_selection),
            attestation: Some(AttestationConveyancePreference::Indirect),
            extensions: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKeyCredentialUserEntity {
    pub name: String,
    pub id: UserHandle,
    pub display_name: String,
}

impl PublicKeyCredentialUserEntity {
    pub async fn generate(name: String, display_name: String) -> PublicKeyCredentialUserEntity {
        let id = generate_user_handle().await;

        PublicKeyCredentialUserEntity {
            name,
            id,
            display_name,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: AuthenticatorAttachment,
    pub resident_key: ResidentKeyRequirement,
    pub require_resident_key: bool,
    pub user_verification: UserVerificationRequirement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthenticatorAttachment {
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ResidentKeyRequirement {
    #[serde(rename = "discouraged")]
    Discouraged,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "required")]
    Required,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AttestationConveyancePreference {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "indirect")]
    Indirect,
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "enterprise")]
    Enterprise,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn public_key_credential_creation_options() -> Result<(), Box<dyn std::error::Error>> {
        let test_rp_entity = PublicKeyCredentialRpEntity {
            name: String::from("some_rp_name"),
            id: String::from("some_rp_entity_id"),
        };
        let test_user_entity = PublicKeyCredentialUserEntity::generate(
            String::from("some_user_name"),
            String::from("some_display_name"),
        )
        .await;
        let mut test_creation_options =
            PublicKeyCredentialCreationOptions::generate(test_rp_entity, test_user_entity).await;

        assert_eq!(test_creation_options.rp.id, "some_rp_entity_id");
        assert_eq!(test_creation_options.user.name, "some_user_name");
        assert_eq!(test_creation_options.user.display_name, "some_display_name");
        assert!(test_creation_options.challenge.len() >= 16);
        assert_eq!(
            test_creation_options.public_key_credential_parameters.len(),
            2,
        );
        assert_eq!(
            test_creation_options.public_key_credential_parameters[0].r#type,
            PublicKeyCredentialType::PublicKey,
        );
        assert_eq!(
            test_creation_options.public_key_credential_parameters[0].alg,
            -8,
        );
        assert_eq!(
            test_creation_options.public_key_credential_parameters[1].r#type,
            PublicKeyCredentialType::PublicKey,
        );
        assert_eq!(
            test_creation_options.public_key_credential_parameters[1].alg,
            -7,
        );

        assert!(test_creation_options.timeout.is_some());
        assert_eq!(test_creation_options.timeout.unwrap(), 300000);
        assert!(test_creation_options.exclude_credentials.is_none());
        assert!(test_creation_options.authenticator_selection.is_some());
        assert_eq!(
            test_creation_options
                .authenticator_selection
                .as_ref()
                .unwrap()
                .authenticator_attachment,
            AuthenticatorAttachment::CrossPlatform,
        );
        assert_eq!(
            test_creation_options
                .authenticator_selection
                .as_ref()
                .unwrap()
                .resident_key,
            ResidentKeyRequirement::Preferred,
        );
        assert!(
            !test_creation_options
                .authenticator_selection
                .as_ref()
                .unwrap()
                .require_resident_key,
        );
        assert_eq!(
            test_creation_options
                .authenticator_selection
                .as_ref()
                .unwrap()
                .user_verification,
            UserVerificationRequirement::Preferred,
        );
        assert!(test_creation_options.attestation.is_some());
        assert_eq!(
            test_creation_options.attestation.as_ref().unwrap(),
            &AttestationConveyancePreference::Indirect,
        );
        assert!(test_creation_options.extensions.is_none());

        test_creation_options.user.id = [0; 16].to_vec();
        test_creation_options.challenge = [0; 16].to_vec();

        let test_options_json = r#"{"rp":{"name":"some_rp_name","id":"some_rp_entity_id"},"user":{"name":"some_user_name","id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"display_name":"some_display_name"},"challenge":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"public_key_credential_parameters":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7}],"timeout":300000,"authenticator_selection":{"authenticator_attachment":"cross-platform","resident_key":"preferred","require_resident_key":false,"user_verification":"preferred"},"attestation":"indirect"}"#;
        let test_assertion_json = serde_json::to_string(&test_creation_options)?;

        assert_eq!(test_options_json, test_assertion_json);

        Ok(())
    }

    #[tokio::test]
    async fn public_key_credential_user_entity() -> Result<(), Box<dyn std::error::Error>> {
        let test_name = String::from("some_name");
        let test_display_name = String::from("some_display_name");
        let mut test_public_key_credential_user_entity =
            PublicKeyCredentialUserEntity::generate(test_name, test_display_name).await;

        assert_eq!(test_public_key_credential_user_entity.name, "some_name");
        assert!(test_public_key_credential_user_entity.id.len() >= 16);
        assert_eq!(
            test_public_key_credential_user_entity.display_name,
            "some_display_name",
        );

        test_public_key_credential_user_entity.id = Uuid::nil().into_bytes().to_vec();

        let test_user_entity_json = b"{\"name\":\"some_name\",\"id\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"display_name\":\"some_display_name\"}".to_vec();
        let test_assertion_json = serde_json::to_vec(&test_public_key_credential_user_entity)?;
        let test_assertion_user_entity: PublicKeyCredentialUserEntity =
            serde_json::from_slice(&test_user_entity_json)?;

        assert_eq!(test_user_entity_json, test_assertion_json);
        assert_eq!(
            test_assertion_user_entity,
            test_public_key_credential_user_entity,
        );

        Ok(())
    }
}
