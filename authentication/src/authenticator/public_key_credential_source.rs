use crate::api::supporting_data_structures::PublicKeyCredentialType;
use crate::authenticator::attestation::{COSEAlgorithm, COSEKey};
use crate::security::uuid::{
    generate_credential_id, generate_user_handle, CredentialId, UserHandle,
};

#[derive(Clone, Debug)]
pub struct PublicKeyCredentialSource {
    pub r#type: PublicKeyCredentialType,
    pub id: CredentialId,
    pub private_key: COSEKey,
    pub rpid: String,
    pub user_handle: UserHandle,
    pub other_ui: String,
}

impl PublicKeyCredentialSource {
    pub async fn generate() -> PublicKeyCredentialSource {
        let r#type = PublicKeyCredentialType::PublicKey;
        let id = generate_credential_id().await;
        let private_key = COSEKey::generate(COSEAlgorithm::EdDSA).await.1;
        let rpid = String::from("some_rpid");
        let user_handle = generate_user_handle().await;
        let other_ui = String::from("some_other_ui");

        PublicKeyCredentialSource {
            r#type,
            id,
            private_key,
            rpid,
            user_handle,
            other_ui,
        }
    }
}
