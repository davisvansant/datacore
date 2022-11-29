use crate::api::supporting_data_structures::PublicKeyCredentialType;
use crate::authenticator::attestation::{COSEAlgorithm, COSEKey};

#[derive(Clone, Debug)]
pub struct PublicKeyCredentialSource {
    pub r#type: PublicKeyCredentialType,
    pub id: [u8; 16],
    // pub private_key: Vec<u8>,
    pub private_key: COSEKey,
    pub rpid: String,
    pub user_handle: [u8; 16],
    pub other_ui: String,
}

impl PublicKeyCredentialSource {
    pub async fn generate() -> PublicKeyCredentialSource {
        let r#type = PublicKeyCredentialType::PublicKey;
        let id = [0; 16];
        // let private_key = Vec::with_capacity(0);
        let private_key = COSEKey::generate(COSEAlgorithm::EdDSA).await.1;
        let rpid = String::from("some_rpid");
        let user_handle = [0; 16];
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
