use crate::api::supporting_data_structures::PublicKeyCredentialType;

#[derive(Clone)]
pub struct PublicKeyCredentialSource {
    pub r#type: PublicKeyCredentialType,
    // pub id: String,
    pub id: [u8; 16],
    pub private_key: Vec<u8>,
    pub rpid: String,
    // pub user_handle: String,
    pub user_handle: [u8; 16],
    pub other_ui: String,
}

impl PublicKeyCredentialSource {
    pub async fn generate() -> PublicKeyCredentialSource {
        let r#type = PublicKeyCredentialType::PublicKey;
        // let id = String::from("some_id");
        let id = [0; 16];
        // let private_key = String::from("some_private_key");
        let private_key = Vec::with_capacity(0);
        let rpid = String::from("some_rpid");
        // let user_handle = String::from("some_user_handle");
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
