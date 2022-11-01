use crate::api::supporting_data_structures::PublicKeyCredentialType;

#[derive(Eq, PartialEq)]
pub struct PublicKeyCredentialParameters {
    pub r#type: PublicKeyCredentialType,
    pub algorithm: i32,
}
