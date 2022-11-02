use crate::api::supporting_data_structures::{COSEAlgorithmIdentifier, PublicKeyCredentialType};

#[derive(Eq, PartialEq)]
pub struct PublicKeyCredentialParameters {
    pub r#type: PublicKeyCredentialType,
    pub alg: COSEAlgorithmIdentifier,
}
