use serde::{Deserialize, Serialize};

use crate::api::supporting_data_structures::{COSEAlgorithmIdentifier, PublicKeyCredentialType};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKeyCredentialParameters {
    pub r#type: PublicKeyCredentialType,
    pub alg: COSEAlgorithmIdentifier,
}
