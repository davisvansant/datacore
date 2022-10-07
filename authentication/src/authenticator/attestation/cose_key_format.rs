use serde::{Deserialize, Serialize};

use crate::api::supporting_data_structures::COSEAlgorithmIdentifier;

#[derive(Deserialize, Clone, Serialize)]
pub struct COSEKey {
    pub kty: KeyType,
    pub kid: String,
    pub alg: COSEAlgorithmIdentifier,
    pub key_ops: Vec<KeyOperation>,
    pub base_iv: Option<String>,
}

impl COSEKey {
    pub async fn generate(algorithm: COSEAlgorithm) -> COSEKey {
        let mut key_ops = Vec::with_capacity(10);

        match algorithm {
            COSEAlgorithm::EdDSA => COSEKey {
                kty: KeyType::OKP,
                kid: String::from("some_key_id"),
                alg: COSEAlgorithm::EdDSA.identifier().await,
                key_ops: {
                    key_ops.push(KeyOperation::Sign);
                    key_ops.push(KeyOperation::Verify);

                    key_ops
                },
                base_iv: None,
            },
            COSEAlgorithm::ES256 => unimplemented!(),
        }
    }
}

#[derive(Deserialize, Clone, Serialize)]
pub enum KeyType {
    OKP = 1,
    EC2 = 2,
    Symmetric = 4,
}

#[derive(Deserialize, Clone, PartialEq, Serialize)]
pub enum COSEAlgorithm {
    EdDSA,
    ES256,
}

impl COSEAlgorithm {
    pub async fn identifier(&self) -> COSEAlgorithmIdentifier {
        match self {
            COSEAlgorithm::EdDSA => -8,
            COSEAlgorithm::ES256 => -7,
        }
    }
}

#[derive(Deserialize, Clone, Serialize)]
pub enum EllipticCurve {
    Ed25519 = 6,
}

#[derive(Deserialize, Clone, Serialize)]
pub enum KeyOperation {
    Sign = 1,
    Verify = 2,
    Encrypt = 3,
    Decrypt = 4,
    WrapKey = 5,
    UnwrapKey = 6,
    DeriveKey = 7,
    DeriveBits = 8,
    MACCreate = 9,
    MACVerify = 10,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct OctetKeyPair {
    crv: EllipticCurve,
    x: [u8; 32],
    d: [u8; 32],
}
