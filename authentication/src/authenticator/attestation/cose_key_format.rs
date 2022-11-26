use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey, Signature};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::api::supporting_data_structures::COSEAlgorithmIdentifier;
use crate::authenticator::data::AuthenticatorData;
use crate::error::{AuthenticationError, AuthenticationErrorType};

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum COSEKey {
    OctetKeyPair(OctetKeyPair),
}

impl COSEKey {
    pub async fn generate(algorithm: COSEAlgorithm) -> (COSEKey, ExpandedSecretKey) {
        match algorithm {
            COSEAlgorithm::EdDSA => {
                let mut csprng = ChaCha20Rng::from_entropy();
                let keypair = Keypair::generate(&mut csprng);

                (
                    COSEKey::OctetKeyPair(OctetKeyPair {
                        kty: COSEKeyType::Okp,
                        alg: COSEAlgorithm::EdDSA,
                        key_ops: None,
                        crv: COSEEllipticCurve::Ed25519,
                        x: Some(keypair.public.to_bytes()),
                        d: None,
                    }),
                    ExpandedSecretKey::from(&keypair.secret),
                )
            }
            COSEAlgorithm::ES256 => unimplemented!(),
        }
    }

    pub async fn algorithm(&self) -> COSEAlgorithmIdentifier {
        match self {
            COSEKey::OctetKeyPair(parameters) => parameters.alg.identifier().await,
        }
    }

    pub async fn public_key(&self) -> [u8; 32] {
        match self {
            COSEKey::OctetKeyPair(parameters) => match parameters.x {
                Some(x) => x,
                None => panic!("add better error handling here"),
            },
        }
    }

    pub async fn verify_signature(
        &self,
        signature: &[u8],
        authenticator_data: &AuthenticatorData,
        hash: &[u8],
    ) -> Result<(), AuthenticationError> {
        match self {
            COSEKey::OctetKeyPair(_) => {
                let public_key_bytes = self.public_key().await;

                if let Ok(public_key) = PublicKey::from_bytes(&public_key_bytes) {
                    let signature =
                        Signature::from_bytes(signature).expect("signature::from_bytes failed");

                    let serialized_authenticator_data =
                        bincode::serialize(authenticator_data).expect("serialized_data");

                    let mut concatenation = Vec::with_capacity(500);

                    for element in serialized_authenticator_data {
                        concatenation.push(element.to_owned());
                    }

                    for element in hash {
                        concatenation.push(element.to_owned());
                    }

                    concatenation.shrink_to_fit();

                    match public_key.verify_strict(concatenation.as_slice(), &signature) {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            println!("error -> {:?}", error);

                            Err(AuthenticationError {
                                error: AuthenticationErrorType::OperationError,
                            })
                        }
                    }
                } else {
                    Err(AuthenticationError {
                        error: AuthenticationErrorType::OperationError,
                    })
                }
            }
        }
    }
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Serialize)]
pub enum COSEEllipticCurve {
    #[serde(rename = "6")]
    Ed25519,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Serialize)]
pub enum COSEAlgorithm {
    #[serde(rename = "-8")]
    EdDSA,
    #[serde(rename = "-7")]
    ES256,
}

impl COSEAlgorithm {
    pub async fn identifier(&self) -> COSEAlgorithmIdentifier {
        match self {
            COSEAlgorithm::EdDSA => -8,
            COSEAlgorithm::ES256 => -7,
        }
    }

    pub async fn from(identifier: COSEAlgorithmIdentifier) -> COSEAlgorithm {
        match identifier {
            -8 => COSEAlgorithm::EdDSA,
            -7 => COSEAlgorithm::ES256,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct OctetKeyPair {
    #[serde(rename = "1")]
    pub kty: COSEKeyType,
    #[serde(rename = "3")]
    pub alg: COSEAlgorithm,
    #[serde(rename = "4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<COSEKeyOperation>>,
    #[serde(rename = "-1")]
    pub crv: COSEEllipticCurve,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "-2")]
    pub x: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "-4")]
    pub d: Option<[u8; 32]>,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Serialize)]
pub enum COSEKeyType {
    #[serde(rename = "1")]
    Okp,
    Ec2,
    Symmetric,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub enum COSEKeyOperation {
    #[serde(rename = "1")]
    Sign,
    #[serde(rename = "2")]
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
    MACCreate,
    MACVerify,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::cbor;

    #[tokio::test]
    async fn octet_key_pair() -> Result<(), Box<dyn std::error::Error>> {
        let mut test_csprng = ChaCha20Rng::from_entropy();
        let test_keypair = Keypair::generate(&mut test_csprng);

        let test_cose_key = COSEKey::OctetKeyPair(OctetKeyPair {
            kty: COSEKeyType::Okp,
            alg: COSEAlgorithm::EdDSA,
            key_ops: None,
            crv: COSEEllipticCurve::Ed25519,
            x: Some(test_keypair.public.to_bytes()),
            d: None,
        });

        let test_cose_key_cbor_value = cbor!({
            "1" => "1",
            "3" => "-8",
            "-1" => "6",
            "-2" => test_keypair.public.to_bytes(),
        })?;

        let mut test_cose_key_cbor = Vec::with_capacity(300);
        let mut test_assertion_cbor = Vec::with_capacity(300);

        ciborium::ser::into_writer(&test_cose_key, &mut test_cose_key_cbor)?;
        ciborium::ser::into_writer(&test_cose_key_cbor_value, &mut test_assertion_cbor)?;

        assert_eq!(test_assertion_cbor, test_cose_key_cbor);

        let test_deserialized_cose_key: OctetKeyPair =
            ciborium::de::from_reader(&mut test_assertion_cbor.as_slice())?;

        match test_cose_key {
            COSEKey::OctetKeyPair(test_okp) => {
                assert_eq!(test_okp.kty, test_deserialized_cose_key.kty);
                assert_eq!(test_okp.alg, test_deserialized_cose_key.alg);
                assert_eq!(test_okp.crv, test_deserialized_cose_key.crv);
                assert_eq!(test_okp.x, test_deserialized_cose_key.x);
            }
        }

        Ok(())
    }
}
