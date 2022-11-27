use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::authenticator::attestation::cose_key_format::{COSEAlgorithm, COSEKey};
pub use crate::authenticator::attestation::statement_format::{
    AttestationStatement, AttestationStatementFormat, AttestationStatementFormatIdentifier,
    AttestationVerificationProcedureOutput, PackedAttestationStatementSyntax,
};
use crate::authenticator::data::AuthenticatorData;
use crate::error::AuthenticationError;

mod cose_key_format;
mod statement_format;

#[derive(Deserialize, Clone, Serialize)]
pub struct AttestationObject {
    #[serde(rename = "authData")]
    pub authenticator_data: Vec<u8>,
    #[serde(rename = "fmt")]
    pub format: AttestationStatementFormatIdentifier,
    #[serde(rename = "attStmt")]
    pub attestation_statement: AttestationStatement,
}

impl AttestationObject {
    pub async fn generate(
        attestation_format: AttestationStatementFormat,
        authenticator_data: Vec<u8>,
        hash: &[u8],
    ) -> Result<AttestationObject, AuthenticationError> {
        let format = attestation_format.identifier().await;
        let attestation_statement = match attestation_format {
            AttestationStatementFormat::Packed => AttestationStatement::Packed(
                PackedAttestationStatementSyntax::signing_procedure(&authenticator_data, hash)
                    .await?,
            ),
        };

        Ok(AttestationObject {
            format,
            attestation_statement,
            authenticator_data,
        })
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct AttestedCredentialData {
    pub aaguid: [u8; 16],
    pub credential_id_length: [u8; 2],
    pub credential_id: [u8; 16],
    pub credential_public_key: COSEKey,
}

impl AttestedCredentialData {
    pub async fn generate() -> AttestedCredentialData {
        let aaguid = Uuid::new_v4().simple().into_uuid().into_bytes();
        let credential_id = [0; 16];
        let credential_id_length = credential_id.len() as u16;
        let credential_id_length_bytes = credential_id_length.to_be_bytes();
        let credential_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await.0;

        AttestedCredentialData {
            aaguid,
            credential_id_length: credential_id_length_bytes,
            credential_id,
            credential_public_key,
        }
    }

    pub async fn to_byte_array(&self) -> Vec<u8> {
        let mut byte_array = Vec::with_capacity(1000);

        for element in self.aaguid {
            byte_array.push(element);
        }

        for element in self.credential_id_length {
            byte_array.push(element);
        }

        for element in self.credential_id {
            byte_array.push(element);
        }

        let mut credential_public_key_cbor = Vec::with_capacity(1000);

        ciborium::ser::into_writer(&self.credential_public_key, &mut credential_public_key_cbor)
            .expect("some cbor");

        credential_public_key_cbor.shrink_to_fit();

        for element in credential_public_key_cbor {
            byte_array.push(element);
        }

        byte_array.shrink_to_fit();
        byte_array
    }

    pub async fn from_byte_array(data: &[u8]) -> AttestedCredentialData {
        let mut aaguid: [u8; 16] = [0; 16];
        let mut credential_id_length: [u8; 2] = [0; 2];
        let mut credential_id: [u8; 16] = [0; 16];

        let (aaguid_data, remaining) = data.split_at(16);
        let (credential_id_length_bytes, remaining) = remaining.split_at(2);

        credential_id_length.copy_from_slice(credential_id_length_bytes);

        let credential_id_index = u16::from_be_bytes(credential_id_length) as usize;
        let (credential_id_data, credential_public_key_cbor) =
            remaining.split_at(credential_id_index);
        let credential_public_key = ciborium::de::from_reader(credential_public_key_cbor).unwrap();

        aaguid.copy_from_slice(aaguid_data);
        credential_id.copy_from_slice(credential_id_data);

        AttestedCredentialData {
            aaguid,
            credential_id_length,
            credential_id,
            credential_public_key,
        }
    }
}

pub enum AttestationType {
    BasicAttestation,
    SelfAttestation,
    AttestationCA,
    AnonymousCA,
    None,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::attestation::cose_key_format::COSEEllipticCurve;

    #[tokio::test]
    async fn attested_credential_data_byte_array() -> Result<(), Box<dyn std::error::Error>> {
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_byte_array = test_attested_credential_data.to_byte_array().await;

        for element in &test_byte_array {
            assert_eq!(std::mem::size_of_val(element), 1);
        }

        assert!(test_byte_array.len() >= 18);
        assert!(test_byte_array.capacity() >= 18);
        assert!(std::mem::size_of_val(&*test_byte_array) >= 18);

        let test_from_byte_array = AttestedCredentialData::from_byte_array(&test_byte_array).await;

        assert_eq!(test_from_byte_array.aaguid.len(), 16);
        assert_eq!(test_from_byte_array.credential_id.len(), 16);

        match test_from_byte_array.credential_public_key {
            COSEKey::OctetKeyPair(test_octet_key_pair) => {
                assert_eq!(test_octet_key_pair.alg, COSEAlgorithm::EdDSA);
                assert_eq!(test_octet_key_pair.crv, COSEEllipticCurve::Ed25519);
                assert!(test_octet_key_pair.x.is_some());
                assert!(test_octet_key_pair.d.is_none());
            }
        }

        Ok(())
    }
}
