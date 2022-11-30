use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::authenticator::attestation::cose_key_format::{COSEAlgorithm, COSEKey};
pub use crate::authenticator::attestation::statement_format::{
    AttestationStatement, AttestationStatementFormat, AttestationStatementFormatIdentifier,
    AttestationVerificationProcedureOutput, PackedAttestationStatementSyntax,
};
use crate::error::{AuthenticationError, AuthenticationErrorType};

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
        private_key: COSEKey,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let format = attestation_format.identifier().await;
        let attestation_statement = match attestation_format {
            AttestationStatementFormat::Packed => AttestationStatement::Packed(
                PackedAttestationStatementSyntax::signing_procedure(
                    &authenticator_data,
                    hash,
                    private_key,
                )
                .await?,
            ),
        };

        let attestation_object = AttestationObject {
            format,
            attestation_statement,
            authenticator_data,
        };

        let mut cbor = Vec::with_capacity(500);

        match ciborium::ser::into_writer(&attestation_object, &mut cbor) {
            Ok(()) => {
                cbor.shrink_to_fit();

                Ok(cbor)
            }
            Err(_) => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
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
    pub async fn generate(
        credential_id: [u8; 16],
        credential_public_key: COSEKey,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let aaguid = Uuid::new_v4().simple().into_uuid().into_bytes();
        let credential_id_length = credential_id.len() as u16;
        let credential_id_length_bytes = credential_id_length.to_be_bytes();
        let attested_credential_data = AttestedCredentialData {
            aaguid,
            credential_id_length: credential_id_length_bytes,
            credential_id,
            credential_public_key,
        };

        let mut byte_array = Vec::with_capacity(1000);

        for element in attested_credential_data.aaguid {
            byte_array.push(element);
        }

        for element in attested_credential_data.credential_id_length {
            byte_array.push(element);
        }

        for element in attested_credential_data.credential_id {
            byte_array.push(element);
        }

        let mut credential_public_key_cbor = Vec::with_capacity(1000);

        match ciborium::ser::into_writer(
            &attested_credential_data.credential_public_key,
            &mut credential_public_key_cbor,
        ) {
            Ok(()) => (),
            Err(error) => {
                println!("error serializing public key into CBOR -> {:?}", error);

                return Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                });
            }
        }

        credential_public_key_cbor.shrink_to_fit();

        for element in credential_public_key_cbor {
            byte_array.push(element);
        }

        byte_array.shrink_to_fit();

        Ok(byte_array)
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
    use crate::authenticator::data::AuthenticatorData;
    use ciborium::cbor;

    #[tokio::test]
    async fn attestation_object() -> Result<(), Box<dyn std::error::Error>> {
        let test_attestation_format = AttestationStatementFormat::Packed;
        let test_credential_id = [0u8; 16];
        let test_keypair = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_attested_credential_data =
            AttestedCredentialData::generate(test_credential_id, test_keypair.0).await?;
        let test_rp_id = "test_rp_id";
        let test_user_present = true;
        let test_user_verified = true;
        let test_sign_count = [0u8; 4];
        let test_authenticator_data = AuthenticatorData::generate(
            test_rp_id,
            test_user_present,
            test_user_verified,
            test_sign_count,
            Some(test_attested_credential_data),
            None,
        )
        .await;
        let test_hash = Vec::with_capacity(0);
        let test_attestation_object = AttestationObject::generate(
            test_attestation_format,
            test_authenticator_data.to_owned(),
            &test_hash,
            test_keypair.1.to_owned(),
        )
        .await?;

        let test_attestation_statement = AttestationStatement::Packed(
            PackedAttestationStatementSyntax::signing_procedure(
                &test_authenticator_data,
                &test_hash,
                test_keypair.1,
            )
            .await?,
        );

        let mut test_cbor = Vec::with_capacity(500);
        let test_assertion_cbor_value = cbor!({
            "authData" => test_authenticator_data,
            "fmt" => "packed",
            "attStmt" => test_attestation_statement,
        })?;

        ciborium::ser::into_writer(&test_assertion_cbor_value, &mut test_cbor)?;

        test_cbor.shrink_to_fit();

        assert_eq!(test_attestation_object, test_cbor);

        Ok(())
    }

    #[tokio::test]
    async fn attested_credential_data() -> Result<(), Box<dyn std::error::Error>> {
        let test_credential_id = [0u8; 16];
        let test_keypair = COSEKey::generate(COSEAlgorithm::EdDSA).await;
        let test_byte_array =
            AttestedCredentialData::generate(test_credential_id, test_keypair.0).await?;

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
