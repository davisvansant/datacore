use serde::{Deserialize, Serialize};

use crate::api::supporting_data_structures::COSEAlgorithmIdentifier;
use crate::authenticator::attestation::{
    AttestationType, AttestationVerificationProcedureOutput, COSEKey,
};
use crate::authenticator::data::AuthenticatorData;
use crate::error::{AuthenticationError, AuthenticationErrorType};

#[derive(Deserialize, Clone, Serialize)]
pub struct PackedAttestationStatementSyntax {
    pub alg: COSEAlgorithmIdentifier,
    pub sig: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<Vec<u8>>>,
}

impl PackedAttestationStatementSyntax {
    pub async fn generate() -> PackedAttestationStatementSyntax {
        let alg = -8;
        let sig = [0; 64].to_vec();
        let mut x5c = Vec::with_capacity(0);
        let attestation_cert = Vec::with_capacity(0);

        x5c.push(attestation_cert);

        PackedAttestationStatementSyntax {
            alg,
            sig,
            x5c: Some(x5c),
        }
    }

    pub async fn signing_procedure(
        authenticator_data: &[u8],
        client_data_hash: &[u8],
        private_key: COSEKey,
    ) -> Result<PackedAttestationStatementSyntax, AuthenticationError> {
        let alg = private_key.algorithm().await;
        let sig = private_key
            .sign(authenticator_data, client_data_hash)
            .await?;

        Ok(PackedAttestationStatementSyntax {
            alg,
            sig: sig.to_vec(),
            x5c: None,
        })
    }

    pub async fn verification_procedure(
        attestation_statement: &PackedAttestationStatementSyntax,
        authenticator_data: &[u8],
        client_data_hash: &[u8],
    ) -> Result<AttestationVerificationProcedureOutput, AuthenticationError> {
        let attested_credential_data =
            AuthenticatorData::attested_credential_data(authenticator_data).await?;
        let public_key_alg = attested_credential_data
            .credential_public_key
            .algorithm()
            .await;

        match attestation_statement.x5c.is_some() {
            true => {
                println!("run basic/attca attestation procedures...");

                Ok(AttestationVerificationProcedureOutput {
                    attestation_type: AttestationType::BasicAttestation,
                    x5c: Some(vec![Vec::with_capacity(0)]),
                })
            }
            false => match attestation_statement.alg == public_key_alg {
                true => {
                    println!("do alg specific verification");

                    attested_credential_data
                        .credential_public_key
                        .verify_signature(
                            &attestation_statement.sig,
                            authenticator_data,
                            client_data_hash,
                        )
                        .await?;

                    Ok(AttestationVerificationProcedureOutput {
                        attestation_type: AttestationType::SelfAttestation,
                        x5c: None,
                    })
                }
                false => Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                }),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::attestation::{AttestedCredentialData, COSEAlgorithm, COSEKey};
    use ciborium::cbor;

    #[tokio::test]
    async fn serde() -> Result<(), Box<dyn std::error::Error>> {
        let test_packed_attestation_statement_syntax_some = PackedAttestationStatementSyntax {
            alg: -8,
            sig: [0; 64].to_vec(),
            x5c: Some(vec![Vec::<u8>::with_capacity(0)]),
        };

        let mut test_cbor_some = Vec::with_capacity(50);

        ciborium::ser::into_writer(
            &test_packed_attestation_statement_syntax_some,
            &mut test_cbor_some,
        )?;

        let test_cbor_sig = [0; 64].to_vec();

        let test_assertion_cbor_value = cbor!({
            "alg" => -8,
            "sig" => test_cbor_sig,
            "x5c" => Some(vec![Vec::<u8>::with_capacity(0)]),
        })
        .unwrap();

        let mut test_assertion_cbor = Vec::with_capacity(0);

        ciborium::ser::into_writer(&test_assertion_cbor_value, &mut test_assertion_cbor)?;

        assert_eq!(test_assertion_cbor, test_cbor_some);

        let test_deserialized_cbor_some: PackedAttestationStatementSyntax =
            ciborium::de::from_reader(test_cbor_some.as_slice())?;

        assert_eq!(test_deserialized_cbor_some.alg, -8);
        assert_eq!(test_deserialized_cbor_some.sig.len(), 64);
        assert_eq!(test_deserialized_cbor_some.x5c.unwrap().len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn signing_procedure() -> Result<(), Box<dyn std::error::Error>> {
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
        let test_hash = b"test_client_data".to_vec();
        let test_output = PackedAttestationStatementSyntax::signing_procedure(
            &test_authenticator_data,
            &test_hash,
            test_keypair.1,
        )
        .await?;

        assert_eq!(test_output.alg, -8);
        assert_eq!(test_output.sig.len(), 64);
        assert!(test_output.x5c.is_none());

        Ok(())
    }
}
