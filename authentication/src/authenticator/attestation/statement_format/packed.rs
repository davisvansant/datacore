use ed25519_dalek::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::api::supporting_data_structures::COSEAlgorithmIdentifier;
use crate::authenticator::attestation::{AttestationType, AttestationVerificationProcedureOutput};
use crate::authenticator::data::AuthenticatorData;
use crate::error::{AuthenticationError, AuthenticationErrorType};

#[derive(Deserialize, Clone, Serialize)]
pub struct PackedAttestationStatementSyntax {
    pub alg: COSEAlgorithmIdentifier,
    pub sig: Vec<u8>,
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
        authenticator_data: &AuthenticatorData,
        // client_data_hash: Vec<u8>,
        client_data_hash: &[u8],
    ) -> PackedAttestationStatementSyntax {
        let mut attest = Vec::with_capacity(500);
        let serialized_authenticator_data =
            bincode::serialize(authenticator_data).expect("serialized_data");

        for element in serialized_authenticator_data {
            attest.push(element);
        }
        for element in client_data_hash {
            attest.push(*element);
        }

        attest.shrink_to_fit();

        println!("{:?}", attest);

        // let alg = authenticator_data
        //     .attestedcredentialdata
        //     .credential_public_key
        //     .algorithm()
        //     .await;
        let alg = if let Some(attested_credential_data) = &authenticator_data.attestedcredentialdata
        {
            attested_credential_data
                .credential_public_key
                .algorithm()
                .await
        } else {
            panic!("need better error handling...")
        };
        let sig = [0; 64].to_vec();

        PackedAttestationStatementSyntax {
            alg,
            sig,
            x5c: None,
        }
    }

    pub async fn verification_procedure(
        attestation_statement: &PackedAttestationStatementSyntax,
        authenticator_data: &AuthenticatorData,
        client_data_hash: &[u8],
    ) -> Result<AttestationVerificationProcedureOutput, AuthenticationError> {
        let (public_key_alg, public_key) =
            if let Some(attested_credential_data) = &authenticator_data.attestedcredentialdata {
                let alg = attested_credential_data
                    .credential_public_key
                    .algorithm()
                    .await;

                let public_key = attested_credential_data
                    .credential_public_key
                    .public_key()
                    .await;

                (alg, public_key)
            } else {
                panic!("need better error handling here...");
            };

        match attestation_statement.x5c.is_some() {
            true => {
                println!("run basic/attca attestation procedures...");

                Ok(AttestationVerificationProcedureOutput {
                    attestation_type: AttestationType::BasicAttestation,
                    x5c: Some(vec![Vec::with_capacity(0)]),
                })
            }
            false => {
                match attestation_statement.alg == public_key_alg {
                    true => {
                        println!("do alg specific verification");

                        // let public_key = authenticator_data
                        //     .attestedcredentialdata
                        //     .credential_public_key
                        //     .public_key()
                        //     .await;

                        match attestation_statement.alg {
                            -8 => {
                                if let Ok(public_key) = PublicKey::from_bytes(&public_key) {
                                    let signature =
                                        Signature::from_bytes(&attestation_statement.sig)
                                            .expect("signature::from_bytes failed");

                                    match public_key.verify_strict(client_data_hash, &signature) {
                                        Ok(()) => (),
                                        Err(error) => {
                                            println!("error -> {:?}", error);

                                            return Err(AuthenticationError {
                                                error: AuthenticationErrorType::OperationError,
                                            });
                                        }
                                    }
                                } else {
                                    return Err(AuthenticationError {
                                        error: AuthenticationErrorType::OperationError,
                                    });
                                }
                            }
                            _ => unimplemented!(),
                        }

                        Ok(AttestationVerificationProcedureOutput {
                            attestation_type: AttestationType::SelfAttestation,
                            x5c: None,
                        })
                    }
                    false => Err(AuthenticationError {
                        error: AuthenticationErrorType::OperationError,
                    }),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::attestation::AttestedCredentialData;
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
        let test_attested_credential_data = AttestedCredentialData::generate().await;
        let test_authenticator_data =
            AuthenticatorData::generate("test_rp_id", test_attested_credential_data).await;
        let test_hash = b"test_client_data".to_vec();
        let test_output = PackedAttestationStatementSyntax::signing_procedure(
            &test_authenticator_data,
            &test_hash,
        )
        .await;

        assert_eq!(test_output.alg, -8);
        assert_eq!(test_output.sig.len(), 64);
        assert!(test_output.x5c.is_none());

        Ok(())
    }
}
