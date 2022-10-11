use serde::{Deserialize, Serialize};

use crate::api::supporting_data_structures::COSEAlgorithmIdentifier;
use crate::authenticator::attestation::{AttestationStatement, AttestationType};
use crate::authenticator::data::AuthenticatorData;
use crate::error::AuthenticationError;

pub struct PackedVerificationProcedureOutput {
    pub attestation_type: AttestationType,
    pub x5c: Option<Vec<Vec<u8>>>,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct PackedAttestationStatementSyntax {
    pub alg: COSEAlgorithmIdentifier,
    pub sig: [u8; 32],
    pub x5c: Option<Vec<Vec<u8>>>,
}

impl PackedAttestationStatementSyntax {
    pub async fn generate() -> PackedAttestationStatementSyntax {
        let alg = 3;
        let sig = [0; 32];
        let mut x5c = Vec::with_capacity(0);
        let attestnCert = Vec::with_capacity(0);

        x5c.push(attestnCert);

        PackedAttestationStatementSyntax {
            alg,
            sig,
            x5c: Some(x5c),
        }
    }

    pub async fn verification_procedure(
        authenticator_data: &AuthenticatorData,
        hash: &[u8],
    ) -> Result<PackedVerificationProcedureOutput, AuthenticationError> {
        Ok(PackedVerificationProcedureOutput {
            attestation_type: AttestationType::SelfAttestation,
            x5c: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::cbor;

    #[tokio::test]
    async fn serde() -> Result<(), Box<dyn std::error::Error>> {
        let test_packed_attestation_statement_syntax_some = PackedAttestationStatementSyntax {
            alg: -8,
            sig: [0; 32],
            x5c: Some(vec![Vec::<u8>::with_capacity(0)]),
        };

        let mut test_cbor_some = Vec::with_capacity(50);

        ciborium::ser::into_writer(
            &test_packed_attestation_statement_syntax_some,
            &mut test_cbor_some,
        )?;

        let test_cbor_sig = [0; 32];

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
        assert_eq!(test_deserialized_cbor_some.sig.len(), 32);
        assert_eq!(test_deserialized_cbor_some.x5c.unwrap().len(), 1);

        Ok(())
    }
}
