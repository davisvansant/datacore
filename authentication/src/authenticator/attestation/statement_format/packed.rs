use crate::api::supporting_data_structures::COSEAlgorithmIdentifier;
use crate::authenticator::attestation::AttestationStatement;
use crate::authenticator::data::AuthenticatorData;
use crate::error::AuthenticationError;

#[derive(Clone)]
pub struct PackedAttestationStatementSyntax {
    alg: COSEAlgorithmIdentifier,
    sig: Vec<u8>,
    x5c: Vec<Vec<u8>>,
}

impl PackedAttestationStatementSyntax {
    pub async fn build() -> PackedAttestationStatementSyntax {
        let alg = 3;
        let sig = Vec::with_capacity(0);
        let mut x5c = Vec::with_capacity(0);
        let attestnCert = Vec::with_capacity(0);

        x5c.push(attestnCert);

        PackedAttestationStatementSyntax { alg, sig, x5c }
    }

    pub async fn verification_procedure(
        attestation_statement: &AttestationStatement,
        authenticator_data: &AuthenticatorData,
        hash: &[u8],
    ) -> Result<(), AuthenticationError> {
        Ok(())
    }
}
