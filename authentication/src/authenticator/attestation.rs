use serde::{Deserialize, Serialize};

pub use crate::authenticator::attestation::cose_key_format::{COSEAlgorithm, COSEKey};
pub use crate::authenticator::attestation::statement_format::{
    AttestationStatement, AttestationStatementFormat, AttestationStatementFormatIdentifier,
    PackedAttestationStatementSyntax,
};
use crate::authenticator::data::AuthenticatorData;

mod cose_key_format;
mod statement_format;

#[derive(Deserialize, Clone, Serialize)]
pub struct AttestationObject {
    pub authData: AuthenticatorData,
    pub fmt: AttestationStatementFormatIdentifier,
    pub attStmt: AttestationStatement,
}

impl AttestationObject {
    pub async fn generate(
        attestation_format: AttestationStatementFormat,
        authData: AuthenticatorData,
        hash: Vec<u8>,
    ) -> AttestationObject {
        let fmt = attestation_format.identifier().await;
        let attStmt = attestation_format.syntax().await;

        AttestationObject {
            fmt,
            attStmt,
            authData,
        }
    }
}

#[derive(Deserialize, Clone, Serialize)]
pub struct AttestedCredentialData {
    pub aaguid: Vec<u8>,
    pub credential_id_length: u16,
    pub credential_id: Vec<u8>,
    pub credential_public_key: COSEKey,
}

impl AttestedCredentialData {
    pub async fn generate() -> AttestedCredentialData {
        let aaguid = Vec::with_capacity(0);
        let credential_id_length = 0;
        let credential_id = Vec::with_capacity(0);
        let credential_public_key = COSEKey::generate(COSEAlgorithm::EdDSA).await;

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
