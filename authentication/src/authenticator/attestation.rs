pub use crate::authenticator::attestation::statement_format::{
    AttestationStatement, AttestationStatementFormat, AttestationStatementFormatIdentifier,
};
use crate::authenticator::data::AuthenticatorData;

mod statement_format;

#[derive(Clone)]
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

#[derive(Clone)]
pub struct AttestedCredentialData {
    pub aaguid: Vec<u8>,
    pub credential_id_length: u16,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
}

impl AttestedCredentialData {
    pub async fn generate() -> AttestedCredentialData {
        let aaguid = Vec::with_capacity(0);
        let credential_id_length = 0;
        let credential_id = Vec::with_capacity(0);
        let credential_public_key = Vec::with_capacity(0);

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
