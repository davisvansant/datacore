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
    pub authenticator_data: AuthenticatorData,
    #[serde(rename = "fmt")]
    pub format: AttestationStatementFormatIdentifier,
    #[serde(rename = "attStmt")]
    pub attestation_statement: AttestationStatement,
}

impl AttestationObject {
    pub async fn generate(
        attestation_format: AttestationStatementFormat,
        authenticator_data: AuthenticatorData,
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
}

pub enum AttestationType {
    BasicAttestation,
    SelfAttestation,
    AttestationCA,
    AnonymousCA,
    None,
}
