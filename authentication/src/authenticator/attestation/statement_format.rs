use serde::{Deserialize, Serialize};

pub use crate::authenticator::attestation::statement_format::packed::PackedAttestationStatementSyntax;
use crate::authenticator::attestation::AttestationType;
use crate::authenticator::data::AuthenticatorData;

use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::convert::TryFrom;

pub type AttestationStatementFormatIdentifier = String;

mod packed;

pub struct AttestationVerificationProcedureOutput {
    pub attestation_type: AttestationType,
    pub x5c: Option<Vec<Vec<u8>>>,
}

#[derive(Deserialize, Clone, Serialize)]
pub enum AttestationStatement {
    Packed(PackedAttestationStatementSyntax),
}

#[derive(Debug, Eq, PartialEq)]
pub enum AttestationStatementFormat {
    Packed,
}

impl AttestationStatementFormat {
    pub async fn identifier(&self) -> AttestationStatementFormatIdentifier {
        match self {
            AttestationStatementFormat::Packed => String::from("packed"),
        }
    }

    pub async fn signing_procedure(
        &self,
        authenticator_data: &AuthenticatorData,
        hash: &[u8],
    ) -> AttestationStatement {
        match self {
            AttestationStatementFormat::Packed => {
                AttestationStatement::Packed(PackedAttestationStatementSyntax {
                    alg: -8,
                    sig: [0; 32],
                    x5c: None,
                })
            }
        }
    }

    pub async fn verification_procedure(
        &self,
        attestation_statement: &AttestationStatement,
        authenticator_data: &AuthenticatorData,
        client_data_hash: &[u8],
    ) -> Result<AttestationVerificationProcedureOutput, AuthenticationError> {
        match self {
            AttestationStatementFormat::Packed => Ok(AttestationVerificationProcedureOutput {
                attestation_type: AttestationType::SelfAttestation,
                x5c: None,
            }),
        }
    }
}

impl TryFrom<&String> for AttestationStatementFormat {
    type Error = AuthenticationError;

    fn try_from(
        identifier: &AttestationStatementFormatIdentifier,
    ) -> Result<AttestationStatementFormat, AuthenticationError> {
        match identifier.as_str() {
            "packed" => Ok(AttestationStatementFormat::Packed),
            _ => Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            }),
        }
    }
}
