use serde::{Deserialize, Serialize};

pub use crate::authenticator::attestation::statement_format::packed::{
    PackedAttestationStatementSyntax, PackedVerificationProcedureOutput,
};

use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::convert::TryFrom;

pub type AttestationStatementFormatIdentifier = String;

mod packed;

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
