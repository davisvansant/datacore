use serde::{Deserialize, Serialize};

pub use crate::authenticator::attestation::statement_format::packed::PackedAttestationStatementSyntax;
use crate::authenticator::attestation::AttestationType;
// use crate::authenticator::data::AuthenticatorData;

use crate::error::{AuthenticationError, AuthenticationErrorType};

use std::convert::TryFrom;

pub type AttestationStatementFormatIdentifier = String;

mod packed;

pub struct AttestationVerificationProcedureOutput {
    pub attestation_type: AttestationType,
    pub x5c: Option<Vec<Vec<u8>>>,
}

#[derive(Deserialize, Clone, Serialize)]
#[serde(untagged)]
pub enum AttestationStatement {
    Packed(PackedAttestationStatementSyntax),
}

impl AttestationStatement {
    pub async fn packed(&self) -> &PackedAttestationStatementSyntax {
        match self {
            AttestationStatement::Packed(syntax) => syntax,
        }
    }
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
