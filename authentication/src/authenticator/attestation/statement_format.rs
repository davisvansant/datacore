use crate::authenticator::attestation::statement_format::packed::PackedAttestationStatementSyntax;
use crate::authenticator::data::AuthenticatorData;

use crate::error::{AuthenticationError, AuthenticationErrorType};

pub mod packed;

#[derive(Clone)]
pub struct AttestationStatementFormatIdentifier(String);

impl AttestationStatementFormatIdentifier {
    pub async fn attestation_statement_format(
        &self,
    ) -> Result<AttestationStatementFormat, AuthenticationError> {
        let attestation_statement_format = match self.0.as_str() {
            "packed" => AttestationStatementFormat::Packed,
            "tpm" => AttestationStatementFormat::Tpm,
            "android-key" => AttestationStatementFormat::AndroidKey,
            "android-safetynet" => AttestationStatementFormat::AndroidSafetyNet,
            "fido-uf2" => AttestationStatementFormat::FidoUf2,
            "none" => AttestationStatementFormat::None,
            "apple" => AttestationStatementFormat::AppleAnonymous,
            _ => {
                return Err(AuthenticationError {
                    error: AuthenticationErrorType::OperationError,
                })
            }
        };

        Ok(attestation_statement_format)
    }
}

pub enum AttestationStatementFormat {
    Packed,
    Tpm,
    AndroidKey,
    AndroidSafetyNet,
    FidoUf2,
    None,
    AppleAnonymous,
}

impl AttestationStatementFormat {
    pub async fn identifier(&self) -> AttestationStatementFormatIdentifier {
        match self {
            AttestationStatementFormat::Packed => {
                AttestationStatementFormatIdentifier(String::from("packed"))
            }
            AttestationStatementFormat::Tpm => {
                AttestationStatementFormatIdentifier(String::from("tpm"))
            }
            AttestationStatementFormat::AndroidKey => {
                AttestationStatementFormatIdentifier(String::from("android-key"))
            }
            AttestationStatementFormat::AndroidSafetyNet => {
                AttestationStatementFormatIdentifier(String::from("android-safetynet"))
            }
            AttestationStatementFormat::FidoUf2 => {
                AttestationStatementFormatIdentifier(String::from("fido-u2f"))
            }
            AttestationStatementFormat::None => {
                AttestationStatementFormatIdentifier(String::from("none"))
            }
            AttestationStatementFormat::AppleAnonymous => {
                AttestationStatementFormatIdentifier(String::from("apple"))
            }
        }
    }

    pub async fn syntax(&self) -> AttestationStatement {
        match self {
            AttestationStatementFormat::Packed => {
                let syntax = PackedAttestationStatementSyntax::build().await;

                AttestationStatement::Packed(syntax)
            }
            AttestationStatementFormat::Tpm => unimplemented!(),
            AttestationStatementFormat::AndroidKey => unimplemented!(),
            AttestationStatementFormat::AndroidSafetyNet => unimplemented!(),
            AttestationStatementFormat::FidoUf2 => unimplemented!(),
            AttestationStatementFormat::None => unimplemented!(),
            AttestationStatementFormat::AppleAnonymous => unimplemented!(),
        }
    }

    pub async fn verification_procedure(
        &self,
        attestation_statement: &AttestationStatement,
        authenticator_data: &AuthenticatorData,
        client_data_hash: &[u8],
    ) -> Result<(), AuthenticationError> {
        match self {
            AttestationStatementFormat::Packed => {
                PackedAttestationStatementSyntax::verification_procedure(
                    attestation_statement,
                    authenticator_data,
                    client_data_hash,
                )
                .await?
            }
            _ => unimplemented!(),
        }

        Ok(())
    }
}

#[derive(Clone)]
pub enum AttestationStatement {
    Packed(PackedAttestationStatementSyntax),
}
