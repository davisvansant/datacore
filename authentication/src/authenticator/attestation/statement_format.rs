use crate::authenticator::attestation::statement_format::packed::PackedAttestationStatementSyntax;

pub type AttestationStatementFormatIdentifier = String;

pub mod packed;

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
            AttestationStatementFormat::Packed => String::from("packed"),
            AttestationStatementFormat::Tpm => String::from("tpm"),
            AttestationStatementFormat::AndroidKey => String::from("android-key"),
            AttestationStatementFormat::AndroidSafetyNet => String::from("android-safetynet"),
            AttestationStatementFormat::FidoUf2 => String::from("fido-u2f"),
            AttestationStatementFormat::None => String::from("none"),
            AttestationStatementFormat::AppleAnonymous => String::from("apple"),
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
}

pub enum AttestationStatement {
    Packed(PackedAttestationStatementSyntax),
}
