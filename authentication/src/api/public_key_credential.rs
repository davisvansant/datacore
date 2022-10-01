use crate::api::assertion_generation_options::PublicKeyCredentialRequestOptions;
use crate::api::authenticator_responses::{
    AuthenticatorAttestationResponse, AuthenticatorResponse,
};
use crate::api::credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::authenticator::attestation::{
    AttestationObject, AttestationStatementFormat, AttestedCredentialData,
};
use crate::authenticator::data::AuthenticatorData;

pub struct PublicKeyCredential {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: AuthenticatorResponse,
    pub r#type: String,
}

impl PublicKeyCredential {
    pub async fn generate() -> PublicKeyCredential {
        let id = String::from("some_id");
        let raw_id = Vec::with_capacity(0);
        let attestation_statement_format = AttestationStatementFormat::Packed;
        let rp_id = "rp_id";
        let attested_credential_data = AttestedCredentialData::generate().await;
        let authenticator_data = AuthenticatorData::generate(rp_id, attested_credential_data).await;
        let hash = Vec::with_capacity(0);
        let attestation_object =
            AttestationObject::generate(attestation_statement_format, authenticator_data, hash)
                .await;
        let response = AuthenticatorResponse::AuthenticatorAttestationResponse(
            AuthenticatorAttestationResponse::generate(attestation_object).await,
        );
        let r#type = String::from("some_type");

        PublicKeyCredential {
            id,
            raw_id,
            response,
            r#type,
        }
    }
}

pub struct CredentialCreationOptions {
    public_key: PublicKeyCredentialCreationOptions,
}

pub struct CredentialRequestOptions {
    public_key: PublicKeyCredentialRequestOptions,
}
