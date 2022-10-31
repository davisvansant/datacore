use crate::api::credential_creation_options::{
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};
use crate::api::credential_generation_parameters::PublicKeyCredentialParameters;
use crate::api::supporting_data_structures::PublicKeyCredentialDescriptor;
use crate::authenticator::attestation::{
    AttestationObject, AttestationStatementFormat, AttestedCredentialData,
};
// use crate::authenticator::credential_object::CredentialObject;
use crate::authenticator::data::AuthenticatorData;
use crate::error::AuthenticationError;

pub struct AuthenticatorMakeCrendential {
    hash: Vec<u8>,
    rp_entity: PublicKeyCredentialRpEntity,
    user_entity: PublicKeyCredentialUserEntity,
    require_resident_key: bool,
    require_user_presence: bool,
    require_user_verification: bool,
    cred_types_and_pub_key_apis: Vec<PublicKeyCredentialParameters>,
    exclude_credential_descriptor_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    enterprise_attestation_possible: bool,
    extensions: String,
}

impl AuthenticatorMakeCrendential {
    pub async fn collect_parameters(
        hash: Vec<u8>,
        rp_entity: PublicKeyCredentialRpEntity,
        user_entity: PublicKeyCredentialUserEntity,
        require_resident_key: bool,
        require_user_presence: bool,
        require_user_verification: bool,
        cred_types_and_pub_key_apis: Vec<PublicKeyCredentialParameters>,
        exclude_credential_descriptor_list: Option<Vec<PublicKeyCredentialDescriptor>>,
        enterprise_attestation_possible: bool,
        extensions: String,
    ) -> AuthenticatorMakeCrendential {
        AuthenticatorMakeCrendential {
            hash,
            rp_entity,
            user_entity,
            require_resident_key,
            require_user_presence,
            require_user_verification,
            cred_types_and_pub_key_apis,
            exclude_credential_descriptor_list,
            enterprise_attestation_possible,
            extensions,
        }
    }

    pub async fn check_parameters(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn check_supported_combinations(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn authorize_disclosure(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn require_resident_key(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn require_user_verification(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn collect_authorization_gesture(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn process_extensions(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn signature_counter(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn attested_credential_data(
        &self,
    ) -> Result<AttestedCredentialData, AuthenticationError> {
        let attested_credential_data = AttestedCredentialData::generate().await;

        Ok(attested_credential_data)
    }

    pub async fn authenticator_data(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn create_attestation_object(
        &self,
        attested_credential_data: AttestedCredentialData,
    ) -> Result<AttestationObject, AuthenticationError> {
        // let _ = CredentialObject::generate().await;

        let attestation_format = AttestationStatementFormat::Packed;
        let authenticator_data =
            AuthenticatorData::generate(&self.rp_entity.id, attested_credential_data).await;
        let hash = Vec::with_capacity(0);

        let attestation_object =
            AttestationObject::generate(attestation_format, authenticator_data, hash).await;

        Ok(attestation_object)
    }
}
