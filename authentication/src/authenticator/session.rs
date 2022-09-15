use crate::authenticator::attestation_object::AttestationObject;
use crate::authenticator::operation::AuthenticatorMakeCrendential;
use crate::error::AuthenticationError;

pub struct Session {}

impl Session {
    pub async fn init() -> Session {
        Session {}
    }

    pub async fn lookup(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn authenticator_make_credential(
        operation: AuthenticatorMakeCrendential,
    ) -> Result<AttestationObject, AuthenticationError> {
        operation.check_parameters().await?;
        operation.check_supported_combinations().await?;
        operation.authorize_disclosure().await?;
        operation.require_resident_key().await?;
        operation.require_user_verification().await?;
        operation.collect_authorization_gesture().await?;

        let processed_extensions = operation.process_extensions().await?;

        operation.signature_counter().await?;

        let attested_credential_data = operation.attested_credential_data().await?;
        let authenticator_data = operation.authenticator_data().await?;
        let attestation_object = operation.create_attestation_object().await?;

        Ok(attestation_object)
    }
}
