use crate::authenticator::operation::{AuthenticatorGetAssertion, AuthenticatorMakeCrendential};
use crate::authenticator::store::CredentialsChannel;
use crate::error::AuthenticationError;

pub struct Session {
    store: CredentialsChannel,
}

impl Session {
    pub async fn init(store: CredentialsChannel) -> Session {
        Session { store }
    }

    pub async fn lookup(&self) -> Result<(), AuthenticationError> {
        Ok(())
    }

    pub async fn authenticator_make_credential(
        &self,
        operation: AuthenticatorMakeCrendential,
    ) -> Result<(), AuthenticationError> {
        operation.check_parameters().await?;
        operation.check_supported_combinations().await?;
        operation.authorize_disclosure(&self.store).await?;
        operation.require_resident_key().await?;
        operation.require_user_verification().await?;
        operation.collect_authorization_gesture().await?;

        let (credential_id, public_key) = operation
            .generate_new_credential_object(&self.store)
            .await?;

        // let _processed_extensions = operation.process_extensions().await?;

        operation.signature_counter(&self.store).await?;

        let attested_credential_data = operation
            .attested_credential_data(credential_id, public_key)
            .await?;
        let authenticator_data = operation
            .authenticator_data(attested_credential_data)
            .await?;

        operation
            .create_attestation_object(authenticator_data)
            .await?;

        Ok(())
    }

    pub async fn authenticator_get_assertion(
        &self,
        operation: AuthenticatorGetAssertion,
    ) -> Result<(), AuthenticationError> {
        operation.check_parameters().await?;

        let credential_options = operation.credential_options(&self.store).await?;
        let selected_credential = operation
            .collect_authorization_gesture(credential_options)
            .await?;

        // let _processed_extensions = operation.process_extensions().await?;

        operation
            .increment_signature_counter(&self.store, &selected_credential)
            .await?;

        let authenticator_data = operation
            .authenticator_data(&self.store, &selected_credential)
            .await?;

        operation
            .assertion_signature(&authenticator_data, &selected_credential)
            .await?;

        Ok(())
    }
}
