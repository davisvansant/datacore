use crate::api::supporting_data_structures::TokenBinding;
use crate::error::AuthenticationError;
use crate::relying_party::operation::{AuthenticationCeremony, Register};

pub mod operation;

pub struct RelyingParty {
    identifier: String,
}

impl RelyingParty {
    pub async fn init() -> RelyingParty {
        let identifier = String::from("some_identifier");

        RelyingParty { identifier }
    }

    pub async fn register_new_credential(
        &self,
        operation: Register,
    ) -> Result<(), AuthenticationError> {
        let options = operation.public_key_credential_creation_options().await?;
        let credential = operation.call_credentials_create(&options).await?;
        let response = operation
            .authenticator_attestation_response(&credential)
            .await?;
        let client_extension_results = operation.client_extension_results(&credential).await?;
        let json_text = operation.json(&response).await?;
        let client_data = operation.client_data(&json_text).await?;

        let connection_token_binding = TokenBinding::generate().await;

        operation.verify_type(&client_data).await?;
        operation.verify_challenge(&client_data, &options).await?;
        operation
            .verify_origin(&client_data, &self.identifier)
            .await?;
        operation
            .verify_token_binding(&client_data, &connection_token_binding)
            .await?;

        let hash = operation.hash(&response).await?;
        let (fmt, authenticator_data, attestation_statement) =
            operation.perform_decoding(response).await?;

        operation
            .verify_rp_id_hash(&authenticator_data, &self.identifier)
            .await?;
        operation.verify_user_present(&authenticator_data).await?;
        operation
            .verify_user_verification(&authenticator_data)
            .await?;
        operation
            .verify_algorithm(&authenticator_data, &options)
            .await?;
        operation
            .verify_extension_outputs(&client_extension_results, &authenticator_data)
            .await?;
        operation
            .determine_attestation_statement_format(&fmt)
            .await?;

        let attestation_statement_format = operation
            .determine_attestation_statement_format(&fmt)
            .await?;
        let attestation_statement_output = operation
            .verify_attestation_statement(
                &attestation_statement_format,
                &attestation_statement,
                &authenticator_data,
                &hash,
            )
            .await?;

        operation
            .assess_attestation_trustworthiness(attestation_statement_output)
            .await?;
        operation.check_credential_id(&authenticator_data).await?;
        operation.register(options, authenticator_data).await?;

        Ok(())
    }

    pub async fn verify_authentication_assertion(
        &self,
        operation: AuthenticationCeremony,
    ) -> Result<(), AuthenticationError> {
        let options = operation.public_key_credential_request_options().await?;
        let credential = operation.call_credentials_get(&options).await?;
        let response = operation
            .authenticator_assertion_response(&credential)
            .await?;
        let client_extension_results = operation.client_extension_results(&credential).await?;

        operation
            .verify_credential_id(&options, &credential)
            .await?;

        operation.identify_user_and_verify(&response).await?;

        let credential_public_key = operation.credential_public_key(&credential).await?;
        let (client_data_json, authenticator_data, signature) =
            operation.response_values(response).await?;
        let client_data = operation.client_data(&client_data_json).await?;

        let token_binding = TokenBinding::generate().await;

        operation.verify_client_data_type(&client_data).await?;
        operation
            .verify_client_data_challenge(&client_data, &options)
            .await?;
        operation
            .verify_client_data_origin(&client_data, &self.identifier)
            .await?;
        operation
            .verify_client_data_token_binding(&client_data, &token_binding)
            .await?;
        operation
            .verify_rp_id_hash(&authenticator_data, &self.identifier)
            .await?;
        operation.verify_user_present(&authenticator_data).await?;
        operation
            .verify_user_verification(&authenticator_data)
            .await?;
        operation
            .verify_client_extension_results(&client_extension_results, &authenticator_data)
            .await?;

        let hash = operation.hash(&client_data_json).await?;

        operation
            .verifiy_signature(
                &credential_public_key,
                &signature,
                &authenticator_data,
                &hash,
            )
            .await?;

        operation
            .stored_sign_count(&credential, &authenticator_data)
            .await?;

        Ok(())
    }
}
