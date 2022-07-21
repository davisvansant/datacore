use serde::Deserialize;

#[derive(Deserialize)]
pub struct ClientMetadata {
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub grant_types: String,
    pub response_types: Vec<String>,
    pub client_name: String,
    pub client_uri: String,
    pub logo_uri: String,
    pub scope: String,
    pub contacts: String,
    pub tos_uri: String,
    pub policy_uri: String,
    pub jwks_uri: String,
    pub jwks: String,
    pub software_id: String,
    pub software_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_value, json};

    #[tokio::test]
    async fn client_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let test_json = json!({
            "redirect_uris": [
                "some_test_uri_one",
                "some_test_uri_two",
            ],
            "token_endpoint_auth_method": "some_test_token_endpoint_auth_method",
            "grant_types": "some_test_grant_type",
            "response_types": [
                "some_test_response_type_one",
                "some_test_response_type_two",
            ],
            "client_name": "some_test_client_name",
            "client_uri": "some_test_client_uri",
            "logo_uri": "some_test_logo_uri",
            "scope": "some_test_scope",
            "contacts": "some_test_contacts",
            "tos_uri": "some_test_tos_uri",
            "policy_uri": "some_test_policy_uri",
            "jwks_uri": "some_test_jwks_uri",
            "jwks": "some_test_jwks",
            "software_id": "some_test_software_id",
            "software_version": "some_test_software_version",
        });

        let test_client_metadata: ClientMetadata = from_value(test_json)?;

        assert_eq!(test_client_metadata.redirect_uris[0], "some_test_uri_one");
        assert_eq!(test_client_metadata.redirect_uris[1], "some_test_uri_two");
        assert_eq!(
            test_client_metadata.token_endpoint_auth_method,
            "some_test_token_endpoint_auth_method",
        );
        assert_eq!(test_client_metadata.grant_types, "some_test_grant_type");
        assert_eq!(
            test_client_metadata.response_types[0],
            "some_test_response_type_one",
        );
        assert_eq!(
            test_client_metadata.response_types[1],
            "some_test_response_type_two",
        );
        assert_eq!(test_client_metadata.client_name, "some_test_client_name");
        assert_eq!(test_client_metadata.client_uri, "some_test_client_uri");
        assert_eq!(test_client_metadata.logo_uri, "some_test_logo_uri");
        assert_eq!(test_client_metadata.scope, "some_test_scope");
        assert_eq!(test_client_metadata.contacts, "some_test_contacts");
        assert_eq!(test_client_metadata.tos_uri, "some_test_tos_uri");
        assert_eq!(test_client_metadata.policy_uri, "some_test_policy_uri");
        assert_eq!(test_client_metadata.jwks_uri, "some_test_jwks_uri");
        assert_eq!(test_client_metadata.jwks, "some_test_jwks");
        assert_eq!(test_client_metadata.software_id, "some_test_software_id");
        assert_eq!(
            test_client_metadata.software_version,
            "some_test_software_version",
        );

        Ok(())
    }
}
