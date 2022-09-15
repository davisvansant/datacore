pub struct AttestationObject {
    attestation_format: String,
    auth_type: String,
    hash: String,
}

impl AttestationObject {
    pub async fn generate() -> AttestationObject {
        let attestation_format = String::from("some_attestation_format");
        let auth_type = String::from("some_attestation_auth_type");
        let hash = String::from("some_hash");

        AttestationObject {
            attestation_format,
            auth_type,
            hash,
        }
    }
}
