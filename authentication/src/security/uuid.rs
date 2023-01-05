use uuid::Uuid;

pub type AAGUID = [u8; 16];
pub type CredentialId = Vec<u8>;
pub type SessionId = [u8; 32];
pub type UserHandle = Vec<u8>;

pub async fn generate_aaguid() -> AAGUID {
    let mut uuid = [0u8; 32];
    let mut aaguid: AAGUID = [0; 16];

    uuid.copy_from_slice(Uuid::new_v4().simple().to_string().as_bytes());

    let split_uuid = uuid.split_at(16);

    aaguid.copy_from_slice(split_uuid.0);
    aaguid
}

pub async fn generate_credential_id() -> CredentialId {
    Uuid::new_v4().simple().to_string().as_bytes().to_vec()
}

pub async fn generate_session_id() -> SessionId {
    let mut session_id: SessionId = [0; 32];

    session_id.copy_from_slice(Uuid::new_v4().simple().to_string().as_bytes());

    session_id
}

pub async fn generate_user_handle() -> UserHandle {
    Uuid::new_v4().simple().to_string().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn generate_aaguid() -> Result<(), Box<dyn std::error::Error>> {
        let test_aaguid = super::generate_aaguid().await;

        assert_eq!(test_aaguid.len(), 16);

        Ok(())
    }

    #[tokio::test]
    async fn generate_credential_id() -> Result<(), Box<dyn std::error::Error>> {
        let test_credential_id = super::generate_credential_id().await;

        assert_eq!(test_credential_id.len(), 32);

        Ok(())
    }

    #[tokio::test]
    async fn generate_session_id() -> Result<(), Box<dyn std::error::Error>> {
        let test_session_id = super::generate_session_id().await;

        assert_eq!(test_session_id.len(), 32);

        Ok(())
    }

    #[tokio::test]
    async fn generate_user_handle() -> Result<(), Box<dyn std::error::Error>> {
        let test_user_handle = super::generate_user_handle().await;

        assert_eq!(test_user_handle.len(), 32);

        Ok(())
    }
}
