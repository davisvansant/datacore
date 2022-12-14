use uuid::Uuid;

pub type SessionId = [u8; 32];

pub async fn generate_session_id() -> SessionId {
    let mut session_id: SessionId = [0; 32];

    session_id.copy_from_slice(Uuid::new_v4().simple().to_string().as_bytes());

    session_id
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn generate_session_id() -> Result<(), Box<dyn std::error::Error>> {
        let test_session_id = super::generate_session_id().await;

        assert_eq!(test_session_id.len(), 32);

        Ok(())
    }
}
