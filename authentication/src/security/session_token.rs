use rand::distributions::{Alphanumeric, DistString};
use rand::thread_rng;

pub type SessionToken = [u8; 16];

pub async fn generate_session_token() -> SessionToken {
    let mut session_token: SessionToken = [0; 16];

    session_token.copy_from_slice(Alphanumeric.sample_string(&mut thread_rng(), 16).as_bytes());

    session_token
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn generate_session_token() -> Result<(), Box<dyn std::error::Error>> {
        let test_session_token = super::generate_session_token().await;

        assert_eq!(test_session_token.len(), 16);

        Ok(())
    }
}
