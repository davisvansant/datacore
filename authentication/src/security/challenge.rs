use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::{thread_rng, Rng};

use crate::error::{AuthenticationError, AuthenticationErrorType};

pub type Challenge = [u8; 16];

pub async fn generate_challenge() -> Challenge {
    let mut challenge = thread_rng();

    challenge.gen()
}

pub async fn base64_encode_challenge(challenge: &Challenge) -> String {
    STANDARD.encode(challenge)
}

pub async fn base64_decode_challenge(challenge: &str) -> Result<Vec<u8>, AuthenticationError> {
    match STANDARD.decode(challenge) {
        Ok(decoded_challenge) => Ok(decoded_challenge),
        Err(error) => {
            println!("base64 decoding error -> {:?}", error);

            Err(AuthenticationError {
                error: AuthenticationErrorType::OperationError,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate() -> Result<(), Box<dyn std::error::Error>> {
        let test_challenge = generate_challenge().await;

        assert_eq!(test_challenge.len(), 16);

        Ok(())
    }

    #[tokio::test]
    async fn base64() -> Result<(), Box<dyn std::error::Error>> {
        let test_base64_challenge = base64_encode_challenge(b"_test_challenge_").await;

        assert_eq!(test_base64_challenge, "X3Rlc3RfY2hhbGxlbmdlXw==");
        assert_eq!(
            base64_decode_challenge(&test_base64_challenge).await?,
            b"_test_challenge_",
        );

        Ok(())
    }
}
