use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub async fn generate_hash(message: &[u8]) -> Hash {
    let mut digest = Sha256::new();
    let mut hash: Hash = [0; 32];

    digest.update(message);
    hash.copy_from_slice(&digest.finalize());

    hash
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[tokio::test]
    async fn generate_hash() -> Result<(), Box<dyn std::error::Error>> {
        let test_empty_hash = super::generate_hash(b"").await;
        let test_empty_hex =
            hex_literal::hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        assert_eq!(test_empty_hash, test_empty_hex);

        let test_hash = super::generate_hash(b"test").await;
        let test_hash_error = super::generate_hash(b"test.").await;
        let test_hex =
            hex_literal::hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");

        assert_eq!(test_hash, test_hex);
        assert_ne!(test_hash_error, test_hex);

        Ok(())
    }
}
