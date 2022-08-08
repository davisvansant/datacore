use std::collections::HashMap;

pub struct Clients {
    metadata: HashMap<String, String>,
}

impl Clients {
    pub async fn init() -> Clients {
        let metadata = HashMap::with_capacity(50);

        Clients { metadata }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init() -> Result<(), Box<dyn std::error::Error>> {
        let test_clients = Clients::init().await;

        assert!(test_clients.metadata.is_empty());

        Ok(())
    }
}
