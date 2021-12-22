use system::authorization_server::AuthorizationServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let authorization_server = AuthorizationServer::init().await;

    authorization_server.run().await?;

    Ok(())
}
