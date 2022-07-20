use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use system::authorization_server::AuthorizationServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let authorization_server_socket_address =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6749);
    let authorization_server = AuthorizationServer::init(authorization_server_socket_address).await;

    authorization_server.run().await?;

    Ok(())
}
