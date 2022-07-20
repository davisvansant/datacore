use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use system::authorization_server::AuthorizationServer;
use system::client_registration::ClientRegistration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ip_address = Ipv4Addr::new(127, 0, 0, 1);
    let authorization_server_socket_address = SocketAddr::new(IpAddr::V4(ip_address), 6749);
    let authorization_server = AuthorizationServer::init(authorization_server_socket_address).await;

    let authorization_server_handle = tokio::spawn(async move {
        if let Err(error) = authorization_server.run().await {
            println!("authorization server -> {:?}", error);
        }
    });

    let client_registration_socket_address = SocketAddr::new(IpAddr::V4(ip_address), 7591);
    let client_registration = ClientRegistration::init(client_registration_socket_address).await;

    let client_registration_handle = tokio::spawn(async move {
        if let Err(error) = client_registration.run().await {
            println!("client registration -> {:?}", error);
        }
    });

    tokio::try_join!(authorization_server_handle, client_registration_handle)?;

    Ok(())
}
