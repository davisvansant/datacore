use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use system::endpoint::authorization_server::AuthorizationServer;
use system::endpoint::client_registration::ClientRegistration;
use system::endpoint::token_introspection::TokenIntrospection;
use system::state::access_tokens::AccessTokens;
use system::state::authorization_codes::AuthorizationCodes;
use system::state::client_registry::ClientRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut client_registry, client_registry_request) = ClientRegistry::init().await;

    let client_registry_handle = tokio::spawn(async move {
        if let Err(error) = client_registry.run().await {
            println!("client registry -> {:?}", error);
        }
    });

    let (mut authorization_codes, authorization_codes_request) = AuthorizationCodes::init().await;

    let authorization_codes_handle = tokio::spawn(async move {
        if let Err(error) = authorization_codes.run().await {
            println!("authorization codes -> {:?}", error);
        }
    });

    let (mut access_tokens, access_tokens_request) = AccessTokens::init().await;

    let access_tokens_handle = tokio::spawn(async move {
        if let Err(error) = access_tokens.run().await {
            println!("access tokens -> {:?}", error);
        }
    });

    let ip_address = Ipv4Addr::new(127, 0, 0, 1);
    let authorization_server_socket_address = SocketAddr::new(IpAddr::V4(ip_address), 6749);
    let authorization_server = AuthorizationServer::init(
        authorization_server_socket_address,
        authorization_codes_request,
        access_tokens_request.to_owned(),
    )
    .await;

    let authorization_server_handle = tokio::spawn(async move {
        if let Err(error) = authorization_server.run().await {
            println!("authorization server -> {:?}", error);
        }
    });

    let client_registration_socket_address = SocketAddr::new(IpAddr::V4(ip_address), 7591);
    let client_registration =
        ClientRegistration::init(client_registration_socket_address, client_registry_request).await;

    let client_registration_handle = tokio::spawn(async move {
        if let Err(error) = client_registration.run().await {
            println!("client registration -> {:?}", error);
        }
    });

    let token_introspection_socket_address = SocketAddr::new(IpAddr::V4(ip_address), 7662);
    let token_introspection = TokenIntrospection::init(
        token_introspection_socket_address,
        access_tokens_request.to_owned(),
    )
    .await;

    let token_introspection_handle = tokio::spawn(async move {
        if let Err(error) = token_introspection.run().await {
            println!("token introspection -> {:?}", error);
        }
    });

    tokio::try_join!(
        client_registry_handle,
        authorization_codes_handle,
        access_tokens_handle,
        authorization_server_handle,
        client_registration_handle,
        token_introspection_handle,
    )?;

    Ok(())
}
