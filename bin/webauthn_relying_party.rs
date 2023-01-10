use authentication::relying_party::protocol::websockets::Websockets;
use authentication::relying_party::RelyingParty;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut relying_party = RelyingParty::init().await;
    let mut protocol = Websockets::init(relying_party.0).await;

    let relying_party_join_handle = tokio::spawn(async move {
        relying_party.1.run().await;
    });

    let protocol_join_handle = tokio::spawn(async move {
        if let Err(error) = protocol.run().await {
            println!("relying party protocol -> {:?}", error);
        }
    });

    tokio::try_join!(relying_party_join_handle, protocol_join_handle)?;

    Ok(())
}
