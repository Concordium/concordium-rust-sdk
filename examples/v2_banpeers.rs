//! Example of banning functionality of the node.
use std::str::FromStr;

use anyhow::{ensure, Context};
use clap::AppSettings;
use concordium_rust_sdk::{types::network::PeerToBan, v2};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    ensure!(
        client.get_banned_peers().await?.is_empty(),
        "We expect no peers are currently banned."
    );
    let ip_to_ban = std::net::IpAddr::from_str("192.0.2.0")?;
    let peer_to_ban = PeerToBan::IpAddr(ip_to_ban);
    client.ban_peer(peer_to_ban).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let banned_peers = client.get_banned_peers().await?;
    ensure!(
        banned_peers.len() == 1,
        "The peer should be reflected in the get_banned_peers result"
    );
    ensure!(
        banned_peers
            .get(0)
            .context("Expected a banned peer here")?
            .0
            == ip_to_ban,
        "Unexpected peer in the ban list"
    );
    let banned_peer_0 = banned_peers.get(0).context("Expected a peer")?;
    client.unban_peer(banned_peer_0).await?;
    ensure!(
        client.get_banned_peers().await?.is_empty(),
        "Ban list should be empty now."
    );

    Ok(())
}
