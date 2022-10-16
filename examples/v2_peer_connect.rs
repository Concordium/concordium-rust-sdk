//! Example of how to instruct a node to connect/disconnect to a certain peer
//! given by its IP and port.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::v2;
use std::net::SocketAddr;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "peer", help = "peer to connect to")]
    peer:     SocketAddr,
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

    client.peer_connect(app.peer).await?;
    println!("Connected to {:#?}", app.peer);
    // We wait 10 seconds and drop the peer again.
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    client.peer_disconnect(app.peer).await?;
    println!("Dropped {:#?}", app.peer);

    Ok(())
}
