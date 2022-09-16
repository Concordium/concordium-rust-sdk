/// Test the `GetInstanceList` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{endpoints::BlocksAtHeightInput, v2};
use futures::StreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: tonic::transport::Endpoint,
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

    let info = client.get_consensus_info().await?;

    let mut response = client
        .get_blocks_at_height(&BlocksAtHeightInput::Absolute {
            height: info.best_block_height,
        })
        .await?;
    println!(
        "Blocks at best block {} ({}):",
        info.best_block, info.best_block_height
    );
    while let Some(a) = response.next().await {
        println!("{}", a?);
    }

    Ok(())
}
