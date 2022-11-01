//! Test the `GetBlockFinalizationSummary` endpoint.
//! Query all blocks from genesis and print their height, hash, and whether they
//! contain a finalization record.
use anyhow::Context;
use clap::AppSettings;
use structopt::StructOpt;

use concordium_rust_sdk::v2;

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

    let mut receiver = client.get_finalized_blocks_from(0u64.into()).await?;
    while let Some(v) = receiver.next().await {
        let fin_data = client.get_block_finalization_summary(v.block_hash).await?;
        println!(
            "{}: {}: {}",
            v.height,
            v.block_hash,
            fin_data.response.is_some()
        )
    }

    Ok(())
}
