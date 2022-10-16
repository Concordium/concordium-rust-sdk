//! Test the `GetAncestors` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{types::hashes::BlockHash, v2, v2::BlockIdentifier};
use futures::StreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "block_hash",
        help = "Block hash to query. Default: \"best\" block."
    )]
    block:    Option<BlockHash>,
    #[structopt(long = "amount", help = "Maximum amount of ancestors to be returned.")]
    amount:   u64,
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

    let bi = app
        .block
        .map_or(BlockIdentifier::Best, BlockIdentifier::Given);

    let mut res = client.get_ancestors(&bi, app.amount).await?;
    println!("Blockhash: {}", res.block_hash);
    while let Some(a) = res.response.next().await {
        println!("{}", a?);
    }

    Ok(())
}
