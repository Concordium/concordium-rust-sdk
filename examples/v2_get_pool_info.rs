//! Test the `GetPoolInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::hashes::BlockHash;
use concordium_rust_sdk::{types::BakerId, v2};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "block", help = "Block to query in.")]
    block: Option<BlockHash>,
    #[structopt(long = "baker-id", help = "Pool identifier.")]
    baker_id: BakerId,
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

    let block_ident = app
        .block
        .map_or(v2::BlockIdentifier::LastFinal, v2::BlockIdentifier::Given);
    let status = client.get_pool_info(&block_ident, app.baker_id).await?;
    println!("{:#?}", status);
    Ok(())
}
