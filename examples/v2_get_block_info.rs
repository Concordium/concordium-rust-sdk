//! Test the `GetBlockInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use structopt::StructOpt;

use concordium_rust_sdk::v2::{self, BlockIdentifier};

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "block", help = "Block identifier.", default_value = "best")]
    block:    BlockIdentifier,
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

    {
        let ai = client.get_block_info(&app.block).await?;
        println!("{}: {:#?}", ai.block_hash, ai.response);
    }

    Ok(())
}
