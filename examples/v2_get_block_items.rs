//! Test the `GetBlockItems` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::v2;
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
        let mut response = client.get_block_items(v.block_hash).await?;
        assert_eq!(
            response.block_hash, v.block_hash,
            "Querying for a given block should return data for the block."
        );
        println!("Blockhash: {}", response.block_hash);
        while let Some(a) = response.response.next().await.transpose()? {
            println!(" - {:#?}", &a);
        }
    }
    Ok(())
}
