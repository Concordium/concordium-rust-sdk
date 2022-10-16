/// Test the `BlockItemStatus` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::types::hashes::TransactionHash;
use structopt::StructOpt;

use concordium_rust_sdk::v2;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:    v2::Endpoint,
    #[structopt(long = "transaction", help = "Transaction hash to query.")]
    transaction: TransactionHash,
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

    let res = client.get_block_item_status(&app.transaction).await?;
    println!("{:#?}", res);

    Ok(())
}
