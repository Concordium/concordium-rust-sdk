//! Test the `GetBlockTransactionEvents` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    types::{AbsoluteBlockHeight, ContractAddress},
    v2,
};
use futures::StreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "height",
        help = "Starting height, defaults to 0.",
        default_value = "0"
    )]
    height:   AbsoluteBlockHeight,
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

    let mut receiver = client.get_finalized_blocks_from(app.height).await?;
    while let Some(v) = receiver.next().await {
        let bi = client.get_block_info(v.block_hash).await?;
        if bi.response.transaction_count > 0 {
            let mut events = client
                .get_block_transaction_events(v.block_hash)
                .await?
                .response;
            while let Some(event) = events.next().await.transpose()? {
                if event
                    .affected_contracts()
                    .contains(&ContractAddress::new(866, 0))
                {
                    println!(
                        "Transaction {} with sender {}.",
                        event.hash,
                        event.sender_account().unwrap()
                    )
                }
            }
        } else {
        };
    }
    Ok(())
}
