//! Traverse all transactions on the chain from a given block backwards.
//! This is mainly used to test integration and compatibility of the SDK with
//! the node.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    endpoints::{self, Endpoint},
    types, v2,
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node-v1",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint_v1: Endpoint,
    #[structopt(
        long = "node-v2",
        help = "GRPC2 interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint_v2: Endpoint,
    #[structopt(long = "block")]
    start_block: Option<types::hashes::BlockHash>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app: App = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client_v1 = endpoints::Client::connect(app.endpoint_v1, "rpcadmin".to_string())
        .await
        .context("Cannot connect to grpc v1")?;

    let client_v2 = v2::Client::new(app.endpoint_v2)
        .await
        .context("Cannot connect to grpc v2.")?;

    let consensus_info = client_v1.get_consensus_status().await?;
    println!("{}", serde_json::to_string_pretty(&consensus_info).unwrap());

    let gb = consensus_info.genesis_block;
    let mut cb = app.start_block.unwrap_or(consensus_info.best_block);
    while cb != gb {
        println!("{}", cb);
        let bi = client_v1.get_block_info(&cb).await?;
        if bi.transaction_count != 0 {
            println!("Processing block {}", cb);
            let bs = client_v1
                .get_block_summary(&cb)
                .await
                .context("Could not get block summary")?;
            let trxs = bs.transaction_summaries();

            for trx in trxs {
                let mut cc2 = client_v2.clone();
                let hash = trx.hash;
                tokio::spawn(async move {
                    match cc2.get_block_item_status(&hash).await {
                        Ok(res) => {
                            println!("{:#?}", res);
                        }
                        Err(e) => {
                            panic!("Failed to process transaction: {}: {}", hash, e);
                        }
                    }
                });
            }
        }
        cb = bi.block_parent;
    }

    println!("Done.");

    Ok(())
}
