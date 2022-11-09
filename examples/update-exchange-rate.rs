//! An example showing how to do a simple update of the exchange rate between
//! CCD and EUR.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::types::TransactionTime,
    endpoints::{self, Endpoint},
    types::{
        transactions::{update, BlockItem, Payload},
        BlockSummary, ExchangeRate, TransactionStatus, UpdateKeyPair, UpdatePayload,
    },
};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint: Endpoint,
    #[structopt(
        long = "rpc-token",
        help = "GRPC interface access token for accessing all the nodes.",
        default_value = "rpcadmin"
    )]
    token:    String,
    #[structopt(long = "key", help = "Path to update keys to use.")]
    keys:     Vec<PathBuf>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let kps: Vec<UpdateKeyPair> = app
        .keys
        .iter()
        .map(|p| {
            serde_json::from_reader(std::fs::File::open(p).context("Could not open file.")?)
                .context("Could not read keys from file.")
        })
        .collect::<anyhow::Result<_>>()?;

    let mut client = endpoints::Client::connect(app.endpoint, app.token).await?;

    let consensus_status = client
        .get_consensus_status()
        .await
        .context("Could not obtain status of consensus.")?;

    // Get the key indices, as well as the next sequence number from the last
    // finalized block.
    let summary: BlockSummary = client
        .get_block_summary(&consensus_status.last_finalized_block)
        .await
        .context("Could not obtain last finalized block")?;

    // find the key indices to sign with
    let signer = summary
        .common_update_keys()
        .construct_update_signer(&summary.common_update_keys().micro_gtu_per_euro, kps)
        .context("Invalid keys supplied.")?;

    let seq_number = match &summary {
        BlockSummary::V0 { data, .. } => {
            data.updates
                .update_queues
                .micro_gtu_per_euro
                .next_sequence_number
        }
        BlockSummary::V1 { data, .. } => {
            data.updates
                .update_queues
                .micro_gtu_per_euro
                .next_sequence_number
        }
    };

    let effective_time = 0.into(); // immediate effect
    let timeout =
        TransactionTime::from_seconds(chrono::offset::Utc::now().timestamp() as u64 + 300); // 5min expiry.,
    let payload = UpdatePayload::MicroGTUPerEuro(ExchangeRate::new_unchecked(1, 1));
    let block_item: BlockItem<Payload> =
        update::update(&signer, seq_number, effective_time, timeout, payload).into();

    let submission_id = client
        .send_block_item(&block_item)
        .await
        .context("Could not send the update instruction.")?;

    println!("Submitted update with hash {}", submission_id);

    // wait until it's finalized.
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        match client
            .get_transaction_status(&submission_id)
            .await
            .context("Could not query submission status.")?
        {
            TransactionStatus::Finalized(blocks) => {
                println!(
                    "Submission is finalized in blocks {:?}",
                    blocks.keys().collect::<Vec<_>>()
                );
                break;
            }
            TransactionStatus::Committed(blocks) => {
                println!(
                    "Submission is committed to blocks {:?}",
                    blocks.keys().collect::<Vec<_>>()
                );
            }
            TransactionStatus::Received => {
                println!("Submission is received.")
            }
        }
    }

    Ok(())
}
