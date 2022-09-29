//! An example showing how to do a simple update of the exchange rate between
//! CCD and EUR. It sets the rate to be the same as the current.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    endpoints,
    types::{
        transactions::{update, BlockItem, Payload},
        BlockSummary, TransactionStatus, UpdateKeyPair, UpdatePayload,
    },
    v2,
};
use crypto_common::types::TransactionTime;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node-v1",
        help = "GRPC v1 interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint_v1: tonic::transport::Endpoint,
    #[structopt(
        long = "node-v2",
        help = "GRPC v2 interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint_v2: tonic::transport::Endpoint,
    #[structopt(long = "key", help = "Path to update keys to use.")]
    keys:        Vec<PathBuf>,
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

    let mut client = v2::Client::new(app.endpoint_v2)
        .await
        .context("Cannot connect to v2")?;

    // Get the key indices, as well as the next sequence number from the last
    // finalized block.
    // TODO: Use v2 client once chain parameter endpoint is implemented.
    let summary: BlockSummary = {
        let mut client_v1 = endpoints::Client::connect(app.endpoint_v1, "rpcadmin")
            .await
            .context("Cannot connect to v1")?;

        let consensus_status = client_v1
            .get_consensus_status()
            .await
            .context("Could not obtain status of consensus.")?;

        // Get the key indices, as well as the next sequence number from the last
        // finalized block.
        client_v1
            .get_block_summary(&consensus_status.last_finalized_block)
            .await
            .context("Could not obtain last finalized block")?
    };

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

    let exchange_rate = match &summary {
        BlockSummary::V0 { data, .. } => data.updates.chain_parameters.micro_gtu_per_euro,
        BlockSummary::V1 { data, .. } => data.updates.chain_parameters.micro_gtu_per_euro,
    };

    let effective_time = 0.into(); // immediate effect
    let timeout =
        TransactionTime::from_seconds(chrono::offset::Utc::now().timestamp() as u64 + 300); // 5min expiry.
    let payload = UpdatePayload::MicroGTUPerEuro(exchange_rate);
    let block_item: BlockItem<Payload> =
        update::update(&signer, seq_number, effective_time, timeout, payload).into();

    println!("Sending block item");

    let submission_id = client
        .send_block_item_unencoded(&block_item)
        .await
        .context("Could not send the update instruction.")?;

    println!("Submitted update with hash {}", submission_id);

    // wait until it's finalized.
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        match client
            .get_block_item_status(&submission_id)
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
