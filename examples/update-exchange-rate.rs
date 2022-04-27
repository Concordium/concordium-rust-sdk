//! An example showing how to do a simple update of the exchange rate between
//! CCD and EUR.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    constants::DEFAULT_NETWORK_ID,
    endpoints,
    types::{
        transactions::{update, BlockItem, Payload},
        BlockSummary, ExchangeRate, TransactionStatus, UpdateKeysIndex, UpdatePayload,
    },
};
use crypto_common::{
    base16_encode_string,
    types::{KeyPair, TransactionTime},
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
    endpoint: tonic::transport::Endpoint,
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

    let kps: Vec<KeyPair> = app
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

    let update_keys = &summary.common_update_keys().keys;
    let update_key_indices = &summary.common_update_keys().micro_gtu_per_euro;
    // find the key indices to sign with
    let mut signer = Vec::new();
    for kp in kps {
        if let Some(i) = update_keys
            .iter()
            .position(|public| public.public == kp.public.into())
        {
            let idx = UpdateKeysIndex { index: i as u16 };
            if update_key_indices.authorized_keys.contains(&idx) {
                signer.push((idx, kp))
            } else {
                anyhow::bail!(
                    "The given key {} is not registered for the CCD/Eur rate update.",
                    base16_encode_string(&kp.public)
                );
            }
        } else {
            anyhow::bail!(
                "The given key {} is not registered for any level 2 updates.",
                base16_encode_string(&kp.public)
            );
        }
    }

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
    let payload = UpdatePayload::MicroGTUPerEuro(ExchangeRate {
        numerator:   1,
        denominator: 1,
    }); // make the exchange rate 1:1
    let block_item: BlockItem<Payload> = update::update(
        signer.as_slice(),
        seq_number,
        effective_time,
        timeout,
        payload,
    )
    .into();

    let response = client
        .send_transaction(DEFAULT_NETWORK_ID, &block_item)
        .await
        .context("Could not send transaction.")?;
    anyhow::ensure!(response, "Submission of the update instruction failed.");

    let submission_id = block_item.hash();
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
