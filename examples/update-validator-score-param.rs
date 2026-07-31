//! An example showing how to do a simple update of the validator score
//! parameters.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::updates::ValidatorScoreParameters;
use concordium_rust_sdk::{
    common::types::TransactionTime,
    types::{
        chain_parameters::ChainParameters,
        transactions::{update, BlockItem, Payload},
        TransactionStatus, UpdateKeyPair, UpdatePayload,
    },
    v2::{self, BlockIdentifier},
};
use std::path::PathBuf;
use structopt::StructOpt;
use tokio_stream::StreamExt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "key", help = "Path to update keys to use.")]
    keys: Vec<PathBuf>,
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

    let mut client = v2::Client::new(app.endpoint).await?;

    // Get the key indices, as well as the next sequence number from the last
    // finalized block.
    let summary: ChainParameters = client
        .get_block_chain_parameters(BlockIdentifier::LastFinal)
        .await
        .context("Could not obtain last finalized block's chain parameters")?
        .response;

    let keys = summary
        .keys
        .level_2_keys
        .context("No level 2 keys in chain parameters.")?;

    // find the key indices to sign with
    let signer = keys
        .construct_update_signer(
            keys.micro_ccd_per_euro
                .as_ref()
                .context("Missing micro CCD per Euro update keys.")?,
            kps,
        )
        .context("Invalid keys supplied.")?;

    let seq_number = client
        .get_next_update_sequence_numbers(BlockIdentifier::LastFinal)
        .await?
        .response;
    let seq_number = seq_number.validator_score_parameters;

    let now = chrono::offset::Utc::now().timestamp() as u64;
    let effective_time = TransactionTime::from_seconds(now + 300); // effective in 5min
    let timeout = TransactionTime::from_seconds(now + 60); // 1min expiry.
    let payload = UpdatePayload::ValidatorScoreParametersCPV3(ValidatorScoreParameters {
        max_missed_rounds: 10,
    });
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
    let mut pending_updates = client
        .get_block_pending_updates(BlockIdentifier::LastFinal)
        .await?
        .response;

    while let Some(update) = pending_updates.next().await.transpose()? {
        // Display the update with the serde JSON serialization.
        #[cfg(feature = "serde_deprecated")]
        println!("Pending update: {}", serde_json::to_string_pretty(&update)?);
        #[cfg(not(feature = "serde_deprecated"))]
        println!("Pending update: {:?}", &update);
    }

    Ok(())
}
