//! Traverse blocks in a given time span and query statistics.
//! For each block print
//! - block hash
//! - block slot time
//! - receive time of the block at the given node
//! - arrive time of the block at the given node
//! - difference between receive and slot times
//! - difference between arrive and slot times
//! - number of events associated with payday
//! - whether the block contains a finalization record
//! - the number of transactions included in the block
use chrono::Utc;
use clap::AppSettings;
use concordium_rust_sdk::{
    types::{AbsoluteBlockHeight, SpecialTransactionOutcome},
    v2,
    v2::Endpoint,
};
use futures::TryStreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC V2 interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: Endpoint,
    #[structopt(long = "from", help = "Starting time. Defaults to genesis time.")]
    from:     Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(long = "to", help = "End time. Defaults to the time the tool has run.")]
    to:       Option<chrono::DateTime<Utc>>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint).await?;

    // Find the starting block.
    let mut h = if let Some(start_time) = app.from {
        let b = client
            .find_at_lowest_height(.., |mut client, height| async move {
                let bi = client.get_block_info(&height).await?.response;
                Ok(if bi.block_slot_time >= start_time {
                    Some(bi)
                } else {
                    None
                })
            })
            .await;
        match b {
            Ok(bi) => bi.block_height,
            Err(e) if e.is_not_found() => {
                anyhow::bail!("Last finalized block is not after the requested start time.")
            }
            Err(e) => anyhow::bail!("An error occurred: {e:#}"),
        }
    } else {
        AbsoluteBlockHeight::from(0u64)
    };
    let mut block_count: u32 = 0;
    let mut finalization_count: u32 = 0;
    let mut blocks = client.get_finalized_blocks_from(h).await?;
    let end_time = app.to.unwrap_or_else(chrono::Utc::now);
    while let Some(block) = blocks.next().await {
        let bi = client.get_block_info(block.block_hash).await?.response;
        if bi.block_slot_time > end_time {
            break;
        }
        let payday_block = client
            .get_block_special_events(bi.block_hash)
            .await?
            .response
            .try_fold(0, |count, ev| async move {
                let add = match ev {
                    SpecialTransactionOutcome::PaydayFoundationReward { .. } => 1u32,
                    SpecialTransactionOutcome::PaydayAccountReward { .. } => 1u32,
                    SpecialTransactionOutcome::PaydayPoolReward { .. } => 1u32,
                    _ => 0u32,
                };
                Ok(count + add)
            })
            .await?;
        h = h.next();
        let has_finalization_data = client
            .get_block_finalization_summary(bi.block_hash)
            .await?
            .response
            .is_some();
        println!(
            "{}, {}, {}, {}, {}ms, {}ms, {}, {}, {}",
            bi.block_hash,
            bi.block_slot_time.format("%H:%M:%S%.3f"),
            bi.block_receive_time.format("%H:%M:%S%.3f"),
            bi.block_arrive_time.format("%H:%M:%S%.3f"),
            bi.block_receive_time
                .signed_duration_since(bi.block_slot_time)
                .num_milliseconds(),
            bi.block_arrive_time
                .signed_duration_since(bi.block_slot_time)
                .num_milliseconds(),
            payday_block,
            has_finalization_data,
            bi.transaction_count
        );
        if has_finalization_data {
            finalization_count += 1
        };
        block_count += 1;
    }
    println!("Block count = {}", block_count);
    println!("Finalization record count = {}", finalization_count);
    Ok(())
}
