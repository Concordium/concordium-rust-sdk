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
use anyhow::Context;
use chrono::Utc;
use clap::AppSettings;
use concordium_rust_sdk::{
    endpoints::{self, Endpoint},
    types::{queries::BlockInfo, AbsoluteBlockHeight, BlockSummary, SpecialTransactionOutcome},
};
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
        long = "num",
        help = "How many queries to make in parallel.",
        default_value = "1"
    )]
    num:      u64,
    #[structopt(long = "from", help = "Starting time. Defaults to genesis time.")]
    from:     Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(long = "to", help = "End time. Defaults to infinity.")]
    to:       Option<chrono::DateTime<Utc>>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = endpoints::Client::connect(app.endpoint, "rpcadmin".to_string()).await?;

    let cs = client.get_consensus_status().await?;

    // Find the starting block.
    let mut h = if let Some(start_time) = app.from {
        let cb = cs.last_finalized_block;
        let mut bi = client.get_block_info(&cb).await?;
        anyhow::ensure!(
            bi.block_slot_time >= start_time,
            "Last finalized block is not after the requested start time ({})",
            bi.block_slot_time.to_rfc3339()
        );
        let mut end: u64 = bi.block_height.into();
        let mut start = 0;
        while start < end {
            let mid = (start + end) / 2;
            let bh = client
                .get_blocks_at_height(AbsoluteBlockHeight::from(mid).into())
                .await?[0];
            bi = client.get_block_info(&bh).await?;
            if bi.block_slot_time < start_time {
                start = mid + 1;
            } else {
                end = mid;
            }
        }
        start.into()
    } else {
        AbsoluteBlockHeight::from(0u64)
    };
    let mut block_count: u32 = 0;
    let mut finalization_count: u32 = 0;
    loop {
        let mut handles = Vec::with_capacity(app.num as usize);
        for height in u64::from(h)..u64::from(h) + app.num {
            let cc = client.clone();
            handles.push(tokio::spawn(async move {
                let h: AbsoluteBlockHeight = height.into();
                let mut cc = cc.clone();
                let blocks = cc
                    .get_blocks_at_height(h.into())
                    .await
                    .context("Blocks at height.")?;
                if blocks.is_empty() {
                    return Ok::<Option<(BlockInfo, BlockSummary)>, anyhow::Error>(None);
                }
                let bi = cc.get_block_info(&blocks[0]).await.context("Block info.")?;
                if !bi.finalized {
                    return Ok::<_, anyhow::Error>(None);
                }
                let summary = cc
                    .get_block_summary(&blocks[0])
                    .await
                    .context("Block summary.")?;
                Ok(Some((bi, summary)))
            }))
        }
        let mut success = true;
        for res in futures::future::join_all(handles).await {
            if let Some((bi, summary)) = res?? {
                if let Some(end) = app.to.as_ref() {
                    if end <= &bi.block_slot_time {
                        return Ok(());
                    }
                }
                let payday_block = summary
                    .special_events()
                    .iter()
                    .map(|ev| match ev {
                        SpecialTransactionOutcome::PaydayFoundationReward { .. } => 1u32,
                        SpecialTransactionOutcome::PaydayAccountReward { .. } => 1u32,
                        SpecialTransactionOutcome::PaydayPoolReward { .. } => 1u32,
                        _ => 0u32,
                    })
                    .sum::<u32>();
                h = h.next();
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
                    summary.finalization_data().is_some(),
                    bi.transaction_count
                );
                if summary.finalization_data().is_some() {
                    finalization_count += 1
                };
                block_count += 1;
            } else {
                success = false;
                break;
            }
        }
        if !success {
            break;
        }
    }
    println!("Block count = {}", block_count);
    println!("Finalization record count = {}", finalization_count);
    Ok(())
}
