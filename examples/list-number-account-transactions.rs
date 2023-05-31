//! List the number of transactions sent by each account
//! starting at the given time and then every interval after.
//!
//! The output of the script is on stdout. For each account
//! it prints a comma separated list of transactions submitted by that account
//! per day.
//!
//! The script also outputs progress on stderr before printing the final result.
use std::collections::BTreeMap;

use clap::AppSettings;
use concordium_base::contracts_common::AccountAddress;
use concordium_rust_sdk::{types::AbsoluteBlockHeight, v2};
use futures::{stream::FuturesOrdered, StreamExt, TryStreamExt};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC V2 interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "start-time",
        help = "Start time. If not given take the genesis time."
    )]
    block:    Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(
        long = "interval",
        help = "Interval duration in seconds.",
        default_value = "86400"
    )]
    interval: u64,
    #[structopt(
        long = "num",
        help = "How many queries to make in parallel.",
        default_value = "8"
    )]
    num:      usize,
}

#[derive(Eq)]
struct Aliased(AccountAddress);

impl Ord for Aliased {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.0 .0[..29].cmp(&other.0 .0[..29]) }
}

impl PartialEq for Aliased {
    fn eq(&self, other: &Self) -> bool { self.0.is_alias(&other.0) }
}

impl PartialOrd for Aliased {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0 .0[..29].partial_cmp(&other.0 .0[..29])
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app: App = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint).await?;

    let consensus_info = client.get_consensus_info().await?;

    let start_time = app.block.unwrap_or(consensus_info.genesis_time);
    let mut account_table = BTreeMap::new();

    let start_block = client
        .find_first_finalized_block_no_later_than(
            ..=consensus_info.last_finalized_block_height,
            start_time,
        )
        .await?;

    let heights =
        u64::from(start_block.block_height)..=u64::from(consensus_info.last_finalized_block_height);

    let mut blocks = heights.map(|n| {
        let mut client = client.clone();
        async move {
            let bi = client.get_block_info(&AbsoluteBlockHeight::from(n)).await?;
            let v = client
                .get_block_transaction_events(bi.block_hash)
                .await?
                .response
                .map_ok(|e| e.sender_account())
                .try_collect::<Vec<_>>()
                .await;
            Ok::<_, anyhow::Error>(v.map(|r| (bi.response, r)))
        }
    });

    let mut max_days = 0;
    while let Some(n) = blocks.next() {
        let mut chunk = Vec::with_capacity(app.num);
        chunk.push(n);
        for _ in 1..app.num {
            if let Some(n) = blocks.next() {
                chunk.push(n);
            } else {
                break;
            }
        }
        let mut stream = chunk.into_iter().collect::<FuturesOrdered<_>>();
        while let Some((bi, r)) = stream.next().await.transpose()?.transpose()? {
            eprintln!(
                "Processing block {} at height {}.",
                bi.block_hash, bi.block_height
            );
            let day = bi
                .block_slot_time
                .signed_duration_since(start_time)
                .num_seconds()
                / app.interval as i64;
            max_days = std::cmp::max(day as usize, max_days);
            for acc in r.into_iter().flatten() {
                if let Some(n) = account_table
                    .entry(Aliased(acc))
                    .or_insert_with(|| vec![0u64; day as usize + 1])
                    .last_mut()
                {
                    *n += 1;
                }
            }
            eprintln!("Processed block.");
        }
    }
    for (acc, mut values) in account_table {
        values.resize(max_days, 0);
        println!(
            "{}, {}",
            acc.0,
            values
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(())
}
