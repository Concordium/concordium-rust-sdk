//! List the number of transactions sent by each account
//! starting at the given time and then every interval after.
//!
//! The output of the script is on stdout. For each account
//! it prints a comma separated list of transactions submitted by that account
//! per day.
//!
//! The script also outputs progress on stderr before printing the final result.
use clap::AppSettings;
use concordium_base::contracts_common::AccountAddress;
use concordium_rust_sdk::{
    indexer::{TransactionIndexer, TraverseConfig},
    v2,
};
use std::collections::BTreeMap;
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
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app: App = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint.clone()).await?;

    let consensus_info = client.get_consensus_info().await?;

    let start_time = app.block.unwrap_or(consensus_info.genesis_time);
    let mut account_table = BTreeMap::new();

    let start_block = client
        .find_first_finalized_block_no_earlier_than(
            ..=consensus_info.last_finalized_block_height,
            start_time,
        )
        .await?;

    let (sender, mut receiver) = tokio::sync::mpsc::channel(10);
    let cancel_handle = tokio::spawn(
        TraverseConfig::new_single(app.endpoint, start_block.block_height)
            .set_max_parallel(app.num)
            .traverse(TransactionIndexer, sender),
    );

    let mut max_days = 0;
    while let Some((bi, r)) = receiver.recv().await {
        if bi.block_height > consensus_info.last_finalized_block_height {
            break;
        }
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
        for acc in r.into_iter().filter_map(|x| x.sender_account()) {
            if let Some(n) = account_table
                .entry(Aliased(acc))
                .or_insert_with(|| vec![0u64; day as usize + 1])
                .last_mut()
            {
                *n += 1;
            }
        }
    }
    cancel_handle.abort();
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
