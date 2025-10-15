//! List account transactions in a given time span. Either all, or
//! just the specified types.
use anyhow::Context;
use chrono::Utc;
use clap::AppSettings;
use concordium_rust_sdk::{
    indexer::{TransactionIndexer, TraverseConfig},
    types::{
        AbsoluteBlockHeight, AccountTransactionEffects, BlockItemSummaryDetails, TransactionType,
    },
    v2::{self, upward::Upward},
};
use std::collections::HashSet;
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
        long = "num",
        help = "How many queries to make in parallel.",
        default_value = "1"
    )]
    num: usize,
    #[structopt(long = "from", help = "Starting time. Defaults to genesis time.")]
    from: Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(long = "to", help = "End time. Defaults to infinity.")]
    to: Option<chrono::DateTime<Utc>>,
    #[structopt(
        long = "only",
        help = "Only display the given transaction type(s). If no specific types are given all \
                types are displayed."
    )]
    types: Vec<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let types = app
        .types
        .into_iter()
        .map(|x| {
            let addr = serde_json::from_value(serde_json::Value::String(x))?;
            Ok(addr)
        })
        .collect::<anyhow::Result<HashSet<TransactionType>>>()
        .context("Could not read transaction types.")?;

    let mut client = v2::Client::new(app.endpoint.clone()).await?;

    // Find the block to start at.
    let h = if let Some(start_time) = app.from {
        let start = client
            .find_first_finalized_block_no_earlier_than(.., start_time)
            .await?;
        start.block_height
    } else {
        AbsoluteBlockHeight::from(0u64)
    };
    // Query blocks by increasing height.
    let (sender, mut receiver) = tokio::sync::mpsc::channel(10);
    tokio::spawn(
        TraverseConfig::new_single(app.endpoint, h)
            .set_max_parallel(app.num)
            .traverse(TransactionIndexer, sender),
    );
    while let Some((bi, summary)) = receiver.recv().await {
        if let Some(end) = app.to.as_ref() {
            if end <= &bi.block_slot_time {
                return Ok(());
            }
        }
        for bisummary in summary {
            let Upward::Known(BlockItemSummaryDetails::AccountTransaction(at)) = &bisummary.details
            else {
                continue;
            };
            let Upward::Known(effects) = &at.effects else {
                continue;
            };
            let Some(transaction_type) = effects.transaction_type() else {
                continue;
            };
            if !types.is_empty() && !types.contains(&transaction_type) {
                continue;
            }
            let is_success = !matches!(effects, AccountTransactionEffects::None { .. });
            println!(
                "{}, {}, {}, {}, {}",
                bi.block_slot_time, bi.block_hash, bisummary.hash, is_success, transaction_type
            );
        }
    }
    Ok(())
}
