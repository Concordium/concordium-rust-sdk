//! List account transactions in a given time span. Either all, or
//! just the specified types.
use anyhow::Context;
use chrono::Utc;
use clap::AppSettings;
use concordium_rust_sdk::{
    types::{
        AbsoluteBlockHeight, AccountTransactionEffects, BlockItemSummaryDetails, TransactionType,
    },
    v2,
};
use futures::TryStreamExt;
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
    num:      u64,
    #[structopt(long = "from", help = "Starting time. Defaults to genesis time.")]
    from:     Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(long = "to", help = "End time. Defaults to infinity.")]
    to:       Option<chrono::DateTime<Utc>>,
    #[structopt(
        long = "only",
        help = "Only display the given transaction type(s). If no specific types are given all \
                types are displayed."
    )]
    types:    Vec<String>,
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

    let mut client = v2::Client::new(app.endpoint).await?;

    let _cs = client.get_consensus_info().await?;

    // Find the block to start at.
    let mut h = if let Some(start_time) = app.from {
        let start = client
            .find_first_finalized_block_no_earlier_than(.., start_time)
            .await?;
        start.block_height
    } else {
        AbsoluteBlockHeight::from(0u64)
    };
    // Query blocks by increasing height.
    let mut block_stream = client.get_finalized_blocks_from(h).await?;
    while let Ok((timeout, chunk)) = block_stream
        .next_chunk_timeout(app.num as usize, std::time::Duration::from_millis(500))
        .await
    {
        let mut handles = Vec::with_capacity(app.num as usize);
        for block in chunk {
            let mut cc = client.clone();
            handles.push(tokio::spawn(async move {
                let bi = cc
                    .get_block_info(block.block_hash)
                    .await
                    .context("Block info.")?
                    .response;
                if bi.transaction_count != 0 {
                    let summary = cc
                        .get_block_transaction_events(block.block_hash)
                        .await
                        .context("Block summary.")?
                        .response
                        .try_collect::<Vec<_>>()
                        .await?;
                    Ok((bi, Some(summary)))
                } else {
                    Ok::<_, anyhow::Error>((bi, None))
                }
            }))
        }
        for res in futures::future::join_all(handles).await {
            let (bi, summary) = res??;
            if let Some(end) = app.to.as_ref() {
                if end <= &bi.block_slot_time {
                    return Ok(());
                }
            }
            h = h.next();
            if let Some(summary) = summary {
                for bisummary in summary {
                    if let BlockItemSummaryDetails::AccountTransaction(at) = &bisummary.details {
                        if types.is_empty()
                            || at
                                .transaction_type()
                                .map_or(false, |tt| types.contains(&tt))
                        {
                            let is_success =
                                !matches!(&at.effects, AccountTransactionEffects::None { .. });
                            let type_string = at
                                .transaction_type()
                                .map_or_else(|| "N/A".into(), |tt| tt.to_string());
                            println!(
                                "{}, {}, {}, {}, {}",
                                bi.block_slot_time,
                                bi.block_hash,
                                bisummary.hash,
                                is_success,
                                type_string
                            )
                        }
                    }
                }
            }
        }
        if timeout {
            // if we failed and end time is not yet here, then wait a bit
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    Ok(())
}
