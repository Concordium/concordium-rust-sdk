//! List all account creations in a given time span.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    endpoints::{self, Endpoint},
    types::{
        queries::BlockInfo, AbsoluteBlockHeight, BlockItemSummary, BlockItemSummaryDetails,
        BlockSummary, CredentialType,
    },
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
        help = "Number of parallel queries to make.",
        default_value = "4"
    )]
    num:      u64,
    #[structopt(long = "from", help = "Starting time. Defaults to genesis time.")]
    from:     Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(long = "to", help = "End time. Defaults to infinity.")]
    to:       Option<chrono::DateTime<chrono::Utc>>,
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
                    return Ok::<Option<(BlockInfo, Option<BlockSummary>)>, anyhow::Error>(None);
                }
                let bi = cc.get_block_info(&blocks[0]).await.context("Block info.")?;
                if !bi.finalized {
                    return Ok::<_, anyhow::Error>(None);
                }
                if bi.transaction_count != 0 {
                    let summary = cc
                        .get_block_summary(&blocks[0])
                        .await
                        .context("Block summary.")?;
                    Ok(Some((bi, Some(summary))))
                } else {
                    Ok::<_, anyhow::Error>(Some((bi, None)))
                }
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
                h = h.next();
                if let Some(summary) = summary {
                    for BlockItemSummary {
                        index: _,
                        energy_cost: _,
                        hash: _,
                        details,
                    } in summary.transaction_summaries()
                    {
                        match details {
                            BlockItemSummaryDetails::AccountTransaction(_) => {}
                            BlockItemSummaryDetails::AccountCreation(x) => {
                                let acc_type = match x.credential_type {
                                    CredentialType::Initial => "initial",
                                    CredentialType::Normal => "normal",
                                };
                                println!(
                                    "{}, {}, {}, {}",
                                    x.address, bi.block_hash, bi.block_slot_time, acc_type
                                );
                            }
                            BlockItemSummaryDetails::Update(_) => (),
                        }
                    }
                }
            } else {
                success = false;
                break;
            }
        }
        if !success {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}
