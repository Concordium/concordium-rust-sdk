//! List all account creations in a given time span.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    types::{
        queries::BlockInfo, AbsoluteBlockHeight, BlockItemSummary, BlockItemSummaryDetails,
        BlockSummary, CredentialType,
    },
    v2,
};
use futures::TryStreamExt;
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

    let mut client = v2::Client::new(app.endpoint).await?;

    let mut h = if let Some(start_time) = app.from {
        let start = client
            .find_first_finalized_block_no_earlier_than(.., start_time)
            .await?;
        start.block_height
    } else {
        AbsoluteBlockHeight::from(0u64)
    };

    let mut block_stream = client.get_finalized_blocks_from(h).await?;

    while let Ok(chunk) = block_stream.next_chunk(app.num as usize).await {
        let mut handles = Vec::with_capacity(chunk.len());

        for (h, block) in (u64::from(h)..).zip(chunk) {
            let cc = client.clone();
            handles.push(tokio::spawn(async move {
                let mut cc = cc.clone();
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
                    } in summary
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
    Ok(())
}
