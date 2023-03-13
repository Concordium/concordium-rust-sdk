//! List all discoverable CIS2 contracts.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    cis2,
    types::{queries::BlockInfo, AbsoluteBlockHeight, BlockItemSummary, ContractAddress},
    v2,
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
    endpoint:     v2::Endpoint,
    #[structopt(
        long = "height",
        help = "Height to start on. Defaults to when the instance was created."
    )]
    start_height: Option<AbsoluteBlockHeight>,
    #[structopt(
        long = "num",
        help = "How many queries to make in parallel.",
        default_value = "8"
    )]
    num:          u64,
    #[structopt(long = "contract", help = "Which contract to query.")]
    contract:     ContractAddress,
}

/// Attempt to extract CIS2 events from the block item.
/// If the transaction is a smart contract init or update transaction then
/// attempt to parse the events as CIS2 events. If any of the events fail
/// parsing then the logs for that section of execution are ignored, since it
/// indicates an error in the contract.
///
/// The return value of [`None`] means there are no understandable CIS2 logs
/// produced.
fn get_cis2_events(bi: &BlockItemSummary) -> Option<Vec<(ContractAddress, Vec<cis2::Event>)>> {
    match bi.contract_update_logs() {
        Some(log_iter) => Some(
            log_iter
                .flat_map(|(ca, logs)| {
                    match logs
                        .iter()
                        .map(cis2::Event::try_from)
                        .collect::<Result<Vec<cis2::Event>, _>>()
                    {
                        Ok(events) => Some((ca, events)),
                        Err(_) => None,
                    }
                })
                .collect(),
        ),
        None => {
            let init = bi.contract_init()?;
            let cis2 = init
                .events
                .iter()
                .map(cis2::Event::try_from)
                .collect::<Result<Vec<cis2::Event>, _>>()
                .ok()?;
            Some(vec![(init.address, cis2)])
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint).await?;

    let mut h = if let Some(h) = app.start_height {
        h
    } else {
        client
            .find_instance_creation(AbsoluteBlockHeight::from(0).., app.contract)
            .await?
            .0
    };
    let end = client
        .get_consensus_info()
        .await?
        .last_finalized_block_height;

    loop {
        let mut handles = Vec::with_capacity(app.num as usize);
        for height in u64::from(h)..u64::from(h) + app.num {
            let cc = client.clone();
            handles.push(tokio::spawn(async move {
                let h: AbsoluteBlockHeight = height.into();
                let mut cc = cc.clone();
                let blocks = cc
                    .get_blocks_at_height(&h.into())
                    .await
                    .context("Blocks at height.")?;
                if blocks.is_empty() {
                    return Ok::<Option<(BlockInfo, Option<Vec<BlockItemSummary>>)>, anyhow::Error>(
                        None,
                    );
                }
                let bi = cc.get_block_info(&blocks[0]).await.context("Block info.")?;
                if bi.response.transaction_count != 0 {
                    let summary = cc
                        .get_block_transaction_events(&blocks[0])
                        .await
                        .context("Block summary.")?;
                    Ok(Some((
                        bi.response,
                        Some(summary.response.try_collect().await?),
                    )))
                } else {
                    Ok::<_, anyhow::Error>(Some((bi.response, None)))
                }
            }))
        }
        for res in futures::future::join_all(handles).await {
            if let Some((bi, summary)) = res?? {
                if end <= bi.block_height {
                    return Ok(());
                }
                h = h.next();
                if let Some(summary) = summary {
                    for bisummary in summary {
                        let affected = bisummary
                            .affected_contracts()
                            .contains(&ContractAddress::new(599, 0));
                        if affected {
                            println!("Transaction {} affects contract at 599.", bisummary.hash);
                            if let Some(events) = get_cis2_events(&bisummary) {
                                for (ca, events) in events {
                                    if ca == app.contract {
                                        for event in events {
                                            println!("{event}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                break;
            }
        }
    }
}
