//! Find when an account was created on the chain.
//! That is, the block in which the account creation transaction is committed.
use clap::AppSettings;
use concordium_rust_sdk::{
    endpoints,
    id::types::AccountAddress,
    types::{self, AbsoluteBlockHeight, BlockItemSummaryDetails},
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint:    endpoints::Endpoint,
    #[structopt(long = "block")]
    start_block: Option<types::hashes::BlockHash>,
    #[structopt(long = "account")]
    account:     AccountAddress,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = endpoints::Client::connect(app.endpoint, "rpcadmin".to_string()).await?;

    let consensus_info = client.get_consensus_status().await?;

    let cb = app.start_block.unwrap_or(consensus_info.best_block);
    let goal_addr = &app.account;
    let bi = client.get_block_info(&cb).await?;
    let mut end: u64 = bi.block_height.into();
    let mut start = 0;
    // We do bisection to fixate on the block height.
    while start < end {
        let mid = (start + end) / 2;
        let bh = client
            .get_blocks_at_height(AbsoluteBlockHeight::from(mid).into())
            .await?[0];
        println!("Processing block at height {}.", mid);
        match client.get_account_info(goal_addr, &bh).await {
            Ok(_) => {
                end = mid;
            }
            Err(e) if e.is_not_found() => {
                start = mid + 1;
            }
            Err(e) => anyhow::bail!(e),
        }
    }
    // Once we found the height, we get the account info and the hash of the
    // creation transaction.
    let bh = client
        .get_blocks_at_height(AbsoluteBlockHeight::from(start).into())
        .await?[0];
    if client.get_account_info(goal_addr, &bh).await.is_ok() {
        println!("Account created in block {}.", bh);
        let bi = client.get_block_info(&bh).await?;
        println!("Timestamp of this block {}.", bi.block_slot_time);
        let block_summary = client.get_block_summary(&bh).await?;
        for summary in block_summary.transaction_summaries() {
            if let BlockItemSummaryDetails::AccountCreation(ac) = &summary.details {
                if ac.address == app.account {
                    println!("Created by transaction hash {}", summary.hash);
                    break;
                }
            }
        }
    } else {
        println!("Account not found.")
    }
    Ok(())
}
