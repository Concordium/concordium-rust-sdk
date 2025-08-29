//! Find when an account was created on the chain.
//! That is, the block in which the account creation transaction is committed.
use clap::AppSettings;
use concordium_rust_sdk::{id::types::AccountAddress, types::BlockItemSummaryDetails, v2};
use futures::stream::StreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC V2 interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "account")]
    account: AccountAddress,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint).await?;

    let Ok((_, bh, _)) = client.find_account_creation(.., app.account).await else {
        println!("Account not found.");
        return Ok(());
    };
    println!("Account created in block {}.", bh);
    let bi = client.get_block_info(&bh).await?.response;
    println!("Timestamp of this block {}.", bi.block_slot_time);
    let mut block_summary = client.get_block_transaction_events(&bh).await?.response;
    while let Some(summary) = block_summary.next().await.transpose()? {
        if let BlockItemSummaryDetails::AccountCreation(ac) = &summary.details {
            if ac.address == app.account {
                println!("Created by transaction hash {}", summary.hash);
                break;
            }
        }
    }
    Ok(())
}
