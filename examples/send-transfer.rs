//! Basic example that shows how to send a transaction, in this case a transfer
//! from the account to itself.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::types::{Amount, TransactionTime},
    endpoints,
    types::{
        transactions::{send, BlockItem},
        AccountInfo, WalletAccount,
    },
};
use std::path::PathBuf;
use structopt::*;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint:  endpoints::Endpoint,
    #[structopt(long = "account", help = "Path to the account key file.")]
    keys_path: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = endpoints::Client::connect(app.endpoint, "rpcadmin").await?;

    // load account keys and sender address from a file
    let keys: WalletAccount =
        WalletAccount::from_json_file(app.keys_path).context("Could not read the keys file.")?;

    let consensus_info = client.get_consensus_status().await?;
    // Get the initial nonce at the last finalized block.
    let acc_info: AccountInfo = client
        .get_account_info(&keys.address, &consensus_info.last_finalized_block)
        .await?;

    let nonce = acc_info.account_nonce;
    // set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    let tx = send::transfer(
        &keys,
        keys.address,
        nonce,
        expiry,
        keys.address,              // send to ourselves
        Amount::from_micro_ccd(1), // send 1 microCCD
    );

    let item = BlockItem::AccountTransaction(tx);
    // submit the transaction to the chain
    let transaction_hash = client.send_block_item(&item).await?;
    println!(
        "Transaction {} submitted (nonce = {}).",
        transaction_hash, nonce,
    );
    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
