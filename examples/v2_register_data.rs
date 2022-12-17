//! Basic example that shows how to register data.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::types::TransactionTime,
    types::{
        transactions::{send, BlockItem},
        WalletAccount,
    },
    v2,
};
use std::path::PathBuf;
use structopt::*;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:  v2::Endpoint,
    #[structopt(long = "account", help = "Path to the account key file.")]
    keys_path: PathBuf,
    #[structopt(
        long = "data",
        help = "Path to a file with the data to register. (Note: Max data size is 256 bytes)"
    )]
    data_path: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    // load account keys and sender address from a file
    let keys: WalletAccount =
        WalletAccount::from_json_file(app.keys_path).context("Could not parse the keys file.")?;

    // Get the initial nonce at the last finalized block.
    let ai = client
        .get_account_info(&keys.address.into(), &v2::BlockIdentifier::Best)
        .await?;

    let nonce = ai.response.account_nonce;
    // set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    let tx = {
        let contents = std::fs::read(app.data_path).context("Could not read data file.")?;
        let data = contents.try_into()?;
        send::register_data(&keys, keys.address, nonce, expiry, data)
    };

    let item = BlockItem::AccountTransaction(tx);
    // submit the transaction to the chain
    println!("Registering data");
    let transaction_hash = client.send_block_item(&item).await?;
    println!(
        "Transaction {} submitted (nonce = {}).",
        transaction_hash, nonce,
    );
    println!("Waiting until finalized.");
    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
