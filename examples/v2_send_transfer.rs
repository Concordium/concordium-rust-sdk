//! Basic example that shows how to send a transaction with an optional memo, in
//! this case a transfer from the account to itself.
//!
//! The keys are meant to be supplied in the browser extension wallet export
//! format.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::types::{Amount, TransactionTime},
    types::{transactions::send, WalletAccount},
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
        long = "memo",
        help = "Optional memo to be included in the transaction."
    )]
    memo:      Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    // load account keys and sender address from a file
    let keys: WalletAccount =
        serde_json::from_str(&std::fs::read_to_string(app.keys_path).context(
            "Could not read the keys
    file.",
        )?)
        .context("Could not parse the keys file.")?;

    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    // Get the initial nonce at the last finalized block.
    let ai = client
        .get_account_info(&keys.address.into(), &v2::BlockIdentifier::Best)
        .await?;

    let nonce = ai.response.account_nonce;
    // set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    let tx = match &app.memo {
        None => {
            send::transfer(
                &keys,
                keys.address,
                nonce,
                expiry,
                keys.address,              // send to ourselves
                Amount::from_micro_ccd(1), // send 1 microCCD
            )
        }
        Some(memo) => {
            let memo = memo.as_bytes().to_owned().try_into()?;
            send::transfer_with_memo(
                &keys,
                keys.address,
                nonce,
                expiry,
                keys.address,
                Amount::from_micro_ccd(1),
                memo,
            )
        }
    };

    // submit the transaction to the chain
    if let Some(memo) = app.memo {
        println!("Sending transfer with memo: \"{}\"", memo);
    } else {
        println!("Sending transfer");
    }
    let transaction_hash = client.send_account_transaction(tx).await?;
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
