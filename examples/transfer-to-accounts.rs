//! Send a given amount of CCD to the account listed in a provided file.
//! The file format should be one account address per line.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::types::{Amount, TransactionTime},
    id::types::AccountAddress,
    types::{
        self,
        transactions::{send, BlockItem},
        WalletAccount,
    },
    v2::{self, BlockIdentifier},
};
use std::{io::BufRead, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "V2 GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint:  v2::Endpoint,
    #[structopt(long = "sender", help = "Account keys of the sender.")]
    account:   PathBuf,
    #[structopt(
        long = "receivers",
        help = "File with a list of receivers. One account address per line."
    )]
    receivers: PathBuf,
    #[structopt(long = "amount", help = "Amount to send.", default_value = "100.0")]
    amount:    Amount,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint).await?;

    let keys: WalletAccount =
        WalletAccount::from_json_file(app.account).context("Could not read the keys file.")?;

    let accounts: Vec<AccountAddress> = {
        std::fs::read(app.receivers)
            .context("Could not read the receivers file.")?
            .lines()
            .map(|l| {
                let l = l.context("Could not read line.")?;
                l.parse::<AccountAddress>().map_err(|e| anyhow::anyhow!(e))
            })
            .collect::<anyhow::Result<_>>()?
    };
    anyhow::ensure!(!accounts.is_empty(), "List of receivers must not be empty.");

    // Get the initial nonce.
    let acc_info: types::AccountInfo = client
        .get_account_info(&keys.address.into(), BlockIdentifier::LastFinal)
        .await?
        .response;

    println!(
        "Using account {} for sending, starting at nonce {}.",
        &keys.address, acc_info.account_nonce
    );

    // Create a channel between the task signing and the task sending transactions.
    let (sender, mut rx) = tokio::sync::mpsc::channel(100);
    let amount_to_send = app.amount;
    let generator = async move {
        let mut nonce = acc_info.account_nonce;
        for addr in accounts {
            let expiry: TransactionTime =
                TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 3600) as u64);
            let tx = send::transfer(&keys, keys.address, nonce, expiry, addr, amount_to_send);
            nonce.next_mut();
            sender.send(tx).await.unwrap();
        }
    };

    // Spawn it to run in the background.
    let _handle = tokio::spawn(generator);

    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(10));
    loop {
        interval.tick().await;
        if let Some(tx) = rx.recv().await {
            let nonce = tx.header.nonce;
            let energy = tx.header.energy_amount;
            let item = BlockItem::AccountTransaction(tx);
            let transaction_hash = client.send_block_item(&item).await?;
            println!(
                "Transaction {} submitted (nonce = {}, energy = {}).",
                transaction_hash, nonce, energy
            );
        } else {
            break;
        }
    }

    Ok(())
}
