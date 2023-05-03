use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::types::{Amount, TransactionTime},
    endpoints::Endpoint,
    id::types::AccountAddress,
    types::{
        transactions::{send, BlockItem},
        WalletAccount,
    },
    v2::{self, BlockIdentifier},
};
use futures::TryStreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint:  Endpoint,
    #[structopt(long = "sender")]
    account:   PathBuf,
    #[structopt(long = "receivers")]
    receivers: Option<PathBuf>,
    #[structopt(long = "tps")]
    tps:       u16,
    #[structopt(
        long = "amount",
        help = "CCD amount to send in each transaction",
        default_value = "0"
    )]
    amount:    Amount,
    #[structopt(
        long = "expiry",
        help = "Expiry of transactions in seconds.",
        default_value = "7200"
    )]
    expiry:    u32,
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
        WalletAccount::from_json_file(app.account).context("Could not parse the keys file.")?;
    let accounts: Vec<AccountAddress> = match app.receivers {
        None => {
            client
                .get_account_list(BlockIdentifier::LastFinal)
                .await
                .context("Could not obtain a list of accounts.")?
                .response
                .try_collect()
                .await?
        }
        Some(receivers) => serde_json::from_str(
            &std::fs::read_to_string(receivers).context("Could not read the receivers file.")?,
        )
        .context("Could not parse the receivers file.")?,
    };
    anyhow::ensure!(!accounts.is_empty(), "List of receivers must not be empty.");

    // Get the initial nonce.
    let nonce = client
        .get_next_account_sequence_number(&keys.address)
        .await?;

    anyhow::ensure!(nonce.all_final, "Not all transactions are finalized.");

    println!(
        "Using account {} for sending, starting at nonce {}.",
        &keys.address, nonce.nonce
    );

    // Create a channel between the task signing and the task sending transactions.
    let (sender, mut rx) = tokio::sync::mpsc::channel(100);

    let transfer_amount = app.amount;

    // A task that will generate and sign transactions. Transactions are sent in a
    // round-robin fashion to all accounts in the list of receivers.
    let generator = async move {
        let mut nonce = nonce.nonce;
        let mut count = 0;
        loop {
            let expiry: TransactionTime = TransactionTime::seconds_after(app.expiry);
            let tx = send::transfer(
                &keys,
                keys.address,
                nonce,
                expiry,
                accounts[count % accounts.len()],
                transfer_amount,
            );
            nonce.next_mut();
            count += 1;
            sender.send(tx).await.unwrap();
        }
    };

    // Spawn it to run in the background.
    let _handle = tokio::spawn(generator);

    // In the main task we poll the channel and send a transaction to match the
    // given TPS.
    let mut interval = tokio::time::interval(tokio::time::Duration::from_micros(
        1_000_000 / u64::from(app.tps),
    ));
    loop {
        interval.tick().await;
        if let Some(tx) = rx.recv().await {
            let nonce = tx.header.nonce;
            let energy = tx.header.energy_amount;
            let item = BlockItem::AccountTransaction(tx);
            let transaction_hash = client.send_block_item(&item).await?;
            println!(
                "{}: Transaction {} submitted (nonce = {}, energy = {}).",
                chrono::Utc::now(),
                transaction_hash,
                nonce,
                energy
            );
        } else {
            break;
        }
    }

    Ok(())
}
