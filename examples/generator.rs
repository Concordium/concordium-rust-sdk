use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{
        types::{Amount, TransactionTime},
        SerdeDeserialize, SerdeSerialize,
    },
    endpoints,
    id::types::{AccountAddress, AccountKeys},
    types::{
        self,
        transactions::{send, BlockItem},
    },
};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint:  tonic::transport::Endpoint,
    #[structopt(long = "sender")]
    account:   PathBuf,
    #[structopt(long = "receivers")]
    receivers: Option<PathBuf>,
    #[structopt(long = "tps")]
    tps:       u16,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct AccountData {
    account_keys: AccountKeys,
    address:      AccountAddress,
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

    let keys: AccountData = serde_json::from_str(
        &std::fs::read_to_string(app.account).context("Could not read the keys file.")?,
    )
    .context("Could not parse the keys file.")?;
    let accounts: Vec<AccountAddress> = match app.receivers {
        None => client
            .get_account_list(&consensus_info.last_finalized_block)
            .await
            .context("Could not obtain a list of accounts.")?,
        Some(receivers) => serde_json::from_str(
            &std::fs::read_to_string(receivers).context("Could not read the receivers file.")?,
        )
        .context("Could not parse the receivers file.")?,
    };
    anyhow::ensure!(!accounts.is_empty(), "List of receivers must not be empty.");

    // Get the initial nonce.
    let acc_info: types::AccountInfo = client
        .get_account_info(&keys.address, &consensus_info.last_finalized_block)
        .await?;

    println!(
        "Using account {} for sending, starting at nonce {}.",
        &keys.address, acc_info.account_nonce
    );

    // Create a channel between the task signing and the task sending transactions.
    let (sender, mut rx) = tokio::sync::mpsc::channel(100);

    // A task that will generate and sign transactions. Transactions are sent in a
    // round-robin fashion to all accounts in the list of receivers.
    let generator = async move {
        let mut nonce = acc_info.account_nonce;
        let mut count = 0;
        loop {
            let expiry: TransactionTime =
                TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
            let tx = send::transfer(
                &keys.account_keys,
                keys.address,
                nonce,
                expiry,
                accounts[count % accounts.len()],
                Amount::zero(),
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
                "Transaction {} submitted (nonce = {}, energy = {}).",
                transaction_hash, nonce, energy
            );
        } else {
            break;
        }
    }

    Ok(())
}
