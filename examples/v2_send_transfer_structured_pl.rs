//! Basic example that shows how to send a transaction, in this case a transfer
//! from the account to itself.
//!
//! It also exercises the endpoint for getting the
//! transaction sign hash and using sending in a structured protobuf payload.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{types::TransactionTime, SerdeDeserialize, SerdeSerialize},
    id::types::{AccountAddress, AccountKeys},
    types::{
        transactions::{
            AccountTransaction, BlockItem, Payload, PayloadSize, TransactionHeader,
            TransactionSigner,
        },
        Energy,
    },
    v2,
};
use crypto_common::types::Amount;
use std::path::PathBuf;
use structopt::*;

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Account address and keys that will be supplied in a JSON file.
/// The transaction will be signed with the given keys.
struct AccountData {
    account_keys: AccountKeys,
    address:      AccountAddress,
}

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:  tonic::transport::Endpoint,
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
    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    // load account keys and sender address from a file
    let keys: AccountData = serde_json::from_str(&std::fs::read_to_string(app.keys_path).context(
        "Could not read the keys
    file.",
    )?)
    .context("Could not parse the keys file.")?;

    // Get the initial nonce at the last finalized block.
    let ai = client
        .get_account_info(&keys.address.into(), &v2::BlockIdentifier::Best)
        .await?;

    let nonce = ai.response.account_nonce;
    // set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    let header = TransactionHeader {
        sender: keys.address,
        nonce,
        energy_amount: Energy { energy: 10000 },
        payload_size: PayloadSize::from(0), // The node calculates this automatically now.
        expiry,
    };
    let payload = Payload::Transfer {
        to_address: keys.address,
        amount:     Amount::from_micro_ccd(1),
    };

    let trx_sign_hash = client
        .get_account_transaction_sign_hash(&header, &payload)
        .await?;

    let signature = keys.account_keys.sign_transaction_hash(&trx_sign_hash);
    let bi = BlockItem::AccountTransaction(AccountTransaction {
        signature,
        header,
        payload,
    });

    // submit the transaction to the chain
    println!("Sending transfer");
    let transaction_hash = client.send_block_item_unencoded(&bi).await?;
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
