//! Example that shows how to update token metadata for a token.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::protocol_level_tokens::{operations, MetadataUrl, TokenId};
use concordium_rust_sdk::{
    common::types::TransactionTime,
    types::{
        transactions::{send, BlockItem},
        WalletAccount,
    },
    v2::{self},
};
use std::{collections::HashMap, path::PathBuf};
use structopt::*;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "V2 GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "account",
        help = "Path to the account keys file of the governance account."
    )]
    account: PathBuf,
    #[structopt(long = "token", help = "Token to update metadata.")]
    token_id: String,
    #[structopt(
        long = "metadata url string to update",
        help = "Meta data url string to update for the token."
    )]
    metadata_url: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint).await?;

    // Token id of the fungible PLT token
    let token_id = TokenId::try_from(app.token_id.clone())?;

    // Load account keys and sender address from a file
    let keys: WalletAccount = WalletAccount::from_json_file(app.account)
        .context("Could not read the account keys file.")?;

    // Get the initial nonce at the last finalized block.
    let nonce = client
        .get_next_account_sequence_number(&keys.address)
        .await?
        .nonce;

    // Set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);

    // Create operation to update metadata url
    let metadata = MetadataUrl {
        additional: HashMap::new(),
        checksum_sha_256: None,
        url: app.metadata_url,
    };

    let operation = operations::update_metadata(metadata);

    // Compose operation to transaction
    let txn = send::token_update_operations(
        &keys,
        keys.address,
        nonce,
        expiry,
        token_id,
        [operation].into_iter().collect(),
    );

    let item = BlockItem::AccountTransaction(txn);

    // Submit the transaction to the chain
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
