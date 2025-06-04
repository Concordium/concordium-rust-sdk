//! Example that shows how to administrate allow and deny lists for (PLT)
//! tokens.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    contracts_common::AccountAddress,
    protocol_level_tokens::{operations, TokenId},
};
use concordium_rust_sdk::{
    common::types::TransactionTime,
    types::{
        transactions::{send, BlockItem},
        WalletAccount,
    },
    v2::{self},
};
use std::{path::PathBuf, str::FromStr};
use structopt::*;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "V2 GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "account", help = "Account keys of the governance account.")]
    account:  PathBuf,
    #[structopt(long = "token", help = "Token to add/remove to/from allow/deny list.")]
    token_id: String,
    #[structopt(subcommand)]
    cmd:      AddRemoveAllowDeny,
    #[structopt(long = "target", help = "Target address.")]
    target:   String,
}

/// Token allow/deny list operation
#[derive(StructOpt)]
enum AddRemoveAllowDeny {
    AddAllow,
    RemoveAllow,
    AddDeny,
    RemoveDeny,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint).await?;

    // Token id of the fungible PLT token to transfer
    let token_id = TokenId::try_from(app.token_id.clone())?;

    // Target for list operation
    let target_address = AccountAddress::from_str(&app.target)?;

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

    // Create token list operation
    let operation = match app.cmd {
        AddRemoveAllowDeny::AddAllow => operations::add_token_allow_list(target_address),
        AddRemoveAllowDeny::RemoveAllow => operations::remove_token_allow_list(target_address),
        AddRemoveAllowDeny::AddDeny => operations::add_token_deny_list(target_address),
        AddRemoveAllowDeny::RemoveDeny => operations::remove_token_deny_list(target_address),
    };

    // Compose operation to transaction
    let txn = send::token_governance_operations(
        &keys,
        keys.address,
        nonce,
        expiry,
        token_id,
        [operation].into_iter().collect(),
    )?;

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
