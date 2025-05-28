//! Basic example that shows how to send a transaction, in this case a transfer
//! from the account to itself.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    contracts_common::AccountAddress,
    protocol_level_tokens::{TokenAmount, TokenId},
};
use concordium_rust_sdk::{
    common::types::TransactionTime,
    types::{
        transactions::{send, BlockItem},
        WalletAccount,
    },
    v2::{
        BlockIdentifier, {self},
    },
};
use rust_decimal::Decimal;
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
    #[structopt(long = "sender", help = "Account keys of the sender.")]
    account:  PathBuf,
    #[structopt(long = "receiver", help = "Receiver address.")]
    receiver: String,
    #[structopt(long = "token", help = "Token send.")]
    token_id: String,
    #[structopt(long = "amount", help = "Amount to send.", default_value = "100.0")]
    amount:   Decimal,
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

    // Token info, we need the number of decimals in the token amount representation
    let token_info = client
        .get_token_info(token_id.clone(), BlockIdentifier::LastFinal)
        .await?
        .response;

    // Amount of tokens to send. The number of decimals in the TokenAmount
    // must be the same as the number of decimals in the TokenInfo
    let mut amount = app.amount;
    amount.rescale(token_info.token_state.nr_of_decimals as u32);
    let token_amount =
        TokenAmount::from_raw(amount.mantissa().try_into()?, amount.scale().try_into()?);
    println!("Token amount: {}", token_amount,);

    // Receiver of the tokens
    let receiver_address = AccountAddress::from_str(&app.receiver)?;

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

    // Create transfer tokens transaction
    let txn = send::transfer_tokens(
        &keys,
        keys.address,
        nonce,
        expiry,
        receiver_address,
        token_id,
        token_amount,
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
