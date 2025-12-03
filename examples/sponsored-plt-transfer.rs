//! Example that shows how to create a sponsored PLT token transfer.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    contracts_common::AccountAddress,
    protocol_level_tokens::{operations, ConversionRule, TokenAmount, TokenId},
};
use concordium_rust_sdk::{
    common::types::TransactionTime,
    types::{transactions::BlockItem, WalletAccount},
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
    #[structopt(long = "sender", help = "Path to the sender account key file.")]
    sender_account: PathBuf,
    #[structopt(long = "sponsor", help = "Path to the sponsor account key file.")]
    sponsor_account: PathBuf,
    #[structopt(long = "receiver", help = "Receiver address.")]
    receiver: String,
    #[structopt(long = "token", help = "Token id of token.")]
    token_id: String,
    #[structopt(long = "amount", help = "Amount to send.", default_value = "100.0")]
    amount: Decimal,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint).await?;

    // Token id of the PLT token to transfer
    let token_id = TokenId::try_from(app.token_id.clone())?;

    // Token info, we need the number of decimals in the token amount representation
    let token_info = client
        .get_token_info(token_id.clone(), BlockIdentifier::LastFinal)
        .await?
        .response;

    // Amount of tokens to send. The number of decimals in the TokenAmount
    // must be the same as the number of decimals in the TokenInfo
    let token_amount = TokenAmount::try_from_rust_decimal(
        app.amount,
        token_info.token_state.decimals,
        ConversionRule::AllowRounding,
    )?;
    println!("Token amount: {}", token_amount,);

    // Receiver of the tokens
    let receiver_address = AccountAddress::from_str(&app.receiver)?;

    // Load account keys and address for sender and sponsor from a file
    let sender_keys: WalletAccount = WalletAccount::from_json_file(app.sender_account)
        .context("Could not read the sender account keys file.")?;
    let sponsor_keys: WalletAccount = WalletAccount::from_json_file(app.sponsor_account)
        .context("Could not read the sponsor account keys file.")?;

    // Get the initial nonce at the last finalized block.
    let nonce = client
        .get_next_account_sequence_number(&sender_keys.address)
        .await?
        .nonce;

    // Set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);

    // Create transfer tokens transaction
    let operation = operations::transfer_tokens(receiver_address, token_amount);

    // Compose operation to transaction
    let txn = concordium_base::transactions::construct::token_update_operations(
        1,
        sender_keys.address,
        nonce,
        expiry,
        token_id,
        [operation].into_iter().collect(),
    )?
    // Extend the transaction and add a sponsor.
    .extend()
    .add_sponsor(sponsor_keys.address, 1)
    .map_err(|e| anyhow::anyhow!(e))?
    // Sender signs the transaction.
    .sign(&sender_keys)
    // Sponsor signs the now sponsored transaction.
    .sponsor(&sponsor_keys)
    .map_err(|e| anyhow::anyhow!(e))?
    .finalize()
    .map_err(|e| anyhow::anyhow!(e))?;

    let item = BlockItem::AccountTransactionV1(txn);

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
