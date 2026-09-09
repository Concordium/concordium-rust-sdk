//! Example that composes mint, lock create, fund, and lock send in one transaction.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    contracts_common::AccountAddress,
    protocol_level_locks::{
        LockConfig, LockConfigSimpleV0, LockControllerSimpleV0Capability,
        LockControllerSimpleV0Grant, LockMetadata, LockRecipients,
    },
    protocol_level_tokens::{
        meta_operations, CborHolderAccount, ConversionRule, TokenAmount, TokenId,
    },
    transactions::{construct, BlockItem, ExactSizeTransactionSigner},
};
use concordium_rust_sdk::{
    common::types::TransactionTime,
    protocol_level_tokens::lock_client::get_next_lock_id,
    types::WalletAccount,
    v2::{self, BlockIdentifier},
};
use rust_decimal::Decimal;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "V2 GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "sender", help = "Path to the sender account key file.")]
    account: PathBuf,
    #[structopt(long = "recipient", help = "Recipient address.")]
    recipient: AccountAddress,
    #[structopt(long = "token", help = "Token id of token.")]
    token_id: TokenId,
    #[structopt(
        long = "amount",
        help = "Amount to mint/send.",
        default_value = "100.0"
    )]
    amount: Decimal,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let keys: WalletAccount = WalletAccount::from_json_file(app.account)
        .context("Could not read the account keys file.")?;
    let mut client = v2::Client::new(app.endpoint).await?;

    let token_info = client
        .get_token_info(app.token_id.clone(), BlockIdentifier::LastFinal)
        .await?
        .response;
    let token_amount = TokenAmount::try_from_rust_decimal(
        app.amount,
        token_info.token_state.decimals,
        ConversionRule::AllowRounding,
    )?;

    let lock_id = get_next_lock_id(&mut client, keys.address, 0).await?;

    let metadata = LockMetadata {
        name: Some("Mint and lock".to_string()),
        description: Some("Created by the Rust SDK mint-lock example".to_string()),
        ..Default::default()
    };

    // Construct composed payload.
    let config = LockConfig::SimpleV0(LockConfigSimpleV0 {
        recipients: LockRecipients::Limited(vec![CborHolderAccount::from(app.recipient)]),
        expiry: TransactionTime::hours_after(1),
        grants: vec![LockControllerSimpleV0Grant {
            account: CborHolderAccount::from(keys.address),
            roles: vec![
                LockControllerSimpleV0Capability::Fund,
                LockControllerSimpleV0Capability::Send,
            ],
        }],
        tokens: vec![app.token_id.clone()],
        keep_alive: false,
        memo: None,
        metadata: Some(metadata.encode_raw_cbor()),
    });

    let operations = [
        meta_operations::mint_tokens(app.token_id.clone(), token_amount),
        meta_operations::lock_create(config),
        meta_operations::lock_fund(app.token_id.clone(), lock_id.clone(), token_amount, None),
    ]
    .into_iter()
    .collect();

    let nonce = client
        .get_next_account_sequence_number(&keys.address)
        .await?
        .nonce;
    let expiry = TransactionTime::minutes_after(5);
    let txn = construct::meta_update_operations(
        keys.num_keys(),
        keys.address,
        nonce,
        expiry,
        &operations,
    )
    .sign(&keys);
    let item = BlockItem::AccountTransaction(txn);

    // Submit transaction.
    let transaction_hash = client.send_block_item(&item).await?;
    println!(
        "Transaction {} submitted (nonce = {}).",
        transaction_hash, nonce
    );
    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
