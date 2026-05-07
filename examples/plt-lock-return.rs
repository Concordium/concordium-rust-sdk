//! Example that returns funds controlled by an existing lock.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    contracts_common::AccountAddress,
    protocol_level_locks::LockId,
    protocol_level_tokens::{ConversionRule, TokenAmount, TokenId},
};
use concordium_rust_sdk::{
    protocol_level_tokens::lock_client::{LockClient, ReturnTokens, Validation},
    types::WalletAccount,
    v2::{self, BlockIdentifier},
};
use rust_decimal::Decimal;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(long = "node", default_value = "http://localhost:20000")]
    endpoint: v2::Endpoint,
    #[structopt(long = "sender", help = "Path to the sender account key file.")]
    account: PathBuf,
    #[structopt(long = "token", help = "Token id of token.")]
    token_id: TokenId,
    #[structopt(long = "amount", help = "Amount to return.", default_value = "100.0")]
    amount: Decimal,
    #[structopt(long = "source", help = "Source address.")]
    source: AccountAddress,
    #[structopt(
        long = "lock-id",
        help = "Lock id in the form P{account_index}L{sequence_number}T{creation_order}L"
    )]
    lock_id: LockId,
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
    let token_id = app.token_id.clone();
    let mut client = v2::Client::new(app.endpoint).await?;

    // Amount of tokens to mint or burn. The number of decimals in the TokenAmount
    // must be the same as the number of decimals in the TokenInfo
    let token_info = client
        .get_token_info(token_id.clone(), BlockIdentifier::LastFinal)
        .await?
        .response;
    let token_amount = TokenAmount::try_from_rust_decimal(
        app.amount,
        token_info.token_state.decimals,
        ConversionRule::AllowRounding,
    )?;

    // Construct the lock client
    let mut lock = LockClient::from_lock_id(client, app.lock_id).await?;
    // Construct payload.
    let payload = ReturnTokens {
        token_id,
        source: app.source,
        amount: token_amount,
        memo: None,
    };
    // Submit transaction.
    let hash = lock
        .return_funds(&keys, payload, None, Validation::Validate)
        .await?;
    println!("submitted transaction: {}", hash);

    Ok(())
}
