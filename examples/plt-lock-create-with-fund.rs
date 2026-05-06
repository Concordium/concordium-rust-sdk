//! Example that composes a lock creation and funding operation in one transaction.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    common::types::TransactionTime,
    protocol_level_locks::{
        LockConfig, LockController, LockControllerSimpleV0, LockControllerSimpleV0Capability,
        LockControllerSimpleV0Grant,
    },
    protocol_level_tokens::{CborHolderAccount, ConversionRule, TokenAmount, TokenId},
};
use concordium_rust_sdk::{
    protocol_level_tokens::lock_client::{FundTokens, LockClient},
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
    #[structopt(long = "amount", help = "Amount to lock.", default_value = "100.0")]
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

    // Construct lock configuration payload.
    let config = LockConfig {
        recipients: vec![CborHolderAccount::from(keys.address)],
        expiry: TransactionTime::hours_after(1),
        controller: LockController::SimpleV0(LockControllerSimpleV0 {
            grants: vec![LockControllerSimpleV0Grant {
                account: CborHolderAccount::from(keys.address),
                roles: vec![
                    LockControllerSimpleV0Capability::Fund,
                    LockControllerSimpleV0Capability::Send,
                    LockControllerSimpleV0Capability::Return,
                    LockControllerSimpleV0Capability::Cancel,
                ],
            }],
            tokens: vec![token_id.clone()],
            keep_alive: false,
            memo: None,
        }),
    };

    // Construct composed payload.
    let pending = LockClient::create_compose(keys.address, config)
        .fund(FundTokens {
            token_id,
            amount: token_amount,
            memo: None,
        })
        // Submit transaction.
        .submit(&mut client, &keys, None)
        .await?;

    println!("submitted transaction: {}", pending.transaction_hash());

    // Await the lock creation.
    let lock = pending.wait_for_finalization(None).await?;
    println!("created lock: {:?}", lock.lock_info().lock);

    Ok(())
}
