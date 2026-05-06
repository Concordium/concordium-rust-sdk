//! Example that creates a lock and waits for finalization.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    common::types::TransactionTime,
    protocol_level_locks::{
        LockConfig, LockController, LockControllerSimpleV0, LockControllerSimpleV0Capability,
        LockControllerSimpleV0Grant,
    },
    protocol_level_tokens::{CborHolderAccount, TokenId},
};
use concordium_rust_sdk::{
    protocol_level_tokens::lock_client::LockClient, types::WalletAccount, v2,
};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(long = "node", default_value = "http://localhost:20000")]
    endpoint: v2::Endpoint,
    #[structopt(long = "account")]
    account: PathBuf,
    #[structopt(long = "token")]
    token_id: TokenId,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let keys = WalletAccount::from_json_file(app.account).context("Could not read account keys")?;
    let client = v2::Client::new(app.endpoint).await?;

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
            tokens: vec![app.token_id],
            keep_alive: false,
            memo: None,
        }),
    };

    // Submit transaction.
    let pending = LockClient::create(client, &keys, config, None).await?;
    println!("submitted transaction: {}", pending.transaction_hash());

    // Await the lock creation.
    let lock = pending.wait_for_finalization(None).await?;
    println!("created lock: {:?}", lock.lock_info().lock);

    Ok(())
}
