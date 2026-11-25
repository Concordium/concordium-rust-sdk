//! Example that creates a lock and waits for finalization.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    common::types::TransactionTime,
    protocol_level_locks::{
        LockCreateConfig, LockMetadata, LockRecipients, SimpleLockConfigCapability,
        SimpleLockConfigRoles, SimpleLockConfigV0,
    },
    protocol_level_tokens::{CborHolderAccount, TokenId},
};
use concordium_rust_sdk::{
    protocol_level_tokens::lock_client::create_lock, types::WalletAccount, v2,
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

    // Construct typed metadata, then store it in the lock configuration as raw CBOR bytes.
    let metadata = LockMetadata {
        name: Some("Example lock".to_string()),
        description: Some("Created by the Rust SDK lock-create example".to_string()),
        ..Default::default()
    };

    // Construct an any-recipient lock configuration payload.
    let config = LockCreateConfig::SimpleV0(SimpleLockConfigV0 {
        recipients: LockRecipients::Any,
        holders: vec![CborHolderAccount::from(keys.address)],
        expiry: TransactionTime::hours_after(1),
        roles: vec![SimpleLockConfigRoles {
            account: CborHolderAccount::from(keys.address),
            roles: vec![
                SimpleLockConfigCapability::Send,
                SimpleLockConfigCapability::Release,
                SimpleLockConfigCapability::Cancel,
            ],
        }],
        tokens: vec![app.token_id],
        metadata: Some(metadata.encode_raw_cbor()),
    });

    // Submit transaction.
    let pending = create_lock(client, &keys, config, None).await?;
    println!("submitted transaction: {}", pending.transaction_hash());

    // Await the lock creation.
    let lock = pending.wait_for_finalization(None).await?;
    println!("created lock: {:}", lock.lock_info().lock);

    Ok(())
}
