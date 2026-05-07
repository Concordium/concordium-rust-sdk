//! Example that cancels an existing lock.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::protocol_level_locks::LockId;
use concordium_rust_sdk::{
    protocol_level_tokens::lock_client::{LockClient, Validation},
    types::WalletAccount,
    v2,
};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(long = "node", default_value = "http://localhost:20000")]
    endpoint: v2::Endpoint,
    #[structopt(long = "account")]
    account: PathBuf,
    #[structopt(long = "lock-id", help = "Base58Check-encoded lock id.")]
    lock_id: LockId,
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

    // construct the lock client
    let mut lock = LockClient::from_lock_id(client, app.lock_id).await?;

    // submit the transaction
    let hash = lock.cancel(&keys, None, None, Validation::Validate).await?;
    println!("submitted transaction: {}", hash);

    Ok(())
}
