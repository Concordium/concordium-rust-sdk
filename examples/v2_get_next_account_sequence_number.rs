//! Test the `GetNextAccountSequenceNumber` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{id::types::AccountAddress, v2};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "account", help = "Address of the account to query.")]
    account:  AccountAddress,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    let next_nonce = client
        .get_next_account_sequence_number(&app.account)
        .await?;
    println!(
        "nonce {}, all_final {:?}",
        next_nonce.nonce, next_nonce.all_final
    );

    Ok(())
}
