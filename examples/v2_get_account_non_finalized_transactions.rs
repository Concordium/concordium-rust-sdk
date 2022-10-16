//! Test the `GetAccountNonFinalizedTransactions` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{common::types::AccountAddress, v2};
use futures::StreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "account",
        help = "Account address to get non-finalized transactions for.",
        default_value = "http://localhost:10001"
    )]
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
    let mut response = client
        .get_account_non_finalized_transactions(&app.account)
        .await?;

    println!("Non-finalized transactions for {}:", app.account);
    while let Some(a) = response.next().await.transpose()? {
        println!(" - {:?}", &a);
    }
    Ok(())
}
