//! Test the `GetAccountList` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{v2, endpoints::Endpoint};
use futures::StreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: Endpoint,
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
    let mut al = client
        .get_account_list(&v2::BlockIdentifier::LastFinal)
        .await?;
    println!("Blockhash: {}", al.block_hash);
    while let Some(a) = al.response.next().await {
        println!("{}", a?);
    }
    Ok(())
}
