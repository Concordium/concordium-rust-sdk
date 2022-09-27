//! Test the `GetPassiveDelegators` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{endpoints::Endpoint, v2};
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
    let mut response_delegators = client
        .get_passive_delegators(&v2::BlockIdentifier::LastFinal)
        .await?;

    println!("Blockhash: {}", response_delegators.block_hash);
    while let Some(a) = response_delegators.response.next().await.transpose()? {
        println!(" - {:?}", &a);
    }
    Ok(())
}