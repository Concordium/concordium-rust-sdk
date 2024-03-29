//! Test the `GetAnonymityRevokers` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::v2;
use futures::StreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
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
        .get_anonymity_revokers(&v2::BlockIdentifier::LastFinal)
        .await?;

    println!("Blockhash: {}", response.block_hash);
    while let Some(a) = response.response.next().await.transpose()? {
        println!(" - {:?}", &a);
    }
    Ok(())
}
