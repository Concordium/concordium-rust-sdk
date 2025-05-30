//! Test the `GetConsensusDetailedStatus` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::v2;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint:      v2::Endpoint,
    #[structopt(long = "genesis-index", help = "The genesis index to query.")]
    genesis_index: Option<u32>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint.clone())
        .await
        .context("Cannot connect.")?;

    let info = client
        .get_consensus_detailed_status(app.genesis_index.map(Into::into))
        .await?;
    println!("{:#?}", info);

    Ok(())
}
