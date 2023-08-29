//! Test the `GetBakerEarliestWinTime` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{types::BakerId, v2};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,

    #[structopt(long = "baker-id", help = "The id of the baker", default_value = "0")]
    baker_id: BakerId,
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

    let ts = client.get_baker_earliest_win_time(app.baker_id).await?;
    println!("{}", ts);

    Ok(())
}
