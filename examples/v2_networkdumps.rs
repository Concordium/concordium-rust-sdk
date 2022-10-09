//! Test the `network_dump` feature related endpoints.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{v2, endpoints::Endpoint};
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

    client.dump_start("/some/accessible/path/dump".to_string(), true).await?;
    println!("Successfully started network dump");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    client.dump_stop().await?;
    println!("Successfully stopped network dump.");
    Ok(())
}
