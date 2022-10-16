//! Test the `GetInstanceInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{smart_contracts::common::ContractAddress, v2};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "address", help = "Contract address to query.")]
    address:  ContractAddress,
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

    let res = client
        .get_instance_info(app.address, &v2::BlockIdentifier::Best)
        .await?;
    println!("{:#?}", res);

    Ok(())
}
