/// Test the `GetInstanceInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_contracts_common::ContractAddress;
use structopt::StructOpt;

use concordium_rust_sdk::v2;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: tonic::transport::Endpoint,
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
        .get_instance_info(&app.address.into(), &v2::BlockIdentifier::Best)
        .await?;
    // TODO: Block hash and module_source printed with only ~8 characters.
    println!("{:#?}", res);

    Ok(())
}
