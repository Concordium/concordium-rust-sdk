//! Test the `InvokeInstance` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    smart_contracts::common::{Amount, ContractAddress, OwnedReceiveName},
    types::smart_contracts::ContractContext,
    v2::{self, BlockIdentifier},
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:     v2::Endpoint,
    #[structopt(long = "contract", help = "The address of the contract to invoke")]
    contract:     ContractAddress,
    #[structopt(long = "entrypoint", help = "The entrypoint of the contract to invoke")]
    receive_name: OwnedReceiveName,
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

    let context = ContractContext {
        invoker:   None,
        contract:  app.contract,
        amount:    Amount::zero(),
        method:    app.receive_name,
        parameter: Default::default(),
        energy:    1000000.into(),
    };

    let info = client
        .invoke_instance(&BlockIdentifier::Best, &context)
        .await?;
    println!("{:#?}", info);

    Ok(())
}
