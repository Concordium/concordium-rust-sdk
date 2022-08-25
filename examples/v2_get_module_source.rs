/// Test the `GetModuleSource` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::types::smart_contracts::ModuleRef;
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
    #[structopt(long = "module", help = "Module reference to query.")]
    module:   ModuleRef,
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
        .get_module_source(&app.module.into(), &v2::BlockIdentifier::LastFinal)
        .await?;
    // TODO: Print in binary so you can pipe to file, or make user provide file.
    println!("{:#?}", res);

    Ok(())
}
