//! Test the `GetAccountInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{id::types::AccountAddress, v2};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "address", help = "Account address to query.")]
    address:  AccountAddress,
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

    {
        let ai = client
            .get_account_info(&app.address.into(), &v2::BlockIdentifier::Best)
            .await?;
        println!("{:#?}", ai);
    }

    {
        let ai = client
            .get_account_info(&app.address.into(), &v2::BlockIdentifier::LastFinal)
            .await?;
        println!("{:#?}", ai);
    }

    Ok(())
}
