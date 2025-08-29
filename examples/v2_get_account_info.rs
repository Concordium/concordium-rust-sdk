//! Test the `GetAccountInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::hashes::BlockHash;
use concordium_rust_sdk::v2;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "address", help = "Account address to query.")]
    address: v2::AccountIdentifier,
    #[structopt(long = "block", help = "Block to query the account in.")]
    block: Option<BlockHash>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let block_ident = app
        .block
        .map_or(v2::BlockIdentifier::LastFinal, v2::BlockIdentifier::Given);

    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    {
        let ai = client.get_account_info(&app.address, &block_ident).await?;
        println!("{ai:#?}");
    }

    Ok(())
}
