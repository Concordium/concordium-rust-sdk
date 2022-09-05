/// Test the `GetAccountInfo` endpoint.
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
        default_value = "http://localhost:10001"
    )]
    endpoint: tonic::transport::Endpoint,
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

    let mut accounts = client.get_account_list(&v2::BlockIdentifier::Best).await?;
    while let Some(account) = accounts.response.next().await {
        let account = account?;
        let next_nonce = client.get_next_account_nonce(&account.into()).await?;
        println!(
            "{}: nonce {}, all_final {:?}",
            account, next_nonce.nonce, next_nonce.all_final
        );
    }

    Ok(())
}
