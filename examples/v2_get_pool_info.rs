//! Test the `GetPoolInfo` endpoint.
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
    endpoint: v2::Endpoint,
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

    let mut res = client.get_baker_list(&v2::BlockIdentifier::Best).await?;
    println!("Best block {:#?}:", res.block_hash);
    while let Some(a) = res.response.next().await {
        let baker_id = a?;
        let status = client
            .get_pool_info(&v2::BlockIdentifier::Best, baker_id)
            .await?;
        println!("Baker {:#?}: {:#?}", baker_id, status);
    }

    Ok(())
}
