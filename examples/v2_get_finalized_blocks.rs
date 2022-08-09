/// Test the `GetFinalizedBlocks` endpoint.
use anyhow::Context;
use clap::AppSettings;
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

    let mut client = concordium_rust_sdk::v2::queries_client::QueriesClient::connect(app.endpoint)
        .await
        .context("Cannot connect.")?;

    let fb = client
        .finalized_blocks(concordium_rust_sdk::v2::Empty::default())
        .await?;
    let stream = fb.into_inner();

    stream
        .for_each(|fb| async move { println!("{:?}", fb) })
        .await;

    Ok(())
}
