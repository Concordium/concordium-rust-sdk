/// Test the `GetAccountList` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    types::{hashes::BlockHash, smart_contracts::concordium_contracts_common as contracts_common},
    v2,
};
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
    #[structopt(long = "index", help = "Index of the smart contract to query.")]
    index:    contracts_common::ContractIndex,
    #[structopt(long = "block", help = "Hash of the block in which to query.")]
    block:    Option<BlockHash>,
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
    let block = app
        .block
        .map_or(v2::BlockIdentifier::LastFinal, v2::BlockIdentifier::Given);
    let mut al = client
        .get_instance_state(
            contracts_common::ContractAddress::new(app.index, 0u64.into()),
            &block,
        )
        .await?;
    println!("{}", al.block_hash);
    let mut s = 0;
    let mut len = 0;
    while let Some(a) = al.response.next().await {
        s += 1;
        let a = a?;
        len += a.1.len();
        len += a.0.len();
    }
    println!("{s} ({len})");
    Ok(())
}
