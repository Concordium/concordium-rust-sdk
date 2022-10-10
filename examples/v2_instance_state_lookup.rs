/// Test the `InstanceStateLookup` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    endpoints::Endpoint, smart_contracts::common, types::hashes::BlockHash, v2,
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
    endpoint: Endpoint,
    #[structopt(long = "index", help = "Index of the smart contract to query.")]
    index:    common::ContractIndex,
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
    let addr = common::ContractAddress::new(app.index, 0u64.into());
    let mut al = client.get_instance_state(addr, &block).await?;
    println!("{}", al.block_hash);
    // check that instance state lookup returns the same values
    // that we got from the entire state.
    let mut s = 0;
    // we do this in parallel since work is IO bound on the node.
    let mut futures = Vec::new();
    while let Some(kv) = al.response.next().await {
        let (k, v) = kv?;
        s += 1;
        let mut client = client.clone();
        futures.push(tokio::spawn(async move {
            let value = client
                .instance_state_lookup(addr, k, &al.block_hash.into())
                .await?;
            assert_eq!(value.response, v, "Different value.");
            Ok::<_, anyhow::Error>(())
        }));
        // we complete 20 queries at a time
        if s % 20 == 0 {
            let handles = std::mem::take(&mut futures);
            futures::future::join_all(handles).await;
        }
    }
    println!("Checked {s} keys.");
    Ok(())
}
