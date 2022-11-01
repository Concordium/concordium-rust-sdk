/// Test the `InstanceStateLookup` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{smart_contracts::common, types::hashes::BlockHash, v2};
use futures::TryStreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
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
    let addr = common::ContractAddress::new(app.index, 0u64);
    let al = client.get_instance_state(addr, &block).await?;
    println!("{}", al.block_hash);
    // check that instance state lookup returns the same values
    // that we got from the entire state.
    let s = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let outer = s.clone();
    // we do this in parallel since work is IO bound on the node.
    al.response
        .map_err(|e| anyhow::anyhow!("RPC Error: {}", e))
        .try_for_each_concurrent(None, |(k, v)| {
            let client = client.clone();
            let s = s.clone();
            async move {
                s.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                let mut client = client.clone();
                let value = client.instance_state_lookup(addr, k, al.block_hash).await?;
                assert_eq!(value.response, v, "Different value.");
                Ok(())
            }
        })
        .await?;
    println!(
        "Checked {} keys.",
        outer.load(std::sync::atomic::Ordering::Acquire)
    );
    Ok(())
}
