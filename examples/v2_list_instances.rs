//! Print statistics on how many V0 and V1 instances there are in the state of a
//! given block.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    types::{hashes::BlockHash, smart_contracts::InstanceInfo},
    v2,
};
use futures::TryStreamExt;
use std::sync::Arc;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "block",
        help = "Block to query the data in. Defaults to last finalized block."
    )]
    block:    Option<BlockHash>,
    #[structopt(
        long = "num",
        help = "How many queries to make in parallel.",
        default_value = "8"
    )]
    num:      usize,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint).await?;

    let block = app
        .block
        .map_or(v2::BlockIdentifier::LastFinal, v2::BlockIdentifier::Given);

    let instances = client.get_instance_list(&block).await?;

    println!("Listing instances in block {}.", instances.block_hash);

    let v0_instances = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let v1_instances = Arc::new(std::sync::atomic::AtomicU64::new(0));

    instances
        .response
        .map_err(|e| anyhow::anyhow!("RPC error: {}", e))
        .try_for_each_concurrent(Some(app.num), |ia| {
            let mut client = client.clone();
            let v0_instances = v0_instances.clone();
            let v1_instances = v1_instances.clone();
            async move {
                let info = client
                    .get_instance_info(ia, &block)
                    .await
                    .context(format!("Getting instance {} failed.", ia))?;
                match info.response {
                    InstanceInfo::V0 { .. } => {
                        v0_instances.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    }
                    InstanceInfo::V1 { .. } => {
                        v1_instances.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    }
                }
                Ok::<(), anyhow::Error>(())
            }
        })
        .await?;
    println!(
        "There are {} V0 instances, and {} V1 instances.",
        v0_instances.load(std::sync::atomic::Ordering::Acquire),
        v1_instances.load(std::sync::atomic::Ordering::Acquire)
    );

    Ok(())
}
