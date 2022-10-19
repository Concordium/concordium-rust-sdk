//! List all discoverable CIS2 contracts.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    cis0,
    types::{hashes::BlockHash, smart_contracts::InstanceInfo},
    v2,
};
use futures::TryStreamExt;
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

    println!("Listing CIS2 contracts block {}.", instances.block_hash);

    instances
        .response
        .map_err(|e| anyhow::anyhow!("RPC error: {}", e))
        .try_for_each_concurrent(Some(app.num), |ia| {
            let mut client = client.clone();
            async move {
                let info = client
                    .get_instance_info(ia, &block)
                    .await
                    .context(format!("Getting instance {} failed.", ia))?;
                match info.response {
                    InstanceInfo::V0 { .. } => {}
                    InstanceInfo::V1 { name, amount, .. } => {
                        if let Ok(r) = cis0::supports(
                            &mut client,
                            &block,
                            ia,
                            name.as_contract_name(),
                            cis0::StandardIdentifier::CIS2,
                        )
                        .await
                        {
                            if r.response.is_support() {
                                println!("{}, {}", ia, amount)
                            }
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            }
        })
        .await?;

    Ok(())
}
