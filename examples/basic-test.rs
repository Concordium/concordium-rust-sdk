use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{SerdeDeserialize, SerdeSerialize},
    endpoints::{self, Endpoint},
    id::types::{AccountAddress, AccountKeys},
    types,
};
use rand::{prelude::SliceRandom, thread_rng};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint:    Endpoint,
    #[structopt(long = "block")]
    start_block: Option<types::hashes::BlockHash>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app: App = {
        let app = App::clap()
            // .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = endpoints::Client::connect(app.endpoint, "rpcadmin".to_string()).await?;

    let version = client.version().await?;
    println!("{}", version);
    let peers = client.peer_list(true).await?;
    println!("{:?}", peers);

    let ni = client.node_info().await?;
    println!("{:?}", ni);

    let consensus_info = client.get_consensus_status().await?;
    println!("{}", serde_json::to_string_pretty(&consensus_info).unwrap());

    let gb = consensus_info.genesis_block;
    let mut cb = app.start_block.unwrap_or(consensus_info.best_block);
    let mut rng = thread_rng();
    while cb != gb {
        println!("{}", cb);
        let bi = client.get_block_info(&cb).await?;
        if bi.transaction_count != 0 {
            println!("Processing block {}", cb);
            let accs = client.get_account_list(&cb).await?;
            let accs = accs
                .choose_multiple(&mut rng, 100)
                .copied()
                .collect::<Vec<_>>();
            {
                let mut handles = Vec::with_capacity(100);
                for acc in accs {
                    let cc = client.clone();
                    handles.push(tokio::spawn(async move {
                        let mut cc = cc;
                        cc.get_account_info(acc, &cb).await
                    }));
                }
                let x = futures::future::join_all(handles).await;
                for res in x {
                    // check the account response was OK.
                    let _info = res??;
                }
            }
            let _birks = client
                .get_birk_parameters(&cb)
                .await
                .context("Could not get birk parameters.")?;
            // println!("{:?}", birks);
        }
        let start = chrono::Utc::now();
        let _summary = client
            .get_block_summary(&cb)
            .await
            .context("Could not get block summary.")?;
        let end = chrono::Utc::now();
        let diff = end.signed_duration_since(start).num_milliseconds();
        println!("  Took {}ms to query block summary.", diff);
        cb = bi.block_parent;
    }

    println!("Done.");

    Ok(())
}
