use clap::AppSettings;
use concordium_rust_sdk::{
    common::{SerdeDeserialize, SerdeSerialize},
    endpoints,
    id::types::{AccountAddress, AccountKeys},
    types,
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint:    tonic::transport::Endpoint,
    #[structopt(long = "block")]
    start_block: Option<types::hashes::BlockHash>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct AccountData {
    account_keys: AccountKeys,
    address:      AccountAddress,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
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
    while cb != gb {
        println!("{}", cb);
        let bi = client.get_block_info(&cb).await?;
        if bi.transaction_count != 0 {
            println!("Processing block {}", cb);
            let accs = client.get_account_list(&cb).await?;
            {
                let mut handles = Vec::with_capacity(accs.len());
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
            let _birks = client.get_birk_parameters(&cb).await?;
            // println!("{:?}", birks);

            let _summary = client.get_block_summary(&cb).await?;
            // println!("{:?}", summary);
        }
        cb = bi.block_parent;
    }

    println!("Done.");

    Ok(())
}
