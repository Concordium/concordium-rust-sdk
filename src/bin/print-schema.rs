// use anyhow::Context;
// use concordium_rust_sdk::{self, endpoints, *};

// #[tokio::main(flavor = "multi_thread")]
// async fn main() -> anyhow::Result<()> {
//     let mut client = endpoints::Client::connect("http://localhost:10000", "rpcadmin").await?;

//     let consensus_info = client.get_consensus_status().await?;

//     let res = client
//         .get_pool_status_raw(None, &consensus_info.best_block)
//         .await?;
//     println!("{}", res);
//     Ok(())
// }

use concordium_rust_sdk::types::{queries::*, smart_contracts::InstanceInfo, *};
fn main() -> anyhow::Result<()> {
    let schema = schemars::schema_for!(AccountInfo);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
    Ok(())
}
