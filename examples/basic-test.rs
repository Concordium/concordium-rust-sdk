use std::path::PathBuf;

use clap::AppSettings;
use concordium_rust_sdk::{
    endpoints::{self, DEFAULT_NETWORK_ID},
    types::{
        self,
        transactions::{make_and_sign_transaction, BlockItem, Payload},
    },
};
use crypto_common::{types::TransactionTime, SerdeDeserialize, SerdeSerialize};
use id::types::{AccountAddress, AccountKeys};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(long = "grpc")]
    endpoint:    tonic::transport::Endpoint,
    #[structopt(long = "block")]
    start_block: Option<types::hashes::BlockHash>,
    #[structopt(long = "keys")]
    account:     PathBuf,
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

    let keys: AccountData = serde_json::from_str(&std::fs::read_to_string(app.account)?)?;

    let mut client = endpoints::Client::connect(app.endpoint, "rpcadmin".to_string()).await?;

    let version = client.version().await?;
    println!("{}", version);
    let peers = client.peer_list(true).await?;
    println!("{:?}", peers);

    let ni = client.node_info().await?;
    println!("{:?}", ni);

    let consensus_info = client.get_consensus_status().await?;
    println!("{}", serde_json::to_string_pretty(&consensus_info).unwrap());

    // send transaction
    let acc_info = client
        .get_account_info(&keys.address, &consensus_info.last_finalized_block)
        .await?;
    println!("{:?}", acc_info);
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    let keys_to_sign = keys
        .account_keys
        .keys
        .iter()
        .map(|(k, v)| (k, v.keys.iter()));
    let tx = make_and_sign_transaction(
        keys_to_sign,
        keys.address,
        acc_info.account_nonce,
        600.into(),
        expiry,
        &Payload::Transfer {
            to_address: keys.address,
            amount:     1.into(),
        },
    );
    let item = BlockItem::AccountTransaction(tx);
    let transaction_hash = item.hash();
    let res = client.send_transaction(DEFAULT_NETWORK_ID, &item).await?;
    anyhow::ensure!(res, "Transaction not accepted.");
    println!("Transaction {} submitted.", transaction_hash);
    loop {
        let status = client.get_transaction_status(&transaction_hash).await?;
        match status {
            types::TransactionStatus::Received => {
                println!("Transaction received.");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            types::TransactionStatus::Finalized(outcome) => {
                println!("Transaction finalized.");
                println!("{:?}", outcome);
                break;
            }
            types::TransactionStatus::Committed(outcomes) => {
                println!("Transaction committed.");
                println!("{:?}", outcomes);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }

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
                    let info = res?;
                }
            }
            let birks = client.get_birk_parameters(&cb).await?;
            // println!("{:?}", birks);

            let summary = client.get_block_summary(&cb).await?;
            // println!("{:?}", summary);
        }
        cb = bi.block_parent;
    }

    println!("Done.");

    Ok(())
}
