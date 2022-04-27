use anyhow::Context;
use common::Versioned;
use concordium_rust_sdk::{
    self, endpoints,
    types::{
        hashes::TransactionHash,
        queries::*,
        smart_contracts::{InstanceInfo, ModuleRef},
        *,
    },
    *,
};
use id::types::{AccountAddress, ArInfo, GlobalContext, IpInfo};
use schemars::JsonSchema;
use std::fs;

const SCHEMA_FOLDER: &str = "schemas";
const TEST_CASE_FOLDER: &str = "test_cases";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // generate_and_write_schemas();
    crawl_and_save_test_cases().await;
    Ok(())
}

fn generate_and_write_schemas() {
    // Ensure the schema folder exists.
    fs::create_dir_all(SCHEMA_FOLDER).expect("Could not create schema folder");

    write_schema_to_file::<TransactionStatusInBlock>("GetTransactionStatusInBlock");
    write_schema_to_file::<TransactionStatus>("GetTransactionStatus");
    write_schema_to_file::<ConsensusInfo>("GetConsensusInfo");
    write_schema_to_file::<BlockInfo>("GetBlockInfo");
    write_schema_to_file::<BlockSummary>("GetBlockSummary");
    // GetBlocksAtHeight (Omitted)
    write_schema_to_file::<Vec<AccountAddress>>("GetAccountList");
    write_schema_to_file::<Vec<ContractAddress>>("GetInstances");
    write_schema_to_file::<AccountInfo>("GetAccountInfo");
    write_schema_to_file::<Vec<TransactionHash>>("GetAccountNonFinalized");
    write_schema_to_file::<AccountNonceResponse>("GetNextAccountNonce");
    write_schema_to_file::<InstanceInfo>("GetInstanceInfo");
    // InvokeContract (Omitted)
    write_schema_to_file::<PoolStatus>("GetPoolStatus");
    write_schema_to_file::<Vec<BakerId>>("GetBakerList");
    write_schema_to_file::<RewardsOverview>("GetRewardStatus");
    write_schema_to_file::<BirkParameters>("GetBirkParameters");
    write_schema_to_file::<Vec<ModuleRef>>("GetModuleList");
    // GetNodeInfo..GetAncestors (Omitted)
    write_schema_to_file::<Branch>("GetBranches");
    // GetBannedPeers..DumpStop (Omitted)
    write_schema_to_file::<Vec<IpInfo<wrappers::WrappedPairing>>>("GetIdentityProviders");
    write_schema_to_file::<Vec<ArInfo<wrappers::WrappedCurve>>>("GetAnonymityRevokers");
    write_schema_to_file::<Versioned<GlobalContext<wrappers::WrappedCurve>>>(
        "GetCryptographicParameters",
    );
}

fn write_schema_to_file<T: JsonSchema>(endpoint_name: &str) {
    let file_name = format!("{}/{}.json", SCHEMA_FOLDER, endpoint_name);
    println!("Writing {}", file_name);
    let schema = schemars::schema_for!(T);
    let contents = format!(
        "{}",
        serde_json::to_string_pretty(&schema).expect("Unable to pretty print JSON schema")
    );
    fs::write(file_name, contents).expect("Unable to write file");
}

async fn crawl_and_save_test_cases() -> anyhow::Result<()> {
    // Ensure folder is created for tests
    let block_summary_folder = format!("{}/block_summary", TEST_CASE_FOLDER);
    let transactions_folder = format!("{}/trx_status", TEST_CASE_FOLDER);
    fs::create_dir_all(&block_summary_folder).expect("Could not create test folder");
    fs::create_dir_all(&transactions_folder).expect("Could not create test folder");

    let mut client = endpoints::Client::connect("http://localhost:10000", "rpcadmin").await?;

    let consensus_info = client.get_consensus_status().await?;
    let gb = consensus_info.genesis_block;

    let mut cb = consensus_info.best_block;
    while cb != gb {
        println!("{}", cb);

        // Get block summary and write to a file.
        let bs = client
            .get_block_summary(&cb)
            .await
            .context("Could not get block summary.")?;

        let trxs = bs.transaction_summaries();

        if trxs.len() != 0 {
            let mut handles = Vec::with_capacity(1000);
            for trx in trxs {
                let th = trx.hash;
                println!("        {}", th);
                let cc = client.clone();
                handles.push(tokio::spawn(async move {
                    let mut cc = cc;
                    (th, cc.get_transaction_status(&th).await)
                }));
            }
            let x = futures::future::join_all(handles).await;
            for res in x {
                let (th, trx_status_res) = res?;
                let trx_status = trx_status_res?;
                let trx_file = format!("{}/{}.json", transactions_folder, th);
                fs::write(
                    trx_file,
                    serde_json::to_string_pretty(&trx_status)
                        .expect("Could not serialize transaction status to json"),
                )?;
            }
        }

        let file = format!("{}/{}.json", block_summary_folder, cb);
        fs::write(
            file,
            serde_json::to_string_pretty(&bs).expect("Could not serialize block summary to json"),
        )?;

        // Find parent block hash
        let bi = client.get_block_info(&cb).await?;
        cb = bi.block_parent;
    }
    Ok(())
}
