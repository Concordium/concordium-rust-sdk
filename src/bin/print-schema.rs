#![allow(dead_code)]
use anyhow::Context;
use clap::AppSettings;
use common::Versioned;
use concordium_rust_sdk::{
    self,
    endpoints::{self, QueryError},
    types::{
        hashes::TransactionHash,
        queries::*,
        smart_contracts::{InstanceInfo, ModuleRef},
        *,
    },
    *,
};
use id::types::{AccountAddress, ArInfo, GlobalContext, IpInfo};
use jsonschema::JSONSchema;
use rand::{prelude::SliceRandom, thread_rng};
use schemars::JsonSchema;
use serde::Serialize;
use std::{fs, sync::Arc};
use structopt::StructOpt;

const SCHEMA_FOLDER: &str = "schemas";

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:    tonic::transport::Endpoint,
    #[structopt(long = "block")]
    start_block: Option<types::hashes::BlockHash>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app: App = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    // generate_and_write_schemas();
    crawl_and_validate_against_schemas(app).await?;
    // validate_all_schemas();
    Ok(())
}

fn validate_all_schemas() {
    compile_schema::<TransactionStatusInBlock>("GetTransactionStatusInBlock");
    compile_schema::<TransactionStatus>("GetTransactionStatus");
    compile_schema::<ConsensusInfo>("GetConsensusInfo");
    compile_schema::<BlockInfo>("GetBlockInfo");
    compile_schema::<BlockSummary>("GetBlockSummary");
    // GetBlocksAtHeight (Omitted)
    compile_schema::<Vec<AccountAddress>>("GetAccountList");
    compile_schema::<Vec<ContractAddress>>("GetInstances");
    compile_schema::<AccountInfo>("GetAccountInfo");
    compile_schema::<Vec<TransactionHash>>("GetAccountNonFinalized");
    compile_schema::<AccountNonceResponse>("GetNextAccountNonce");
    compile_schema::<InstanceInfo>("GetInstanceInfo");
    // InvokeContract (Omitted)
    compile_schema::<PoolStatus>("GetPoolStatus");
    compile_schema::<Vec<BakerId>>("GetBakerList");
    compile_schema::<RewardsOverview>("GetRewardStatus");
    compile_schema::<BirkParameters>("GetBirkParameters");
    compile_schema::<Vec<ModuleRef>>("GetModuleList");
    // GetNodeInfo..GetAncestors (Omitted)
    compile_schema::<Branch>("GetBranches");
    // GetBannedPeers..DumpStop (Omitted)
    compile_schema::<Vec<IpInfo<wrappers::WrappedPairing>>>("GetIdentityProviders");
    compile_schema::<Vec<ArInfo<wrappers::WrappedCurve>>>("GetAnonymityRevokers");
    compile_schema::<Versioned<GlobalContext<wrappers::WrappedCurve>>>(
        "GetCryptographicParameters",
    );
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

async fn crawl_and_validate_against_schemas(app: App) -> anyhow::Result<()> {
    // Create schemas for block summary, trx_status, account_info, and?
    // Compile the schemas
    // Crawl chain
    // For every block with trxs
    //   Choose 100 random accounts and check their account infos against schema
    //   Check all trxs against schema

    fn validate_and_print_errors(schema: &JSONSchema, input: &impl Serialize) {
        let json = serde_json::to_value(input).expect("Could not serialize into JSON value");
        let validation_result = schema.validate(&json);
        if let Err(errors) = validation_result {
            for error in errors {
                println!("Validation error: {}", error);
                println!("Instance path: {}", error.instance_path);
            }
        }
    }

    let schema_block_summary = compile_schema::<BlockSummary>("BlockSummary");
    let schema_account_info = Arc::new(compile_schema::<AccountInfo>("AccountInfo"));
    let schema_transaction_status =
        Arc::new(compile_schema::<TransactionStatus>("TransactionStatus"));

    let mut client = endpoints::Client::connect(app.endpoint, "rpcadmin").await?;

    let consensus_info = client.get_consensus_status().await?;
    let gb = consensus_info.genesis_block;

    let mut cb = app.start_block.unwrap_or(consensus_info.best_block);
    let mut rng = thread_rng();
    while cb != gb {
        println!("Block: {}", cb);

        // Get block summary and write to a file.
        let bs = client
            .get_block_summary(&cb)
            .await
            .context("Could not get block summary.")?;

        // Validate block summary.
        validate_and_print_errors(&schema_block_summary, &bs);

        let trxs = bs.transaction_summaries();

        // Validate all transaction summaries.
        if trxs.len() != 0 {
            let mut handles = Vec::with_capacity(trxs.len());
            for trx in trxs {
                let th = trx.hash;
                let cc = client.clone();
                let trx_schema = Arc::clone(&schema_transaction_status);
                handles.push(tokio::spawn(async move {
                    println!("    Transaction: {}", th);
                    let mut cc = cc;
                    let status = cc.get_transaction_status(&th).await?;
                    validate_and_print_errors(&trx_schema, &status);
                    Ok::<_, QueryError>(())
                }));
            }
            futures::future::join_all(handles).await;

            // Validate 100 random account infos.
            let accs = client.get_account_list(&cb).await?;
            let accs = accs
                .choose_multiple(&mut rng, 10)
                .copied()
                .collect::<Vec<_>>();
            let mut acc_handles = Vec::with_capacity(accs.len());
            for acc in accs {
                println!("    Account: {}", acc);
                let cc = client.clone();
                let acc_schema = Arc::clone(&schema_account_info);
                acc_handles.push(tokio::spawn(async move {
                    let mut cc = cc;
                    let acc_info = cc.get_account_info(acc, &cb).await?;
                    validate_and_print_errors(&acc_schema, &acc_info);
                    Ok::<_, QueryError>(())
                }))
            }
            futures::future::join_all(acc_handles).await;
        }

        // Find parent block hash
        let bi = client.get_block_info(&cb).await?;
        cb = bi.block_parent;
    }
    Ok(())
}

fn validate_json() -> anyhow::Result<()> {
    let schema_file =
        fs::read_to_string("schemas/GetBlockSummary.json").context("Loading schema")?;
    let schema = serde_json::from_str(&schema_file).expect("Schema is valid JSON");
    let instance_file = fs::read_to_string(
        "test_cases/block_summary/\
         0a0aaaf8722b6d5ebb707d99dcf300ab6bc909e1015d8e5ee30a2473a319c3c2.json",
    )
    .context("Loading test case")?;
    let instance = serde_json::from_str(&instance_file).expect("Instance is valid JSON");
    let compiled = JSONSchema::options()
        .compile(&schema)
        .expect("A valid schema");
    let result = compiled.validate(&instance);
    if let Err(errors) = result {
        for error in errors {
            println!("Validation error: {}", error);
            println!("Instance path: {}", error.instance_path);
        }
    }
    Ok(())
}

/// Validates whether the schema generated for the type `T` is valid according
/// to the Json Schema Draft 7 specification.
/// Returns the schema if it is valid. Otherwise, it panics.
fn compile_schema<T: JsonSchema>(schema_name: &str) -> JSONSchema {
    let schema = schemars::schema_for!(T);
    let schema_json = serde_json::value::to_value(schema).expect("Schema should be valid JSON");
    JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&schema_json)
        .expect(&format!("{} is not valid", schema_name))
}
