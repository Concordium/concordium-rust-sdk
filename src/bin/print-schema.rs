#![allow(dead_code)]
use anyhow::Context;
use clap::AppSettings;
use common::Versioned;
use concordium_rust_sdk::{
    self,
    endpoints::{Client, QueryError, RPCError},
    types::{
        hashes::{BlockHash, TransactionHash},
        queries::*,
        smart_contracts::{InstanceInfo, ModuleRef},
        *,
    },
    *,
};
use id::types::{AccountAddress, ArInfo, GlobalContext, IpInfo};
use jsonschema::JSONSchema;
use rand::{
    distributions::Uniform,
    prelude::{Distribution, SliceRandom, SmallRng},
    Rng, SeedableRng,
};
use schemars::JsonSchema;
use serde::Serialize;
use std::{fs, sync::Arc};
use structopt::StructOpt;

const SCHEMA_FOLDER: &str = "schemas";
static mut TRX_IN_BLOCK_CHECKED: bool = false;
static mut ONE_OFF_VALIDATION_CHECKED: bool = false;

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
    // NOTE: The rust-sdk returns it without Version<T>, but the gRPC API includes
    // the version wrapper.
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

/// Crawl the chain from provided block back and back to genesis.
/// The node being queried is the primary bottleneck, so giving it more cores to
/// run on signicantly increases the speed of this function. Also make sure to
/// build this binary in release mode.
async fn crawl_and_validate_against_schemas(app: App) -> anyhow::Result<()> {
    let schema_transaction_status_in_block = Arc::new(compile_schema::<TransactionStatusInBlock>(
        "GetTransactionStatusInBlock",
    ));
    let schema_transaction_status =
        Arc::new(compile_schema::<TransactionStatus>("GetTransactionStatus"));
    let schema_consensus_info = Arc::new(compile_schema::<ConsensusInfo>("GetConsensusInfo"));
    let schema_block_info = Arc::new(compile_schema::<BlockInfo>("GetBlockInfo"));
    let schema_block_summary = Arc::new(compile_schema::<BlockSummary>("GetBlockSummary"));
    // GetBlocksAtHeight (Omitted)
    let schema_account_list = Arc::new(compile_schema::<Vec<AccountAddress>>("GetAccountList"));
    let schema_instances = Arc::new(compile_schema::<Vec<ContractAddress>>("GetInstances"));
    let schema_account_info = Arc::new(compile_schema::<AccountInfo>("GetAccountInfo"));
    // GetAccountNonFinalized (Omitted as I run it on the old (dead) testnet).
    let schema_account_nonce = Arc::new(compile_schema::<AccountNonceResponse>(
        "GetNextAccountNonce",
    ));
    let schema_instance_info = Arc::new(compile_schema::<InstanceInfo>("GetInstanceInfo"));
    // InvokeContract (Omitted)
    let schema_pool_status = Arc::new(compile_schema::<PoolStatus>("GetPoolStatus"));
    let schema_baker_list = Arc::new(compile_schema::<Vec<BakerId>>("GetBakerList"));
    let schema_rewards_overview = Arc::new(compile_schema::<RewardsOverview>("GetRewardStatus"));
    let schema_birk_parameters = Arc::new(compile_schema::<BirkParameters>("GetBirkParameters"));
    let schema_module_list = Arc::new(compile_schema::<Vec<ModuleRef>>("GetModuleList"));
    // GetNodeInfo..GetAncestors (Omitted)
    let schema_branch = Arc::new(compile_schema::<Branch>("GetBranches"));
    // GetBannedPeers..DumpStop (Omitted)
    let schema_identity_providers = Arc::new(
        compile_schema::<Vec<IpInfo<wrappers::WrappedPairing>>>("GetIdentityProviders"),
    );
    let schema_anonymity_revokers = Arc::new(
        compile_schema::<Vec<ArInfo<wrappers::WrappedCurve>>>("GetAnonymityRevokers"),
    );
    // NOTE: The rust-sdk returns it without Version<T>, but the gRPC API includes
    // the version wrapper.
    let schema_cryptographic_parameters = Arc::new(compile_schema::<
        GlobalContext<wrappers::WrappedCurve>,
    >("GetCryptographicParameters"));

    let mut client = Client::connect(app.endpoint, "rpcadmin").await?;

    let consensus_info = client.get_consensus_status().await?;
    let gb = consensus_info.genesis_block;

    let mut cb = app.start_block.unwrap_or(consensus_info.best_block);

    let mut rng = rand::rngs::SmallRng::from_entropy();
    let r_range = Uniform::from(u8::MIN..u8::MAX);
    while cb != gb {
        println!("Block: {}", cb);
        let cc = client.clone();
        // Used for selecting which schemas to validate for the given block.
        let r: u8 = r_range.sample(&mut rng);
        let rng = rng.clone();
        let schema_transaction_status_in_block = schema_transaction_status_in_block.clone();
        let schema_transaction_status = schema_transaction_status.clone();
        let schema_consensus_info = schema_consensus_info.clone();
        let schema_block_info = schema_block_info.clone();
        let schema_block_summary = schema_block_summary.clone();
        let schema_account_list = schema_account_list.clone();
        let schema_instances = schema_instances.clone();
        let schema_account_info = schema_account_info.clone();
        let schema_account_nonce = schema_account_nonce.clone();
        let schema_instance_info = schema_instance_info.clone();
        let schema_pool_status = schema_pool_status.clone();
        let schema_baker_list = schema_baker_list.clone();
        let schema_rewards_overview = schema_rewards_overview.clone();
        let schema_birk_parameters = schema_birk_parameters.clone();
        let schema_module_list = schema_module_list.clone();
        let schema_branch = schema_branch.clone();
        let schema_identity_providers = schema_identity_providers.clone();
        let schema_anonymity_revokers = schema_anonymity_revokers.clone();
        let schema_cryptographic_parameters = schema_cryptographic_parameters.clone();

        tokio::spawn(async move {
            let mut cc = cc;
            // Get block summary.
            let bs = cc
                .get_block_summary(&cb)
                .await
                .context("Could not get block summary.")?;

            let trxs = bs.transaction_summaries();

            if trxs.len() != 0 {
                // Always check all transaction summaries.
                validate_transaction_summaries(&cc, trxs, &schema_transaction_status);

                // Check a trx in cb and gb. Only once.
                // A potential race condition is fine. The worst that can happen is that it is
                // checked ~twice.
                unsafe {
                    if !TRX_IN_BLOCK_CHECKED {
                        let th = trxs[0].hash;
                        validate_transaction_status_in_block(
                            &cc,
                            &cb, // Current block
                            &th,
                            &schema_transaction_status_in_block,
                        );
                        validate_transaction_status_in_block(
                            &cc,
                            &gb, // Genesis block (where trx will be missing)
                            &th,
                            &schema_transaction_status_in_block,
                        );
                        TRX_IN_BLOCK_CHECKED = true;
                    }
                }
            }

            match r {
                0..=19 => validate_consensus_info(&cc, schema_consensus_info),
                40..=42 => validate_account_list_and_info_and_nonce(
                    &cc,
                    &cb,
                    rng.clone(),
                    10,
                    schema_account_list,
                    schema_account_info,
                    schema_account_nonce,
                ),
                100..=110 => {
                    validate_instances_and_info(&cc, &cb, schema_instances, schema_instance_info)
                }
                140..=142 => validate_baker_list_and_pool_status(
                    &cc,
                    &cb,
                    rng.clone(),
                    schema_baker_list,
                    schema_pool_status,
                ),
                160..=162 => validate_rewards_overview(&cc, &cb, schema_rewards_overview),
                180..=182 => validate_block_info(&cc, &cb, schema_block_info),
                _ => (), /* Do nothing in a lot of the cases since there are plenty of blocks to
                          * check. */
            }

            // Always validate the block summary.
            validate_with_schema(&schema_block_summary, &bs, format!("BlockSummary {}", cb));

            // Validate these once.
            // A potential race condition is fine. The worst that can happen is that it is
            // checked ~twice.
            unsafe {
                if !ONE_OFF_VALIDATION_CHECKED {
                    validate_birk_parameters(&cc, &cb, schema_birk_parameters);
                    validate_branches(&cc, schema_branch);
                    validate_identity_providers(&cc, &cb, schema_identity_providers);
                    validate_anonymity_revokers(&cc, &cb, schema_anonymity_revokers);
                    validate_cryptographic_parameters(&cc, &cb, schema_cryptographic_parameters);
                    validate_module_list(&cc, &cb, schema_module_list);
                    ONE_OFF_VALIDATION_CHECKED = true;
                }
            }

            Ok::<_, anyhow::Error>(())
        });

        // Find parent block hash
        let bi = client.get_block_info(&cb).await?;
        cb = bi.block_parent;
    }
    Ok(())
}

fn validate_cryptographic_parameters(cc: &Client, bh: &BlockHash, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("   CryptographicParameters for block: {}", bh);
        let data = cc.get_cryptographic_parameters(&bh).await?;
        validate_with_schema(&schema, &data, "CryptoParams");
        Ok::<_, QueryError>(())
    });
}

fn validate_anonymity_revokers(cc: &Client, bh: &BlockHash, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("   AnonymityRevokers for block: {}", bh);
        let data = cc.get_anonymity_revokers(&bh).await?;
        validate_with_schema(&schema, &data, "AnonymityRevokers");
        Ok::<_, QueryError>(())
    });
}

fn validate_identity_providers(cc: &Client, bh: &BlockHash, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("   IdentityProviders for block: {}", bh);
        let data = cc.get_identity_providers(&bh).await?;
        validate_with_schema(&schema, &data, "IdentityProviders");
        Ok::<_, QueryError>(())
    });
}

fn validate_branches(cc: &Client, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    tokio::spawn(async move {
        println!("   Branches");
        let data = cc.get_branches().await?;
        validate_with_schema(&schema, &data, "Branches");
        Ok::<_, QueryError>(())
    });
}

fn validate_module_list(cc: &Client, bh: &BlockHash, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("   ModuleList for block: {}", bh);
        let data = cc.get_module_list(&bh).await?;
        validate_with_schema(&schema, &data, "ModuleList");
        Ok::<_, QueryError>(())
    });
}

fn validate_birk_parameters(cc: &Client, bh: &BlockHash, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("   BirkParameters for block: {}", bh);
        let data = cc.get_birk_parameters(&bh).await?;
        validate_with_schema(&schema, &data, "BirkParameters");
        Ok::<_, QueryError>(())
    });
}

fn validate_rewards_overview(cc: &Client, bh: &BlockHash, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("   RewardsOverview for block: {}", bh);
        let data = cc.get_reward_status(&bh).await?;
        validate_with_schema(&schema, &data, format!("RewardsOverview {}", bh));
        Ok::<_, QueryError>(())
    });
}

fn validate_baker_list_and_pool_status(
    cc: &Client,
    bh: &BlockHash,
    rng: SmallRng,
    schema_baker_list: Arc<JSONSchema>,
    schema_pool_status: Arc<JSONSchema>,
) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("   Baker list in block: {}", bh);
        let bakers = cc.get_baker_list(&bh).await?;
        validate_with_schema(&schema_baker_list, &bakers, format!("BakerList {}", bh));
        validate_random_pool_status(&cc, &bakers, &bh, rng, schema_pool_status);
        Ok::<_, QueryError>(())
    });
}

fn validate_random_pool_status(
    cc: &Client,
    pools: &[BakerId],
    bh: &BlockHash,
    mut rng: SmallRng,
    schema: Arc<JSONSchema>,
) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    let r: u8 = rng.gen();
    let baker_id = if r < 20 {
        None
    } else {
        pools.choose(&mut rng).cloned()
    };
    tokio::spawn(async move {
        if let Some(baker_id) = baker_id {
            println!("    Pool Info for: {} in block: {}", baker_id, bh);
        } else {
            println!("    Passive delegation info in block: {}", bh);
        }
        let info = cc.get_pool_status(baker_id, &bh).await?;
        validate_with_schema(&schema, &info, format!("PoolStatus {}", bh));
        Ok::<_, QueryError>(())
    });
}

fn validate_instance_info(
    cc: &Client,
    addr: ContractAddress,
    bh: &BlockHash,
    schema: Arc<JSONSchema>,
) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("    Instance info for: <{},{}>", addr.index, addr.subindex);
        let info = cc.get_instance_info(addr, &bh).await?;
        validate_with_schema(
            &schema,
            &info,
            format!(
                "InstanceInfo addr: <{},{}>, bh: {}",
                addr.index, addr.subindex, bh
            ),
        );
        Ok::<_, QueryError>(())
    });
}

fn validate_next_account_none(cc: &Client, addr: AccountAddress, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    tokio::spawn(async move {
        println!("    Account nonce for account: {}", addr);
        let nonce = cc.get_next_account_nonce(&addr).await?;
        validate_with_schema(&schema, &nonce, format!("AccountNonce addr: {}", addr));
        Ok::<_, RPCError>(())
    });
}

/// Validate account list and `number_of_infos` account infos. Also validates a
/// nonce.
fn validate_account_list_and_info_and_nonce(
    cc: &Client,
    bh: &BlockHash,
    mut rng: SmallRng,
    number_of_infos: usize,
    schema_account_list: Arc<JSONSchema>,
    schema_account_info: Arc<JSONSchema>,
    schema_account_nonce: Arc<JSONSchema>,
) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("    Account list in block: {}", bh);
        let accs = cc.get_account_list(&bh).await?;
        validate_with_schema(&schema_account_list, &accs, format!("AccountList {}", bh));
        validate_n_account_infos(
            &mut cc,
            &bh,
            &accs,
            &schema_account_info,
            &mut rng,
            number_of_infos,
        );
        if accs.len() != 0 {
            validate_next_account_none(&cc, accs[0], schema_account_nonce);
        }
        Ok::<_, QueryError>(())
    });
}

fn validate_instances_and_info(
    cc: &Client,
    bh: &BlockHash,
    schema_instances: Arc<JSONSchema>,
    schema_instance_info: Arc<JSONSchema>,
) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("    Instances in block: {}", bh.to_string());
        let instances = cc.get_instances(&bh).await?;
        validate_with_schema(&schema_instances, &instances, format!("Instances {}", bh));
        // Validate a random instance.
        let addr = instances.choose(&mut rand::thread_rng());
        if let Some(addr) = addr {
            validate_instance_info(&cc, *addr, &bh, schema_instance_info);
        }
        Ok::<_, QueryError>(())
    });
}

fn validate_transaction_status_in_block(
    cc: &Client,
    bh: &BlockHash,
    th: &TransactionHash,
    schema: &Arc<JSONSchema>,
) {
    let mut cc = cc.clone();
    let schema = schema.clone();
    let bh = bh.clone();
    let th = th.clone();
    tokio::spawn(async move {
        println!("   TransactionStatusInBlock: {} in block {}", th, bh);
        let status = cc.get_transaction_status_in_block(&bh, &th).await?;
        validate_with_schema(&schema, &status, format!("TransactionStatusInBlock {}", bh));
        Ok::<_, QueryError>(())
    });
}

fn validate_block_info(cc: &Client, bh: &BlockHash, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    let bh = bh.clone();
    tokio::spawn(async move {
        println!("    BlockInfo: {}", bh);
        let block_info = cc.get_block_info(&bh).await?;
        validate_with_schema(&schema, &block_info, format!("BlockInfo {}", bh));
        Ok::<_, QueryError>(())
    });
}

fn validate_consensus_info(cc: &Client, schema: Arc<JSONSchema>) {
    let mut cc = cc.clone();
    tokio::spawn(async move {
        println!("    ConsensusInfo");
        let info = cc.get_consensus_status().await?;
        validate_with_schema(&schema, &info, format!("ConsensusInfo"));
        Ok::<_, RPCError>(())
    });
}

/// Validate all transaction summaries given.
fn validate_transaction_summaries(
    cc: &Client,
    trxs: &[BlockItemSummary],
    trx_schema: &Arc<JSONSchema>,
) {
    for trx in trxs {
        let th = trx.hash;
        let mut cc = cc.clone();
        let trx_schema = Arc::clone(&trx_schema);
        tokio::spawn(async move {
            println!("    Transaction: {}", th);
            let status = cc.get_transaction_status(&th).await?;
            validate_with_schema(&trx_schema, &status, format!("TransactionSummary {}", th));
            Ok::<_, QueryError>(())
        });
    }
}

/// Validate n random account infos.
fn validate_n_account_infos(
    cc: &mut Client,
    bh: &BlockHash,
    accs: &[AccountAddress],
    acc_schema: &Arc<JSONSchema>,
    rng: &mut rand::rngs::SmallRng,
    n: usize,
) {
    let accs = accs.choose_multiple(rng, n).copied().collect::<Vec<_>>();
    for acc in accs {
        println!("    Account: {}", acc);
        let cc = cc.clone();
        let acc_schema = Arc::clone(&acc_schema);
        let bh = bh.clone();

        tokio::spawn(async move {
            let mut cc = cc;
            let acc_info = cc.get_account_info(acc, &bh).await?;
            validate_with_schema(
                &acc_schema,
                &acc_info,
                format!("AccountInfo addr: {}, bh: {}", acc, bh),
            );
            Ok::<_, QueryError>(())
        });
    }
}

/// Validates the input with the schema and prints any errors to stdout.
fn validate_with_schema<S: AsRef<str> + std::fmt::Display>(
    schema: &JSONSchema,
    input: &impl Serialize,
    identifier: S,
) {
    let json = serde_json::to_value(input).expect("Could not serialize into JSON value");
    let validation_result = schema.validate(&json);
    if let Err(errors) = validation_result {
        for error in errors {
            println!("--------- {} :: Validation error: {}", identifier, error);
            println!(
                "--------- {} :: Instance path: {}",
                identifier, error.instance_path
            );
        }
    }
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
