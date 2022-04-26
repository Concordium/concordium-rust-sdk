use concordium_rust_sdk::types::{
    hashes::TransactionHash,
    queries::*,
    smart_contracts::{InstanceInfo, ModuleRef},
    *,
};
use id::types::{AccountAddress, ArInfo, GlobalContext, IpInfo};
use schemars::JsonSchema;
use std::fs;

const SCHEMA_FOLDER: &str = "schemas";

fn main() { generate_and_write_schemas(); }

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
    write_schema_to_file::<AccountNonceResponse>("NextAccountNonce");
    write_schema_to_file::<InstanceInfo>("GetInstances");
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
    write_schema_to_file::<GlobalContext<wrappers::WrappedCurve>>("GetCryptographicParameters");
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
