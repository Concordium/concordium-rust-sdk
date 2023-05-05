//! Basic example that shows how to deploy, initialize, and update a smart
//! contract.
//!
//! In particular, it uses the "weather" contract which is part of the
//! [icecream example contract](https://github.com/Concordium/concordium-rust-smart-contracts/blob/main/examples/icecream/src/lib.rs).
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{self, types::TransactionTime, SerdeDeserialize, SerdeSerialize},
    smart_contracts::{
        common as concordium_std,
        common::Amount,
        types::{OwnedContractName, OwnedReceiveName},
    },
    types::{
        smart_contracts::{ModuleReference, OwnedParameter, WasmModule},
        transactions::{send, BlockItem, InitContractPayload, UpdateContractPayload},
        AccountInfo, ContractAddress, WalletAccount,
    },
    v2,
};
use std::path::PathBuf;
use structopt::*;
use thiserror::Error;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint:  v2::Endpoint,
    #[structopt(long = "account", help = "Path to the account key file.")]
    keys_path: PathBuf,
    #[structopt(subcommand, help = "The action you want to perform.")]
    action:    Action,
}

#[derive(StructOpt)]
enum Action {
    #[structopt(about = "Deploy the module")]
    Deploy {
        #[structopt(long = "module", help = "Path to the contract module.")]
        module_path: PathBuf,
    },
    #[structopt(about = "Initialize the contract with the provided weather")]
    Init {
        #[structopt(long, help = "The initial weather.")]
        weather:    Weather,
        #[structopt(
            long,
            help = "The module reference used for initializing the contract instance."
        )]
        module_ref: ModuleReference,
    },
    #[structopt(about = "Update the contract and set the provided weather")]
    Update {
        #[structopt(long, help = "The new weather.")]
        weather: Weather,
        #[structopt(long, help = "The contract to update the weather on.")]
        address: ContractAddress,
    },
    #[structopt(
        about = "Update the contract and set the provided weather using JSON parameters and a \
                 schema."
    )]
    UpdateWithSchema {
        #[structopt(long, help = "Path of the JSON parameter.")]
        parameter: PathBuf,
        #[structopt(long, help = "Path to the schema.")]
        schema:    PathBuf,
        #[structopt(long, help = "The contract to update the weather on.")]
        address:   ContractAddress,
    },
}

// The order must match the enum defined in the contract code. Otherwise, the
// serialization will be incorrect.
#[derive(SerdeSerialize, SerdeDeserialize, concordium_std::Serial, StructOpt)]
enum Weather {
    Rainy,
    Sunny,
}

#[derive(Debug, Error)]
#[error("invalid weather variant; expected \"rainy\" or \"sunny\", but got \"{0}\"")]
struct WeatherError(String);

impl std::str::FromStr for Weather {
    type Err = WeatherError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rainy" => Ok(Weather::Rainy),
            "sunny" => Ok(Weather::Sunny),
            _ => Err(WeatherError(s.to_owned())),
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    // load account keys and sender address from a file
    let keys: WalletAccount =
        WalletAccount::from_json_file(app.keys_path).context("Could not read the keys file.")?;

    // Get the initial nonce at the last finalized block.
    let acc_info: AccountInfo = client
        .get_account_info(&keys.address.into(), &v2::BlockIdentifier::Best)
        .await?
        .response;

    let nonce = acc_info.account_nonce;
    // set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);

    let tx = match app.action {
        Action::Init {
            weather,
            module_ref: mod_ref,
        } => {
            let param = OwnedParameter::from_serial(&weather)
                .expect("Known to not exceed parameter size limit.");
            let payload = InitContractPayload {
                amount: Amount::zero(),
                mod_ref,
                init_name: OwnedContractName::new_unchecked("init_weather".to_string()),
                param,
            };

            send::init_contract(&keys, keys.address, nonce, expiry, payload, 10000u64.into())
        }
        Action::Update { weather, address } => {
            let message = OwnedParameter::from_serial(&weather)
                .expect("Known to not exceed parameter size limit.");
            let payload = UpdateContractPayload {
                amount: Amount::zero(),
                address,
                receive_name: OwnedReceiveName::new_unchecked("weather.set".to_string()),
                message,
            };

            send::update_contract(&keys, keys.address, nonce, expiry, payload, 10000u64.into())
        }
        Action::UpdateWithSchema {
            parameter,
            schema,
            address,
        } => {
            let parameter: serde_json::Value = serde_json::from_slice(
                &std::fs::read(parameter).context("Unable to read parameter file.")?,
            )
            .context("Unable to parse parameter JSON.")?;
            let schema_source = std::fs::read(schema).context("Unable to read the schema file.")?;
            let schema = concordium_std::from_bytes::<concordium_std::schema::VersionedModuleSchema>(
                &schema_source,
            )?;
            let param_schema = schema.get_receive_param_schema("weather", "set")?;
            let serialized_parameter = param_schema.serial_value(&parameter)?;
            let message = OwnedParameter::try_from(serialized_parameter).unwrap();
            let payload = UpdateContractPayload {
                amount: Amount::zero(),
                address,
                receive_name: OwnedReceiveName::new_unchecked("weather.set".to_string()),
                message,
            };

            send::update_contract(&keys, keys.address, nonce, expiry, payload, 10000u64.into())
        }
        Action::Deploy { module_path } => {
            let contents = std::fs::read(module_path).context("Could not read contract module.")?;
            let payload: WasmModule =
                common::Deserial::deserial(&mut std::io::Cursor::new(contents))?;
            send::deploy_module(&keys, keys.address, nonce, expiry, payload)
        }
    };

    let item = BlockItem::AccountTransaction(tx);
    // submit the transaction to the chain
    let transaction_hash = client.send_block_item(&item).await?;
    println!(
        "Transaction {} submitted (nonce = {}).",
        transaction_hash, nonce,
    );
    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
