//! Basic example that shows how to deploy, initialize, and update a smart
//! contract.
//!
//! In particular, it uses the "weather" contract which is part of the
//! [icecream example contract](https://github.com/Concordium/concordium-rust-smart-contracts/blob/main/examples/icecream/src/lib.rs).
//!
//! It also exercises the endpoint for getting the
//! transaction sign hash and using sending in a structured protobuf payload.
use anyhow::Context;
use clap::AppSettings;
use concordium_contracts_common::{
    Amount, ContractAddress, OwnedContractName, OwnedReceiveName, Serial,
};
use concordium_rust_sdk::{
    common::{types::TransactionTime, SerdeDeserialize, SerdeSerialize},
    endpoints,
    id::types::{AccountAddress, AccountKeys},
    types::{
        smart_contracts::{ModuleRef, Parameter, WasmModule},
        transactions::{
            AccountTransaction, BlockItem, InitContractPayload, Payload, PayloadSize,
            TransactionHeader, TransactionSigner, UpdateContractPayload,
        },
        AccountInfo,
    },
    v2,
};
use crypto_common::Deserial;
use std::path::PathBuf;
use structopt::*;
use thiserror::Error;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:  endpoints::Endpoint,
    #[structopt(long = "account", help = "Path to the account key file.")]
    keys_path: PathBuf,
    #[structopt(subcommand, help = "The action you want to perform.")]
    action:    Action,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Account address and keys that will be supplied in a JSON file.
/// The transaction will be signed with the given keys.
struct AccountData {
    account_keys: AccountKeys,
    address:      AccountAddress,
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
        module_ref: ModuleRef,
    },
    #[structopt(about = "Update the contract and set the provided weather")]
    Update {
        #[structopt(long, help = "The new weather.")]
        weather: Weather,
        #[structopt(long, help = "The contract to update the weather on.")]
        address: ContractAddress,
    },
}

// The order must match the enum defined in the contract code. Otherwise, the
// serialization will be incorrect.
#[derive(SerdeSerialize, SerdeDeserialize, Serial, StructOpt)]
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
    let keys: AccountData = serde_json::from_str(
        &std::fs::read_to_string(app.keys_path).context("Could not read the keys file.")?,
    )
    .context("Could not parse the keys file.")?;

    // Get the initial nonce at the last finalized block.
    let acc_info: AccountInfo = client
        .get_account_info(&keys.address.into(), &v2::BlockIdentifier::Best)
        .await?
        .response;

    let nonce = acc_info.account_nonce;
    // set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);

    let header = TransactionHeader {
        sender: keys.address,
        nonce,
        energy_amount: 30000u64.into(),
        payload_size: PayloadSize::from(0), // The node calculates this automatically now.
        expiry,
    };

    let payload = match app.action {
        Action::Init {
            weather,
            module_ref: mod_ref,
        } => {
            let param = Parameter::from(concordium_contracts_common::to_bytes(&weather));
            let payload = InitContractPayload {
                amount: Amount::zero(),
                mod_ref,
                init_name: OwnedContractName::new_unchecked("init_weather".to_string()),
                param,
            };
            Payload::InitContract { payload }
        }
        Action::Update { weather, address } => {
            let message = Parameter::from(concordium_contracts_common::to_bytes(&weather));
            let payload = UpdateContractPayload {
                amount: Amount::zero(),
                address,
                receive_name: OwnedReceiveName::new_unchecked("weather.set".to_string()),
                message,
            };
            Payload::Update { payload }
        }
        Action::Deploy { module_path } => {
            let contents = std::fs::read(module_path).context("Could not read contract module.")?;
            let module: WasmModule = Deserial::deserial(&mut std::io::Cursor::new(contents))?;
            Payload::DeployModule { module }
        }
    };

    let trx_sign_hash = client
        .get_account_transaction_sign_hash(&header, &payload)
        .await?;

    let signature = keys.account_keys.sign_transaction_hash(&trx_sign_hash);
    let bi = BlockItem::AccountTransaction(AccountTransaction {
        signature,
        header,
        payload,
    });

    // submit the transaction to the chain
    let transaction_hash = client.send_block_item_unencoded(&bi).await?;
    println!(
        "Transaction {} submitted (nonce = {}).",
        transaction_hash, nonce,
    );
    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
