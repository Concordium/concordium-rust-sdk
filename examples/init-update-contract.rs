//! Basic example that shows how to initialize and update a smart contract.
//!
//! In particular, it uses the "weather" contract which is part of the
//! [icecream example contract](https://github.com/Concordium/concordium-rust-smart-contracts/blob/main/examples/icecream/src/lib.rs).
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{SerdeDeserialize, SerdeSerialize},
    contract_client::{ContractClient, ContractInitBuilder, ViewError},
    endpoints,
    smart_contracts::{
        common as concordium_std,
        common::{Amount, ContractAddress, Serial},
    },
    types::{smart_contracts::ModuleReference, WalletAccount},
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
    endpoint: endpoints::Endpoint,
    #[structopt(long = "account", help = "Path to the account key file.")]
    keys_path: PathBuf,
    #[structopt(subcommand, help = "The action you want to perform.")]
    action: Action,
}

#[derive(StructOpt)]
enum Action {
    #[structopt(about = "Initialize the contract with the provided weather")]
    Init {
        #[structopt(long, help = "The initial weather.")]
        weather: Weather,
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

enum WeatherContractMarker {}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let client = v2::Client::new(app.endpoint).await?;

    // load account keys and sender address from a file
    let account: WalletAccount =
        WalletAccount::from_json_file(app.keys_path).context("Could not parse the keys file.")?;

    match app.action {
        Action::Init {
            weather,
            module_ref: mod_ref,
        } => {
            let builder = ContractInitBuilder::<WeatherContractMarker>::dry_run_new_instance(
                client,
                account.address,
                mod_ref,
                "weather",
                Amount::zero(),
                &weather,
            )
            .await?;
            println!(
                "The maximum amount of NRG allowed for the transaction is {}.",
                builder.current_energy()
            );
            let handle = builder.send(&account).await?;
            println!("Transaction {handle} submitted. Waiting for finalization.");
            let (contract_client, events) = handle.wait_for_finalization().await?;
            println!(
                "Initialized a new smart contract instance at address {}.",
                contract_client.address
            );
            println!("The following events were generated.");
            for event in events {
                println!("{event}");
            }
        }
        Action::Update { weather, address } => {
            let mut contract_client =
                ContractClient::<WeatherContractMarker>::create(client, address).await?;
            let builder = contract_client
                .dry_run_update::<_, ViewError>("set", Amount::zero(), account.address, &weather)
                .await?;
            println!(
                "The maximum amount of execution NRG allowed for the transaction is {}.",
                builder.current_energy()
            );
            let handle = builder.send(&account).await?;
            println!("Transaction {handle} submitted. Waiting for finalization.");
            let result = handle.wait_for_finalization().await?;
            println!(
                "Update smart contract instance. It cost {}CCD.",
                result.cost
            );
        }
    };
    Ok(())
}
