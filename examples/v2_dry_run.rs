//! Example of dry-run functionality of the node.

use std::time::Duration;

use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    base::Energy,
    common::types::Timestamp,
    contracts_common::{Address, Amount, ContractAddress, EntrypointName},
    smart_contracts::{OwnedParameter, OwnedReceiveName},
    transactions::Payload,
};
use concordium_rust_sdk::{
    types::smart_contracts::ContractContext,
    v2::{self, dry_run::DryRunTransaction, BlockIdentifier},
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:25162"
    )]
    endpoint: v2::Endpoint,
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

    let mut dry_run = client.dry_run().await?;

    let fut1 = dry_run.load_block_state(BlockIdentifier::Best).await?;
    tokio::time::sleep(Duration::from_millis(2500)).await;

    let fut2 = dry_run.load_block_state(BlockIdentifier::LastFinal).await?;

    let res2 = fut2.await?;
    let res1 = fut1.await?;
    println!(
        "Best block: {} ({:?})",
        res1.inner.block_hash, res1.inner.current_timestamp
    );
    println!(
        "Last final: {} ({:?})",
        res2.inner.block_hash, res2.inner.current_timestamp
    );

    let res3 = dry_run
        .get_account_info(&v2::AccountIdentifier::Index(0.into()))
        .await?
        .await?;

    println!("Account 0: {}", res3.inner.account_address);

    let contract_addr = ContractAddress {
        index:    0,
        subindex: 0,
    };

    let res4 = dry_run.get_instance_info(&contract_addr).await?.await?;

    println!(
        "Instance <0,0>: {} {:?}",
        res4.inner.name(),
        res4.inner.entrypoints()
    );

    let invoke_target = OwnedReceiveName::construct(
        res4.inner.name().as_contract_name(),
        EntrypointName::new(&"view")?,
    )?;
    let parameter = OwnedParameter::empty();

    let context = ContractContext {
        invoker:   Some(Address::Account(res3.inner.account_address)),
        contract:  contract_addr,
        amount:    Amount::zero(),
        method:    invoke_target,
        parameter,
        energy:    10000.into(),
    };

    let res5 = dry_run.invoke_instance(&context).await?.await;

    println!("Invoked view on <0,0>: {:?}", res5);

    let _res6 = dry_run
        .mint_to_account(&res3.inner.account_address, Amount::from_ccd(20))
        .await?
        .await?;

    let _res7 = dry_run.set_timestamp(Timestamp::now()).await?.await?;

    let payload = Payload::TransferToEncrypted {
        amount: Amount::from_ccd(20),
    };
    let transaction =
        DryRunTransaction::new(res3.inner.account_address, Energy::from(5000), &payload);
    let res8 = dry_run.run_transaction(transaction).await?.await?;
    println!("Transferred to encrypted: {:?}", res8);

    Ok(())
}
