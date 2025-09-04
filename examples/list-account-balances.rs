//! List accounts and their balances ordered by decreasing CCD amount in a CSV
//! file.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{types::Amount, SerdeSerialize},
    id,
    id::types::AccountAddress,
    types::{AccountStakingInfo, CredentialType},
    v2::{self, BlockIdentifier, Upward},
};
use futures::TryStreamExt;
use serde::Serializer;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "lastfinal",
        help = "Block to query the data in. Defaults to last finalized block."
    )]
    block: BlockIdentifier,
    #[structopt(
        long = "out",
        help = "File to output the list of accounts with their balances to."
    )]
    out: PathBuf,
    #[structopt(
        long = "num",
        help = "How many queries to make in parallel.",
        default_value = "8"
    )]
    num: usize,
}

#[derive(SerdeSerialize)]
struct Row {
    #[serde(rename = "Account address")]
    address: AccountAddress,
    #[serde(rename = "Account balance in CCD", serialize_with = "to_string")]
    balance: Amount,
    #[serde(rename = "isBaker")]
    is_baker: bool,
    #[serde(rename = "Account type")]
    acc_type: CredentialType,
}

fn to_string<S: Serializer>(x: &Amount, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&x.to_string())
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

    // create the file early so that we don't spend time querying all accounts and
    // then find the output file cannot be created.
    let mut out = csv::Writer::from_path(app.out).context("Could not create output file.")?;

    let mut client = v2::Client::new(app.endpoint).await?;

    let block = client.get_block_info(app.block).await?;
    println!(
        "Listing accounts in block {} with timestamp {}.",
        block.block_hash, block.response.block_slot_time
    );
    let block = block.block_hash;

    let accounts = client
        .get_account_list(&block)
        .await?
        .response
        .try_collect::<Vec<_>>()
        .await?;

    let total_accounts = accounts.len();
    let mut num_bakers = 0;
    let mut num_initial = 0;
    let mut total_staked_amount = Amount::zero();
    let mut total_delegated_amount = Amount::zero();
    let mut total_amount = Amount::zero();

    let mut acc_balances = Vec::with_capacity(accounts.len());
    for accs in accounts.chunks(app.num).map(Vec::from) {
        let mut handles = Vec::with_capacity(app.num);
        for acc in accs {
            let mut client = client.clone();
            handles.push(tokio::spawn(async move {
                let info = client
                    .get_account_info(&acc.into(), &block)
                    .await
                    .context(format!("Getting account {} failed.", acc))?
                    .response;
                Ok::<_, anyhow::Error>((acc, info))
            }));
        }

        for res in futures::future::join_all(handles).await {
            let (acc, info) = res??;
            let is_baker = if let Some(account_stake) = info.account_stake {
                match account_stake {
                    Upward::Known(AccountStakingInfo::Baker { staked_amount, .. }) => {
                        num_bakers += 1;
                        total_staked_amount += staked_amount;
                        true
                    }
                    Upward::Known(AccountStakingInfo::Delegated { staked_amount, .. }) => {
                        total_delegated_amount += staked_amount;

                        false
                    }
                    Upward::Unknown => false,
                }
            } else {
                false
            };

            total_amount += info.account_amount;

            if let Some(acc_type) = info.account_credentials.get(&0.into()).map_or(
                Some(CredentialType::Normal),
                |cdi| match cdi.value {
                    Upward::Known(id::types::AccountCredentialWithoutProofs::Initial {
                        ..
                    }) => {
                        num_initial += 1;
                        Some(CredentialType::Initial)
                    }
                    Upward::Known(id::types::AccountCredentialWithoutProofs::Normal { .. }) => {
                        Some(CredentialType::Normal)
                    }
                    Upward::Unknown => None,
                },
            ) {
                let row = Row {
                    address: acc,
                    balance: info.account_amount,
                    is_baker,
                    acc_type,
                };
                acc_balances.push(row);
            };
        }
    }

    // Sort decreasing by amount
    acc_balances.sort_by_key(|x| std::cmp::Reverse(x.balance));

    for row in acc_balances {
        out.serialize(row)?;
    }

    println!(
        "There are in total {} accounts in block {}.",
        total_accounts, block
    );
    println!(
        "{} of these accounts are bakers, and {} are initial accounts.",
        num_bakers, num_initial
    );

    println!("Total amount of CCD is {}.", total_amount);
    println!(
        "Total amount of staked CCD is {}, which amounts to {:.2}%.",
        total_staked_amount,
        (total_staked_amount.micro_ccd() as f64 / total_amount.micro_ccd() as f64) * 100f64
    );
    println!(
        "Total amount of delegated CCD is {}, which amounts to {:.2}%.",
        total_delegated_amount,
        (total_delegated_amount.micro_ccd() as f64 / total_amount.micro_ccd() as f64) * 100f64
    );

    Ok(())
}
