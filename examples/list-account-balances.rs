//! List accounts and their balances ordered by decreasing CCD amount in a CSV
//! file.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::SerdeSerialize,
    endpoints,
    id::types::AccountAddress,
    types::{hashes::BlockHash, CredentialType},
};
use crypto_common::types::Amount;
use serde::Serializer;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint: tonic::transport::Endpoint,
    #[structopt(
        long = "block",
        help = "Block to query the data in. Defaults to last finalized block."
    )]
    block:    Option<BlockHash>,
    #[structopt(long = "token", help = "GRPC login token", default_value = "rpcadmin")]
    token:    String,
    #[structopt(
        long = "out",
        help = "File to output the list of accounts with their balances to."
    )]
    out:      PathBuf,
    #[structopt(
        long = "num",
        help = "How many queries to make in parallel.",
        default_value = "8"
    )]
    num:      usize,
}

#[derive(SerdeSerialize)]
struct Row {
    #[serde(rename = "Account address")]
    address:  AccountAddress,
    #[serde(rename = "Account balance in CCD", serialize_with = "to_string")]
    balance:  Amount,
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

    let mut client = endpoints::Client::connect(app.endpoint, app.token).await?;

    let consensus_info = client.get_consensus_status().await?;

    let block = app.block.unwrap_or(consensus_info.last_finalized_block);
    println!("Listing accounts in block {}.", block);

    let accounts = client.get_account_list(&block).await?;

    let total_accounts = accounts.len();
    let mut num_bakers = 0;
    let mut num_initial = 0;
    let mut staked_amount: Amount = 0.into();
    let mut total_amount: Amount = 0.into();

    let mut acc_balances = Vec::with_capacity(accounts.len());
    for accs in accounts.chunks(app.num).map(Vec::from) {
        let mut handles = Vec::with_capacity(app.num);
        for acc in accs {
            let mut client = client.clone();
            handles.push(tokio::spawn(async move {
                let info = client.get_account_info(&acc, &block).await?;
                Ok::<_, anyhow::Error>((acc, info))
            }));
        }

        for res in futures::future::join_all(handles).await {
            let (acc, info) = res??;
            let is_baker = if let Some(baker) = info.account_baker {
                num_bakers += 1;
                staked_amount = (staked_amount + baker.staked_amount)
                    .context("Total staked amount exceeds u64. This should not happen.")?;
                true
            } else {
                false
            };

            total_amount = (total_amount + info.account_amount)
                .context("Total amount exceeds u64. This should not happen.")?;

            let acc_type =
                info.account_credentials
                    .get(&0.into())
                    .map_or(CredentialType::Normal, |cdi| match cdi.value {
                        id::types::AccountCredentialWithoutProofs::Initial { .. } => {
                            num_initial += 1;
                            CredentialType::Initial
                        }
                        id::types::AccountCredentialWithoutProofs::Normal { .. } => {
                            CredentialType::Normal
                        }
                    });

            let row = Row {
                address: acc,
                balance: info.account_amount,
                is_baker,
                acc_type,
            };
            if row.is_baker {}
            acc_balances.push(row);
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
        staked_amount,
        (u64::from(staked_amount) as f64 / u64::from(total_amount) as f64) * 100f64
    );

    Ok(())
}
