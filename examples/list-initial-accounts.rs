//! List initial accounts created between two given timestamps.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{types::AccountInfo, v2};
use futures::TryStreamExt;
use std::{collections::BTreeSet, io::Write, path::PathBuf};
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
        long = "start",
        help = "Timestamp to start at. This is inclusive and defaults to genesis time."
    )]
    from: Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(long = "end", help = "Timestamp to end. This is exclusive.")]
    to: Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(
        long = "num",
        help = "Number of parallel queries to make.",
        default_value = "8"
    )]
    num: usize,
    #[structopt(
        long = "initial",
        help = "File to output the list of initial accounts to."
    )]
    initial: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app: App = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    // create the file early so that we don't spend time querying all accounts and
    // then find the output file cannot be created.
    let mut out = std::fs::File::create(app.initial).context("Could not create output file.")?;

    let mut client = v2::Client::new(app.endpoint).await?;

    let cs = client.get_consensus_info().await?;

    let end_block = if let Some(end_time) = app.to {
        let block = client
            .find_first_finalized_block_no_earlier_than(.., end_time)
            .await?;
        block.block_parent
    } else {
        cs.last_finalized_block
    };

    let start_block = if let Some(start_time) = app.from {
        let cb = cs.last_finalized_block;
        if cs.genesis_time > start_time {
            None
        } else {
            let bi = client.get_block_info(&cb).await?.response;
            anyhow::ensure!(
                bi.block_slot_time >= start_time,
                "Last finalized block is not after the requested start time ({})",
                bi.block_slot_time.to_rfc3339()
            );
            let _block = client
                .find_first_finalized_block_no_earlier_than(.., start_time)
                .await?;
            if bi.block_slot_time <= start_time {
                Some(bi.block_hash)
            } else {
                Some(bi.block_parent)
            }
        }
    } else {
        None
    };

    let end_block = client.get_block_info(&end_block).await?.response;
    eprintln!(
        "Listing initial accounts in block {} with timestamp {}.",
        end_block.block_hash, end_block.block_slot_time
    );

    let start_block_accounts = if let Some(block) = start_block {
        let block = client.get_block_info(&block).await?.response;
        eprintln!(
            "Without initial accounts existing in block {} with timestamp {}.",
            block.block_hash, block.block_slot_time
        );
        let block_hash = block.block_hash;
        client
            .get_account_list(block_hash)
            .await?
            .response
            .try_collect::<BTreeSet<_>>()
            .await?
    } else {
        BTreeSet::new()
    };

    let accounts = client
        .get_account_list(&end_block.block_hash)
        .await?
        .response
        .try_collect::<Vec<_>>()
        .await?;

    for accs in accounts.chunks(app.num) {
        let mut handles = Vec::with_capacity(app.num);
        for &acc in accs {
            let mut client = client.clone();
            let block = end_block.block_hash;
            handles.push(async move { client.get_account_info(&acc.into(), &block).await })
        }
        for ainfo in futures::future::join_all(handles).await {
            let ainfo: AccountInfo = ainfo?.response;
            let mut is_initial = false;
            if let Some(acred) = ainfo.account_credentials.get(&0.into()) {
                let err_or_is_initial = match acred.value {
                    v2::Upward::Known(
                        concordium_rust_sdk::id::types::AccountCredentialWithoutProofs::Initial {
                            ..
                        },
                    ) => Ok(true),
                    v2::Upward::Known(
                        concordium_rust_sdk::id::types::AccountCredentialWithoutProofs::Normal {
                            ..
                        },
                    ) => Ok(false),
                    v2::Upward::Unknown => Err(anyhow::anyhow!(
                        "Unknown AccountCredentialWithoutProofs variant"
                    )),
                };

                is_initial = err_or_is_initial?;
            }
            if is_initial && !start_block_accounts.contains(&ainfo.account_address) {
                writeln!(&mut out, "{}", ainfo.account_address)?;
            }
        }
    }

    Ok(())
}
