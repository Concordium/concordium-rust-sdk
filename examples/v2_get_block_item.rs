/// Get the exact block item that was part of a block.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::transactions::Payload;
use concordium_rust_sdk::types::{
    hashes::TransactionHash,
    smart_contracts::{ContractContext, DEFAULT_INVOKE_ENERGY, InvokeContractResult},
};
use futures::TryStreamExt;
use structopt::StructOpt;

use concordium_rust_sdk::v2;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:    v2::Endpoint,
    #[structopt(long = "transaction", help = "Transaction hash to query.")]
    transaction: TransactionHash,
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

    let target_hash = app.transaction;

    let res = client.get_block_item_status(&target_hash).await?;
    let (block, _) = res
        .is_finalized()
        .context("Transaction is not finalized.")?;

    let txs = client
        .get_block_items(block)
        .await?
        .response
        .try_filter(move |s| {
            let h = s.hash();
            async move { h == target_hash }
        })
        .try_collect::<Vec<_>>()
        .await?;

    for tx in txs {
        match tx {
            concordium_base::transactions::BlockItem::AccountTransaction(at) => {
                println!("Transaction stated energy: {}", at.header.energy_amount);
                let payload = at.payload.decode()?;
                if let Payload::Update { payload } = payload {
                    println!("Parameter = {}", payload.message);
                    println!("Parameter = {:?}", payload.message);
                    let ctx = ContractContext::new_from_payload(
                        at.header.sender,
                        at.header.energy_amount,
                        payload,
                    );
                    println!("INVOKING");
                    let parent = client.get_block_info(block).await?.response.block_parent;
                    let res = client.invoke_instance(parent, &ctx).await?.response;
                    match res {
                        InvokeContractResult::Success {
                            events,..
                        } => {
                            for event in events {
                                println!("{:#?}", event);
                            }
                        }
                        _ => todo!()
                    }
                }
            }
            concordium_base::transactions::BlockItem::CredentialDeployment(_) => todo!(),
            concordium_base::transactions::BlockItem::UpdateInstruction(_) => todo!(),
        }
    }

    Ok(())
}
