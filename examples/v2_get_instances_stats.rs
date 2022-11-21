//! Print the list of all instances with a little bit of information about them.
//! Namely, address, version of the contract, size of the state, account that
//! created it, owned amount of CCD, and name of the contract.
//! For V1 instances an additional column containing the size of the serialized
//! state is added. Sizes are in bytes.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    smart_contracts::{engine, types::InstanceInfo},
    types::hashes::BlockHash,
    v2,
};
use futures::StreamExt;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "block",
        help = "Hash of the block in which to query. Defaults to the last finalized block."
    )]
    block:    Option<BlockHash>,
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
    let block = app
        .block
        .map_or(v2::BlockIdentifier::LastFinal, v2::BlockIdentifier::Given);
    let mut instances = client.get_instance_list(&block).await?;
    let block = instances.block_hash;
    println!("Using block {}", instances.block_hash);
    while let Some(ia) = instances.response.next().await {
        let ia = ia?;
        let ii = client.get_instance_info(ia, &block).await?;
        match ii.response {
            InstanceInfo::V0 {
                model,
                owner,
                amount,
                name,
                ..
            } => {
                println!(
                    "{}, V0, {}, {}, {}, {}",
                    ia,
                    model.len(),
                    owner,
                    amount,
                    String::from(name)
                );
            }
            InstanceInfo::V1 {
                owner,
                amount,
                name,
                ..
            } => {
                let al = client.get_instance_state(ia, &block).await?;
                // reconstruct the state from the key-value pairs.
                let mut state =
                    engine::v1::trie::PersistentState::try_from_stream(al.response).await?;
                // serialize the state to a vector. This is useful if we just want to load the
                // state later using the `PersistentState::deserialize` method.
                let serialized_size = {
                    // since the state is entirely in memory any loader will do, no data needs to be
                    // accessed from the backing store.
                    let mut loader = engine::v1::trie::Loader { inner: Vec::new() };
                    let mut out = Vec::new();
                    state.serialize(&mut loader, &mut out)?;
                    out.len()
                };
                // Store the state into a buffer that allows partial loading.
                // This is how the state is stored in the node so that partial updates are
                // efficient.
                let stored_size = {
                    let mut storer = engine::v1::trie::Storer {
                        inner: std::io::Cursor::new(Vec::new()),
                    };
                    let _root_ref = state.store_update(&mut storer)?;
                    storer.inner.into_inner().len()
                };
                println!(
                    "{}, V1, {}, {}, {}, {}, ({})",
                    ia,
                    stored_size,
                    owner,
                    amount,
                    String::from(name),
                    serialized_size,
                )
            }
        }
    }
    Ok(())
}
