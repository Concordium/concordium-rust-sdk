/// Test the `GetInstanceState` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    smart_contracts::{common, engine},
    types::hashes::BlockHash,
    v2,
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "index", help = "Index of the smart contract to query.")]
    index:    common::ContractIndex,
    #[structopt(long = "block", help = "Hash of the block in which to query.")]
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
    let al = client
        .get_instance_state(common::ContractAddress::new(app.index, 0u64), &block)
        .await?;
    println!("{}", al.block_hash);
    // reconstruct the state from the key-value pairs.
    let mut state = engine::v1::trie::PersistentState::try_from_stream(al.response).await?;
    // serialize the state to a vector. This is useful if we just want to load the
    // state later using the `PersistentState::deserialize` method.
    {
        // since the state is entirely in memory any loader will do, no data needs to be
        // accessed from the backing store.
        let mut loader = engine::v1::trie::Loader { inner: Vec::new() };
        let mut out = Vec::new();
        state.serialize(&mut loader, &mut out)?;
        println!("Serialized state size: {}", out.len());
    }
    // Store the state into a buffer that allows partial loading.
    // This is how the state is stored in the node so that partial updates are
    // efficient.
    {
        let mut storer = engine::v1::trie::Storer {
            inner: std::io::Cursor::new(Vec::new()),
        };
        let root_ref = state.store_update(&mut storer)?;
        // the contract state is stored in the inner vector of the `storer`.
        // the `root_ref` is the place in this vector where the root of the tree
        // can be loaded from.
        println!(
            "Stored state has size {}, root is at position {:?}.",
            storer.inner.into_inner().len(),
            root_ref
        );
    }
    Ok(())
}
