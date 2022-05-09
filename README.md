![CI](https://github.com/Concordium/concordium-rust-sdk/actions/workflows/build-and-test.yaml/badge.svg)

# An SDK for Rust to interact with the Concordium blockchain

The SDK has support for constructing and sending transactions, and for querying
various aspects of the chain and the node itself.

## Add it to your project

Until the SDK is published on [crates.io](crates.io) the recommended way to use it is to add this repository as a git submodule to your project and then add a dependency to your Cargo.toml

```toml
[dependencies]
concordium-rust-sdk = { path = "./deps/concordium-rust-sdk", version = "1" }
```

assuming the submodule is cloned into the directory `./deps/concordium-rust-sdk`.

## Basic usage

The core structure of the SDK is the [Client](http://developer.concordium.software/concordium-rust-sdk/concordium_rust_sdk/endpoints/struct.Client.html) which maintains a connection to the node and supports querying the node and sending messages to it.

The `Client` is constructed using the [connect](http://developer.concordium.software/concordium-rust-sdk/concordium_rust_sdk/endpoints/struct.Client.html#method.connect) method.

```rust
use concordium_rust_sdk::*;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // Establish a connection to the node running locally and listening on port 10000.
    let mut client = endpoints::Client::connect("http://localhost:10000", "rpcadmin").await?;

    let version = client.version().await?;
    println!("{}", version);

    // Print information about the node peers.
    let peers = client.peer_list(true).await?;
    println!("{:?}", peers);

    // Print basic node information.
    let ni = client.node_info().await?;
    println!("{:?}", ni);

    // Query consensus information and print it.
    let consensus_info = client.get_consensus_status().await?;
    println!("{}", serde_json::to_string_pretty(&consensus_info).unwrap());
    Ok(())
}
```

## Signing transactions

The
[`transactions::send`](http://developer.concordium.software/concordium-rust-sdk/concordium_rust_sdk/types/transactions/send/index.html)
contains methods for constructing and sending transactions. There is an
accompanying module
[`transactions::construct`](http://developer.concordium.software/concordium-rust-sdk/concordium_rust_sdk/types/transactions/construct/index.html)
which can be used if transactions only need to be constructed, but not
immediately signed.

Each supported transaction has a method to construct it that takes minimal data
needed for the transaction. Once a transaction is constructed it can be sent to
the node and the chain using the
[`send_block_item`](http://developer.concordium.software/concordium-rust-sdk/concordium_rust_sdk/endpoints/struct.Client.html#method.send_block_item)
endpoint.


### Example showing how to send a transfer from an account to itself.

```rust
use anyhow::Context;
use concordium_rust_sdk::{
    common::{types::TransactionTime, SerdeDeserialize, SerdeSerialize},
    constants::DEFAULT_NETWORK_ID,
    endpoints,
    id::types::{AccountAddress, AccountKeys},
    types::{
        transactions::{send, BlockItem},
        AccountInfo,
    },
};

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct AccountData {
    account_keys: AccountKeys,
    address:      AccountAddress,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let mut client = endpoints::Client::connect("http://localhost:10000", "rpcadmin").await?;

    let consensus_info = client.get_consensus_status().await?;

    // load account keys and sender address from a file
    let keys: AccountData = serde_json::from_str(
        &std::fs::read_to_string("keys.json").context("Could not read the keys file.")?,
    )
    .context("Could not parse the keys file.")?;

    // Get the initial nonce.
    let acc_info: AccountInfo = client
        .get_account_info(&keys.address, &consensus_info.last_finalized_block)
        .await?;

    let nonce = acc_info.account_nonce;
    // set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    let tx = send::transfer(
        &keys.account_keys,
        keys.address,
        nonce,
        expiry,
        keys.address, // send to ourselves
        1.into(),     // send 1 microCCD
    );

    let item = BlockItem::AccountTransaction(tx);
    let transaction_hash = item.hash();
    // submit the transaction to the chain
    let transaction_hash = client.send_block_item(&item).await?;
    println!(
        "Transaction {} submitted (nonce = {}).",
        transaction_hash, nonce,
    );
    Ok(())
}
```

## Optional features

The SDK has an optional `postgres` feature which enables functionality to
interface with a postgres database where the node logs transactions indexed by
affected account.

## Documentation

The rendered documentation is available at http://developer.concordium.software/concordium-rust-sdk/
