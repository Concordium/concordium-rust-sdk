![CI](https://github.com/Concordium/concordium-rust-sdk/actions/workflows/build-and-test.yaml/badge.svg)

# An SDK for Rust to interact with the Concordium blockchain

The SDK has support for constructing and sending transactions, and for querying
various aspects of the chain and the node itself.

The SDK version 2 supports both the old V1 node GRPC API (accessible via the
`endpoints` module) as well as the new V2 API (accessible via the `v2` module).
New users should use the API since it is more flexible, has more features, and
performs better. The V1 API will be deprecated in the next SDK version.

## Minimum supported Rust version

The current minimal version is 1.57. A MSRV bump will be accompanied by a minor
version bump of the SDK.

## Add it to your project

Until the SDK is published on [crates.io](crates.io) the recommended way to use it is to add this repository as a git submodule to your project and then add a dependency to your Cargo.toml

```toml
[dependencies]
concordium-rust-sdk = { path = "./deps/concordium-rust-sdk", version = "1" }
```

assuming the submodule is cloned into the directory `./deps/concordium-rust-sdk`.

## Versions

- Minimum supported Rust version: 1.57.
- Node version compatibility: 4.*

## Basic usage

The core structure of the SDK is the
[Client](http://developer.concordium.software/concordium-rust-sdk/concordium_rust_sdk/v2/struct.Client.html)
which maintains a connection to the node and supports querying the node and
sending messages to it. This client is cheaply clonable.

The `Client` is constructed using the [new](http://developer.concordium.software/concordium-rust-sdk/concordium_rust_sdk/v2/struct.Client.html#method.new) method.

```rust
use concordium_rust_sdk::*;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // Establish a connection to the node running locally and listening on port 20000
    let mut client = v2::Client::new(v2::Endpoint::from_str("http://localhost:20000")?).await?;

    // Query consensus information and print it as JSON
    let consensus_info = client.get_consensus_info().await?;
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
[`send_block_item`](http://developer.concordium.software/concordium-rust-sdk/concordium_rust_sdk/v2/struct.Client.html#method.send_block_item)
endpoint.

## Examples

There are a number of examples showing basic usage of the different endpoints.
They can be found in the [examples](./examples) directory.

As a basic example, see [v2_send_transfer](./examples/v2_send_transfer.rs) for a
complete example of constructing a transfer transaction and sending it.

All examples can be compiled with

```shell
cargo build --release --example $NAME
```

for example


```shell
cargo build --release --example v2_send_transfer
```

## Optional features

The SDK has an optional `postgres` feature which enables functionality to
interface with a postgres database where the node logs transactions indexed by
affected account.

## Documentation

The rendered documentation is available at http://developer.concordium.software/concordium-rust-sdk/

## Migration from V1 to V2

The endpoints in V1 and V2 APIs for the most part mirror each other. However
some endpoints were split in the V2 API to make it possible to only query data
that is commonly needed faster. The main differences are

- The `V1` endpoint `get_block_summary` has been split into
  - `get_block_events` (for transaction events, i.e., outcomes of transactions
    sent by users)
  - `get_block_special_events` (for special events such as CCD minting, and delegation/baker rewards)
  - `get_chain_parameters` for chain parameters
  - `get_update_next_sequence_numbers` for sequence numbers of update instructions
  - `get_finalization_summary` for the details of finalization records in a
    block.

- The node information has been consolidated into two endpoints,
  `get_node_info`, and `get_peers_info`, the latter of which now returns both
  the list of peers and their details.
