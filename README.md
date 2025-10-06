![CI](https://github.com/Concordium/concordium-rust-sdk/actions/workflows/build-and-test.yaml/badge.svg)

# An SDK for Rust to interact with the Concordium blockchain

The SDK has support for constructing and sending transactions, and for querying
various aspects of the chain and the node itself.

## Minimum supported Rust version

The minimal supported rust version is stated in the `Cargo.toml` manifest. A
MSRV bump will be accompanied by at least a minor version bump of the SDK.

## Add it to your project

The SDK is published on [crates.io](https://crates.io/crates/concordium-rust-sdk).

```shell
cargo add concordium-rust-sdk
```

## Versions

- Node version compatibility: 5.4+

## Basic usage

The core structure of the SDK is the
[Client](https://docs.rs/concordium-rust-sdk/latest/concordium_rust_sdk/v2/struct.Client.html)
which maintains a connection to the node and supports querying the node and
sending messages to it. This client is cheaply clonable.

The `Client` is constructed using the [new](https://docs.rs/concordium-rust-sdk/latest/concordium_rust_sdk/v2/struct.Client.html#method.new) method.

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
[`transactions::send`](https://docs.rs/concordium-rust-sdk/latest/concordium_rust_sdk/types/transactions/send/index.html)
contains methods for constructing and sending transactions. There is an
accompanying module
[`transactions::construct`](https://docs.rs/concordium-rust-sdk/latest/concordium_rust_sdk/types/transactions/construct/index.html)
which can be used if transactions only need to be constructed, but not
immediately signed.

Each supported transaction has a method to construct it that takes minimal data
needed for the transaction. Once a transaction is constructed it can be sent to
the node and the chain using the
[`send_block_item`](https://docs.rs/concordium-rust-sdk/latest/concordium_rust_sdk/v2/struct.Client.html#method.send_block_item)
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

## Documentation

The rendered documentation is available at https://docs.rs/concordium-rust-sdk/latest/

## For developers

The SDK relies on files generated from [protobuf schemas](https://github.com/Concordium/concordium-grpc-api).
These files are committed to the repository so that users of the SDK do not have to have the
protobuf compiler installed in order to use the SDK.

Occasionally there is a need to update the generated files, if the schemas
change. This can be done by running the binary in `proto-generate`,

```
cd proto-generate
cargo run
```

Updating these files should only be done when the node's API, determined by the
schemas, changes and we need to support the new API in the SDK.

The use of serde is guarded by the flag `serde_deprecated`. Enable the flag to use the sdk with serde.

```
[dependencies]
concordium-rust-sdk = { version = "...", features = ["serde_deprecated"] }
```