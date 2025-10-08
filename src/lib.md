A library for interacting with the Concordium blockchain. The library is structured around multiple modules.

- [`v2`] contains the main entrypoint to the library.
  In particular it contains the [`Client`](v2::Client) struct which maintains a connection to the node, and supports queries and node manipulation.
  This client uses gRPC API version 2 of the Concordium node.
- [`constants`] contains a number of constants and type definitions that are
  relevant when using the chain.
- [`types`] contains most type definitions to model responses as well as
  types defining transactions.
  The latter are in a submodule [`types::transactions`].

In addition to these, the library re-exports a number of core crates that implement the core cryptographic protocols of the Concordium blockchain.

- [`id`] is the implementation of most of the protocols in the identity layer
- [`common`] has some common type definitions, as well as traits and helpers for binary serialization
- [`encrypted_transfers`] implements structures and zero knowledge proofs related to encrypted transfers. Note that this functionality has been deprecated in protocol version 7.
- [`eddsa_ed25519`] is a re-export of the signature scheme used for blocks and accounts on the Concordium blockchain.
- [`aggregate_sig`] is a re-export of the BLS signature scheme, used by the validators. This is useful for constructing baker transactions.
- [`ecvrf`] is a re-export of the implementation of the VRF function used to determine lottery winners in consensus.
- [`concordium_base`] is a re-export as [`base`]. The main purpose of this is to enable the use of `concordium_base_derive` serialization macros.

## Migration guide: 7 to 8

The SDK major version 8 introduces a lot of minor breaking changes, all with common goal of improving forward-compatibility with Concordium Node API versions.

#### Motivation

Up until this release, certain extensions to the Concordium Node API have resulted in the SDK failing to parse query responses with errors like 'Unknown protocol version: x' or 'missing field in response', resulting in the entire query to fail.
This is the case even for the larger queries where the unknown/missing information is only a small part of the response preventing the application to access the entire response.
Usually the fix was to update the SDK to a newer version which know how to parse the new information, but this imposes work for the ecosystem for every change in the API (usually part of protocol version updates).

This major release introduces [`Upward<A>`] a type wrapper representing information which might be extended in future version of the API, providing a variant representing unknown information such that queries can provide partial information.
It makes potentially extended information explicit in the types and allows each application to decide how to handle the case of new unknown data on a case by case basis.

#### Handling `Upward`

Several types and fields in the SDK are now wrapped in [`Upward`] and the wrapper provides several methods to ease the migration depending on the desired behavior of the application.
For some situations unknown information should cause an error, where in other situations it is safe to ignore, and maybe logging warnings to be handled in a future iteration of the application.

```rust,no_compile
if let Upward::Known(details) = block_item_summary.details {
    // Data is familiar so we handle details as usual.
} else {
    // Data is unknown to this SDK version, so we fallback to some other behavior.
}
```

To produce an error in the case of unknown data use [`known_or_err`], converting [`Upward<A>`] into [`Result<A, UnknownDataError>`](v2::upward::UnknownDataError).

```rust,no_compile
let details = block_item_summary.details.known_or_err()?;
```

Alternatively [`known_or`] or similarly named variants can be used for directly mapping the unknown data case to an error.

```rust,no_compile
let details = block_item_summary.details.known_or(MyError::UnknownData)?;
```

For the quick proof of concept application the value can be unwrapped using [`unwrap`] which triggers a panic when encountering unknown information, hence not recommended in production code.

[`Upward<A>`]: v2::Upward
[`Upward`]: v2::Upward
[`known_or_err`]: v2::Upward::known_or_err
[`known_or`]: v2::Upward::known_or
[`unwrap`]: v2::Upward::unwrap
