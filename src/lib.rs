//! A library for interacting with the Concordium blockchain.
//!
//! To use this in your project the recommended setup is to clone the repository
//! (e.g., add it as a submodule), and then declare a local dependency in your
//! `Cargo.toml`, e.g.,
//!
//! ```toml
//! [dependencies]
//! concordium-rust-sdk = { path = "./deps/concordium-rust-sdk", version = "1" }
//! ```
//!
//! The library is structured around multiple modules.
//!
//! - [`endpoints`] contains the main entrypoint to the library. In particular
//!   it contains the [`Client`](endpoints::Client) struct
//! which maintains a connection to the node, and supports queries and node
//! manipulation.
//! - [`constants`] contains a number of constants and type definitions that are
//!   relevant when using the chain. In particular
//!   [`DEFAULT_NETWORK_ID`](constants::DEFAULT_NETWORK_ID).
//! - [`types`] contains most type definitions to model responses as well as
//!   types defining transactions.
//! The latter are in a submodule [`types::transactions`].
//!
//! In addition to these, the library re-exports a number of core crates that
//! implement the core cryptographic protocols of the Concordium blockchain.
//!
//! - [`id`] is the implementation of most of the protocols in the identity
//!   layer
//! - [`common`] has some common type definitions, as well as traits and helpers
//!   for binary serialization
//! - [`encrypted_transfers`] implements structures and zero knowledge proofs
//!   related to encrypted transfers
//! - [`eddsa_ed25519`] is a re-export of the signature scheme used for blocks
//!   and accounts on the Concordium blockchain.
//! - [`aggregate_sig`] is a re-export of the BLS signature scheme, used by the
//!   finalizers.
//! - [`ecvrf`] is a re-export of the implementation of the VRF function used to
//!   determine lottery winners in consensus.

/// Various constants and types that apply to the chain.
pub mod constants;
/// Wrapper for the node's GRPC API. The return values are parsed and wrapped in
/// structured values.
pub mod endpoints;
mod generated_types;
mod internal;
/// Interface to the (optional) postgres database that the node logs finalized
/// transactions in.
#[cfg(feature = "postgres")]
pub mod postgres;
/// Type definitions used throughout the rest of the SDK.
pub mod types;

/// Re-export of the identity library.
pub use id;

/// Re-export of common helper functionality.
pub use crypto_common as common;

/// Re-export of functionality for constructing and verifying encrypted
/// transfers.
pub use encrypted_transfers;

/// Re-export of functionality for constructing and verifying aggregate
/// signatures. This is useful for constructing baker transactions.
pub use aggregate_sig;

/// Re-export of Elgamal encryption.
pub use eddsa_ed25519;

/// Re-export the VRF function implementation.
pub use ecvrf;
