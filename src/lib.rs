//! A library for interacting with the Concordium blockchain. The library is
//! structured around multiple modules.
//!
//! - [`v2`] contains the main entrypoint to the library. In particular it
//!   contains the [`Client`](v2::Client) struct
//! which maintains a connection to the node, and supports queries and node
//! manipulation. This client uses gRPC API version 2 of the Concordium node.
//! - [`constants`] contains a number of constants and type definitions that are
//!   relevant when using the chain.
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
//!   related to encrypted transfers. Note that this functionality has been
//!   deprecated in protocol version 7.
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
mod internal;
/// Type definitions used throughout the rest of the SDK.
pub mod types;

/// A generic client for interacting with smart contracts.
pub mod contract_client;

/// Types and functions for working with CIS-0 smart contracts.
pub mod cis0;
/// Types and functions for working with CIS-2 smart contracts.
pub mod cis2;
/// Types and functions for working with CIS-3 smart contracts.
pub mod cis3;
/// Types and functions for working with CIS-4 credential registry standard
/// contracts.
pub mod cis4;

pub mod web3id;

/// Re-export of the identity library.
pub use concordium_base::id;

/// Re-export of common helper functionality.
pub use concordium_base::common;

/// Re-export of functionality for constructing and verifying encrypted
/// transfers.
pub use concordium_base::encrypted_transfers;

/// Re-export of functionality for constructing and verifying aggregate
/// signatures. This is useful for constructing baker transactions.
pub use concordium_base::aggregate_sig;

/// Re-export of Elgamal encryption.
pub use concordium_base::eddsa_ed25519;

/// Re-export the VRF function implementation.
pub use concordium_base::ecvrf;

/// A [client](v2::Client) for the concordium node gRPC API version 2.
pub mod v2;

/// Functionality related to smart contracts.
pub mod smart_contracts;

/// Re-export of [`concordium_base`]. The main purpose of this is
/// to enable the use of `concordium_base_derive` serialization macros.
pub use concordium_base as base;

pub mod indexer;
