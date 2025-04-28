//! A library for interacting with the Concordium blockchain. The library is
//! structured around multiple modules.
//!
//! - [`v2`] contains the main entrypoint to the library. In particular it
//!   contains the [`Client`](v2::Client) struct which maintains a connection to
//!   the node, and supports queries and node manipulation. This client uses
//!   gRPC API version 2 of the Concordium node.
//! - [`constants`] contains a number of constants and type definitions that are
//!   relevant when using the chain.
//! - [`types`] contains most type definitions to model responses as well as
//!   types defining transactions. The latter are in a submodule
//!   [`types::transactions`].
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
//!   validators. This is useful for constructing baker transactions.
//! - [`ecvrf`] is a re-export of the implementation of the VRF function used to
//!   determine lottery winners in consensus.
//! - [`concordium_base`] is a re-export as [`base`]. The main purpose of this
//!   is to enable the use of `concordium_base_derive` serialization macros.
pub mod constants;
pub mod endpoints;
mod internal;
pub mod types;

pub mod contract_client;

pub mod cis0;
pub mod cis2;
pub mod cis3;
pub mod cis4;

pub mod web3id;

pub use concordium_base::{aggregate_sig, common, ecvrf, eddsa_ed25519, encrypted_transfers, id};

pub mod v2;

pub mod smart_contracts;

pub mod signatures;

pub mod indexer;

pub use concordium_base as base;

pub mod protocol_level_tokens;
