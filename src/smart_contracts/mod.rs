/// Types related to smart contracts.
pub use super::types::smart_contracts as types;

/// Access to the execution engine of smart contracts.
/// This has functionality for parsing and executing smart contracts,
/// manipulating their state, and dry-running.
pub use wasm_chain_integration as engine;

/// Functionality that is common to on and off-chain smart contracts.
pub use concordium_base::contracts_common as common;
