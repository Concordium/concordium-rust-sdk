//! Various constants and types that apply to the chain.
pub use concordium_base::constants::*;

/// Identifier of the default network over which messages are transmitted.
/// This is also the only currently supported network.
pub const DEFAULT_NETWORK_ID: super::types::network::NetworkId =
    super::types::network::NetworkId { network_id: 100u16 };

/// Concordium testnet genesis block hash.
pub const TESTNET_GENESIS_BLOCK_HASH: [u8; 32] = [
    66, 33, 51, 45, 52, 225, 105, 65, 104, 194, 160, 192, 179, 253, 15, 39, 56, 9, 97, 44, 177, 61,
    0, 13, 92, 46, 0, 232, 95, 80, 247, 150,
];

/// Concordium mainnet genesis block hash.
pub const MAINNET_GENESIS_BLOCK_HASH: [u8; 32] = [
    157, 217, 202, 77, 25, 233, 57, 56, 119, 210, 196, 75, 112, 248, 154, 203, 252, 8, 131, 194,
    36, 62, 94, 234, 236, 192, 209, 205, 5, 3, 244, 120,
];
