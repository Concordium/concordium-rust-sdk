pub use concordium_base::constants::*;

/// Identifier of the default network over which messages are transmitted.
/// This is also the only currently supported network.
pub const DEFAULT_NETWORK_ID: super::types::network::NetworkId =
    super::types::network::NetworkId { network_id: 100u16 };
