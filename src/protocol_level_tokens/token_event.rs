//! Token events

use crate::protocol_level_tokens::{
    TokenId, TokenModuleEventEnum, TokenSupplyUpdateEvent, TokenTransferEvent,
};

/// An event produced from the effect of a token transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenEvent {
    /// The unique symbol of the token, which produced this event.
    pub token_id: TokenId,
    /// The type of the event.
    pub event: TokenEventDetails,
}

/// The type of the token event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenEventDetails {
    /// An event emitted by the token module.
    Module(TokenModuleEventEnum),
    /// An event emitted when a transfer of tokens is performed.
    Transfer(TokenTransferEvent),
    /// An event emitted when the token supply is updated by minting tokens to a
    /// token holder.
    Mint(TokenSupplyUpdateEvent),
    /// An event emitted when the token supply is updated by burning tokens from
    /// the balance of a token holder.
    Burn(TokenSupplyUpdateEvent),
}
