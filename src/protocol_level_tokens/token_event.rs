//! Token events

use crate::common::cbor::{self, CborSerializationResult};
use crate::protocol_level_tokens::{
    RawCbor, TokenId, TokenModuleCborTypeDiscriminator, TokenModuleEvent, TokenSupplyUpdateEvent,
    TokenTransferEvent,
};
use crate::v2::upward::{CborUpward, Upward};

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
    Module(EncodedTokenModuleEvent),
    /// An event emitted when a transfer of tokens is performed.
    Transfer(TokenTransferEvent),
    /// An event emitted when the token supply is updated by minting tokens to a
    /// token holder.
    Mint(TokenSupplyUpdateEvent),
    /// An event emitted when the token supply is updated by burning tokens from
    /// the balance of a token holder.
    Burn(TokenSupplyUpdateEvent),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedTokenModuleEvent {
    /// The type of event produced.
    #[serde(rename = "type")]
    pub event_type: TokenModuleCborTypeDiscriminator,
    /// The details of the event produced, in the raw byte encoded form.
    pub details: RawCbor,
}

impl EncodedTokenModuleEvent {
    /// Decode token module event from CBOR
    pub fn decode_token_module_event(
        &self,
    ) -> CborSerializationResult<CborUpward<TokenModuleEvent>> {
        use TokenModuleEvent::*;

        Ok(match self.event_type.as_ref() {
            "addAllowList" => {
                Upward::Known(AddAllowList(cbor::cbor_decode(self.details.as_ref())?))
            }
            "removeAllowList" => {
                Upward::Known(RemoveAllowList(cbor::cbor_decode(self.details.as_ref())?))
            }
            "addDenyList" => Upward::Known(AddDenyList(cbor::cbor_decode(self.details.as_ref())?)),
            "removeDenyList" => {
                Upward::Known(RemoveDenyList(cbor::cbor_decode(self.details.as_ref())?))
            }
            "pause" => Upward::Known(Pause(cbor::cbor_decode(self.details.as_ref())?)),
            "unpause" => Upward::Known(Unpause(cbor::cbor_decode(self.details.as_ref())?)),
            _ => Upward::Unknown(cbor::cbor_decode(self.details.as_ref())?),
        })
    }
}
