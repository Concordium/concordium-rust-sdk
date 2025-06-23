//! This module contains the type [`TokenInfo`] which is the response for
//! [`v2::Client::get_token_info`].

use crate::v2::{generated, Require};
use concordium_base::{
    common::{cbor, cbor::CborSerializationResult},
    protocol_level_tokens::{RawCbor, TokenAmount, TokenId, TokenModuleRef, TokenModuleState},
};

/// The token state at the block level.
///
/// Response type for
/// [`Client::get_token_info`](crate::v2::Client::get_token_info).
#[derive(Debug)]
pub struct TokenInfo {
    /// The unique token id.
    pub token_id:    TokenId,
    /// The associated block level state.
    pub token_state: TokenState,
}

/// Token state at the block level
///
/// Part of the response for
/// [`Client::get_token_info`](crate::v2::Client::get_token_info).
#[derive(Debug)]
pub struct TokenState {
    /// The reference of the module implementing this token.
    pub token_module_ref: TokenModuleRef,
    /// Number of decimals in the decimal number representation of amounts.
    pub decimals:         u8,
    /// The total available token supply.
    pub total_supply:     TokenAmount,
    /// Token module specific state, such as token name, feature flags, meta
    /// data.
    pub module_state:     RawCbor,
}

impl TokenState {
    /// Decode the token module state from CBOR
    pub fn decode_module_state(&self) -> CborSerializationResult<TokenModuleState> {
        cbor::cbor_decode(&self.module_state)
    }
}

impl TryFrom<generated::TokenInfo> for TokenInfo {
    type Error = tonic::Status;

    fn try_from(value: generated::TokenInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id:    value.token_id.require()?.try_into()?,
            token_state: value.token_state.require()?.try_into()?,
        })
    }
}

impl TryFrom<generated::plt::TokenState> for TokenState {
    type Error = tonic::Status;

    fn try_from(value: generated::plt::TokenState) -> Result<Self, Self::Error> {
        Ok(Self {
            token_module_ref: value.token_module_ref.require()?.try_into()?,
            decimals:         value
                .decimals
                .try_into()
                .map_err(|_| tonic::Status::internal("Unexpected token decimals"))?,
            total_supply:     value.total_supply.require()?.try_into()?,
            module_state:     value.module_state.require()?.into(),
        })
    }
}
