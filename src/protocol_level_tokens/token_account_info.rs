//! Module with the token information part of [`v2::Client::get_account_info`]
//! response.

use crate::v2::{generated, Require};
use concordium_base::{
    common::{cbor, cbor::CborSerializationResult},
    protocol_level_tokens::{RawCbor, TokenAmount, TokenId, TokenModuleAccountState},
};

/// State of a protocol level token associated with some account.
///
/// Part of the response for
/// [`v2::Client::get_account_info`](crate::v2::Client::get_account_info).
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountToken {
    /// The unique identifier/symbol for the protocol level token.
    pub token_id: TokenId,
    /// The state of the token associated with the account.
    pub state:    TokenAccountState,
}

/// State of a protocol level token associated with some account.
///
/// Part of the response for
/// [`Client::get_account_info`](crate::v2::Client::get_account_info).
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAccountState {
    /// The token balance of the account.
    pub balance:      TokenAmount,
    /// The token-module defined state of the account.
    pub module_state: Option<RawCbor>,
}

impl TryFrom<generated::account_info::Token> for AccountToken {
    type Error = tonic::Status;

    fn try_from(value: generated::account_info::Token) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: value.token_id.require()?.try_into()?,
            state:    value.token_account_state.require()?.try_into()?,
        })
    }
}

impl TryFrom<generated::plt::TokenAccountState> for TokenAccountState {
    type Error = tonic::Status;

    fn try_from(value: generated::plt::TokenAccountState) -> Result<Self, Self::Error> {
        Ok(Self {
            balance:      value.balance.require()?.try_into()?,
            module_state: value.module_state.map(RawCbor::from),
        })
    }
}

impl TokenAccountState {
    /// Decode the token module state from CBOR. If the module state is `None`,
    /// it returns a default `TokenModuleAccountState`.
    pub fn decode_module_state(&self) -> CborSerializationResult<TokenModuleAccountState> {
        match &self.module_state {
            Some(cbor) => cbor::cbor_decode(cbor),
            None => Ok(TokenModuleAccountState::default()),
        }
    }
}
