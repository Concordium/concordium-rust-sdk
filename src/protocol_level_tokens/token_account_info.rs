//! Module with the token information part of [`v2::Client::get_account_info`]
//! response.

use crate::v2::{generated, Require};
use concordium_base::protocol_level_tokens::{TokenAmount, TokenId};

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
    pub balance:           TokenAmount,
    /// Whether the account is a member of the allow list.
    pub member_allow_list: bool,
    /// Whether the account is a member of the deny list.
    pub member_deny_list:  bool,
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
            balance:           value.balance.require()?.try_into()?,
            member_allow_list: value.member_allow_list.require()?,
            member_deny_list:  value.member_deny_list.require()?,
        })
    }
}
