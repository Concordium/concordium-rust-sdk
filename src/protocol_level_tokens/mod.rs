//! Types and functions for working with Protocol Level Tokens (PLT).

use crate::v2::{generated, Require};
use concordium_base::protocol_level_tokens;

mod token_account_info;
mod token_info;

pub use protocol_level_tokens::*;
pub use token_account_info::*;
pub use token_info::*;

// gRPC type conversions for the types which are define as part of
// the `concordium-base` crate.

impl TryFrom<generated::plt::TokenId> for TokenId {
    type Error = tonic::Status;

    fn try_from(value: generated::plt::TokenId) -> Result<Self, Self::Error> {
        Self::try_from(value.symbol)
            .map_err(|err| tonic::Status::internal(format!("Unexpected token identifier: {}", err)))
    }
}

impl From<TokenId> for generated::plt::TokenId {
    fn from(value: protocol_level_tokens::TokenId) -> Self {
        Self {
            symbol: value.into(),
        }
    }
}

impl TryFrom<generated::plt::TokenAmount> for TokenAmount {
    type Error = tonic::Status;

    fn try_from(value: generated::plt::TokenAmount) -> Result<Self, Self::Error> {
        Ok(Self::from_raw(
            value.digits,
            value
                .nr_of_decimals
                .try_into()
                .map_err(|_| tonic::Status::internal("Unexpected token decimals"))?,
        ))
    }
}

impl TryFrom<generated::plt::TokenModuleRef> for TokenModuleRef {
    type Error = tonic::Status;

    fn try_from(value: generated::plt::TokenModuleRef) -> Result<Self, Self::Error> {
        let bytes = value
            .value
            .try_into()
            .map_err(|_| tonic::Status::internal("Unexpected module reference format."))?;
        Ok(Self::new(bytes))
    }
}

impl From<generated::plt::CBor> for RawCbor {
    fn from(wrapper: generated::plt::CBor) -> Self {
        wrapper.value.into()
    }
}

impl TryFrom<generated::plt::TokenHolderEvent> for TokenHolderEvent {
    type Error = tonic::Status;

    fn try_from(_value: generated::plt::TokenHolderEvent) -> Result<Self, Self::Error> {
        todo!() // todo implement as part of COR-1362
                // Ok(Self {
                //     token_id:   value.token_symbol.require()?.try_into()?,
                //     event_type: TokenEventType::try_from(value.r#type)
                //         .map_err(|err|
                // tonic::Status::internal(err.to_string()))?,
                //     details:    value.details.require()?.into(),
                // })
    }
}

impl TryFrom<generated::plt::TokenGovernanceEvent> for TokenGovernanceEvent {
    type Error = tonic::Status;

    fn try_from(_value: generated::plt::TokenGovernanceEvent) -> Result<Self, Self::Error> {
        todo!() // todo implement as part of COR-1362
                // Ok(Self {
                //     token_id:   value.token_symbol.require()?.try_into()?,
                //     event_type: TokenEventType::try_from(value.r#type)
                //         .map_err(|err|
                // tonic::Status::internal(err.to_string()))?,
                //     details:    value.details.require()?.into(),
                // })
    }
}

impl TryFrom<generated::plt::TokenModuleRejectReason> for TokenModuleRejectReason {
    type Error = tonic::Status;

    fn try_from(value: generated::plt::TokenModuleRejectReason) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: value.token_symbol.require()?.try_into()?,
            reason_type: protocol_level_tokens::TokenModuleTypeDiscriminator::try_from(
                value.r#type,
            )
            .map_err(|err| tonic::Status::internal(err.to_string()))?,
            details: value.details.map(|d| d.into()),
        })
    }
}
