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

    fn try_from(token_id: generated::plt::TokenId) -> Result<Self, Self::Error> {
        Self::try_from(token_id.value)
            .map_err(|err| tonic::Status::internal(format!("Unexpected token identifier: {}", err)))
    }
}

impl From<TokenId> for generated::plt::TokenId {
    fn from(value: protocol_level_tokens::TokenId) -> Self {
        Self {
            value: value.into(),
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

impl TryFrom<generated::plt::TokenEvent> for TokenEvent {
    type Error = tonic::Status;

    fn try_from(token_event: generated::plt::TokenEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: token_event.token_id.require()?.try_into()?,
            event: token_event.event.require()?.try_into()?,
        })
    }
}

impl TryFrom<generated::plt::token_event::Event> for TokenEventDetails {
    type Error = tonic::Status;

    fn try_from(event: generated::plt::token_event::Event) -> Result<Self, Self::Error> {
        use generated::plt::token_event::Event as GenEvent;
        let out = match event {
            GenEvent::ModuleEvent(token_module_event) => {
                TokenEventDetails::Module(token_module_event.try_into()?)
            }
            GenEvent::TransferEvent(token_transfer_event) => {
                TokenEventDetails::Transfer(token_transfer_event.try_into()?)
            }
            GenEvent::MintEvent(token_supply_update_event) => {
                TokenEventDetails::Mint(token_supply_update_event.try_into()?)
            }
            GenEvent::BurnEvent(token_supply_update_event) => {
                TokenEventDetails::Burn(token_supply_update_event.try_into()?)
            }
        };
        Ok(out)
    }
}

impl TryFrom<generated::plt::TokenModuleEvent> for TokenModuleEvent {
    type Error = tonic::Status;

    fn try_from(event: generated::plt::TokenModuleEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            event_type: protocol_level_tokens::TokenModuleCborTypeDiscriminator::try_from(
                event.r#type,
            )
            .map_err(|err| tonic::Status::internal(err.to_string()))?,
            details: event.details.require()?.into(),
        })
    }
}

impl TryFrom<generated::plt::TokenTransferEvent> for TokenTransferEvent {
    type Error = tonic::Status;

    fn try_from(event: generated::plt::TokenTransferEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            from: event.from.require()?.try_into()?,
            to: event.to.require()?.try_into()?,
            amount: event.amount.require()?.try_into()?,
            memo: event
                .memo
                .map(concordium_base::transactions::Memo::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<generated::plt::TokenSupplyUpdateEvent> for TokenSupplyUpdateEvent {
    type Error = tonic::Status;

    fn try_from(event: generated::plt::TokenSupplyUpdateEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            target: event.target.require()?.try_into()?,
            amount: event.amount.require()?.try_into()?,
        })
    }
}

impl TryFrom<generated::plt::TokenHolder> for TokenHolder {
    type Error = tonic::Status;

    fn try_from(holder: generated::plt::TokenHolder) -> Result<Self, Self::Error> {
        use generated::plt::token_holder::Address as HolderAddress;
        match holder.address.require()? {
            HolderAddress::Account(account_address) => {
                Ok(TokenHolder::HolderAccount(HolderAccount {
                    coin_info: None,
                    address: account_address.try_into()?,
                }))
            }
        }
    }
}

impl TryFrom<generated::plt::TokenModuleRejectReason> for TokenModuleRejectReason {
    type Error = tonic::Status;

    fn try_from(value: generated::plt::TokenModuleRejectReason) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: value.token_id.require()?.try_into()?,
            reason_type: protocol_level_tokens::TokenModuleCborTypeDiscriminator::try_from(
                value.r#type,
            )
            .map_err(|err| tonic::Status::internal(err.to_string()))?,
            details: value.details.map(|d| d.into()),
        })
    }
}
