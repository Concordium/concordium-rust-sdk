//! Token reject reason.
use crate::common::cbor::{self, CborSerializationResult};
use crate::protocol_level_tokens::{
    RawCbor, TokenId, TokenModuleCborTypeDiscriminator, TokenModuleRejectReason,
};
use crate::v2::upward::{CborUpward, Upward};

use anyhow::Context;

/// Details provided by the token module in the event of rejecting a
/// transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedTokenModuleRejectReason {
    /// The unique symbol of the token, which produced this event.
    pub token_id: TokenId,
    /// The type of the reject reason.
    #[serde(rename = "type")]
    pub reason_type: TokenModuleCborTypeDiscriminator,
    /// (Optional) CBOR-encoded details.
    pub details: Option<RawCbor>,
}

impl EncodedTokenModuleRejectReason {
    /// Decode reject reason from CBOR
    pub fn decode_reject_reason(
        &self,
    ) -> CborSerializationResult<CborUpward<TokenModuleRejectReason>> {
        use TokenModuleRejectReason::*;

        Ok(match self.reason_type.as_ref() {
            "addressNotFound" => Upward::Known(AddressNotFound(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?)),
            "tokenBalanceInsufficient" => Upward::Known(TokenBalanceInsufficient(
                cbor::cbor_decode(self.details.as_ref().context("no CBOR details")?.as_ref())?,
            )),
            "deserializationFailure" => Upward::Known(DeserializationFailure(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?)),
            "unsupportedOperation" => Upward::Known(UnsupportedOperation(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?)),
            "operationNotPermitted" => Upward::Known(OperationNotPermitted(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?)),
            "mintWouldOverflow" => Upward::Known(MintWouldOverflow(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?)),
            _ => Upward::Unknown(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?),
        })
    }
}
