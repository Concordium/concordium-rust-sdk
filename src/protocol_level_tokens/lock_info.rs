use super::{LockAccountFunds, LockConfig, LockId};
use crate::v2::{generated, upward::CborUpward, Require};
use concordium_base::{
    common::{cbor, cbor::CborSerializationResult, CborDeserialize, CborSerialize},
    protocol_level_tokens::RawCbor,
};

/// Decoded lock information with a forward-compatible configuration.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockInfo {
    /// Identifier of the lock.
    pub lock: LockId,
    /// Configuration of the lock, including unsupported versions as raw CBOR values.
    pub config: CborUpward<LockConfig>,
    /// Locked balances currently controlled by the lock.
    pub funds: Vec<LockAccountFunds>,
}

/// Response type for [`Client::get_lock_info`](crate::v2::Client::get_lock_info).
///
/// This mirrors the gRPC response and stores the raw CBOR payload. Call
/// [`LockInfoResponse::decode_lock_info`] to decode it into [`LockInfo`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockInfoResponse {
    /// CBOR-encoded lock information.
    pub lock_info: RawCbor,
}

impl LockInfoResponse {
    /// Decode lock information, preserving unsupported configuration versions.
    pub fn decode_lock_info(&self) -> CborSerializationResult<LockInfo> {
        cbor::cbor_decode(&self.lock_info)
    }
}

/// A lock's identifier and raw configuration returned by
/// [`Client::get_locks_by_grant_account`](crate::v2::Client::get_locks_by_grant_account).
/// Decode the configuration explicitly with [`Self::decode_lock_config`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockConfigurationResponse {
    /// Identifier of the lock.
    pub lock_id: LockId,
    /// Unchanged CBOR-encoded lock configuration.
    pub lock_config: RawCbor,
}

impl LockConfigurationResponse {
    /// Decode the configuration, preserving unsupported versions and rejecting malformed CBOR.
    pub fn decode_lock_config(&self) -> CborSerializationResult<CborUpward<LockConfig>> {
        cbor::cbor_decode(&self.lock_config)
    }
}

impl TryFrom<generated::LockConfiguration> for LockConfigurationResponse {
    type Error = tonic::Status;

    fn try_from(value: generated::LockConfiguration) -> Result<Self, Self::Error> {
        Ok(Self {
            lock_id: value.lock_id.require()?.into(),
            lock_config: value.lock_config.require()?.into(),
        })
    }
}

impl TryFrom<generated::LockInfo> for LockInfoResponse {
    type Error = tonic::Status;

    fn try_from(value: generated::LockInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            lock_info: value.lock_info.require()?.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_level_tokens::{
        LockConfigV0, LockRecipients, LockVariant, LockedTokenAmount, TokenAmount,
    };
    use concordium_base::{
        common::{cbor::value::Value, types::TransactionTime},
        contracts_common::AccountAddress,
    };

    #[test]
    fn decode_lock_info_preserves_unknown_config_and_funds() {
        #[derive(CborSerialize)]
        struct WireInfo {
            lock: LockId,
            config: Value,
            funds: Vec<LockAccountFunds>,
        }

        let wire = WireInfo {
            lock: LockId::new(42, 3, 0),
            config: Value::Map(vec![(Value::Text("version".into()), Value::Positive(7))]),
            funds: vec![LockAccountFunds {
                account: AccountAddress([1; 32]).into(),
                amounts: vec![LockedTokenAmount {
                    token: "tT".parse().unwrap(),
                    amount: TokenAmount::from_raw(52, 2),
                }],
            }],
        };
        let response = LockInfoResponse {
            lock_info: cbor::cbor_encode(&wire).into(),
        };
        assert_eq!(
            response.decode_lock_info().unwrap(),
            LockInfo {
                lock: wire.lock,
                config: CborUpward::Unknown(wire.config),
                funds: wire.funds,
            }
        );
    }

    #[test]
    fn decode_lock_config_preserves_unknown_variant() {
        let config = LockConfig::V0(LockConfigV0 {
            variant: LockVariant::Unknown("futureVariant".into()),
            recipients: LockRecipients::Any,
            holders: vec![AccountAddress([1; 32]).into()],
            expiry: TransactionTime::from_seconds(1_804_806_000),
            roles: vec![],
            tokens: vec!["tT".parse().unwrap()],
            metadata: None,
        });
        let response = LockConfigurationResponse {
            lock_id: LockId::new(42, 3, 0),
            lock_config: cbor::cbor_encode(&config).into(),
        };
        assert_eq!(
            response.decode_lock_config().unwrap(),
            CborUpward::Known(config)
        );
    }
}
