use super::LockId;
use crate::v2::{generated, Require};
use concordium_base::{
    common::{cbor, cbor::CborSerializationResult},
    protocol_level_locks::{LockConfig, LockInfo as DomainLockInfo},
    protocol_level_tokens::RawCbor,
};

/// Response type for [`Client::get_lock_info`](crate::v2::Client::get_lock_info).
///
/// This mirrors the gRPC response and stores the raw CBOR payload. Call
/// [`LockInfoResponse::decode_lock_info`] to decode it into the domain
/// [`DomainLockInfo`] type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockInfoResponse {
    /// CBOR-encoded lock information.
    pub lock_info: RawCbor,
}

impl LockInfoResponse {
    /// Decode the lock information from CBOR.
    pub fn decode_lock_info(&self) -> CborSerializationResult<DomainLockInfo> {
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
    /// Decode the configuration, returning an error if its CBOR is unsupported or invalid.
    pub fn decode_lock_config(&self) -> CborSerializationResult<LockConfig> {
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
