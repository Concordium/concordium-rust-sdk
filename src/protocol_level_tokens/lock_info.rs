use crate::v2::{generated, Require};
use concordium_base::{
    common::{cbor, cbor::CborSerializationResult},
    protocol_level_locks::LockInfo as DomainLockInfo,
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

impl TryFrom<generated::LockInfo> for LockInfoResponse {
    type Error = tonic::Status;

    fn try_from(value: generated::LockInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            lock_info: value.lock_info.require()?.into(),
        })
    }
}
