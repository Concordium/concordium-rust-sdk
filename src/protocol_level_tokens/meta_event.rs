use concordium_base::{protocol_level_locks::LockId, protocol_level_tokens::RawCbor};

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum MetaEvent {
    /// An event related to a particular token.
    Token(super::TokenEvent),
    /// An event emitted when a lock is created.
    LockCreate(LockCreateEvent),
    /// An event emitted when a lock is destroyed.
    LockDestroy(LockDestroyEvent),
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct LockCreateEvent {
    /// The Lock ID of the newly-created lock.
    pub lock_id: LockId,
    /// The CBOR-encoded configuration of the lock.
    pub lock_config: RawCbor,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct LockDestroyEvent {
    /// The Lock ID of the destroyed lock.
    pub lock_id: LockId,
}
