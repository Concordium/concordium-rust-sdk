use concordium_base::{protocol_level_locks::LockId, protocol_level_tokens::RawCbor};

/// Events that may be emitted by token-update transactions.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize),
    serde(untagged)
)]
pub enum OperationEvent {
    /// An event related to a particular token.
    Token(super::TokenEvent),
    /// An event related to a lock.
    Lock(LockEvent),
}

/// Events emitted by protocol-level locks.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum LockEvent {
    /// An event emitted when a lock is created.
    Create(LockCreateEvent),
    /// An event emitted when a lock is destroyed.
    Destroy(LockDestroyEvent),
    /// An amount was locked.
    LockAmount(LockAmountEvent),
    /// An amount was unlocked.
    UnlockAmount(UnlockAmountEvent),
}

/// Event that is emitted when a protocol-level lock is created.
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

/// Event that is emitted when a protocol-level lock is destroyed.
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

/// An amount of tokens moved from available to locked balance.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct LockAmountEvent {
    /// Holder whose balance changed.
    pub token_holder: super::TokenHolder,
    /// Lock controlling the amount.
    pub lock_id: LockId,
    /// Token whose balance changed.
    pub token_id: super::TokenId,
    /// Amount locked.
    pub amount: super::TokenAmount,
}
/// An amount of tokens moved from locked to available balance.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct UnlockAmountEvent {
    /// Holder whose balance changed.
    pub token_holder: super::TokenHolder,
    /// Lock previously controlling the amount.
    pub lock_id: LockId,
    /// Token whose balance changed.
    pub token_id: super::TokenId,
    /// Amount unlocked.
    pub amount: super::TokenAmount,
}
