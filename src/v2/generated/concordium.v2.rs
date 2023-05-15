/// A message that contains no information.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {}
/// Hash of a block. This is always 32 bytes long.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHash {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// A SHA256 hash. This is always 32 bytes long.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Sha256Hash {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Hash of a transaction. This is always 32 bytes long.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionHash {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Hash of the state after some block. This is always 32 bytes long.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateHash {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// The absolute height of a block. This is the number of ancestors of a block
/// since the genesis block. In particular, the chain genesis block has absolute
/// height 0.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AbsoluteBlockHeight {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// The height of a block relative to the last genesis. This differs from the
/// absolute block height in that it counts height from the last protocol
/// update.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHeight {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// The ID of a baker, which is the index of its account.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerId {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// Index of the account in the account table. These are assigned sequentially
/// in the order of creation of accounts. The first account has index 0.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountIndex {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// A smart contract module reference. This is always 32 bytes long.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ModuleRef {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Source bytes of a versioned smart contract module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VersionedModuleSource {
    #[prost(oneof = "versioned_module_source::Module", tags = "1, 2")]
    pub module: ::core::option::Option<versioned_module_source::Module>,
}
/// Nested message and enum types in `VersionedModuleSource`.
pub mod versioned_module_source {
    /// Source bytes of a smart contract v0 module.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ModuleSourceV0 {
        #[prost(bytes = "vec", tag = "1")]
        pub value: ::prost::alloc::vec::Vec<u8>,
    }
    /// Source bytes of a smart contract v1 module.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ModuleSourceV1 {
        #[prost(bytes = "vec", tag = "1")]
        pub value: ::prost::alloc::vec::Vec<u8>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Module {
        #[prost(message, tag = "1")]
        V0(ModuleSourceV0),
        #[prost(message, tag = "2")]
        V1(ModuleSourceV1),
    }
}
/// Unix timestamp in milliseconds.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Timestamp {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// An individual release of a locked balance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Release {
    /// Effective time of the release in milliseconds since unix epoch.
    #[prost(message, optional, tag = "1")]
    pub timestamp:    ::core::option::Option<Timestamp>,
    /// Amount to be released.
    #[prost(message, optional, tag = "2")]
    pub amount:       ::core::option::Option<Amount>,
    /// List of transaction hashes that contribute a balance to this release.
    #[prost(message, repeated, tag = "3")]
    pub transactions: ::prost::alloc::vec::Vec<TransactionHash>,
}
/// A new individual release. Part of a single transfer with schedule
/// transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewRelease {
    /// Effective time of the release in milliseconds since unix epoch.
    #[prost(message, optional, tag = "1")]
    pub timestamp: ::core::option::Option<Timestamp>,
    /// Amount to be released.
    #[prost(message, optional, tag = "2")]
    pub amount:    ::core::option::Option<Amount>,
}
/// State of the account's release schedule. This is the balance of the account
/// that is owned by the account, but cannot be used until the release point.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReleaseSchedule {
    /// Total amount locked in the release schedule.
    #[prost(message, optional, tag = "1")]
    pub total:     ::core::option::Option<Amount>,
    /// A list of releases, ordered by increasing timestamp.
    #[prost(message, repeated, tag = "2")]
    pub schedules: ::prost::alloc::vec::Vec<Release>,
}
/// An encrypted amount, in two chunks in "little endian limbs". That is, the
/// first chunk represents the low 32 bits of an amount, and the second chunk
/// represents the high 32 bits. The chunks are serialized in order and
/// represented as a byte array.
/// Always 192 bytes.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedAmount {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedBalance {
    /// Encrypted amount that is a result of this account's actions.
    /// In particular this list includes the aggregate of
    ///
    /// - remaining amounts that result when transferring to public balance
    /// - remaining amounts when transferring to another account
    /// - encrypted amounts that are transferred from public balance
    ///
    /// When a transfer is made all of these must always be used.
    #[prost(message, optional, tag = "1")]
    pub self_amount:       ::core::option::Option<EncryptedAmount>,
    /// Starting index for incoming encrypted amounts. If an aggregated amount
    /// is present then this index is associated with such an amount and the
    /// list of incoming encrypted amounts starts at the index `start_index
    /// + 1`.
    #[prost(uint64, tag = "2")]
    pub start_index:       u64,
    /// If present, the amount that has resulted from aggregating other amounts
    /// If this field is present so is `num_aggregated`.
    #[prost(message, optional, tag = "3")]
    pub aggregated_amount: ::core::option::Option<EncryptedAmount>,
    /// The number of aggregated amounts (must be at least 2 if present). This
    /// field is present if and only if `aggregated_amount` is present.
    #[prost(uint32, optional, tag = "4")]
    pub num_aggregated:    ::core::option::Option<u32>,
    /// Amounts starting at `start_index` (or at `start_index + 1` if there is
    /// an aggregated amount present). They are assumed to be numbered
    /// sequentially. The length of this list is bounded by the maximum number
    /// of incoming amounts on the accounts, which is currently 32. After
    /// that aggregation kicks in.
    #[prost(message, repeated, tag = "5")]
    pub incoming_amounts:  ::prost::alloc::vec::Vec<EncryptedAmount>,
}
/// Entity to which the account delegates a portion of its stake.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DelegationTarget {
    #[prost(oneof = "delegation_target::Target", tags = "1, 2")]
    pub target: ::core::option::Option<delegation_target::Target>,
}
/// Nested message and enum types in `DelegationTarget`.
pub mod delegation_target {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Target {
        /// Delegate passively, i.e., to no specific baker.
        #[prost(message, tag = "1")]
        Passive(super::Empty),
        /// Delegate to a specific baker.
        #[prost(message, tag = "2")]
        Baker(super::BakerId),
    }
}
/// Baker's public key used to check whether they won the lottery or not.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerElectionVerifyKey {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Baker's public key used to check that they are indeed the ones who
/// produced the block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerSignatureVerifyKey {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Baker's public key used to check signatures on finalization records.
/// This is only used if the baker has sufficient stake to participate in
/// finalization.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerAggregationVerifyKey {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Information about a baker.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerInfo {
    /// Identity of the baker. This is actually the account index of
    /// the account controlling the baker.
    #[prost(message, optional, tag = "1")]
    pub baker_id:        ::core::option::Option<BakerId>,
    /// Baker's public key used to check whether they won the lottery or not.
    #[prost(message, optional, tag = "2")]
    pub election_key:    ::core::option::Option<BakerElectionVerifyKey>,
    /// Baker's public key used to check that they are indeed the ones who
    /// produced the block.
    #[prost(message, optional, tag = "3")]
    pub signature_key:   ::core::option::Option<BakerSignatureVerifyKey>,
    /// Baker's public key used to check signatures on finalization records.
    /// This is only used if the baker has sufficient stake to participate in
    /// finalization.
    #[prost(message, optional, tag = "4")]
    pub aggregation_key: ::core::option::Option<BakerAggregationVerifyKey>,
}
/// Pending change to the stake either of a baker or delegator.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StakePendingChange {
    #[prost(oneof = "stake_pending_change::Change", tags = "1, 2")]
    pub change: ::core::option::Option<stake_pending_change::Change>,
}
/// Nested message and enum types in `StakePendingChange`.
pub mod stake_pending_change {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Reduce {
        #[prost(message, optional, tag = "1")]
        pub new_stake:      ::core::option::Option<super::Amount>,
        /// Unix timestamp in milliseconds when the change takes effect.
        #[prost(message, optional, tag = "2")]
        pub effective_time: ::core::option::Option<super::Timestamp>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Change {
        #[prost(message, tag = "1")]
        Reduce(Reduce),
        /// Remove the stake. The value is a Unix timestamp of the effective
        /// time in milliseconds.
        #[prost(message, tag = "2")]
        Remove(super::Timestamp),
    }
}
/// A fraction of an amount with a precision of `1/100_000`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AmountFraction {
    /// Must not exceed 100000.
    #[prost(uint32, tag = "1")]
    pub parts_per_hundred_thousand: u32,
}
/// Distribution of the rewards for the particular pool.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommissionRates {
    /// Fraction of finalization rewards charged by the pool owner.
    #[prost(message, optional, tag = "1")]
    pub finalization: ::core::option::Option<AmountFraction>,
    /// Fraction of baking rewards charged by the pool owner.
    #[prost(message, optional, tag = "2")]
    pub baking:       ::core::option::Option<AmountFraction>,
    /// Fraction of transaction rewards charged by the pool owner.
    #[prost(message, optional, tag = "3")]
    pub transaction:  ::core::option::Option<AmountFraction>,
}
/// Additional information about a baking pool.
/// This information is added with the introduction of delegation.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerPoolInfo {
    /// Whether the pool allows delegators.
    #[prost(enumeration = "OpenStatus", tag = "1")]
    pub open_status:      i32,
    /// The URL that links to the metadata about the pool.
    #[prost(string, tag = "2")]
    pub url:              ::prost::alloc::string::String,
    /// The commission rates charged by the pool owner.
    #[prost(message, optional, tag = "3")]
    pub commission_rates: ::core::option::Option<CommissionRates>,
}
/// Information about the account stake, if the account is either a baker or a
/// delegator.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountStakingInfo {
    #[prost(oneof = "account_staking_info::StakingInfo", tags = "1, 2")]
    pub staking_info: ::core::option::Option<account_staking_info::StakingInfo>,
}
/// Nested message and enum types in `AccountStakingInfo`.
pub mod account_staking_info {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Baker {
        /// Amount staked at present.
        #[prost(message, optional, tag = "1")]
        pub staked_amount:    ::core::option::Option<super::Amount>,
        /// A flag indicating whether rewards paid to the baker are
        /// automatically restaked or not.
        #[prost(bool, tag = "2")]
        pub restake_earnings: bool,
        /// Information about the baker that is staking.
        #[prost(message, optional, tag = "3")]
        pub baker_info:       ::core::option::Option<super::BakerInfo>,
        /// If present, any pending change to the delegated stake.
        #[prost(message, optional, tag = "4")]
        pub pending_change:   ::core::option::Option<super::StakePendingChange>,
        /// Present if the account is currently a baker, i.e., it is in the
        /// baking committee of the current epoch.
        #[prost(message, optional, tag = "5")]
        pub pool_info:        ::core::option::Option<super::BakerPoolInfo>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Delegator {
        /// The amount that the account delegates.
        #[prost(message, optional, tag = "1")]
        pub staked_amount:    ::core::option::Option<super::Amount>,
        /// Whether the earnings are automatically added to the staked amount.
        #[prost(bool, tag = "2")]
        pub restake_earnings: bool,
        /// The entity to which the account delegates.
        #[prost(message, optional, tag = "3")]
        pub target:           ::core::option::Option<super::DelegationTarget>,
        /// If present, any pending change to the delegated stake.
        #[prost(message, optional, tag = "4")]
        pub pending_change:   ::core::option::Option<super::StakePendingChange>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum StakingInfo {
        /// The account is a baker.
        #[prost(message, tag = "1")]
        Baker(Baker),
        /// The account is a delegator.
        #[prost(message, tag = "2")]
        Delegator(Delegator),
    }
}
/// A sequence number that determines the ordering of transactions from the
/// account. The minimum sequence number is 1.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SequenceNumber {
    /// The sequence number.
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// A sequence number that determines the ordering of update transactions.
/// Equivalent to `SequenceNumber` for account transactions.
/// Update sequence numbers are per update type and the minimum value is 1.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateSequenceNumber {
    /// The sequence number.
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// An amount of microCCD.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Amount {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// Index of a credential on an account.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialIndex {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// The number of signatures required to sign.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureThreshold {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// The number of credentials required to sign an account transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountThreshold {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// An account encryption key. Always 96 bytes.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptionKey {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// An address of an account. Always 32 bytes.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountAddress {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// An address of either a contract or an account.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Address {
    #[prost(oneof = "address::Type", tags = "1, 2")]
    pub r#type: ::core::option::Option<address::Type>,
}
/// Nested message and enum types in `Address`.
pub mod address {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Type {
        #[prost(message, tag = "1")]
        Account(super::AccountAddress),
        #[prost(message, tag = "2")]
        Contract(super::ContractAddress),
    }
}
/// A public key used to verify transaction signatures from an account.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountVerifyKey {
    #[prost(oneof = "account_verify_key::Key", tags = "1")]
    pub key: ::core::option::Option<account_verify_key::Key>,
}
/// Nested message and enum types in `AccountVerifyKey`.
pub mod account_verify_key {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Key {
        #[prost(bytes, tag = "1")]
        Ed25519Key(::prost::alloc::vec::Vec<u8>),
    }
}
/// Public keys of a single credential.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialPublicKeys {
    #[prost(map = "uint32, message", tag = "1")]
    pub keys:      ::std::collections::HashMap<u32, AccountVerifyKey>,
    #[prost(message, optional, tag = "2")]
    pub threshold: ::core::option::Option<SignatureThreshold>,
}
/// A registration ID of a credential, derived from the secret PRF key and a
/// nonce. This is always 48 bytes long.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialRegistrationId {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// An index of the identity provider that identifies them uniquely in the
/// context of a specific chain.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IdentityProviderIdentity {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// Representation of the pair of a year and month.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct YearMonth {
    #[prost(uint32, tag = "1")]
    pub year:  u32,
    #[prost(uint32, tag = "2")]
    pub month: u32,
}
/// Policy on a credential.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Policy {
    /// The year and month when the identity object from which the credential is
    /// derived was created.
    #[prost(message, optional, tag = "1")]
    pub created_at: ::core::option::Option<YearMonth>,
    /// The last year and month when the credential is still valid. After this
    /// expires an account can no longer be created from the credential.
    #[prost(message, optional, tag = "2")]
    pub valid_to:   ::core::option::Option<YearMonth>,
    /// Mapping from attribute tags to attribute values. Attribute tags are
    /// always representable in a single `u8`, attribute values are never
    /// more than 31 bytes in length.
    #[prost(map = "uint32, bytes", tag = "3")]
    pub attributes: ::std::collections::HashMap<u32, ::prost::alloc::vec::Vec<u8>>,
}
/// Values contained in an initial credential.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitialCredentialValues {
    /// Public keys of the credential.
    #[prost(message, optional, tag = "1")]
    pub keys:    ::core::option::Option<CredentialPublicKeys>,
    /// Its registration ID.
    #[prost(message, optional, tag = "2")]
    pub cred_id: ::core::option::Option<CredentialRegistrationId>,
    /// The identity provider who signed the identity object from which this
    /// credential is derived.
    #[prost(message, optional, tag = "3")]
    pub ip_id:   ::core::option::Option<IdentityProviderIdentity>,
    /// Policy of this credential.
    #[prost(message, optional, tag = "4")]
    pub policy:  ::core::option::Option<Policy>,
}
/// Data relating to a single anonymity revoker sent by the account holder to
/// the chain.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainArData {
    /// Share of the encryption of IdCredPub.
    #[prost(bytes = "vec", tag = "1")]
    pub enc_id_cred_pub_share: ::prost::alloc::vec::Vec<u8>,
}
/// The number of anonymity revokers needed to revoke anonymity of a credential
/// holder.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArThreshold {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// A single commitment in the G1 group of the BLS curve. This is always 48
/// bytes in length.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Commitment {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Commitments that are part of a normal credential.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialCommitments {
    /// Commitment to the PRF key.
    #[prost(message, optional, tag = "1")]
    pub prf: ::core::option::Option<Commitment>,
    /// Commitment to the counter used to generate the credential registration
    /// id.
    #[prost(message, optional, tag = "2")]
    pub cred_counter: ::core::option::Option<Commitment>,
    /// Commitment to the `max_accounts` value, which determines the maximum
    /// number of credentials that may be created from the identity object.
    #[prost(message, optional, tag = "3")]
    pub max_accounts: ::core::option::Option<Commitment>,
    /// Commitments to the attributes which have not been revealed in the
    /// policy.
    #[prost(map = "uint32, message", tag = "4")]
    pub attributes: ::std::collections::HashMap<u32, Commitment>,
    /// List of commitments to the coefficients of the sharing polynomial. This
    /// polynomial is used in a shared encryption of `id_cred_pub` among the
    /// anonymity revokers.
    #[prost(message, repeated, tag = "5")]
    pub id_cred_sec_sharing_coeff: ::prost::alloc::vec::Vec<Commitment>,
}
/// Values contained in a normal (non-initial) credential.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NormalCredentialValues {
    /// Public keys of the credential.
    #[prost(message, optional, tag = "1")]
    pub keys:         ::core::option::Option<CredentialPublicKeys>,
    /// Its registration ID.
    #[prost(message, optional, tag = "2")]
    pub cred_id:      ::core::option::Option<CredentialRegistrationId>,
    /// The identity provider who signed the identity object from which this
    /// credential is derived.
    #[prost(message, optional, tag = "3")]
    pub ip_id:        ::core::option::Option<IdentityProviderIdentity>,
    /// Policy of this credential.
    #[prost(message, optional, tag = "4")]
    pub policy:       ::core::option::Option<Policy>,
    /// The number of anonymity revokers that must work together to revoke the
    /// anonymity of the credential holder.
    #[prost(message, optional, tag = "5")]
    pub ar_threshold: ::core::option::Option<ArThreshold>,
    /// Mapping from anonymity revoker identities to revocation data for the
    /// given anonymity revoker.
    #[prost(map = "uint32, message", tag = "6")]
    pub ar_data:      ::std::collections::HashMap<u32, ChainArData>,
    /// Commitments to attributes which have not been revealed.
    #[prost(message, optional, tag = "7")]
    pub commitments:  ::core::option::Option<CredentialCommitments>,
}
/// Credential that is part of an account.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountCredential {
    #[prost(oneof = "account_credential::CredentialValues", tags = "1, 2")]
    pub credential_values: ::core::option::Option<account_credential::CredentialValues>,
}
/// Nested message and enum types in `AccountCredential`.
pub mod account_credential {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CredentialValues {
        #[prost(message, tag = "1")]
        Initial(super::InitialCredentialValues),
        #[prost(message, tag = "2")]
        Normal(super::NormalCredentialValues),
    }
}
/// Information about the account at a particular point in time.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountInfo {
    /// Next sequence number to be used for transactions signed from this
    /// account.
    #[prost(message, optional, tag = "1")]
    pub sequence_number:   ::core::option::Option<SequenceNumber>,
    /// Current (unencrypted) balance of the account.
    #[prost(message, optional, tag = "2")]
    pub amount:            ::core::option::Option<Amount>,
    /// Release schedule for any locked up amount. This could be an empty
    /// release schedule.
    #[prost(message, optional, tag = "3")]
    pub schedule:          ::core::option::Option<ReleaseSchedule>,
    /// Map of all currently active credentials on the account.
    /// This includes public keys that can sign for the given credentials, as
    /// well as any revealed attributes. This map always contains a credential
    /// with index 0.
    #[prost(map = "uint32, message", tag = "4")]
    pub creds:             ::std::collections::HashMap<u32, AccountCredential>,
    /// Lower bound on how many credentials must sign any given transaction from
    /// this account.
    #[prost(message, optional, tag = "5")]
    pub threshold:         ::core::option::Option<AccountThreshold>,
    /// The encrypted balance of the account.
    #[prost(message, optional, tag = "6")]
    pub encrypted_balance: ::core::option::Option<EncryptedBalance>,
    /// The public key for sending encrypted balances to the account.
    #[prost(message, optional, tag = "7")]
    pub encryption_key:    ::core::option::Option<EncryptionKey>,
    /// Internal index of the account. Accounts on the chain get sequential
    /// indices. These should generally not be used outside of the chain,
    /// the account address is meant to be used to refer to accounts,
    /// however the account index serves the role of the baker id, if the
    /// account is a baker. Hence it is exposed here as well.
    #[prost(message, optional, tag = "8")]
    pub index:             ::core::option::Option<AccountIndex>,
    /// Present if the account is a baker or delegator. In that case
    /// it is the information about the baker or delegator.
    #[prost(message, optional, tag = "9")]
    pub stake:             ::core::option::Option<AccountStakingInfo>,
    /// Canonical address of the account. This is derived from the first
    /// credential that created the account.
    #[prost(message, optional, tag = "10")]
    pub address:           ::core::option::Option<AccountAddress>,
}
/// Input to queries which take a block as a parameter.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHashInput {
    #[prost(oneof = "block_hash_input::BlockHashInput", tags = "1, 2, 3, 4, 5")]
    pub block_hash_input: ::core::option::Option<block_hash_input::BlockHashInput>,
}
/// Nested message and enum types in `BlockHashInput`.
pub mod block_hash_input {
    /// Request using a relative block height.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RelativeHeight {
        /// Genesis index to start from.
        #[prost(message, optional, tag = "1")]
        pub genesis_index: ::core::option::Option<super::GenesisIndex>,
        /// Height starting from the genesis block at the genesis index.
        #[prost(message, optional, tag = "2")]
        pub height:        ::core::option::Option<super::BlockHeight>,
        /// Whether to return results only from the specified genesis index
        /// (`true`), or allow results from more recent genesis indices
        /// as well (`false`).
        #[prost(bool, tag = "3")]
        pub restrict:      bool,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum BlockHashInput {
        /// Query for the best block.
        #[prost(message, tag = "1")]
        Best(super::Empty),
        /// Query for the last finalized block.
        #[prost(message, tag = "2")]
        LastFinal(super::Empty),
        /// Query for the block specified by the hash. This hash should always
        /// be 32 bytes.
        #[prost(message, tag = "3")]
        Given(super::BlockHash),
        /// Query for a block at height, if a unique block can be identified at
        /// that height.
        #[prost(message, tag = "4")]
        AbsoluteHeight(super::AbsoluteBlockHeight),
        #[prost(message, tag = "5")]
        RelativeHeight(RelativeHeight),
    }
}
/// Input to queries which take an account as a parameter.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountIdentifierInput {
    #[prost(
        oneof = "account_identifier_input::AccountIdentifierInput",
        tags = "1, 2, 3"
    )]
    pub account_identifier_input:
        ::core::option::Option<account_identifier_input::AccountIdentifierInput>,
}
/// Nested message and enum types in `AccountIdentifierInput`.
pub mod account_identifier_input {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum AccountIdentifierInput {
        /// Identify the account by the address of the account.
        #[prost(message, tag = "1")]
        Address(super::AccountAddress),
        /// Identify the account by the credential that belongs or has belonged
        /// to it.
        #[prost(message, tag = "2")]
        CredId(super::CredentialRegistrationId),
        /// Identify the account via its index.
        #[prost(message, tag = "3")]
        AccountIndex(super::AccountIndex),
    }
}
/// Request for account information.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountInfoRequest {
    /// Block in which to query the account information.
    #[prost(message, optional, tag = "1")]
    pub block_hash:         ::core::option::Option<BlockHashInput>,
    /// Specification of the account.
    #[prost(message, optional, tag = "2")]
    pub account_identifier: ::core::option::Option<AccountIdentifierInput>,
}
/// Information about a finalized block that is part of the streaming response.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizedBlockInfo {
    /// Hash of the block.
    #[prost(message, optional, tag = "1")]
    pub hash:   ::core::option::Option<BlockHash>,
    /// Absolute height of the block, height 0 is the genesis block.
    #[prost(message, optional, tag = "2")]
    pub height: ::core::option::Option<AbsoluteBlockHeight>,
}
/// Request the ancestors for the given block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AncestorsRequest {
    /// The block to get ancestors of.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHashInput>,
    /// The maximum number of ancestors returned.
    #[prost(uint64, tag = "2")]
    pub amount:     u64,
}
/// Request for getting the source of a smart contract module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ModuleSourceRequest {
    /// The block to be used for the query.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHashInput>,
    /// The reference of the module.
    #[prost(message, optional, tag = "2")]
    pub module_ref: ::core::option::Option<ModuleRef>,
}
/// Address of a smart contract instance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractAddress {
    /// The index of the smart contract.
    #[prost(uint64, tag = "1")]
    pub index:    u64,
    /// The subindex of the smart contract instance.
    /// Currently not used, so it is always 0.
    #[prost(uint64, tag = "2")]
    pub subindex: u64,
}
/// Request for getting information about a smart contract instance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceInfoRequest {
    /// The block to be used for the query.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHashInput>,
    /// The address of the smart contract instance.
    #[prost(message, optional, tag = "2")]
    pub address:    ::core::option::Option<ContractAddress>,
}
/// Information about a smart contract instance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceInfo {
    /// The information depends on the smart contract version used by the
    /// instance.
    #[prost(oneof = "instance_info::Version", tags = "1, 2")]
    pub version: ::core::option::Option<instance_info::Version>,
}
/// Nested message and enum types in `InstanceInfo`.
pub mod instance_info {
    /// Version 0 smart contract instance information.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct V0 {
        /// The state of the instance.
        #[prost(message, optional, tag = "1")]
        pub model:         ::core::option::Option<super::ContractStateV0>,
        /// The account address which deployed the instance.
        #[prost(message, optional, tag = "2")]
        pub owner:         ::core::option::Option<super::AccountAddress>,
        /// The amount of CCD tokens in the balance of the instance.
        #[prost(message, optional, tag = "3")]
        pub amount:        ::core::option::Option<super::Amount>,
        /// A list of endpoints exposed by the instance.
        #[prost(message, repeated, tag = "4")]
        pub methods:       ::prost::alloc::vec::Vec<super::ReceiveName>,
        /// The name of the smart contract of the instance.
        #[prost(message, optional, tag = "5")]
        pub name:          ::core::option::Option<super::InitName>,
        /// The module reference for the smart contract module of the instance.
        #[prost(message, optional, tag = "6")]
        pub source_module: ::core::option::Option<super::ModuleRef>,
    }
    /// Version 1 smart contract instance information.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct V1 {
        /// The account address which deployed the instance.
        #[prost(message, optional, tag = "2")]
        pub owner:         ::core::option::Option<super::AccountAddress>,
        /// The amount of CCD tokens in the balance of the instance.
        #[prost(message, optional, tag = "3")]
        pub amount:        ::core::option::Option<super::Amount>,
        /// A list of endpoints exposed by the instance.
        #[prost(message, repeated, tag = "4")]
        pub methods:       ::prost::alloc::vec::Vec<super::ReceiveName>,
        /// The name of the smart contract of the instance.
        #[prost(message, optional, tag = "5")]
        pub name:          ::core::option::Option<super::InitName>,
        /// The module reference for the smart contract module of the instance.
        #[prost(message, optional, tag = "6")]
        pub source_module: ::core::option::Option<super::ModuleRef>,
    }
    /// The information depends on the smart contract version used by the
    /// instance.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Version {
        #[prost(message, tag = "1")]
        V0(V0),
        #[prost(message, tag = "2")]
        V1(V1),
    }
}
/// A smart contract instance key-value pair.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceStateKvPair {
    #[prost(bytes = "vec", tag = "1")]
    pub key:   ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Request for a specific key of a smart contract instance state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceStateLookupRequest {
    /// The block to be used for the query.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHashInput>,
    /// The address of the smart contract instance.
    #[prost(message, optional, tag = "2")]
    pub address:    ::core::option::Option<ContractAddress>,
    /// Key to look up. If the instance is a V0 instance then this will not be
    /// used.
    #[prost(bytes = "vec", tag = "3")]
    pub key:        ::prost::alloc::vec::Vec<u8>,
}
/// Value at the requested key of a smart contract instance state. For V0
/// contracts this will always be the entire state of the contract.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceStateValueAtKey {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// The receive name of a smart contract function. Expected format:
/// `<contract_name>.<func_name>`. It must only consist of atmost 100 ASCII
/// alphanumeric or punctuation characters, and must contain a '.'.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReceiveName {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
/// The init name of a smart contract function. Expected format:
/// `init_<contract_name>`. It must only consist of atmost 100 ASCII
/// alphanumeric or punctuation characters, must not contain a '.' and must
/// start with 'init_'.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitName {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
/// Parameter to a smart contract initialization or invocation.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Parameter {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// A smart contract v0 state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractStateV0 {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Status of a block item known to the node.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockItemStatus {
    #[prost(oneof = "block_item_status::Status", tags = "1, 2, 3")]
    pub status: ::core::option::Option<block_item_status::Status>,
}
/// Nested message and enum types in `BlockItemStatus`.
pub mod block_item_status {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Committed {
        #[prost(message, repeated, tag = "1")]
        pub outcomes: ::prost::alloc::vec::Vec<super::BlockItemSummaryInBlock>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Finalized {
        #[prost(message, optional, tag = "1")]
        pub outcome: ::core::option::Option<super::BlockItemSummaryInBlock>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Status {
        /// Block item is received, but not yet in any blocks.
        #[prost(message, tag = "1")]
        Received(super::Empty),
        /// Block item is committed to one or more blocks. The outcomes are
        /// listed for each block. Note that in the vast majority of
        /// cases the outcome of a transaction should not be dependent
        /// on the block it is in, but this can in principle happen.
        #[prost(message, tag = "2")]
        Committed(Committed),
        /// Block item is finalized in the given block, with the given summary.
        #[prost(message, tag = "3")]
        Finalized(Finalized),
    }
}
/// A block item summary together with a block hash. Used in BlockItemStatus.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockItemSummaryInBlock {
    /// The block hash.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHash>,
    /// The block item summary.
    #[prost(message, optional, tag = "2")]
    pub outcome:    ::core::option::Option<BlockItemSummary>,
}
/// Energy is used to count exact execution cost.
/// This cost is then converted to CCD amounts.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Energy {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// A number representing a slot for baking a block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Slot {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// The response for getNextAccountSequenceNumber.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NextAccountSequenceNumber {
    /// The best guess for the available account sequence number.
    #[prost(message, optional, tag = "1")]
    pub sequence_number: ::core::option::Option<SequenceNumber>,
    /// Whether the guess relies on any non-finalized transactions. If true all
    /// of the relevant transactions are finalized.
    #[prost(bool, tag = "2")]
    pub all_final:       bool,
}
/// A duration of milliseconds.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Duration {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// A reason for why a transaction was rejected. Rejected means included in a
/// block, but the desired action was not achieved. The only effect of a
/// rejected transaction is payment.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RejectReason {
    #[prost(
        oneof = "reject_reason::Reason",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, \
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, \
                43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54"
    )]
    pub reason: ::core::option::Option<reject_reason::Reason>,
}
/// Nested message and enum types in `RejectReason`.
pub mod reject_reason {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct InvalidInitMethod {
        #[prost(message, optional, tag = "1")]
        pub module_ref: ::core::option::Option<super::ModuleRef>,
        #[prost(message, optional, tag = "2")]
        pub init_name:  ::core::option::Option<super::InitName>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct InvalidReceiveMethod {
        #[prost(message, optional, tag = "1")]
        pub module_ref:   ::core::option::Option<super::ModuleRef>,
        #[prost(message, optional, tag = "2")]
        pub receive_name: ::core::option::Option<super::ReceiveName>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AmountTooLarge {
        #[prost(message, optional, tag = "1")]
        pub address: ::core::option::Option<super::Address>,
        #[prost(message, optional, tag = "2")]
        pub amount:  ::core::option::Option<super::Amount>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RejectedInit {
        #[prost(int32, tag = "1")]
        pub reject_reason: i32,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RejectedReceive {
        #[prost(int32, tag = "1")]
        pub reject_reason:    i32,
        #[prost(message, optional, tag = "2")]
        pub contract_address: ::core::option::Option<super::ContractAddress>,
        #[prost(message, optional, tag = "3")]
        pub receive_name:     ::core::option::Option<super::ReceiveName>,
        #[prost(message, optional, tag = "4")]
        pub parameter:        ::core::option::Option<super::Parameter>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DuplicateCredIds {
        #[prost(message, repeated, tag = "1")]
        pub ids: ::prost::alloc::vec::Vec<super::CredentialRegistrationId>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NonExistentCredIds {
        #[prost(message, repeated, tag = "1")]
        pub ids: ::prost::alloc::vec::Vec<super::CredentialRegistrationId>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Reason {
        /// Raised while validating a Wasm module that is not well formed.
        #[prost(message, tag = "1")]
        ModuleNotWf(super::Empty),
        /// The smart contract module hash already exists.
        #[prost(message, tag = "2")]
        ModuleHashAlreadyExists(super::ModuleRef),
        /// Account does not exist.
        #[prost(message, tag = "3")]
        InvalidAccountReference(super::AccountAddress),
        /// Reference to a non-existing contract init method.
        #[prost(message, tag = "4")]
        InvalidInitMethod(InvalidInitMethod),
        /// Reference to a non-existing contract receive method.
        #[prost(message, tag = "5")]
        InvalidReceiveMethod(InvalidReceiveMethod),
        /// Reference to a non-existing smart contract module.
        #[prost(message, tag = "6")]
        InvalidModuleReference(super::ModuleRef),
        /// Contract instance does not exist.
        #[prost(message, tag = "7")]
        InvalidContractAddress(super::ContractAddress),
        /// Runtime exception occurred when running either the init or receive
        /// method.
        #[prost(message, tag = "8")]
        RuntimeFailure(super::Empty),
        /// When one wishes to transfer an amount from A to B but there
        /// are not enough funds on account/contract A to make this
        /// possible. The data are the from address and the amount to transfer.
        #[prost(message, tag = "9")]
        AmountTooLarge(AmountTooLarge),
        /// Serialization of the body failed.
        #[prost(message, tag = "10")]
        SerializationFailure(super::Empty),
        /// We ran of out energy to process this transaction.
        #[prost(message, tag = "11")]
        OutOfEnergy(super::Empty),
        /// Rejected due to contract logic in init function of a contract.
        #[prost(message, tag = "12")]
        RejectedInit(RejectedInit),
        /// Rejected due to contract logic in receive function of a contract.
        #[prost(message, tag = "13")]
        RejectedReceive(RejectedReceive),
        /// Proof that the baker owns relevant private keys is not valid.
        #[prost(message, tag = "14")]
        InvalidProof(super::Empty),
        /// Tried to add baker for an account that already has a baker.
        #[prost(message, tag = "15")]
        AlreadyABaker(super::BakerId),
        /// Tried to remove a baker for an account that has no baker.
        #[prost(message, tag = "16")]
        NotABaker(super::AccountAddress),
        /// The amount on the account was insufficient to cover the proposed
        /// stake.
        #[prost(message, tag = "17")]
        InsufficientBalanceForBakerStake(super::Empty),
        /// The amount provided is under the threshold required for becoming a
        /// baker.
        #[prost(message, tag = "18")]
        StakeUnderMinimumThresholdForBaking(super::Empty),
        /// The change could not be made because the baker is in cooldown for
        /// another change.
        #[prost(message, tag = "19")]
        BakerInCooldown(super::Empty),
        /// A baker with the given aggregation key already exists.
        #[prost(message, tag = "20")]
        DuplicateAggregationKey(super::BakerAggregationVerifyKey),
        /// Encountered credential ID that does not exist.
        #[prost(message, tag = "21")]
        NonExistentCredentialId(super::Empty),
        /// Attempted to add an account key to a key index already in use.
        #[prost(message, tag = "22")]
        KeyIndexAlreadyInUse(super::Empty),
        /// When the account threshold is updated, it must not exceed the amount
        /// of existing keys.
        #[prost(message, tag = "23")]
        InvalidAccountThreshold(super::Empty),
        /// When the credential key threshold is updated, it must not exceed the
        /// amount of existing keys.
        #[prost(message, tag = "24")]
        InvalidCredentialKeySignThreshold(super::Empty),
        /// Proof for an encrypted amount transfer did not validate.
        #[prost(message, tag = "25")]
        InvalidEncryptedAmountTransferProof(super::Empty),
        /// Proof for a secret to public transfer did not validate.
        #[prost(message, tag = "26")]
        InvalidTransferToPublicProof(super::Empty),
        /// Account tried to transfer an encrypted amount to itself, that's not
        /// allowed.
        #[prost(message, tag = "27")]
        EncryptedAmountSelfTransfer(super::AccountAddress),
        /// The provided index is below the start index or above `startIndex +
        /// length incomingAmounts`.
        #[prost(message, tag = "28")]
        InvalidIndexOnEncryptedTransfer(super::Empty),
        /// The transfer with schedule is going to send 0 tokens.
        #[prost(message, tag = "29")]
        ZeroScheduledAmount(super::Empty),
        /// The transfer with schedule has a non strictly increasing schedule.
        #[prost(message, tag = "30")]
        NonIncreasingSchedule(super::Empty),
        /// The first scheduled release in a transfer with schedule has already
        /// expired.
        #[prost(message, tag = "31")]
        FirstScheduledReleaseExpired(super::Empty),
        /// Account tried to transfer with schedule to itself, that's not
        /// allowed.
        #[prost(message, tag = "32")]
        ScheduledSelfTransfer(super::AccountAddress),
        /// At least one of the credentials was either malformed or its proof
        /// was incorrect.
        #[prost(message, tag = "33")]
        InvalidCredentials(super::Empty),
        /// Some of the credential IDs already exist or are duplicated in the
        /// transaction.
        #[prost(message, tag = "34")]
        DuplicateCredIds(DuplicateCredIds),
        /// A credential id that was to be removed is not part of the account.
        #[prost(message, tag = "35")]
        NonExistentCredIds(NonExistentCredIds),
        /// Attemp to remove the first credential.
        #[prost(message, tag = "36")]
        RemoveFirstCredential(super::Empty),
        /// The credential holder of the keys to be updated did not sign the
        /// transaction.
        #[prost(message, tag = "37")]
        CredentialHolderDidNotSign(super::Empty),
        /// Account is not allowed to have multiple credentials because it
        /// contains a non-zero encrypted transfer.
        #[prost(message, tag = "38")]
        NotAllowedMultipleCredentials(super::Empty),
        /// The account is not allowed to receive encrypted transfers because it
        /// has multiple credentials.
        #[prost(message, tag = "39")]
        NotAllowedToReceiveEncrypted(super::Empty),
        /// The account is not allowed to send encrypted transfers (or transfer
        /// from/to public to/from encrypted).
        #[prost(message, tag = "40")]
        NotAllowedToHandleEncrypted(super::Empty),
        /// A configure baker transaction is missing one or more arguments in
        /// order to add a baker.
        #[prost(message, tag = "41")]
        MissingBakerAddParameters(super::Empty),
        /// Finalization reward commission is not in the valid range for a
        /// baker.
        #[prost(message, tag = "42")]
        FinalizationRewardCommissionNotInRange(super::Empty),
        /// Baking reward commission is not in the valid range for a baker.
        #[prost(message, tag = "43")]
        BakingRewardCommissionNotInRange(super::Empty),
        /// Transaction fee commission is not in the valid range for a baker.
        #[prost(message, tag = "44")]
        TransactionFeeCommissionNotInRange(super::Empty),
        /// Tried to add baker for an account that already has a delegator.
        #[prost(message, tag = "45")]
        AlreadyADelegator(super::Empty),
        /// The amount on the account was insufficient to cover the proposed
        /// stake.
        #[prost(message, tag = "46")]
        InsufficientBalanceForDelegationStake(super::Empty),
        /// A configure delegation transaction is missing one or more arguments
        /// in order to add a delegator.
        #[prost(message, tag = "47")]
        MissingDelegationAddParameters(super::Empty),
        /// Delegation stake when adding a delegator was 0.
        #[prost(message, tag = "48")]
        InsufficientDelegationStake(super::Empty),
        /// Account is not a delegation account.
        #[prost(message, tag = "49")]
        DelegatorInCooldown(super::Empty),
        /// Account is not a delegation account.
        #[prost(message, tag = "50")]
        NotADelegator(super::AccountAddress),
        /// Delegation target is not a baker
        #[prost(message, tag = "51")]
        DelegationTargetNotABaker(super::BakerId),
        /// The amount would result in pool capital higher than the maximum
        /// threshold.
        #[prost(message, tag = "52")]
        StakeOverMaximumThresholdForPool(super::Empty),
        /// The amount would result in pool with a too high fraction of
        /// delegated capital.
        #[prost(message, tag = "53")]
        PoolWouldBecomeOverDelegated(super::Empty),
        /// The pool is not open to delegators.
        #[prost(message, tag = "54")]
        PoolClosed(super::Empty),
    }
}
/// Data generated as part of initializing a single contract instance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractInitializedEvent {
    /// Contract version.
    #[prost(enumeration = "ContractVersion", tag = "1")]
    pub contract_version: i32,
    /// Module with the source code of the contract.
    #[prost(message, optional, tag = "2")]
    pub origin_ref:       ::core::option::Option<ModuleRef>,
    /// The newly assigned address of the contract.
    #[prost(message, optional, tag = "3")]
    pub address:          ::core::option::Option<ContractAddress>,
    /// The amount the instance was initialized with.
    #[prost(message, optional, tag = "4")]
    pub amount:           ::core::option::Option<Amount>,
    /// The name of the contract.
    #[prost(message, optional, tag = "5")]
    pub init_name:        ::core::option::Option<InitName>,
    /// Any contract events that might have been genereated by the contract
    /// initialization.
    #[prost(message, repeated, tag = "6")]
    pub events:           ::prost::alloc::vec::Vec<ContractEvent>,
}
/// An event generated by a smart contract.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractEvent {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Data generated as part of updating a single contract instance.
/// In general a single Update transaction will
/// generate one or more of these events, together with possibly some transfers.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceUpdatedEvent {
    /// Contract version.
    #[prost(enumeration = "ContractVersion", tag = "1")]
    pub contract_version: i32,
    /// Address of the affected instance.
    #[prost(message, optional, tag = "2")]
    pub address:          ::core::option::Option<ContractAddress>,
    /// The origin of the message to the smart contract. This can be
    /// either an account or a smart contract.
    #[prost(message, optional, tag = "3")]
    pub instigator:       ::core::option::Option<Address>,
    /// The amount the method was invoked with.
    #[prost(message, optional, tag = "4")]
    pub amount:           ::core::option::Option<Amount>,
    /// The parameter passed to the method.
    #[prost(message, optional, tag = "5")]
    pub parameter:        ::core::option::Option<Parameter>,
    /// The name of the method that was executed.
    #[prost(message, optional, tag = "6")]
    pub receive_name:     ::core::option::Option<ReceiveName>,
    /// Any contract events that might have been generated by the contract
    /// execution.
    #[prost(message, repeated, tag = "7")]
    pub events:           ::prost::alloc::vec::Vec<ContractEvent>,
}
/// Effects produced by successful smart contract invocations.
/// A single invocation will produce a sequence of these effects.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractTraceElement {
    #[prost(oneof = "contract_trace_element::Element", tags = "1, 2, 3, 4, 5")]
    pub element: ::core::option::Option<contract_trace_element::Element>,
}
/// Nested message and enum types in `ContractTraceElement`.
pub mod contract_trace_element {
    /// A contract transferred an amount to an account.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Transferred {
        /// Sender contract.
        #[prost(message, optional, tag = "1")]
        pub sender:   ::core::option::Option<super::ContractAddress>,
        /// Amount transferred.
        #[prost(message, optional, tag = "2")]
        pub amount:   ::core::option::Option<super::Amount>,
        /// Receiver account.
        #[prost(message, optional, tag = "3")]
        pub receiver: ::core::option::Option<super::AccountAddress>,
    }
    /// A contract was interrupted.
    /// This occurs when a contract invokes another contract or makes a transfer
    /// to an account.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Interrupted {
        /// The contract interrupted.
        #[prost(message, optional, tag = "1")]
        pub address: ::core::option::Option<super::ContractAddress>,
        /// The events generated up until the interruption.
        #[prost(message, repeated, tag = "2")]
        pub events:  ::prost::alloc::vec::Vec<super::ContractEvent>,
    }
    /// A previously interrupted contract was resumed.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Resumed {
        /// The contract resumed.
        #[prost(message, optional, tag = "1")]
        pub address: ::core::option::Option<super::ContractAddress>,
        /// Whether the action that caused the interruption (invoke contract or
        /// make transfer) was successful or not.
        #[prost(bool, tag = "2")]
        pub success: bool,
    }
    /// A previously interrupted contract was resumed.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Upgraded {
        /// The that was upgraded.
        #[prost(message, optional, tag = "1")]
        pub address: ::core::option::Option<super::ContractAddress>,
        /// The module from which the contract was upgraded.
        #[prost(message, optional, tag = "2")]
        pub from:    ::core::option::Option<super::ModuleRef>,
        /// The module to which it was upgraded.
        #[prost(message, optional, tag = "3")]
        pub to:      ::core::option::Option<super::ModuleRef>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Element {
        /// A contract instance was updated.
        #[prost(message, tag = "1")]
        Updated(super::InstanceUpdatedEvent),
        /// A contract transferred an amount to an account.
        #[prost(message, tag = "2")]
        Transferred(Transferred),
        /// A contract was interrupted.
        /// This occurs when a contract invokes another contract or makes a
        /// transfer to an account.
        #[prost(message, tag = "3")]
        Interrupted(Interrupted),
        /// A previously interrupted contract was resumed.
        #[prost(message, tag = "4")]
        Resumed(Resumed),
        /// A contract was upgraded.
        #[prost(message, tag = "5")]
        Upgraded(Upgraded),
    }
}
/// Result of a successful change of baker keys.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerKeysEvent {
    /// ID of the baker whose keys were changed.
    #[prost(message, optional, tag = "1")]
    pub baker_id:        ::core::option::Option<BakerId>,
    /// Account address of the baker.
    #[prost(message, optional, tag = "2")]
    pub account:         ::core::option::Option<AccountAddress>,
    /// The new public key for verifying block signatures.
    #[prost(message, optional, tag = "3")]
    pub sign_key:        ::core::option::Option<BakerSignatureVerifyKey>,
    /// The new public key for verifying whether the baker won the block
    /// lottery.
    #[prost(message, optional, tag = "4")]
    pub election_key:    ::core::option::Option<BakerElectionVerifyKey>,
    /// The new public key for verifying finalization records.
    #[prost(message, optional, tag = "5")]
    pub aggregation_key: ::core::option::Option<BakerAggregationVerifyKey>,
}
/// A memo which can be included as part of a transfer. Max size is 256 bytes.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Memo {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerStakeUpdatedData {
    /// Affected baker.
    #[prost(message, optional, tag = "1")]
    pub baker_id:  ::core::option::Option<BakerId>,
    /// New stake.
    #[prost(message, optional, tag = "2")]
    pub new_stake: ::core::option::Option<Amount>,
    /// A boolean which indicates whether it increased
    /// (`true`) or decreased (`false`).
    #[prost(bool, tag = "3")]
    pub increased: bool,
}
/// Event generated when one or more encrypted amounts are consumed from the
/// account.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedAmountRemovedEvent {
    /// The affected account.
    #[prost(message, optional, tag = "1")]
    pub account:      ::core::option::Option<AccountAddress>,
    /// The new self encrypted amount on the affected account.
    #[prost(message, optional, tag = "2")]
    pub new_amount:   ::core::option::Option<EncryptedAmount>,
    /// The input encrypted amount that was removed.
    #[prost(message, optional, tag = "3")]
    pub input_amount: ::core::option::Option<EncryptedAmount>,
    /// The index indicating which amounts were used.
    #[prost(uint64, tag = "4")]
    pub up_to_index:  u64,
}
/// Event generated when an account receives a new encrypted amount.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewEncryptedAmountEvent {
    /// The account onto which the amount was added.
    #[prost(message, optional, tag = "1")]
    pub receiver:         ::core::option::Option<AccountAddress>,
    /// The index the amount was assigned.
    #[prost(uint64, tag = "2")]
    pub new_index:        u64,
    /// The encrypted amount that was added.
    #[prost(message, optional, tag = "3")]
    pub encrypted_amount: ::core::option::Option<EncryptedAmount>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedSelfAmountAddedEvent {
    /// The affected account.
    #[prost(message, optional, tag = "1")]
    pub account:    ::core::option::Option<AccountAddress>,
    /// The new self encrypted amount of the account.
    #[prost(message, optional, tag = "2")]
    pub new_amount: ::core::option::Option<EncryptedAmount>,
    /// The amount that was transferred from public to encrypted balance.
    #[prost(message, optional, tag = "3")]
    pub amount:     ::core::option::Option<Amount>,
}
/// Data registered on the chain with a register data transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisteredData {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Events that may result from the ConfigureBaker transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerEvent {
    #[prost(
        oneof = "baker_event::Event",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11"
    )]
    pub event: ::core::option::Option<baker_event::Event>,
}
/// Nested message and enum types in `BakerEvent`.
pub mod baker_event {
    /// A baker was added.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerAdded {
        /// The keys with which the baker registered.
        #[prost(message, optional, tag = "1")]
        pub keys_event:       ::core::option::Option<super::BakerKeysEvent>,
        /// The amount the account staked to become a baker. This amount is
        /// locked.
        #[prost(message, optional, tag = "2")]
        pub stake:            ::core::option::Option<super::Amount>,
        /// Whether the baker will automatically add earnings to their stake or
        /// not.
        #[prost(bool, tag = "3")]
        pub restake_earnings: bool,
    }
    /// Baker stake increased.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerStakeIncreased {
        /// Baker's id.
        #[prost(message, optional, tag = "1")]
        pub baker_id:  ::core::option::Option<super::BakerId>,
        /// The new stake.
        #[prost(message, optional, tag = "2")]
        pub new_stake: ::core::option::Option<super::Amount>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerStakeDecreased {
        /// Baker's id.
        #[prost(message, optional, tag = "1")]
        pub baker_id:  ::core::option::Option<super::BakerId>,
        /// The new stake.
        #[prost(message, optional, tag = "2")]
        pub new_stake: ::core::option::Option<super::Amount>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerRestakeEarningsUpdated {
        /// Baker's id.
        #[prost(message, optional, tag = "1")]
        pub baker_id:         ::core::option::Option<super::BakerId>,
        /// The new value of the flag.
        #[prost(bool, tag = "2")]
        pub restake_earnings: bool,
    }
    /// Updated open status for a baker pool.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerSetOpenStatus {
        /// Baker's id.
        #[prost(message, optional, tag = "1")]
        pub baker_id:    ::core::option::Option<super::BakerId>,
        /// The new open status.
        #[prost(enumeration = "super::OpenStatus", tag = "2")]
        pub open_status: i32,
    }
    /// Updated metadata url for a baker pool.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerSetMetadataUrl {
        /// Baker's id.
        #[prost(message, optional, tag = "1")]
        pub baker_id: ::core::option::Option<super::BakerId>,
        /// The URL.
        #[prost(string, tag = "2")]
        pub url:      ::prost::alloc::string::String,
    }
    /// Updated transaction fee commission for a baker pool.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerSetTransactionFeeCommission {
        /// Baker's id.
        #[prost(message, optional, tag = "1")]
        pub baker_id:                   ::core::option::Option<super::BakerId>,
        /// The transaction fee commission.
        #[prost(message, optional, tag = "2")]
        pub transaction_fee_commission: ::core::option::Option<super::AmountFraction>,
    }
    /// Updated baking reward commission for baker pool
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerSetBakingRewardCommission {
        /// Baker's id
        #[prost(message, optional, tag = "1")]
        pub baker_id:                 ::core::option::Option<super::BakerId>,
        /// The baking reward commission
        #[prost(message, optional, tag = "2")]
        pub baking_reward_commission: ::core::option::Option<super::AmountFraction>,
    }
    /// Updated finalization reward commission for baker pool
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerSetFinalizationRewardCommission {
        /// Baker's id
        #[prost(message, optional, tag = "1")]
        pub baker_id: ::core::option::Option<super::BakerId>,
        /// The finalization reward commission
        #[prost(message, optional, tag = "2")]
        pub finalization_reward_commission: ::core::option::Option<super::AmountFraction>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Event {
        /// A baker was added.
        #[prost(message, tag = "1")]
        BakerAdded(BakerAdded),
        /// A baker was removed.
        #[prost(message, tag = "2")]
        BakerRemoved(super::BakerId),
        /// The baker's stake was increased.
        #[prost(message, tag = "3")]
        BakerStakeIncreased(BakerStakeIncreased),
        /// The baker's stake was decreased.
        #[prost(message, tag = "4")]
        BakerStakeDecreased(BakerStakeDecreased),
        /// The baker's setting for restaking earnings was updated.
        #[prost(message, tag = "5")]
        BakerRestakeEarningsUpdated(BakerRestakeEarningsUpdated),
        /// Baker keys were updated.
        #[prost(message, tag = "6")]
        BakerKeysUpdated(super::BakerKeysEvent),
        /// The baker's open status was updated.
        #[prost(message, tag = "7")]
        BakerSetOpenStatus(BakerSetOpenStatus),
        /// The baker's metadata URL was updated.
        #[prost(message, tag = "8")]
        BakerSetMetadataUrl(BakerSetMetadataUrl),
        /// The baker's transaction fee commission was updated.
        #[prost(message, tag = "9")]
        BakerSetTransactionFeeCommission(BakerSetTransactionFeeCommission),
        /// The baker's baking reward commission was updated.
        #[prost(message, tag = "10")]
        BakerSetBakingRewardCommission(BakerSetBakingRewardCommission),
        /// The baker's finalization reward commission was updated.
        #[prost(message, tag = "11")]
        BakerSetFinalizationRewardCommission(BakerSetFinalizationRewardCommission),
    }
}
/// The identifier for a delegator.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DelegatorId {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<AccountIndex>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DelegationEvent {
    #[prost(oneof = "delegation_event::Event", tags = "1, 2, 3, 4, 5, 6")]
    pub event: ::core::option::Option<delegation_event::Event>,
}
/// Nested message and enum types in `DelegationEvent`.
pub mod delegation_event {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DelegationStakeIncreased {
        /// Delegator's id
        #[prost(message, optional, tag = "1")]
        pub delegator_id: ::core::option::Option<super::DelegatorId>,
        /// New stake
        #[prost(message, optional, tag = "2")]
        pub new_stake:    ::core::option::Option<super::Amount>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DelegationStakeDecreased {
        /// Delegator's id
        #[prost(message, optional, tag = "1")]
        pub delegator_id: ::core::option::Option<super::DelegatorId>,
        /// New stake
        #[prost(message, optional, tag = "2")]
        pub new_stake:    ::core::option::Option<super::Amount>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DelegationSetRestakeEarnings {
        /// Delegator's id
        #[prost(message, optional, tag = "1")]
        pub delegator_id:     ::core::option::Option<super::DelegatorId>,
        /// Whether earnings will be restaked
        #[prost(bool, tag = "2")]
        pub restake_earnings: bool,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DelegationSetDelegationTarget {
        /// Delegator's id
        #[prost(message, optional, tag = "1")]
        pub delegator_id:      ::core::option::Option<super::DelegatorId>,
        /// New delegation target
        #[prost(message, optional, tag = "2")]
        pub delegation_target: ::core::option::Option<super::DelegationTarget>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Event {
        /// The delegator's stake increased.
        #[prost(message, tag = "1")]
        DelegationStakeIncreased(DelegationStakeIncreased),
        /// The delegator's stake decreased.
        #[prost(message, tag = "2")]
        DelegationStakeDecreased(DelegationStakeDecreased),
        /// The delegator's restaking setting was updated.
        #[prost(message, tag = "3")]
        DelegationSetRestakeEarnings(DelegationSetRestakeEarnings),
        /// The delegator's delegation target was updated.
        #[prost(message, tag = "4")]
        DelegationSetDelegationTarget(DelegationSetDelegationTarget),
        /// A delegator was added.
        #[prost(message, tag = "5")]
        DelegationAdded(super::DelegatorId),
        /// A delegator was removed.
        #[prost(message, tag = "6")]
        DelegationRemoved(super::DelegatorId),
    }
}
/// Effects of an account transaction. All variants except `None`
/// correspond to a unique transaction that was successful.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountTransactionEffects {
    #[prost(
        oneof = "account_transaction_effects::Effect",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19"
    )]
    pub effect: ::core::option::Option<account_transaction_effects::Effect>,
}
/// Nested message and enum types in `AccountTransactionEffects`.
pub mod account_transaction_effects {
    /// No effects other than payment from this transaction.
    /// The rejection reason indicates why the transaction failed.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct None {
        /// Transaction type of a failed transaction, if known.
        /// In case of serialization failure this will not be set.
        #[prost(enumeration = "super::TransactionType", optional, tag = "1")]
        pub transaction_type: ::core::option::Option<i32>,
        /// Reason for rejection of the transaction.
        #[prost(message, optional, tag = "2")]
        pub reject_reason:    ::core::option::Option<super::RejectReason>,
    }
    /// A contract update transaction was issued and produced the given trace.
    /// This is the result of Update transaction.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ContractUpdateIssued {
        #[prost(message, repeated, tag = "1")]
        pub effects: ::prost::alloc::vec::Vec<super::ContractTraceElement>,
    }
    /// A simple account to account transfer occurred. This is the result of a
    /// successful Transfer transaction.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AccountTransfer {
        /// Amount that was transferred.
        #[prost(message, optional, tag = "1")]
        pub amount:   ::core::option::Option<super::Amount>,
        /// Receiver account.
        #[prost(message, optional, tag = "2")]
        pub receiver: ::core::option::Option<super::AccountAddress>,
        /// Memo.
        #[prost(message, optional, tag = "3")]
        pub memo:     ::core::option::Option<super::Memo>,
    }
    /// An account was deregistered as a baker. This is the result of a
    /// successful UpdateBakerStake transaction.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerStakeUpdated {
        /// If the stake was updated (that is, it changed and did not stay the
        /// same) then this is present, otherwise it is not present.
        #[prost(message, optional, tag = "1")]
        pub update: ::core::option::Option<super::BakerStakeUpdatedData>,
    }
    /// An encrypted amount was transferred. This is the result of a successful
    /// EncryptedAmountTransfer transaction.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct EncryptedAmountTransferred {
        #[prost(message, optional, tag = "1")]
        pub removed: ::core::option::Option<super::EncryptedAmountRemovedEvent>,
        #[prost(message, optional, tag = "2")]
        pub added:   ::core::option::Option<super::NewEncryptedAmountEvent>,
        #[prost(message, optional, tag = "3")]
        pub memo:    ::core::option::Option<super::Memo>,
    }
    /// An account transferred part of its encrypted balance to its public
    /// balance. This is the result of a successful TransferToPublic
    /// transaction.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TransferredToPublic {
        #[prost(message, optional, tag = "1")]
        pub removed: ::core::option::Option<super::EncryptedAmountRemovedEvent>,
        #[prost(message, optional, tag = "2")]
        pub amount:  ::core::option::Option<super::Amount>,
    }
    /// A transfer with schedule was performed. This is the result of a
    /// successful TransferWithSchedule transaction.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TransferredWithSchedule {
        /// Receiver account.
        #[prost(message, optional, tag = "1")]
        pub receiver: ::core::option::Option<super::AccountAddress>,
        /// The list of releases. Ordered by increasing timestamp.
        #[prost(message, repeated, tag = "2")]
        pub amount:   ::prost::alloc::vec::Vec<super::NewRelease>,
        /// Optional memo.
        #[prost(message, optional, tag = "3")]
        pub memo:     ::core::option::Option<super::Memo>,
    }
    /// Account's credentials were updated. This is the result of a
    /// successful UpdateCredentials transaction.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CredentialsUpdated {
        /// The credential ids that were added.
        #[prost(message, repeated, tag = "1")]
        pub new_cred_ids:     ::prost::alloc::vec::Vec<super::CredentialRegistrationId>,
        /// The credentials that were removed.
        #[prost(message, repeated, tag = "2")]
        pub removed_cred_ids: ::prost::alloc::vec::Vec<super::CredentialRegistrationId>,
        /// The (possibly) updated account threshold.
        #[prost(message, optional, tag = "3")]
        pub new_threshold:    ::core::option::Option<super::AccountThreshold>,
    }
    /// A baker was configured. The details of what happened are contained in
    /// the list of BakerEvents.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerConfigured {
        #[prost(message, repeated, tag = "1")]
        pub events: ::prost::alloc::vec::Vec<super::BakerEvent>,
    }
    /// An account configured delegation. The details of what happened are
    /// contained in the list of DelegationEvents.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DelegationConfigured {
        #[prost(message, repeated, tag = "1")]
        pub events: ::prost::alloc::vec::Vec<super::DelegationEvent>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Effect {
        /// No effects other than payment from this transaction.
        /// The rejection reason indicates why the transaction failed.
        #[prost(message, tag = "1")]
        None(None),
        /// A smart contract module with the attached reference was deployed.
        #[prost(message, tag = "2")]
        ModuleDeployed(super::ModuleRef),
        /// A smart contract was initialized.
        #[prost(message, tag = "3")]
        ContractInitialized(super::ContractInitializedEvent),
        /// A smart contract instance updated was issued.
        #[prost(message, tag = "4")]
        ContractUpdateIssued(ContractUpdateIssued),
        /// A simple account to account transfer occurred.
        #[prost(message, tag = "5")]
        AccountTransfer(AccountTransfer),
        /// A baker was added.
        #[prost(message, tag = "6")]
        BakerAdded(super::baker_event::BakerAdded),
        /// A baker was removed.
        #[prost(message, tag = "7")]
        BakerRemoved(super::BakerId),
        /// A baker's stake was updated.
        #[prost(message, tag = "8")]
        BakerStakeUpdated(BakerStakeUpdated),
        /// A baker's restake earnings setting was updated.
        #[prost(message, tag = "9")]
        BakerRestakeEarningsUpdated(super::baker_event::BakerRestakeEarningsUpdated),
        /// A baker's keys were updated.
        #[prost(message, tag = "10")]
        BakerKeysUpdated(super::BakerKeysEvent),
        /// An encrypted amount was transferred.
        #[prost(message, tag = "11")]
        EncryptedAmountTransferred(EncryptedAmountTransferred),
        /// An account transferred part of its public balance to its encrypted
        /// balance.
        #[prost(message, tag = "12")]
        TransferredToEncrypted(super::EncryptedSelfAmountAddedEvent),
        /// An account transferred part of its encrypted balance to its public
        /// balance.
        #[prost(message, tag = "13")]
        TransferredToPublic(TransferredToPublic),
        /// A transfer with a release schedule was made.
        #[prost(message, tag = "14")]
        TransferredWithSchedule(TransferredWithSchedule),
        /// Keys of a specific credential were updated.
        #[prost(message, tag = "15")]
        CredentialKeysUpdated(super::CredentialRegistrationId),
        /// Account credentials were updated.
        #[prost(message, tag = "16")]
        CredentialsUpdated(CredentialsUpdated),
        /// Some data was registered on the chain.
        #[prost(message, tag = "17")]
        DataRegistered(super::RegisteredData),
        /// A baker was configured. The details of what happened are contained
        /// in a list of BakerEvents.
        #[prost(message, tag = "18")]
        BakerConfigured(BakerConfigured),
        /// A delegator was configured. The details of what happened are
        /// contained in a list of DelegatorEvents.
        #[prost(message, tag = "19")]
        DelegationConfigured(DelegationConfigured),
    }
}
/// Election difficulty parameter.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ElectionDifficulty {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<AmountFraction>,
}
/// Parameters that determine timeouts in the consensus protocol used from
/// protocol version 6.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimeoutParameters {
    /// The base value for triggering a timeout
    #[prost(message, optional, tag = "1")]
    pub timeout_base:     ::core::option::Option<Duration>,
    /// Factor for increasing the timeout. Must be greater than 1.
    #[prost(message, optional, tag = "2")]
    pub timeout_increase: ::core::option::Option<Ratio>,
    /// Factor for decreasing the timeout. Must be between 0 and 1.
    #[prost(message, optional, tag = "3")]
    pub timeout_decrease: ::core::option::Option<Ratio>,
}
/// Finalization committee parameters used from protocol version 6
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizationCommitteeParameters {
    /// The minimum size of a finalization committee before
    /// `finalizer_relative_stake_threshold` takes effect.
    #[prost(uint32, tag = "1")]
    pub minimum_finalizers:                 u32,
    /// The maximum size of a finalization committee.
    #[prost(uint32, tag = "2")]
    pub maximum_finalizers:                 u32,
    /// The threshold for determining the stake required for being eligible the
    /// finalization committee. The amount is given by `total stake in pools
    /// * finalizer_relative_stake_threshold`
    #[prost(message, optional, tag = "3")]
    pub finalizer_relative_stake_threshold: ::core::option::Option<AmountFraction>,
}
/// Parameters for the consensus protocol used from protocol version 6.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusParametersV1 {
    /// Parameters controlling round timeouts.
    #[prost(message, optional, tag = "1")]
    pub timeout_parameters: ::core::option::Option<TimeoutParameters>,
    /// Minimum time interval between blocks.
    #[prost(message, optional, tag = "2")]
    pub min_block_time:     ::core::option::Option<Duration>,
    /// Maximum energy allowed per block.
    #[prost(message, optional, tag = "3")]
    pub block_energy_limit: ::core::option::Option<Energy>,
}
/// Represents an exchange rate.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExchangeRate {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<Ratio>,
}
/// Represents a ratio, i.e., 'numerator / denominator'.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ratio {
    /// The numerator.
    #[prost(uint64, tag = "1")]
    pub numerator:   u64,
    /// The denominator.
    #[prost(uint64, tag = "2")]
    pub denominator: u64,
}
/// A public key used for chain updates.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdatePublicKey {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// The threshold for how many UpdatePublicKeys are need to make a certain chain
/// update.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateKeysThreshold {
    /// Is ensured to be within between 1 and 2^16.
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// Index of a key in an authorizations update payload.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateKeysIndex {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// Represents root or level 1 keys.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HigherLevelKeys {
    /// The keys.
    #[prost(message, repeated, tag = "1")]
    pub keys:      ::prost::alloc::vec::Vec<UpdatePublicKey>,
    /// The number of keys needed to make a chain update.
    #[prost(message, optional, tag = "2")]
    pub threshold: ::core::option::Option<UpdateKeysThreshold>,
}
/// An access structure which specifies which UpdatePublicKeys in a
/// HigherLevelKeys that are allowed to make chain update of a specific type.
/// The threshold defines the minimum number of allowed keys needed to make the
/// actual update.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccessStructure {
    /// Unique indexes into the set of keys in AuthorizationV0.
    #[prost(message, repeated, tag = "1")]
    pub access_public_keys: ::prost::alloc::vec::Vec<UpdateKeysIndex>,
    /// Number of keys requred to authorize an update.
    #[prost(message, optional, tag = "2")]
    pub access_threshold:   ::core::option::Option<UpdateKeysThreshold>,
}
/// The set of keys authorized for chain updates, together with access
/// structures determining which keys are authorized for which update types.
/// This is the payload of an update to authorization.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthorizationsV0 {
    /// The set of keys authorized for chain updates.
    #[prost(message, repeated, tag = "1")]
    pub keys: ::prost::alloc::vec::Vec<UpdatePublicKey>,
    /// New emergency keys.
    #[prost(message, optional, tag = "2")]
    pub emergency: ::core::option::Option<AccessStructure>,
    /// New protocol update keys.
    #[prost(message, optional, tag = "3")]
    pub protocol: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the consensus parameters.
    /// Previously, this was the election difficulty.
    #[prost(message, optional, tag = "4")]
    pub parameter_consensus: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the euro per energy.
    #[prost(message, optional, tag = "5")]
    pub parameter_euro_per_energy: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the micro CCD per euro.
    #[prost(message, optional, tag = "6")]
    pub parameter_micro_ccd_per_euro: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the foundation account.
    #[prost(message, optional, tag = "7")]
    pub parameter_foundation_account: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the mint distribution.
    #[prost(message, optional, tag = "8")]
    pub parameter_mint_distribution: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the transaction fee distribution.
    #[prost(message, optional, tag = "9")]
    pub parameter_transaction_fee_distribution: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the gas rewards.
    #[prost(message, optional, tag = "10")]
    pub parameter_gas_rewards: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the pool parameters. For V0 this is only
    /// the baker stake threshold, for V1 there are more.
    #[prost(message, optional, tag = "11")]
    pub pool_parameters: ::core::option::Option<AccessStructure>,
    /// Access structure for adding new anonymity revokers.
    #[prost(message, optional, tag = "12")]
    pub add_anonymity_revoker: ::core::option::Option<AccessStructure>,
    /// Access structure for adding new identity providers.
    #[prost(message, optional, tag = "13")]
    pub add_identity_provider: ::core::option::Option<AccessStructure>,
}
/// The set of keys authorized for chain updates, together with access
/// structures determining which keys are authorized for which update types.
/// This is the payload of an update to authorization.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthorizationsV1 {
    #[prost(message, optional, tag = "1")]
    pub v0:                 ::core::option::Option<AuthorizationsV0>,
    /// Access structure for updating the cooldown periods related to baking and
    /// delegation.
    #[prost(message, optional, tag = "2")]
    pub parameter_cooldown: ::core::option::Option<AccessStructure>,
    /// Access structure for updating the length of the reward period.
    #[prost(message, optional, tag = "3")]
    pub parameter_time:     ::core::option::Option<AccessStructure>,
}
/// Description either of an anonymity revoker or identity provider.
/// Metadata that should be visible on the chain.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Description {
    /// The name.
    #[prost(string, tag = "1")]
    pub name:        ::prost::alloc::string::String,
    /// A link to more information about the anonymity revoker or identity
    /// provider.
    #[prost(string, tag = "2")]
    pub url:         ::prost::alloc::string::String,
    /// A free form description of the revoker or provider.
    #[prost(string, tag = "3")]
    pub description: ::prost::alloc::string::String,
}
/// Information on a single anonymity revoker help by the identity provider.
/// Typically an identity provider will hold more than one.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArInfo {
    /// Unique identifier of the anonymity revoker.
    #[prost(message, optional, tag = "1")]
    pub identity:    ::core::option::Option<ar_info::ArIdentity>,
    /// Description of the anonymity revoker.
    #[prost(message, optional, tag = "2")]
    pub description: ::core::option::Option<Description>,
    /// Elgamal encryption key of the anonymity revoker.
    #[prost(message, optional, tag = "3")]
    pub public_key:  ::core::option::Option<ar_info::ArPublicKey>,
}
/// Nested message and enum types in `ArInfo`.
pub mod ar_info {
    /// Identity of the anonymity revoker on the chain. This defines their
    /// evaluateion point for secret sharing, and thus it cannot be 0.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ArIdentity {
        #[prost(uint32, tag = "1")]
        pub value: u32,
    }
    /// Public key of an anonymity revoker.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ArPublicKey {
        #[prost(bytes = "vec", tag = "1")]
        pub value: ::prost::alloc::vec::Vec<u8>,
    }
}
/// A succinct identifier of an identity provider on the chain.
/// In credential deployments, and other interactions with the chain this is
/// used to identify which identity provider is meant.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpIdentity {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// Public information about an identity provider.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpInfo {
    /// Unique identifier of the identity provider.
    #[prost(message, optional, tag = "1")]
    pub identity:       ::core::option::Option<IpIdentity>,
    /// Description of the identity provider.
    #[prost(message, optional, tag = "2")]
    pub description:    ::core::option::Option<Description>,
    /// Pointcheval-Sanders public key of the identity provider.
    #[prost(message, optional, tag = "3")]
    pub verify_key:     ::core::option::Option<ip_info::IpVerifyKey>,
    /// Ed25519 public key of the identity provider.
    #[prost(message, optional, tag = "4")]
    pub cdi_verify_key: ::core::option::Option<ip_info::IpCdiVerifyKey>,
}
/// Nested message and enum types in `IpInfo`.
pub mod ip_info {
    /// Pointcheval-Sanders public key of the identity provider.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct IpVerifyKey {
        #[prost(bytes = "vec", tag = "1")]
        pub value: ::prost::alloc::vec::Vec<u8>,
    }
    /// Ed25519 public key of the identity provider.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct IpCdiVerifyKey {
        #[prost(bytes = "vec", tag = "1")]
        pub value: ::prost::alloc::vec::Vec<u8>,
    }
}
/// A duration in seconds.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DurationSeconds {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// Inclusive range of amount fractions.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InclusiveRangeAmountFraction {
    #[prost(message, optional, tag = "1")]
    pub min: ::core::option::Option<AmountFraction>,
    #[prost(message, optional, tag = "2")]
    pub max: ::core::option::Option<AmountFraction>,
}
/// Ranges of allowed commission values that pools may choose from.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommissionRanges {
    /// The range of allowed finalization commissions.
    #[prost(message, optional, tag = "1")]
    pub finalization: ::core::option::Option<InclusiveRangeAmountFraction>,
    /// The range of allowed baker commissions.
    #[prost(message, optional, tag = "2")]
    pub baking:       ::core::option::Option<InclusiveRangeAmountFraction>,
    /// The range of allowed transaction commissions.
    #[prost(message, optional, tag = "3")]
    pub transaction:  ::core::option::Option<InclusiveRangeAmountFraction>,
}
/// A bound on the relative share of the total staked capital that a baker can
/// have as its stake. This is required to be greater than 0.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CapitalBound {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<AmountFraction>,
}
/// A leverage factor.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LeverageFactor {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<Ratio>,
}
/// A chain epoch.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Epoch {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// Length of a reward period in epochs.
/// Must always be a strictly positive number.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RewardPeriodLength {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<Epoch>,
}
/// A minting rate of CCD.
/// The value is `mantissa * 10^(-exponent)`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MintRate {
    #[prost(uint32, tag = "1")]
    pub mantissa: u32,
    /// This will never exceed 255 and can thus be stored in a single byte.
    #[prost(uint32, tag = "2")]
    pub exponent: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CooldownParametersCpv1 {
    /// Number of seconds that pool owners must cooldown
    /// when reducing their equity capital or closing the pool.
    #[prost(message, optional, tag = "1")]
    pub pool_owner_cooldown: ::core::option::Option<DurationSeconds>,
    /// Number of seconds that a delegator must cooldown
    /// when reducing their delegated stake.
    #[prost(message, optional, tag = "2")]
    pub delegator_cooldown:  ::core::option::Option<DurationSeconds>,
}
/// Parameters related to staking pools.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolParametersCpv1 {
    /// Fraction of finalization rewards charged by the passive delegation.
    #[prost(message, optional, tag = "1")]
    pub passive_finalization_commission: ::core::option::Option<AmountFraction>,
    /// Fraction of baking rewards charged by the passive delegation.
    #[prost(message, optional, tag = "2")]
    pub passive_baking_commission:       ::core::option::Option<AmountFraction>,
    /// Fraction of transaction rewards charged by the L-pool.
    #[prost(message, optional, tag = "3")]
    pub passive_transaction_commission:  ::core::option::Option<AmountFraction>,
    /// Bounds on the commission rates that may be charged by bakers.
    #[prost(message, optional, tag = "4")]
    pub commission_bounds:               ::core::option::Option<CommissionRanges>,
    /// Minimum equity capital required for a new baker.
    #[prost(message, optional, tag = "5")]
    pub minimum_equity_capital:          ::core::option::Option<Amount>,
    /// Maximum fraction of the total staked capital of that a new baker can
    /// have.
    #[prost(message, optional, tag = "6")]
    pub capital_bound:                   ::core::option::Option<CapitalBound>,
    /// The maximum leverage that a baker can have as a ratio of total stake
    /// to equity capital.
    #[prost(message, optional, tag = "7")]
    pub leverage_bound:                  ::core::option::Option<LeverageFactor>,
}
/// The time parameters are introduced as of protocol version 4, and consist of
/// the reward period length and the mint rate per payday. These are coupled as
/// a change to either affects the overall rate of minting.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimeParametersCpv1 {
    #[prost(message, optional, tag = "1")]
    pub reward_period_length: ::core::option::Option<RewardPeriodLength>,
    #[prost(message, optional, tag = "2")]
    pub mint_per_payday:      ::core::option::Option<MintRate>,
}
/// Mint distribution payload as it looks in protocol version 4 and onward.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MintDistributionCpv1 {
    #[prost(message, optional, tag = "1")]
    pub baking_reward:       ::core::option::Option<AmountFraction>,
    #[prost(message, optional, tag = "2")]
    pub finalization_reward: ::core::option::Option<AmountFraction>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtocolUpdate {
    /// A brief message about the update.
    #[prost(string, tag = "1")]
    pub message: ::prost::alloc::string::String,
    /// A URL of a document describing the update.
    #[prost(string, tag = "2")]
    pub specification_url: ::prost::alloc::string::String,
    /// SHA256 hash of the specification document.
    #[prost(message, optional, tag = "3")]
    pub specification_hash: ::core::option::Option<Sha256Hash>,
    /// Auxiliary data whose interpretation is defined by the new specification.
    #[prost(bytes = "vec", tag = "4")]
    pub specification_auxiliary_data: ::prost::alloc::vec::Vec<u8>,
}
/// The minting rate and the distribution of newly-minted CCD among bakers,
/// finalizers, and the foundation account. It must be the case that
/// baking_reward + finalization_reward <= 1. The remaining amount is the
/// platform development charge.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MintDistributionCpv0 {
    /// Mint rate per slot.
    #[prost(message, optional, tag = "1")]
    pub mint_per_slot:       ::core::option::Option<MintRate>,
    /// The fraction of newly created CCD allocated to baker rewards.
    #[prost(message, optional, tag = "2")]
    pub baking_reward:       ::core::option::Option<AmountFraction>,
    /// The fraction of newly created CCD allocated to finalization rewards.
    #[prost(message, optional, tag = "3")]
    pub finalization_reward: ::core::option::Option<AmountFraction>,
}
/// Parameters determining the distribution of transaction fees.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionFeeDistribution {
    /// The fraction allocated to the baker.
    #[prost(message, optional, tag = "1")]
    pub baker:       ::core::option::Option<AmountFraction>,
    /// The fraction allocated to the GAS account.
    #[prost(message, optional, tag = "2")]
    pub gas_account: ::core::option::Option<AmountFraction>,
}
/// Distribution of gas rewards for chain parameters version 0 and 1.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GasRewards {
    /// The fraction paid to the baker.
    #[prost(message, optional, tag = "1")]
    pub baker:              ::core::option::Option<AmountFraction>,
    /// Fraction paid for including a finalization proof in a block.
    #[prost(message, optional, tag = "2")]
    pub finalization_proof: ::core::option::Option<AmountFraction>,
    /// Fraction paid for including each account creation transaction in a
    /// block.
    #[prost(message, optional, tag = "3")]
    pub account_creation:   ::core::option::Option<AmountFraction>,
    /// Fraction paid for including an update transaction in a block.
    #[prost(message, optional, tag = "4")]
    pub chain_update:       ::core::option::Option<AmountFraction>,
}
/// Distribution of gas rewards for chain parameters version 2.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GasRewardsCpv2 {
    /// The fraction paid to the baker.
    #[prost(message, optional, tag = "1")]
    pub baker:            ::core::option::Option<AmountFraction>,
    /// Fraction paid for including each account creation transaction in a
    /// block.
    #[prost(message, optional, tag = "3")]
    pub account_creation: ::core::option::Option<AmountFraction>,
    /// Fraction paid for including an update transaction in a block.
    #[prost(message, optional, tag = "4")]
    pub chain_update:     ::core::option::Option<AmountFraction>,
}
/// Minimum stake needed to become a baker. This only applies to protocol
/// version 1-3.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BakerStakeThreshold {
    /// Minimum threshold required for registering as a baker.
    #[prost(message, optional, tag = "1")]
    pub baker_stake_threshold: ::core::option::Option<Amount>,
}
/// Root updates are the highest kind of key updates. They can update every
/// other set of keys, even themselves. They can only be performed by Root level
/// keys.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RootUpdate {
    #[prost(oneof = "root_update::UpdateType", tags = "1, 2, 3, 4")]
    pub update_type: ::core::option::Option<root_update::UpdateType>,
}
/// Nested message and enum types in `RootUpdate`.
pub mod root_update {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum UpdateType {
        /// The root keys were updated.
        #[prost(message, tag = "1")]
        RootKeysUpdate(super::HigherLevelKeys),
        /// The level 1 keys were updated.
        #[prost(message, tag = "2")]
        Level1KeysUpdate(super::HigherLevelKeys),
        /// The level 2 keys were updated.
        #[prost(message, tag = "3")]
        Level2KeysUpdateV0(super::AuthorizationsV0),
        /// The level 2 keys were updated. This is similar to
        /// `level_2_keys_update_v0` except that a few more keys can be updated.
        #[prost(message, tag = "4")]
        Level2KeysUpdateV1(super::AuthorizationsV1),
    }
}
/// Level 1 updates are the intermediate update kind.
/// They can update themselves or level 2 keys. They can only be performed by
/// level 1 keys.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Level1Update {
    #[prost(oneof = "level1_update::UpdateType", tags = "1, 2, 3")]
    pub update_type: ::core::option::Option<level1_update::UpdateType>,
}
/// Nested message and enum types in `Level1Update`.
pub mod level1_update {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum UpdateType {
        /// The level 1 keys were updated.
        #[prost(message, tag = "1")]
        Level1KeysUpdate(super::HigherLevelKeys),
        /// The level 2 keys were updated.
        #[prost(message, tag = "2")]
        Level2KeysUpdateV0(super::AuthorizationsV0),
        /// The level 2 keys were updated. This is similar to
        /// `level_2_keys_update_v0` except that a few more keys can be updated.
        #[prost(message, tag = "3")]
        Level2KeysUpdateV1(super::AuthorizationsV1),
    }
}
/// The payload of a chain update.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdatePayload {
    #[prost(
        oneof = "update_payload::Payload",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22"
    )]
    pub payload: ::core::option::Option<update_payload::Payload>,
}
/// Nested message and enum types in `UpdatePayload`.
pub mod update_payload {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        /// The protocol version was updated.
        #[prost(message, tag = "1")]
        ProtocolUpdate(super::ProtocolUpdate),
        /// The election difficulty was updated.
        #[prost(message, tag = "2")]
        ElectionDifficultyUpdate(super::ElectionDifficulty),
        /// The euro per energy exchange rate was updated.
        #[prost(message, tag = "3")]
        EuroPerEnergyUpdate(super::ExchangeRate),
        /// The microCCD per euro exchange rate was updated.
        #[prost(message, tag = "4")]
        MicroCcdPerEuroUpdate(super::ExchangeRate),
        /// The foundation account address was updated.
        #[prost(message, tag = "5")]
        FoundationAccountUpdate(super::AccountAddress),
        /// The mint distribution was updated.
        #[prost(message, tag = "6")]
        MintDistributionUpdate(super::MintDistributionCpv0),
        /// The transaction fee distribtuion was updated.
        #[prost(message, tag = "7")]
        TransactionFeeDistributionUpdate(super::TransactionFeeDistribution),
        /// The gas rewards were updated.
        #[prost(message, tag = "8")]
        GasRewardsUpdate(super::GasRewards),
        /// The minimum amount of CCD needed to be come a baker was updated.
        #[prost(message, tag = "9")]
        BakerStakeThresholdUpdate(super::BakerStakeThreshold),
        /// The root keys were updated.
        #[prost(message, tag = "10")]
        RootUpdate(super::RootUpdate),
        /// The level 1 keys were updated.
        #[prost(message, tag = "11")]
        Level1Update(super::Level1Update),
        /// An anonymity revoker was added.
        #[prost(message, tag = "12")]
        AddAnonymityRevokerUpdate(super::ArInfo),
        /// An identity provider was added.
        #[prost(message, tag = "13")]
        AddIdentityProviderUpdate(super::IpInfo),
        /// The cooldown parameters were updated.
        #[prost(message, tag = "14")]
        CooldownParametersCpv1Update(super::CooldownParametersCpv1),
        /// The pool parameters were updated.
        #[prost(message, tag = "15")]
        PoolParametersCpv1Update(super::PoolParametersCpv1),
        /// The time parameters were updated.
        #[prost(message, tag = "16")]
        TimeParametersCpv1Update(super::TimeParametersCpv1),
        /// The mint distribution was updated.
        #[prost(message, tag = "17")]
        MintDistributionCpv1Update(super::MintDistributionCpv1),
        /// The gas rewards were updated (chain parameters version 2).
        #[prost(message, tag = "18")]
        GasRewardsCpv2Update(super::GasRewardsCpv2),
        /// The consensus timeouts were updated (chain parameters version 2).
        #[prost(message, tag = "19")]
        TimeoutParametersUpdate(super::TimeoutParameters),
        /// The minimum time between blocks was updated (chain parameters
        /// version 2).
        #[prost(message, tag = "20")]
        MinBlockTimeUpdate(super::Duration),
        /// The block energy limit was updated (chain parameters version 2).
        #[prost(message, tag = "21")]
        BlockEnergyLimitUpdate(super::Energy),
        /// Finalization committee parameters (chain parameters version 2).
        #[prost(message, tag = "22")]
        FinalizationCommitteeParametersUpdate(super::FinalizationCommitteeParameters),
    }
}
/// Details about an account transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountTransactionDetails {
    /// The cost of the transaction. Paid by the sender.
    #[prost(message, optional, tag = "1")]
    pub cost:    ::core::option::Option<Amount>,
    /// The sender of the transaction.
    #[prost(message, optional, tag = "2")]
    pub sender:  ::core::option::Option<AccountAddress>,
    /// The effects of the transaction.
    #[prost(message, optional, tag = "3")]
    pub effects: ::core::option::Option<AccountTransactionEffects>,
}
/// Details of an account creation. These transactions are free, and we only
/// ever get a response for them if the account is created, hence no failure
/// cases.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountCreationDetails {
    /// Whether this is an initial or normal account.
    #[prost(enumeration = "CredentialType", tag = "1")]
    pub credential_type: i32,
    /// Address of the newly created account.
    #[prost(message, optional, tag = "2")]
    pub address:         ::core::option::Option<AccountAddress>,
    /// Credential registration ID of the first credential.
    #[prost(message, optional, tag = "3")]
    pub reg_id:          ::core::option::Option<CredentialRegistrationId>,
}
/// Transaction time specified as seconds since unix epoch.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionTime {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// Details of an update instruction. These are free, and we only ever get a
/// response for them if the update is successfully enqueued, hence no failure
/// cases.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateDetails {
    /// The time at which the update will be effective.
    #[prost(message, optional, tag = "1")]
    pub effective_time: ::core::option::Option<TransactionTime>,
    /// The paylaod for the update.
    #[prost(message, optional, tag = "2")]
    pub payload:        ::core::option::Option<UpdatePayload>,
}
/// Summary of the outcome of a block item in structured form.
/// The summary determines which transaction type it was.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockItemSummary {
    /// Index of the transaction in the block where it is included.
    #[prost(message, optional, tag = "1")]
    pub index:       ::core::option::Option<block_item_summary::TransactionIndex>,
    /// The amount of NRG the transaction cost.
    #[prost(message, optional, tag = "2")]
    pub energy_cost: ::core::option::Option<Energy>,
    /// Hash of the transaction.
    #[prost(message, optional, tag = "3")]
    pub hash:        ::core::option::Option<TransactionHash>,
    /// Details that are specific to different transaction types.
    #[prost(oneof = "block_item_summary::Details", tags = "4, 5, 6")]
    pub details:     ::core::option::Option<block_item_summary::Details>,
}
/// Nested message and enum types in `BlockItemSummary`.
pub mod block_item_summary {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TransactionIndex {
        #[prost(uint64, tag = "1")]
        pub value: u64,
    }
    /// Details that are specific to different transaction types.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Details {
        /// Detailsa about an account transaction.
        #[prost(message, tag = "4")]
        AccountTransaction(super::AccountTransactionDetails),
        /// Details about an account creation.
        #[prost(message, tag = "5")]
        AccountCreation(super::AccountCreationDetails),
        /// Details about a chain update.
        #[prost(message, tag = "6")]
        Update(super::UpdateDetails),
    }
}
/// The number of chain restarts via a protocol update. An effected
/// protocol update instruction might not change the protocol version
/// specified in the previous field, but it always increments the genesis
/// index.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisIndex {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// The response for GetConsensusInfo.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusInfo {
    /// Hash of the current best block.
    #[prost(message, optional, tag = "1")]
    pub best_block:                  ::core::option::Option<BlockHash>,
    /// Hash of the (original) genesis block.
    #[prost(message, optional, tag = "2")]
    pub genesis_block:               ::core::option::Option<BlockHash>,
    /// Time of the (original) genesis block.
    #[prost(message, optional, tag = "3")]
    pub genesis_time:                ::core::option::Option<Timestamp>,
    /// (Current) slot duration in milliseconds.
    #[prost(message, optional, tag = "4")]
    pub slot_duration:               ::core::option::Option<Duration>,
    /// (Current) epoch duration in milliseconds.
    #[prost(message, optional, tag = "5")]
    pub epoch_duration:              ::core::option::Option<Duration>,
    /// Hash of the last finalized block.
    #[prost(message, optional, tag = "6")]
    pub last_finalized_block:        ::core::option::Option<BlockHash>,
    /// Absolute height of the best block.
    #[prost(message, optional, tag = "7")]
    pub best_block_height:           ::core::option::Option<AbsoluteBlockHeight>,
    /// Absolute height of the last finalized block.
    #[prost(message, optional, tag = "8")]
    pub last_finalized_block_height: ::core::option::Option<AbsoluteBlockHeight>,
    /// Total number of blocks received.
    #[prost(uint32, tag = "9")]
    pub blocks_received_count:       u32,
    /// The last time a block was received.
    #[prost(message, optional, tag = "10")]
    pub block_last_received_time:    ::core::option::Option<Timestamp>,
    /// Exponential moving average latency between a block's slot time and
    /// received time.
    #[prost(double, tag = "11")]
    pub block_receive_latency_ema:   f64,
    /// Standard deviation of exponential moving average latency between a
    /// block's slot time and received time.
    #[prost(double, tag = "12")]
    pub block_receive_latency_emsd:  f64,
    /// Exponential moving average time between receiving blocks.
    #[prost(double, optional, tag = "13")]
    pub block_receive_period_ema:    ::core::option::Option<f64>,
    /// Standard deviation of exponential moving average time between receiving
    /// blocks.
    #[prost(double, optional, tag = "14")]
    pub block_receive_period_emsd:   ::core::option::Option<f64>,
    /// Total number of blocks received and verified.
    #[prost(uint32, tag = "15")]
    pub blocks_verified_count:       u32,
    /// The last time a block was verified (added to the tree).
    #[prost(message, optional, tag = "16")]
    pub block_last_arrived_time:     ::core::option::Option<Timestamp>,
    /// Exponential moving average latency between a block's slot time and its
    /// arrival.
    #[prost(double, tag = "17")]
    pub block_arrive_latency_ema:    f64,
    /// Standard deviation of exponential moving average latency between a
    /// block's slot time and its arrival.
    #[prost(double, tag = "18")]
    pub block_arrive_latency_emsd:   f64,
    /// Exponential moving average time between block arrivals.
    #[prost(double, optional, tag = "19")]
    pub block_arrive_period_ema:     ::core::option::Option<f64>,
    /// Standard deviation of exponential moving average time between block
    /// arrivals.
    #[prost(double, optional, tag = "20")]
    pub block_arrive_period_emsd:    ::core::option::Option<f64>,
    /// Exponential moving average number of transactions per block.
    #[prost(double, tag = "21")]
    pub transactions_per_block_ema:  f64,
    /// Standard deviation of exponential moving average number of transactions
    /// per block.
    #[prost(double, tag = "22")]
    pub transactions_per_block_emsd: f64,
    /// Number of finalizations.
    #[prost(uint32, tag = "23")]
    pub finalization_count:          u32,
    /// Time of last verified finalization.
    #[prost(message, optional, tag = "24")]
    pub last_finalized_time:         ::core::option::Option<Timestamp>,
    /// Exponential moving average time between finalizations.
    #[prost(double, optional, tag = "25")]
    pub finalization_period_ema:     ::core::option::Option<f64>,
    /// Standard deviation of exponential moving average time between
    /// finalizations.
    #[prost(double, optional, tag = "26")]
    pub finalization_period_emsd:    ::core::option::Option<f64>,
    /// Currently active protocol version.
    #[prost(enumeration = "ProtocolVersion", tag = "27")]
    pub protocol_version:            i32,
    /// The number of chain restarts via a protocol update. A completed
    /// protocol update instruction might not change the protocol version
    /// specified in the previous field, but it always increments the genesis
    /// index.
    #[prost(message, optional, tag = "28")]
    pub genesis_index:               ::core::option::Option<GenesisIndex>,
    /// Block hash of the genesis block of current era, i.e., since the last
    /// protocol update. Initially this is equal to 'genesis_block'.
    #[prost(message, optional, tag = "29")]
    pub current_era_genesis_block:   ::core::option::Option<BlockHash>,
    /// Time when the current era started.
    #[prost(message, optional, tag = "30")]
    pub current_era_genesis_time:    ::core::option::Option<Timestamp>,
}
/// Information about an arrived block that is part of the streaming response.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArrivedBlockInfo {
    /// Hash of the block.
    #[prost(message, optional, tag = "1")]
    pub hash:   ::core::option::Option<BlockHash>,
    /// Absolute height of the block, height 0 is the genesis block.
    #[prost(message, optional, tag = "2")]
    pub height: ::core::option::Option<AbsoluteBlockHeight>,
}
/// The response for GetCryptographicParameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CryptographicParameters {
    /// A free-form string used to distinguish between different chains even if
    /// they share other parameters.
    #[prost(string, tag = "1")]
    pub genesis_string:          ::prost::alloc::string::String,
    /// Generators for the bulletproofs.
    /// It is a serialized list of 256 group elements in the G1 group of the
    /// BLS12-381 curve.
    #[prost(bytes = "vec", tag = "2")]
    pub bulletproof_generators:  ::prost::alloc::vec::Vec<u8>,
    /// A shared commitment key known to the chain and the account holder (and
    /// therefore it is public). The account holder uses this commitment key
    /// to generate commitments to values in the attribute list.
    /// It is a serialized pair of group elements  in the G1 group of the
    /// BLS12-381 curve.
    #[prost(bytes = "vec", tag = "3")]
    pub on_chain_commitment_key: ::prost::alloc::vec::Vec<u8>,
}
/// The response for GetBlockInfo.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockInfo {
    /// Hash of the block.
    #[prost(message, optional, tag = "1")]
    pub hash:                     ::core::option::Option<BlockHash>,
    /// Absolute height of the block, height 0 is the genesis block.
    #[prost(message, optional, tag = "2")]
    pub height:                   ::core::option::Option<AbsoluteBlockHeight>,
    /// The parent block hash. For a re-genesis block, this will be the terminal
    /// block of the previous chain. For the initial genesis block, this
    /// will be the hash of the block itself.
    #[prost(message, optional, tag = "3")]
    pub parent_block:             ::core::option::Option<BlockHash>,
    /// The last finalized block when this block was baked.
    #[prost(message, optional, tag = "4")]
    pub last_finalized_block:     ::core::option::Option<BlockHash>,
    /// The genesis index for this block. This counts the number of protocol
    /// updates that have preceded this block, and defines the era of the
    /// block.
    #[prost(message, optional, tag = "5")]
    pub genesis_index:            ::core::option::Option<GenesisIndex>,
    /// The height of this block relative to the (re)genesis block of its era.
    #[prost(message, optional, tag = "6")]
    pub era_block_height:         ::core::option::Option<BlockHeight>,
    /// The time the block was received.
    #[prost(message, optional, tag = "7")]
    pub receive_time:             ::core::option::Option<Timestamp>,
    /// The time the block was verified.
    #[prost(message, optional, tag = "8")]
    pub arrive_time:              ::core::option::Option<Timestamp>,
    /// The slot number in which the block was baked.
    #[prost(message, optional, tag = "9")]
    pub slot_number:              ::core::option::Option<Slot>,
    /// The time of the slot in which the block was baked.
    #[prost(message, optional, tag = "10")]
    pub slot_time:                ::core::option::Option<Timestamp>,
    /// The baker id of account baking this block. Not provided for a genesis
    /// block.
    #[prost(message, optional, tag = "11")]
    pub baker:                    ::core::option::Option<BakerId>,
    /// Whether the block is finalized.
    #[prost(bool, tag = "12")]
    pub finalized:                bool,
    /// The number of transactions in the block.
    #[prost(uint32, tag = "13")]
    pub transaction_count:        u32,
    /// The energy cost of the transactions in the block.
    #[prost(message, optional, tag = "14")]
    pub transactions_energy_cost: ::core::option::Option<Energy>,
    /// The total byte size of all transactions in the block.
    #[prost(uint32, tag = "15")]
    pub transactions_size:        u32,
    /// The hash of the block state after this block.
    #[prost(message, optional, tag = "16")]
    pub state_hash:               ::core::option::Option<StateHash>,
    /// Protocol version to which the block belongs.
    #[prost(enumeration = "ProtocolVersion", tag = "17")]
    pub protocol_version:         i32,
}
/// Request for GetPoolInfo.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolInfoRequest {
    /// Block in which to query the pool information.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHashInput>,
    /// The 'BakerId' of the pool owner.
    #[prost(message, optional, tag = "2")]
    pub baker:      ::core::option::Option<BakerId>,
}
/// A pending change to a baker pool.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolPendingChange {
    #[prost(oneof = "pool_pending_change::Change", tags = "1, 2")]
    pub change: ::core::option::Option<pool_pending_change::Change>,
}
/// Nested message and enum types in `PoolPendingChange`.
pub mod pool_pending_change {
    /// A reduction in baker equity capital is pending.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Reduce {
        /// New baker equity capital.
        #[prost(message, optional, tag = "1")]
        pub reduced_equity_capital: ::core::option::Option<super::Amount>,
        /// Timestamp when the change takes effect.
        #[prost(message, optional, tag = "2")]
        pub effective_time:         ::core::option::Option<super::Timestamp>,
    }
    /// Removal of the pool is pending.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Remove {
        /// Timestamp when the change takes effect.
        #[prost(message, optional, tag = "1")]
        pub effective_time: ::core::option::Option<super::Timestamp>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Change {
        #[prost(message, tag = "1")]
        Reduce(Reduce),
        #[prost(message, tag = "2")]
        Remove(Remove),
    }
}
/// Information about a baker pool in the current reward period.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolCurrentPaydayInfo {
    /// The number of blocks baked in the current reward period.
    #[prost(uint64, tag = "1")]
    pub blocks_baked:            u64,
    /// Whether the baker has contributed a finalization proof in the current
    /// reward period.
    #[prost(bool, tag = "2")]
    pub finalization_live:       bool,
    /// The transaction fees accruing to the pool in the current reward period.
    #[prost(message, optional, tag = "3")]
    pub transaction_fees_earned: ::core::option::Option<Amount>,
    /// The effective stake of the baker in the current reward period.
    #[prost(message, optional, tag = "4")]
    pub effective_stake:         ::core::option::Option<Amount>,
    /// The lottery power of the baker in the current reward period.
    #[prost(double, tag = "5")]
    pub lottery_power:           f64,
    /// The effective equity capital of the baker for the current reward period.
    #[prost(message, optional, tag = "6")]
    pub baker_equity_capital:    ::core::option::Option<Amount>,
    /// The effective delegated capital to the pool for the current reward
    /// period.
    #[prost(message, optional, tag = "7")]
    pub delegated_capital:       ::core::option::Option<Amount>,
}
/// Type for the response of GetPoolInfo.
/// Contains information about a given pool at the end of a given block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolInfoResponse {
    /// The 'BakerId' of the pool owner.
    #[prost(message, optional, tag = "1")]
    pub baker:                  ::core::option::Option<BakerId>,
    /// The account address of the pool owner.
    #[prost(message, optional, tag = "2")]
    pub address:                ::core::option::Option<AccountAddress>,
    /// The equity capital provided by the pool owner.
    #[prost(message, optional, tag = "3")]
    pub equity_capital:         ::core::option::Option<Amount>,
    /// The capital delegated to the pool by other accounts.
    #[prost(message, optional, tag = "4")]
    pub delegated_capital:      ::core::option::Option<Amount>,
    /// The maximum amount that may be delegated to the pool, accounting for
    /// leverage and stake limits.
    #[prost(message, optional, tag = "5")]
    pub delegated_capital_cap:  ::core::option::Option<Amount>,
    /// The pool info associated with the pool: open status, metadata URL and
    /// commission rates.
    #[prost(message, optional, tag = "6")]
    pub pool_info:              ::core::option::Option<BakerPoolInfo>,
    /// Any pending change to the equity carpital.
    #[prost(message, optional, tag = "7")]
    pub equity_pending_change:  ::core::option::Option<PoolPendingChange>,
    /// Information of the pool in the current reward period.
    #[prost(message, optional, tag = "8")]
    pub current_payday_info:    ::core::option::Option<PoolCurrentPaydayInfo>,
    /// Total capital staked across all pools, including passive delegation.
    #[prost(message, optional, tag = "9")]
    pub all_pool_total_capital: ::core::option::Option<Amount>,
}
/// Type for the response of GetPassiveDelegationInfo.
/// Contains information about passive delegators at the end of a given block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PassiveDelegationInfo {
    /// The total capital delegated passively.
    #[prost(message, optional, tag = "1")]
    pub delegated_capital: ::core::option::Option<Amount>,
    /// The passive delegation commission rates.
    #[prost(message, optional, tag = "2")]
    pub commission_rates: ::core::option::Option<CommissionRates>,
    /// The transaction fees accruing to the passive delegators in the current
    /// reward period.
    #[prost(message, optional, tag = "3")]
    pub current_payday_transaction_fees_earned: ::core::option::Option<Amount>,
    /// The effective delegated capital of passive delegators for the current
    /// reward period.
    #[prost(message, optional, tag = "4")]
    pub current_payday_delegated_capital: ::core::option::Option<Amount>,
    /// Total capital staked across all pools, including passive delegation.
    #[prost(message, optional, tag = "5")]
    pub all_pool_total_capital: ::core::option::Option<Amount>,
}
/// Request for GetBlocksAtHeight.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlocksAtHeightRequest {
    #[prost(oneof = "blocks_at_height_request::BlocksAtHeight", tags = "1, 2")]
    pub blocks_at_height: ::core::option::Option<blocks_at_height_request::BlocksAtHeight>,
}
/// Nested message and enum types in `BlocksAtHeightRequest`.
pub mod blocks_at_height_request {
    /// Request using an absolute block height.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Absolute {
        /// The absolute block height.
        #[prost(message, optional, tag = "1")]
        pub height: ::core::option::Option<super::AbsoluteBlockHeight>,
    }
    /// Request using a relative block height.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Relative {
        /// Genesis index to start from.
        #[prost(message, optional, tag = "1")]
        pub genesis_index: ::core::option::Option<super::GenesisIndex>,
        /// Height starting from the genesis block at the genesis index.
        #[prost(message, optional, tag = "2")]
        pub height:        ::core::option::Option<super::BlockHeight>,
        /// Whether to return results only from the specified genesis index
        /// (`true`), or allow results from more recent genesis indices
        /// as well (`false`).
        #[prost(bool, tag = "3")]
        pub restrict:      bool,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum BlocksAtHeight {
        #[prost(message, tag = "1")]
        Absolute(Absolute),
        #[prost(message, tag = "2")]
        Relative(Relative),
    }
}
/// Response for GetBlocksAtHeight.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlocksAtHeightResponse {
    /// Live blocks at the given height.
    #[prost(message, repeated, tag = "1")]
    pub blocks: ::prost::alloc::vec::Vec<BlockHash>,
}
/// Type for the response of GetTokenomicsInfo.
/// Contains information related to tokenomics at the end of a given block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TokenomicsInfo {
    #[prost(oneof = "tokenomics_info::Tokenomics", tags = "1, 2")]
    pub tokenomics: ::core::option::Option<tokenomics_info::Tokenomics>,
}
/// Nested message and enum types in `TokenomicsInfo`.
pub mod tokenomics_info {
    /// Version 0 tokenomics.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct V0 {
        /// The total CCD in existence.
        #[prost(message, optional, tag = "1")]
        pub total_amount:                ::core::option::Option<super::Amount>,
        /// The total CCD in encrypted balances.
        #[prost(message, optional, tag = "2")]
        pub total_encrypted_amount:      ::core::option::Option<super::Amount>,
        /// The amount in the baking reward account.
        #[prost(message, optional, tag = "3")]
        pub baking_reward_account:       ::core::option::Option<super::Amount>,
        /// The amount in the finalization reward account.
        #[prost(message, optional, tag = "4")]
        pub finalization_reward_account: ::core::option::Option<super::Amount>,
        /// The amount in the GAS account.
        #[prost(message, optional, tag = "5")]
        pub gas_account:                 ::core::option::Option<super::Amount>,
        /// The protocol version.
        #[prost(enumeration = "super::ProtocolVersion", tag = "6")]
        pub protocol_version:            i32,
    }
    /// Version 1 tokenomics.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct V1 {
        /// The total CCD in existence.
        #[prost(message, optional, tag = "1")]
        pub total_amount:                   ::core::option::Option<super::Amount>,
        /// The total CCD in encrypted balances.
        #[prost(message, optional, tag = "2")]
        pub total_encrypted_amount:         ::core::option::Option<super::Amount>,
        /// The amount in the baking reward account.
        #[prost(message, optional, tag = "3")]
        pub baking_reward_account:          ::core::option::Option<super::Amount>,
        /// The amount in the finalization reward account.
        #[prost(message, optional, tag = "4")]
        pub finalization_reward_account:    ::core::option::Option<super::Amount>,
        /// The amount in the GAS account.
        #[prost(message, optional, tag = "5")]
        pub gas_account:                    ::core::option::Option<super::Amount>,
        /// The transaction reward fraction accruing to the foundation (to be
        /// paid at next payday).
        #[prost(message, optional, tag = "6")]
        pub foundation_transaction_rewards: ::core::option::Option<super::Amount>,
        /// The time of the next payday.
        #[prost(message, optional, tag = "7")]
        pub next_payday_time:               ::core::option::Option<super::Timestamp>,
        /// The rate at which CCD will be minted (as a proportion of the total
        /// supply) at the next payday.
        #[prost(message, optional, tag = "8")]
        pub next_payday_mint_rate:          ::core::option::Option<super::MintRate>,
        /// The total capital put up as stake by bakers and delegators.
        #[prost(message, optional, tag = "9")]
        pub total_staked_capital:           ::core::option::Option<super::Amount>,
        /// The protocol version.
        #[prost(enumeration = "super::ProtocolVersion", tag = "10")]
        pub protocol_version:               i32,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Tokenomics {
        #[prost(message, tag = "1")]
        V0(V0),
        #[prost(message, tag = "2")]
        V1(V1),
    }
}
/// Request for InvokeInstance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvokeInstanceRequest {
    /// Block to invoke the contract. The invocation will be at the end of the
    /// given block.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHashInput>,
    /// Invoker of the contract. If this is not supplied then the contract will
    /// be invoked by an account with address 0, no credentials and
    /// sufficient amount of CCD to cover the transfer amount. If given, the
    /// relevant address (either account or contract) must exist in the
    /// blockstate.
    #[prost(message, optional, tag = "2")]
    pub invoker:    ::core::option::Option<Address>,
    /// Address of the contract instance to invoke.
    #[prost(message, optional, tag = "3")]
    pub instance:   ::core::option::Option<ContractAddress>,
    /// Amount to invoke the smart contract instance with.
    #[prost(message, optional, tag = "4")]
    pub amount:     ::core::option::Option<Amount>,
    /// The entrypoint of the smart contract instance to invoke.
    #[prost(message, optional, tag = "5")]
    pub entrypoint: ::core::option::Option<ReceiveName>,
    /// The parameter bytes to include in the invocation of the entrypoint.
    #[prost(message, optional, tag = "6")]
    pub parameter:  ::core::option::Option<Parameter>,
    /// And what amount of energy to allow for execution. This cannot exceed
    /// `100_000_000_000`, but in practice it should be much less. The maximum
    /// block energy is typically in the range of a few million.
    #[prost(message, optional, tag = "7")]
    pub energy:     ::core::option::Option<Energy>,
}
/// Response type for InvokeInstance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvokeInstanceResponse {
    #[prost(oneof = "invoke_instance_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<invoke_instance_response::Result>,
}
/// Nested message and enum types in `InvokeInstanceResponse`.
pub mod invoke_instance_response {
    /// Contract execution failed.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Failure {
        /// If invoking a V0 contract this is not provided, otherwise it is
        /// potentially return value produced by the call unless the call failed
        /// with out of energy or runtime error. If the V1 contract
        /// terminated with a logic error then the return value is
        /// present.
        #[prost(bytes = "vec", optional, tag = "1")]
        pub return_value: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        /// Energy used by the execution.
        #[prost(message, optional, tag = "2")]
        pub used_energy:  ::core::option::Option<super::Energy>,
        /// Contract execution failed for the given reason.
        #[prost(message, optional, tag = "3")]
        pub reason:       ::core::option::Option<super::RejectReason>,
    }
    /// Contract execution succeeded.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Success {
        /// If invoking a V0 contract this is absent. Otherwise it is the return
        /// value produced by the contract.
        #[prost(bytes = "vec", optional, tag = "1")]
        pub return_value: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        /// Energy used by the execution.
        #[prost(message, optional, tag = "2")]
        pub used_energy:  ::core::option::Option<super::Energy>,
        /// Effects produced by contract execution.
        #[prost(message, repeated, tag = "3")]
        pub effects:      ::prost::alloc::vec::Vec<super::ContractTraceElement>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Success(Success),
        #[prost(message, tag = "2")]
        Failure(Failure),
    }
}
/// Request for GetPoolDelegators and GetPoolDelegatorsRewardPeriod.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPoolDelegatorsRequest {
    /// Block in which to query the delegators.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHashInput>,
    /// The 'BakerId' of the pool owner.
    #[prost(message, optional, tag = "2")]
    pub baker:      ::core::option::Option<BakerId>,
}
/// Stream item for GetPoolDelegators and GetPassiveDelegators.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DelegatorInfo {
    /// The delegator account address.
    #[prost(message, optional, tag = "1")]
    pub account:        ::core::option::Option<AccountAddress>,
    /// The amount of stake currently staked to the pool.
    #[prost(message, optional, tag = "2")]
    pub stake:          ::core::option::Option<Amount>,
    /// Pending change to the current stake of the delegator.
    #[prost(message, optional, tag = "3")]
    pub pending_change: ::core::option::Option<StakePendingChange>,
}
/// Stream item for GetPoolDelegatorsRewardPeriod and
/// GetPassiveDelegatorsRewardPeriod.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DelegatorRewardPeriodInfo {
    /// The delegator account address.
    #[prost(message, optional, tag = "1")]
    pub account: ::core::option::Option<AccountAddress>,
    /// The amount of stake currently staked to the pool.
    #[prost(message, optional, tag = "2")]
    pub stake:   ::core::option::Option<Amount>,
}
/// Response type for GetBranches.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Branch {
    /// The hash of the block.
    #[prost(message, optional, tag = "1")]
    pub block_hash: ::core::option::Option<BlockHash>,
    /// Further blocks branching of this block.
    #[prost(message, repeated, tag = "2")]
    pub children:   ::prost::alloc::vec::Vec<Branch>,
}
/// The leadership election nonce is an unpredictable value updated once an
/// epoch to make sure that bakers cannot predict too far in the future when
/// they will win the right to bake blocks.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LeadershipElectionNonce {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Response type for GetElectionInfo.
/// Contains information related to baker election for a perticular block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ElectionInfo {
    /// Baking lottery election difficulty.
    #[prost(message, optional, tag = "1")]
    pub election_difficulty: ::core::option::Option<ElectionDifficulty>,
    /// Current leadership election nonce for the lottery.
    #[prost(message, optional, tag = "2")]
    pub election_nonce:      ::core::option::Option<LeadershipElectionNonce>,
    /// List of the currently eligible bakers.
    #[prost(message, repeated, tag = "3")]
    pub baker_election_info: ::prost::alloc::vec::Vec<election_info::Baker>,
}
/// Nested message and enum types in `ElectionInfo`.
pub mod election_info {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Baker {
        /// The ID of the baker.
        #[prost(message, optional, tag = "1")]
        pub baker:         ::core::option::Option<super::BakerId>,
        /// The account address of the baker.
        #[prost(message, optional, tag = "2")]
        pub account:       ::core::option::Option<super::AccountAddress>,
        /// The lottery power of the baker, rounded to the nearest representable
        /// "double".
        #[prost(double, tag = "3")]
        pub lottery_power: f64,
    }
}
/// A protocol generated event that is not directly caused by a transaction.
/// This includes minting new CCD, rewarding different bakers and delegators,
/// etc.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockSpecialEvent {
    #[prost(oneof = "block_special_event::Event", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
    pub event: ::core::option::Option<block_special_event::Event>,
}
/// Nested message and enum types in `BlockSpecialEvent`.
pub mod block_special_event {
    /// A representation of a mapping from an account address to an amount.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AccountAmounts {
        #[prost(message, repeated, tag = "1")]
        pub entries: ::prost::alloc::vec::Vec<account_amounts::Entry>,
    }
    /// Nested message and enum types in `AccountAmounts`.
    pub mod account_amounts {
        /// The entry for the map.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Entry {
            /// The key type
            #[prost(message, optional, tag = "1")]
            pub account: ::core::option::Option<super::super::AccountAddress>,
            /// The value type
            #[prost(message, optional, tag = "2")]
            pub amount:  ::core::option::Option<super::super::Amount>,
        }
    }
    /// Payment to each baker of a previous epoch, in proportion to the number
    /// of blocks they contributed.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakingRewards {
        /// The amount awarded to each baker.
        #[prost(message, optional, tag = "1")]
        pub baker_rewards: ::core::option::Option<AccountAmounts>,
        /// The remaining balance of the baker reward account.
        #[prost(message, optional, tag = "2")]
        pub remainder:     ::core::option::Option<super::Amount>,
    }
    /// Minting of new CCD.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Mint {
        /// The amount allocated to the banking reward account.
        #[prost(message, optional, tag = "1")]
        pub mint_baking_reward:               ::core::option::Option<super::Amount>,
        /// The amount allocated to the finalization reward account.
        #[prost(message, optional, tag = "2")]
        pub mint_finalization_reward:         ::core::option::Option<super::Amount>,
        /// The amount allocated as the platform development charge.
        #[prost(message, optional, tag = "3")]
        pub mint_platform_development_charge: ::core::option::Option<super::Amount>,
        /// The account to which the platform development charge is paid.
        #[prost(message, optional, tag = "4")]
        pub foundation_account:               ::core::option::Option<super::AccountAddress>,
    }
    /// Payment to each finalizer on inclusion of a finalization record in a
    /// block.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FinalizationRewards {
        /// The amount awarded to each finalizer.
        #[prost(message, optional, tag = "1")]
        pub finalization_rewards: ::core::option::Option<AccountAmounts>,
        /// The remaining balance of the finalization reward account.
        #[prost(message, optional, tag = "2")]
        pub remainder:            ::core::option::Option<super::Amount>,
    }
    /// Disbursement of fees from a block between the GAS account,
    /// the baker, and the foundation. It should always be that:
    ///
    /// ```transaction_fees + old_gas_account = new_gas_account + baker_reward +
    /// foundation_charge```
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BlockReward {
        /// The total fees paid for transactions in the block.
        #[prost(message, optional, tag = "1")]
        pub transaction_fees:   ::core::option::Option<super::Amount>,
        /// The old balance of the GAS account.
        #[prost(message, optional, tag = "2")]
        pub old_gas_account:    ::core::option::Option<super::Amount>,
        /// The new balance of the GAS account.
        #[prost(message, optional, tag = "3")]
        pub new_gas_account:    ::core::option::Option<super::Amount>,
        /// The amount awarded to the baker.
        #[prost(message, optional, tag = "4")]
        pub baker_reward:       ::core::option::Option<super::Amount>,
        /// The amount awarded to the foundation.
        #[prost(message, optional, tag = "5")]
        pub foundation_charge:  ::core::option::Option<super::Amount>,
        /// The baker of the block, who receives the award.
        #[prost(message, optional, tag = "6")]
        pub baker:              ::core::option::Option<super::AccountAddress>,
        /// The foundation account.
        #[prost(message, optional, tag = "7")]
        pub foundation_account: ::core::option::Option<super::AccountAddress>,
    }
    /// Foundation tax.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PaydayFoundationReward {
        /// The account that got rewarded.
        #[prost(message, optional, tag = "1")]
        pub foundation_account: ::core::option::Option<super::AccountAddress>,
        /// The transaction fee reward at payday to the account.
        #[prost(message, optional, tag = "2")]
        pub development_charge: ::core::option::Option<super::Amount>,
    }
    /// Reward payment to the given account.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PaydayAccountReward {
        /// The account that got rewarded.
        #[prost(message, optional, tag = "1")]
        pub account:             ::core::option::Option<super::AccountAddress>,
        /// The transaction fee reward at payday to the account.
        #[prost(message, optional, tag = "2")]
        pub transaction_fees:    ::core::option::Option<super::Amount>,
        /// The baking reward at payday to the account.
        #[prost(message, optional, tag = "3")]
        pub baker_reward:        ::core::option::Option<super::Amount>,
        /// The finalization reward at payday to the account.
        #[prost(message, optional, tag = "4")]
        pub finalization_reward: ::core::option::Option<super::Amount>,
    }
    /// Amounts accrued to accounts for each baked block.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BlockAccrueReward {
        /// The total fees paid for transactions in the block.
        #[prost(message, optional, tag = "1")]
        pub transaction_fees:  ::core::option::Option<super::Amount>,
        /// The old balance of the GAS account.
        #[prost(message, optional, tag = "2")]
        pub old_gas_account:   ::core::option::Option<super::Amount>,
        /// The new balance of the GAS account.
        #[prost(message, optional, tag = "3")]
        pub new_gas_account:   ::core::option::Option<super::Amount>,
        /// The amount awarded to the baker.
        #[prost(message, optional, tag = "4")]
        pub baker_reward:      ::core::option::Option<super::Amount>,
        /// The amount awarded to the passive delegators.
        #[prost(message, optional, tag = "5")]
        pub passive_reward:    ::core::option::Option<super::Amount>,
        /// The amount awarded to the foundation.
        #[prost(message, optional, tag = "6")]
        pub foundation_charge: ::core::option::Option<super::Amount>,
        /// The baker of the block, who will receive the award.
        #[prost(message, optional, tag = "7")]
        pub baker:             ::core::option::Option<super::BakerId>,
    }
    /// Payment distributed to a pool or passive delegators.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PaydayPoolReward {
        /// The pool owner (passive delegators when not present).
        #[prost(message, optional, tag = "1")]
        pub pool_owner:          ::core::option::Option<super::BakerId>,
        /// Accrued transaction fees for pool.
        #[prost(message, optional, tag = "2")]
        pub transaction_fees:    ::core::option::Option<super::Amount>,
        /// Accrued baking rewards for pool.
        #[prost(message, optional, tag = "3")]
        pub baker_reward:        ::core::option::Option<super::Amount>,
        /// Accrued finalization rewards for pool.
        #[prost(message, optional, tag = "4")]
        pub finalization_reward: ::core::option::Option<super::Amount>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Event {
        #[prost(message, tag = "1")]
        BakingRewards(BakingRewards),
        #[prost(message, tag = "2")]
        Mint(Mint),
        #[prost(message, tag = "3")]
        FinalizationRewards(FinalizationRewards),
        #[prost(message, tag = "4")]
        BlockReward(BlockReward),
        #[prost(message, tag = "5")]
        PaydayFoundationReward(PaydayFoundationReward),
        #[prost(message, tag = "6")]
        PaydayAccountReward(PaydayAccountReward),
        #[prost(message, tag = "7")]
        BlockAccrueReward(BlockAccrueReward),
        #[prost(message, tag = "8")]
        PaydayPoolReward(PaydayPoolReward),
    }
}
/// A pending update.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PendingUpdate {
    /// The effective time of the update.
    #[prost(message, optional, tag = "1")]
    pub effective_time: ::core::option::Option<TransactionTime>,
    /// The effect of the update.
    #[prost(
        oneof = "pending_update::Effect",
        tags = "2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, \
                24, 25"
    )]
    pub effect:         ::core::option::Option<pending_update::Effect>,
}
/// Nested message and enum types in `PendingUpdate`.
pub mod pending_update {
    /// The effect of the update.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Effect {
        /// Updates to the root keys.
        #[prost(message, tag = "2")]
        RootKeys(super::HigherLevelKeys),
        /// Updates to the level 1 keys.
        #[prost(message, tag = "3")]
        Level1Keys(super::HigherLevelKeys),
        /// Updates to the level 2 keys.
        #[prost(message, tag = "4")]
        Level2KeysCpv0(super::AuthorizationsV0),
        /// Updates to the level 2 keys.
        #[prost(message, tag = "5")]
        Level2KeysCpv1(super::AuthorizationsV1),
        /// Protocol updates.
        #[prost(message, tag = "6")]
        Protocol(super::ProtocolUpdate),
        /// Updates to the election difficulty parameter.
        #[prost(message, tag = "7")]
        ElectionDifficulty(super::ElectionDifficulty),
        /// Updates to the euro:energy exchange rate.
        #[prost(message, tag = "8")]
        EuroPerEnergy(super::ExchangeRate),
        /// Updates to the CCD:EUR exchange rate.
        #[prost(message, tag = "9")]
        MicroCcdPerEuro(super::ExchangeRate),
        /// Updates to the foundation account.
        #[prost(message, tag = "10")]
        FoundationAccount(super::AccountAddress),
        /// Updates to the mint distribution. Is only relevant prior to protocol
        /// version 4.
        #[prost(message, tag = "11")]
        MintDistributionCpv0(super::MintDistributionCpv0),
        /// The mint distribution was updated. Introduced in protocol version 4.
        #[prost(message, tag = "12")]
        MintDistributionCpv1(super::MintDistributionCpv1),
        /// Updates to the transaction fee distribution.
        #[prost(message, tag = "13")]
        TransactionFeeDistribution(super::TransactionFeeDistribution),
        /// Updates to the GAS rewards.
        #[prost(message, tag = "14")]
        GasRewards(super::GasRewards),
        /// Updates baker stake threshold. Is only relevant prior to protocol
        /// version 4.
        #[prost(message, tag = "15")]
        PoolParametersCpv0(super::BakerStakeThreshold),
        /// Updates pool parameters. Introduced in protocol version 4.
        #[prost(message, tag = "16")]
        PoolParametersCpv1(super::PoolParametersCpv1),
        /// Adds a new anonymity revoker.
        #[prost(message, tag = "17")]
        AddAnonymityRevoker(super::ArInfo),
        /// Adds a new identity provider.
        #[prost(message, tag = "18")]
        AddIdentityProvider(super::IpInfo),
        /// Updates to cooldown parameters for chain parameters version 1
        /// introduced in protocol version 4.
        #[prost(message, tag = "19")]
        CooldownParameters(super::CooldownParametersCpv1),
        /// Updates to time parameters for chain parameters version 1 introduced
        /// in protocol version 4.
        #[prost(message, tag = "20")]
        TimeParameters(super::TimeParametersCpv1),
        /// Updates to the GAS rewards effective from protocol version 6 (chain
        /// parameters version 2).
        #[prost(message, tag = "21")]
        GasRewardsCpv2(super::GasRewardsCpv2),
        /// Updates to the consensus timeouts for chain parameters version 2.
        #[prost(message, tag = "22")]
        TimeoutParameters(super::TimeoutParameters),
        /// Updates to the the minimum time between blocks for chain parameters
        /// version 2.
        #[prost(message, tag = "23")]
        MinBlockTime(super::Duration),
        /// Updates to the block energy limit for chain parameters version 2.
        #[prost(message, tag = "24")]
        BlockEnergyLimit(super::Energy),
        /// Updates to the finalization committee for for chain parameters
        /// version 2.
        #[prost(message, tag = "25")]
        FinalizationCommitteeParameters(super::FinalizationCommitteeParameters),
    }
}
/// The response for `GetNextUpdateSequenceNumbers`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NextUpdateSequenceNumbers {
    /// Updates to the root keys.
    #[prost(message, optional, tag = "1")]
    pub root_keys: ::core::option::Option<SequenceNumber>,
    /// Updates to the level 1 keys.
    #[prost(message, optional, tag = "2")]
    pub level1_keys: ::core::option::Option<SequenceNumber>,
    /// Updates to the level 2 keys.
    #[prost(message, optional, tag = "3")]
    pub level2_keys: ::core::option::Option<SequenceNumber>,
    /// Protocol updates.
    #[prost(message, optional, tag = "4")]
    pub protocol: ::core::option::Option<SequenceNumber>,
    /// Updates to the election difficulty parameter.
    #[prost(message, optional, tag = "5")]
    pub election_difficulty: ::core::option::Option<SequenceNumber>,
    /// Updates to the euro:energy exchange rate.
    #[prost(message, optional, tag = "6")]
    pub euro_per_energy: ::core::option::Option<SequenceNumber>,
    /// Updates to the CCD:EUR exchange rate.
    #[prost(message, optional, tag = "7")]
    pub micro_ccd_per_euro: ::core::option::Option<SequenceNumber>,
    /// Updates to the foundation account.
    #[prost(message, optional, tag = "8")]
    pub foundation_account: ::core::option::Option<SequenceNumber>,
    /// Updates to the mint distribution.
    #[prost(message, optional, tag = "9")]
    pub mint_distribution: ::core::option::Option<SequenceNumber>,
    /// Updates to the transaction fee distribution.
    #[prost(message, optional, tag = "10")]
    pub transaction_fee_distribution: ::core::option::Option<SequenceNumber>,
    /// Updates to the GAS rewards.
    #[prost(message, optional, tag = "11")]
    pub gas_rewards: ::core::option::Option<SequenceNumber>,
    /// Updates pool parameters.
    #[prost(message, optional, tag = "12")]
    pub pool_parameters: ::core::option::Option<SequenceNumber>,
    /// Adds a new anonymity revoker.
    #[prost(message, optional, tag = "13")]
    pub add_anonymity_revoker: ::core::option::Option<SequenceNumber>,
    /// Adds a new identity provider.
    #[prost(message, optional, tag = "14")]
    pub add_identity_provider: ::core::option::Option<SequenceNumber>,
    /// Updates to cooldown parameters for chain parameters version 1 introduced
    /// in protocol version 4.
    #[prost(message, optional, tag = "15")]
    pub cooldown_parameters: ::core::option::Option<SequenceNumber>,
    /// Updates to time parameters for chain parameters version 1 introduced in
    /// protocol version 4.
    #[prost(message, optional, tag = "16")]
    pub time_parameters: ::core::option::Option<SequenceNumber>,
    /// Updates to the timeout parameters
    #[prost(message, optional, tag = "17")]
    pub timeout_parameters: ::core::option::Option<SequenceNumber>,
    /// Updates to the the minimum time between blocks for chain parameters
    /// version 2.
    #[prost(message, optional, tag = "18")]
    pub min_block_time: ::core::option::Option<SequenceNumber>,
    /// Updates to the block energy limit for chain parameters version 2.
    #[prost(message, optional, tag = "19")]
    pub block_energy_limit: ::core::option::Option<SequenceNumber>,
    /// Updates to the finalization committee parameters
    #[prost(message, optional, tag = "20")]
    pub finalization_committee_parameters: ::core::option::Option<SequenceNumber>,
}
/// A request to send a new block item to the chain.
/// An IP address
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpAddress {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
/// A port
/// Valid port numbers are expected thus
/// the value is expected to be in the range (0..u16::MAX).
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Port {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// A socket address consisting of
/// an IP + port.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpSocketAddress {
    #[prost(message, optional, tag = "1")]
    pub ip:   ::core::option::Option<IpAddress>,
    #[prost(message, optional, tag = "2")]
    pub port: ::core::option::Option<Port>,
}
/// A peer id
/// An identifier that the peer wants to be
/// be recoknized by.
/// The underlying value is simply a u64.
/// Note. There is no authenticity of the peer id and
/// as such it is only used for logging purposes.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeerId {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
/// A banned peer
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BannedPeer {
    /// The IP address of the banned peer.
    #[prost(message, optional, tag = "1")]
    pub ip_address: ::core::option::Option<IpAddress>,
}
/// The banned peers given by
/// their IP addresses.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BannedPeers {
    #[prost(message, repeated, tag = "1")]
    pub peers: ::prost::alloc::vec::Vec<BannedPeer>,
}
/// A peer to ban specified by its IP.
/// Note. This will ban all peers located behind the
/// specified IP even though they are using different ports.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeerToBan {
    #[prost(message, optional, tag = "1")]
    pub ip_address: ::core::option::Option<IpAddress>,
}
/// Request to enable dumping of network packages.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DumpRequest {
    /// Which file to dump the packages into.
    /// Requires a valid path.
    #[prost(string, tag = "1")]
    pub file: ::prost::alloc::string::String,
    /// Whether the node should dump raw packages.
    #[prost(bool, tag = "2")]
    pub raw:  bool,
}
/// Peers and their associated network related statistics
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeersInfo {
    #[prost(message, repeated, tag = "1")]
    pub peers: ::prost::alloc::vec::Vec<peers_info::Peer>,
}
/// Nested message and enum types in `PeersInfo`.
pub mod peers_info {
    /// A peer that the node is connected to.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Peer {
        /// The identifier of the peer that it
        /// wishes to be identified by.
        #[prost(message, optional, tag = "1")]
        pub peer_id:        ::core::option::Option<super::PeerId>,
        /// The port of the peer.
        #[prost(message, optional, tag = "2")]
        pub socket_address: ::core::option::Option<super::IpSocketAddress>,
        /// Network related statistics for the peer.
        #[prost(message, optional, tag = "3")]
        pub network_stats:  ::core::option::Option<peer::NetworkStats>,
        /// consensus related information of the peer.
        #[prost(oneof = "peer::ConsensusInfo", tags = "4, 5")]
        pub consensus_info: ::core::option::Option<peer::ConsensusInfo>,
    }
    /// Nested message and enum types in `Peer`.
    pub mod peer {
        /// Network statistics for the peer
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct NetworkStats {
            /// The number of messages sent to the peer.
            /// Packets are blocks, transactions, catchup messages, finalization
            /// records and network messages such as pings and peer
            /// requests.
            #[prost(uint64, tag = "2")]
            pub packets_sent:     u64,
            /// The number of messages received from the peer.
            /// Packets are blocks, transactions, catchup messages, finalization
            /// records and network messages such as pings and peer
            /// requests.
            #[prost(uint64, tag = "3")]
            pub packets_received: u64,
            /// The connection latency (i.e., ping time) in milliseconds.
            #[prost(uint64, tag = "4")]
            pub latency:          u64,
        }
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum CatchupStatus {
            /// The peer does not have any data unknown to us. If we receive a
            /// message from the peer that refers to unknown data
            /// (e.g., an unknown block) the peer is marked as pending.
            Uptodate   = 0,
            /// The peer might have some data unknown to us. A peer can be in
            /// this state either because it sent a message that
            /// refers to data unknown to us, or before we have established a
            /// baseline with it. The latter happens during node
            /// startup, as well as upon protocol updates until the initial
            /// catchup handshake completes.
            Pending    = 1,
            /// The node is currently catching up by requesting blocks from this
            /// peer. There will be at most one peer with this
            /// status at a time. Once the peer has responded to the
            /// request, its status will be changed to:
            /// - 'UPTODATE' if the peer has no more data that is not known to
            ///   us
            /// - 'PENDING' if the node has more data that is unknown to us.
            Catchingup = 2,
        }
        impl CatchupStatus {
            /// String value of the enum field names used in the ProtoBuf
            /// definition.
            ///
            /// The values are not transformed in any way and thus are
            /// considered stable (if the ProtoBuf definition does
            /// not change) and safe for programmatic use.
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    CatchupStatus::Uptodate => "UPTODATE",
                    CatchupStatus::Pending => "PENDING",
                    CatchupStatus::Catchingup => "CATCHINGUP",
                }
            }

            /// Creates an enum from field names used in the ProtoBuf
            /// definition.
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "UPTODATE" => Some(Self::Uptodate),
                    "PENDING" => Some(Self::Pending),
                    "CATCHINGUP" => Some(Self::Catchingup),
                    _ => None,
                }
            }
        }
        /// consensus related information of the peer.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum ConsensusInfo {
            /// The peer is of type `Bootstrapper` is not participating in
            /// consensus and thus has no catchup status.
            #[prost(message, tag = "4")]
            Bootstrapper(super::super::Empty),
            /// The peer is a regular node and have
            /// an associated catchup status.
            #[prost(enumeration = "CatchupStatus", tag = "5")]
            NodeCatchupStatus(i32),
        }
    }
}
/// Node info response
/// Contains various information of the
/// enquired node.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeInfo {
    /// The version of the node.
    #[prost(string, tag = "1")]
    pub peer_version: ::prost::alloc::string::String,
    /// local time of the node.
    #[prost(message, optional, tag = "3")]
    pub local_time:   ::core::option::Option<Timestamp>,
    /// Number of milliseconds that the node
    /// has been alive.
    #[prost(message, optional, tag = "4")]
    pub peer_uptime:  ::core::option::Option<Duration>,
    /// Information related to the p2p protocol.
    #[prost(message, optional, tag = "5")]
    pub network_info: ::core::option::Option<node_info::NetworkInfo>,
    /// Details of the node.
    #[prost(oneof = "node_info::Details", tags = "6, 7")]
    pub details:      ::core::option::Option<node_info::Details>,
}
/// Nested message and enum types in `NodeInfo`.
pub mod node_info {
    /// Network related information of the node.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NetworkInfo {
        /// The node id.
        #[prost(message, optional, tag = "1")]
        pub node_id:             ::core::option::Option<super::PeerId>,
        /// Total number of packets sent by the node.
        #[prost(uint64, tag = "2")]
        pub peer_total_sent:     u64,
        /// Total number of packets received by the node.
        #[prost(uint64, tag = "3")]
        pub peer_total_received: u64,
        /// Average outbound throughput in bytes per second.
        #[prost(uint64, tag = "4")]
        pub avg_bps_in:          u64,
        /// Average inbound throughput in bytes per second.
        #[prost(uint64, tag = "5")]
        pub avg_bps_out:         u64,
    }
    /// Consensus info for a node configured with baker keys.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BakerConsensusInfo {
        #[prost(message, optional, tag = "1")]
        pub baker_id: ::core::option::Option<super::BakerId>,
        /// Status of the baker configured node.
        #[prost(oneof = "baker_consensus_info::Status", tags = "2, 3, 4")]
        pub status:   ::core::option::Option<baker_consensus_info::Status>,
    }
    /// Nested message and enum types in `BakerConsensusInfo`.
    pub mod baker_consensus_info {
        /// Tagging message type for a node that
        /// is configured with baker keys and active in
        /// the current baking committee
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ActiveBakerCommitteeInfo {}
        /// Tagging message type for a node that
        /// is configured with baker keys and active in
        /// the current finalizer committee (and also baking committee).
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ActiveFinalizerCommitteeInfo {}
        /// The committee information of a node configured with
        /// baker keys but somehow the node is _not_ part of the
        /// current baking committee.
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum PassiveCommitteeInfo {
            /// The node is started with baker keys however it is currently not
            /// in the baking committee. The node is __not__ baking.
            NotInCommittee    = 0,
            /// The account is registered as a baker but not in the current
            /// `Epoch`. The node is __not__ baking.
            AddedButNotActiveInCommittee = 1,
            /// The node has configured invalid baker keys i.e., the configured
            /// baker keys do not match the current keys on the baker account.
            /// The node is __not__ baking.
            AddedButWrongKeys = 2,
        }
        impl PassiveCommitteeInfo {
            /// String value of the enum field names used in the ProtoBuf
            /// definition.
            ///
            /// The values are not transformed in any way and thus are
            /// considered stable (if the ProtoBuf definition does
            /// not change) and safe for programmatic use.
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    PassiveCommitteeInfo::NotInCommittee => "NOT_IN_COMMITTEE",
                    PassiveCommitteeInfo::AddedButNotActiveInCommittee => {
                        "ADDED_BUT_NOT_ACTIVE_IN_COMMITTEE"
                    }
                    PassiveCommitteeInfo::AddedButWrongKeys => "ADDED_BUT_WRONG_KEYS",
                }
            }

            /// Creates an enum from field names used in the ProtoBuf
            /// definition.
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "NOT_IN_COMMITTEE" => Some(Self::NotInCommittee),
                    "ADDED_BUT_NOT_ACTIVE_IN_COMMITTEE" => Some(Self::AddedButNotActiveInCommittee),
                    "ADDED_BUT_WRONG_KEYS" => Some(Self::AddedButWrongKeys),
                    _ => None,
                }
            }
        }
        /// Status of the baker configured node.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Status {
            /// The node is currently not baking.
            #[prost(enumeration = "PassiveCommitteeInfo", tag = "2")]
            PassiveCommitteeInfo(i32),
            /// The node is configured with baker keys and
            /// is member of the baking committee.
            #[prost(message, tag = "3")]
            ActiveBakerCommitteeInfo(ActiveBakerCommitteeInfo),
            /// The node is configured with baker keys and
            /// is member of the baking and finalization committees.
            #[prost(message, tag = "4")]
            ActiveFinalizerCommitteeInfo(ActiveFinalizerCommitteeInfo),
        }
    }
    /// The node is a regular node.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Node {
        #[prost(oneof = "node::ConsensusStatus", tags = "1, 2, 3")]
        pub consensus_status: ::core::option::Option<node::ConsensusStatus>,
    }
    /// Nested message and enum types in `Node`.
    pub mod node {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum ConsensusStatus {
            /// The node is not running consensus.
            /// This is the case only when the node is
            /// not supporting the protocol on the chain.
            /// The node does not process blocks.
            #[prost(message, tag = "1")]
            NotRunning(super::super::Empty),
            /// Consensus info for a node that is
            /// not configured with baker keys.
            /// The node is only processing blocks and
            /// relaying blocks and transactions and responding to
            /// catchup messages.
            #[prost(message, tag = "2")]
            Passive(super::super::Empty),
            /// The node is configured with baker credentials and consensus is
            /// running.
            #[prost(message, tag = "3")]
            Active(super::BakerConsensusInfo),
        }
    }
    /// Details of the node.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Details {
        /// The node is a bootstrapper and is not running consensus.
        #[prost(message, tag = "6")]
        Bootstrapper(super::Empty),
        /// The node is a regular node and runs the consensus
        /// protocol.
        #[prost(message, tag = "7")]
        Node(Node),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendBlockItemRequest {
    #[prost(oneof = "send_block_item_request::BlockItem", tags = "1, 2, 3")]
    pub block_item: ::core::option::Option<send_block_item_request::BlockItem>,
}
/// Nested message and enum types in `SendBlockItemRequest`.
pub mod send_block_item_request {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum BlockItem {
        /// Account transactions are messages which are signed and paid for by
        /// an account.
        #[prost(message, tag = "1")]
        AccountTransaction(super::AccountTransaction),
        /// Credential deployments create new accounts. They are not paid for
        /// directly by the sender. Instead, bakers are rewarded by the protocol
        /// for including them.
        #[prost(message, tag = "2")]
        CredentialDeployment(super::CredentialDeployment),
        /// Update instructions are messages which can update the chain
        /// parameters. Including which keys are allowed to make future
        /// update instructions.
        #[prost(message, tag = "3")]
        UpdateInstruction(super::UpdateInstruction),
    }
}
/// Credential deployments create new accounts. They are not paid for
/// directly by the sender. Instead, bakers are rewarded by the protocol for
/// including them.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialDeployment {
    #[prost(message, optional, tag = "1")]
    pub message_expiry: ::core::option::Option<TransactionTime>,
    /// The credential to be added.
    #[prost(oneof = "credential_deployment::Payload", tags = "2")]
    pub payload:        ::core::option::Option<credential_deployment::Payload>,
}
/// Nested message and enum types in `CredentialDeployment`.
pub mod credential_deployment {
    /// The credential to be added.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        /// A raw payload, which is just the encoded payload.
        /// A typed variant might be added in the future.
        #[prost(bytes, tag = "2")]
        RawPayload(::prost::alloc::vec::Vec<u8>),
    }
}
/// A single signature. Used when sending block items to a node with
/// `SendBlockItem`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signature {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Wrapper for a map from indexes to signatures.
/// Needed because protobuf doesn't allow nested maps directly.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureMap {
    #[prost(map = "uint32, message", tag = "1")]
    pub signatures: ::std::collections::HashMap<u32, Signature>,
}
/// Wrapper for a map from indexes to signatures.
/// Needed because protobuf doesn't allow nested maps directly.
/// The keys in the SignatureMap must not exceed 2^8.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountSignatureMap {
    #[prost(map = "uint32, message", tag = "1")]
    pub signatures: ::std::collections::HashMap<u32, Signature>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountTransactionSignature {
    /// A map from `CredentialIndex` to `SignatureMap`s.
    /// The type `CredentialIndex` is not used directly, as messages cannot be
    /// keys in maps. The map cannot contain more than 2^8 signatures.
    #[prost(map = "uint32, message", tag = "1")]
    pub signatures: ::std::collections::HashMap<u32, AccountSignatureMap>,
}
/// Header of an account transaction that contains basic data to check whether
/// the sender and the transaction are valid. The header is shared by all
/// transaction types.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountTransactionHeader {
    /// Sender of the transaction.
    #[prost(message, optional, tag = "1")]
    pub sender:          ::core::option::Option<AccountAddress>,
    /// Sequence number of the transaction.
    #[prost(message, optional, tag = "2")]
    pub sequence_number: ::core::option::Option<SequenceNumber>,
    /// Maximum amount of nergy the transaction can take to execute.
    #[prost(message, optional, tag = "3")]
    pub energy_amount:   ::core::option::Option<Energy>,
    /// Latest time the transaction can included in a block.
    #[prost(message, optional, tag = "5")]
    pub expiry:          ::core::option::Option<TransactionTime>,
}
/// Data required to initialize a new contract instance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitContractPayload {
    /// Amount of CCD to send to the instance.
    #[prost(message, optional, tag = "1")]
    pub amount:     ::core::option::Option<Amount>,
    /// Reference to the module from which the instance will be created.
    #[prost(message, optional, tag = "2")]
    pub module_ref: ::core::option::Option<ModuleRef>,
    /// Name of the contract to initialize. This is expected to be in the format
    /// `init_name`.
    #[prost(message, optional, tag = "3")]
    pub init_name:  ::core::option::Option<InitName>,
    /// Parameter to call the `init` of the contract with.
    #[prost(message, optional, tag = "4")]
    pub parameter:  ::core::option::Option<Parameter>,
}
/// Data required to update a contract instance.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateContractPayload {
    /// Amount of CCD to send to the instance.
    #[prost(message, optional, tag = "1")]
    pub amount:       ::core::option::Option<Amount>,
    /// Address of the instance to update.
    #[prost(message, optional, tag = "2")]
    pub address:      ::core::option::Option<ContractAddress>,
    /// Name of the entrypoint to call to update the instance.
    /// This is expected to be in the format `contractName.entrypointName`.
    #[prost(message, optional, tag = "3")]
    pub receive_name: ::core::option::Option<ReceiveName>,
    /// Parameter to pass to the entrypoint.
    #[prost(message, optional, tag = "4")]
    pub parameter:    ::core::option::Option<Parameter>,
}
/// Payload of a transfer between two accounts.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferPayload {
    /// Amount of CCD to send.
    #[prost(message, optional, tag = "1")]
    pub amount:   ::core::option::Option<Amount>,
    /// Receiver address.
    #[prost(message, optional, tag = "2")]
    pub receiver: ::core::option::Option<AccountAddress>,
}
/// Payload of a transfer between two accounts with a memo.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferWithMemoPayload {
    /// Amount of CCD to send.
    #[prost(message, optional, tag = "1")]
    pub amount:   ::core::option::Option<Amount>,
    /// Receiver address.
    #[prost(message, optional, tag = "2")]
    pub receiver: ::core::option::Option<AccountAddress>,
    /// Memo to include with the transfer.
    #[prost(message, optional, tag = "3")]
    pub memo:     ::core::option::Option<Memo>,
}
/// The payload for an account transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountTransactionPayload {
    #[prost(
        oneof = "account_transaction_payload::Payload",
        tags = "1, 2, 3, 4, 5, 6, 7"
    )]
    pub payload: ::core::option::Option<account_transaction_payload::Payload>,
}
/// Nested message and enum types in `AccountTransactionPayload`.
pub mod account_transaction_payload {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        /// A pre-serialized payload in the binary serialization format defined
        /// by the protocol.
        #[prost(bytes, tag = "1")]
        RawPayload(::prost::alloc::vec::Vec<u8>),
        /// A transfer between two accounts. With an optional memo.
        #[prost(message, tag = "2")]
        DeployModule(super::VersionedModuleSource),
        #[prost(message, tag = "3")]
        InitContract(super::InitContractPayload),
        #[prost(message, tag = "4")]
        UpdateContract(super::UpdateContractPayload),
        #[prost(message, tag = "5")]
        Transfer(super::TransferPayload),
        #[prost(message, tag = "6")]
        TransferWithMemo(super::TransferWithMemoPayload),
        #[prost(message, tag = "7")]
        RegisterData(super::RegisteredData),
    }
}
/// An unsigned account transaction. This is used with the
/// `GetTransactionSignHash` endpoint to obtain the message to sign.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreAccountTransaction {
    #[prost(message, optional, tag = "1")]
    pub header:  ::core::option::Option<AccountTransactionHeader>,
    #[prost(message, optional, tag = "2")]
    pub payload: ::core::option::Option<AccountTransactionPayload>,
}
/// Account transactions are messages which are signed and paid for by the
/// sender account.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountTransaction {
    #[prost(message, optional, tag = "1")]
    pub signature: ::core::option::Option<AccountTransactionSignature>,
    #[prost(message, optional, tag = "2")]
    pub header:    ::core::option::Option<AccountTransactionHeader>,
    #[prost(message, optional, tag = "3")]
    pub payload:   ::core::option::Option<AccountTransactionPayload>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateInstructionSignature {
    /// A map from `UpdateKeysIndex` to `Signature`.
    /// The type `UpdateKeysIndex`is not used directly, as messages cannot be
    /// keys in maps.
    #[prost(map = "uint32, message", tag = "1")]
    pub signatures: ::std::collections::HashMap<u32, Signature>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateInstructionHeader {
    #[prost(message, optional, tag = "1")]
    pub sequence_number: ::core::option::Option<UpdateSequenceNumber>,
    #[prost(message, optional, tag = "2")]
    pub effective_time:  ::core::option::Option<TransactionTime>,
    #[prost(message, optional, tag = "3")]
    pub timeout:         ::core::option::Option<TransactionTime>,
}
/// The payload for an UpdateInstruction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateInstructionPayload {
    #[prost(oneof = "update_instruction_payload::Payload", tags = "3")]
    pub payload: ::core::option::Option<update_instruction_payload::Payload>,
}
/// Nested message and enum types in `UpdateInstructionPayload`.
pub mod update_instruction_payload {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        /// A raw payload encoded according to the format defined by the
        /// protocol.
        #[prost(bytes, tag = "3")]
        RawPayload(::prost::alloc::vec::Vec<u8>),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateInstruction {
    /// A map from `UpdateKeysIndex` to `Signature`. Keys must not exceed 2^16.
    #[prost(message, optional, tag = "1")]
    pub signatures: ::core::option::Option<SignatureMap>,
    #[prost(message, optional, tag = "2")]
    pub header:     ::core::option::Option<UpdateInstructionHeader>,
    #[prost(message, optional, tag = "3")]
    pub payload:    ::core::option::Option<UpdateInstructionPayload>,
}
/// Signature on an account transaction is defined to be the signature on the
/// hash of the `PreAccountTransaction`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountTransactionSignHash {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// The number of credential deployments allowed in a block. This in effect
/// determines the number of accounts that can be created in a block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialsPerBlockLimit {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}
/// Updatable chain parameters that apply to protocol versions 1-3.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainParametersV0 {
    /// Election difficulty for consensus lottery.
    #[prost(message, optional, tag = "1")]
    pub election_difficulty:          ::core::option::Option<ElectionDifficulty>,
    /// Euro per energy exchange rate.
    #[prost(message, optional, tag = "2")]
    pub euro_per_energy:              ::core::option::Option<ExchangeRate>,
    /// Micro CCD per euro exchange rate.
    #[prost(message, optional, tag = "3")]
    pub micro_ccd_per_euro:           ::core::option::Option<ExchangeRate>,
    /// Extra number of epochs before reduction in stake, or baker
    /// deregistration is completed.
    #[prost(message, optional, tag = "4")]
    pub baker_cooldown_epochs:        ::core::option::Option<Epoch>,
    /// The limit for the number of account creations in a block.
    #[prost(message, optional, tag = "5")]
    pub account_creation_limit:       ::core::option::Option<CredentialsPerBlockLimit>,
    /// Current mint distribution
    #[prost(message, optional, tag = "6")]
    pub mint_distribution:            ::core::option::Option<MintDistributionCpv0>,
    /// Current transaction fee distribution.
    #[prost(message, optional, tag = "7")]
    pub transaction_fee_distribution: ::core::option::Option<TransactionFeeDistribution>,
    /// Current gas reward parameters.
    #[prost(message, optional, tag = "8")]
    pub gas_rewards:                  ::core::option::Option<GasRewards>,
    /// The foundation account.
    #[prost(message, optional, tag = "9")]
    pub foundation_account:           ::core::option::Option<AccountAddress>,
    /// Minimum threshold for becoming a baker.
    #[prost(message, optional, tag = "10")]
    pub minimum_threshold_for_baking: ::core::option::Option<Amount>,
    /// Keys allowed to do root updates.
    #[prost(message, optional, tag = "11")]
    pub root_keys:                    ::core::option::Option<HigherLevelKeys>,
    /// Keys allowed to do level1 updates;
    #[prost(message, optional, tag = "12")]
    pub level1_keys:                  ::core::option::Option<HigherLevelKeys>,
    /// Keys allowed to do parameter updates.
    #[prost(message, optional, tag = "13")]
    pub level2_keys:                  ::core::option::Option<AuthorizationsV0>,
}
/// Updatable chain parameters that apply to protocol versions 4-5.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainParametersV1 {
    /// Election difficulty for consensus lottery.
    #[prost(message, optional, tag = "1")]
    pub election_difficulty:          ::core::option::Option<ElectionDifficulty>,
    /// Euro per energy exchange rate.
    #[prost(message, optional, tag = "2")]
    pub euro_per_energy:              ::core::option::Option<ExchangeRate>,
    /// Micro CCD per euro exchange rate.
    #[prost(message, optional, tag = "3")]
    pub micro_ccd_per_euro:           ::core::option::Option<ExchangeRate>,
    /// Extra number of epochs before reduction in stake, or baker
    /// deregistration is completed.
    #[prost(message, optional, tag = "4")]
    pub cooldown_parameters:          ::core::option::Option<CooldownParametersCpv1>,
    /// Current time parameters.
    /// The time parameters indicates the mint rate and the
    /// reward period length, i.e. the time between paydays.
    #[prost(message, optional, tag = "5")]
    pub time_parameters:              ::core::option::Option<TimeParametersCpv1>,
    /// The limit for the number of account creations in a block.
    #[prost(message, optional, tag = "6")]
    pub account_creation_limit:       ::core::option::Option<CredentialsPerBlockLimit>,
    /// Current mint distribution
    #[prost(message, optional, tag = "7")]
    pub mint_distribution:            ::core::option::Option<MintDistributionCpv1>,
    /// Current transaction fee distribution.
    #[prost(message, optional, tag = "8")]
    pub transaction_fee_distribution: ::core::option::Option<TransactionFeeDistribution>,
    /// Current gas reward parameters.
    #[prost(message, optional, tag = "9")]
    pub gas_rewards:                  ::core::option::Option<GasRewards>,
    /// The foundation account.
    #[prost(message, optional, tag = "10")]
    pub foundation_account:           ::core::option::Option<AccountAddress>,
    /// Parameters governing baking pools and their commissions.
    #[prost(message, optional, tag = "11")]
    pub pool_parameters:              ::core::option::Option<PoolParametersCpv1>,
    /// Keys allowed to do root updates.
    #[prost(message, optional, tag = "12")]
    pub root_keys:                    ::core::option::Option<HigherLevelKeys>,
    /// Keys allowed to do level1 updates;
    #[prost(message, optional, tag = "13")]
    pub level1_keys:                  ::core::option::Option<HigherLevelKeys>,
    /// Keys allowed to do parameter updates.
    #[prost(message, optional, tag = "14")]
    pub level2_keys:                  ::core::option::Option<AuthorizationsV1>,
}
/// Updatable chain parameters that apply to protocol versions 6.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainParametersV2 {
    /// Consensus parameters.
    #[prost(message, optional, tag = "1")]
    pub consensus_parameters: ::core::option::Option<ConsensusParametersV1>,
    /// Euro per energy exchange rate.
    #[prost(message, optional, tag = "2")]
    pub euro_per_energy: ::core::option::Option<ExchangeRate>,
    /// Micro CCD per euro exchange rate.
    #[prost(message, optional, tag = "3")]
    pub micro_ccd_per_euro: ::core::option::Option<ExchangeRate>,
    /// Extra number of epochs before reduction in stake, or baker
    /// deregistration is completed.
    #[prost(message, optional, tag = "4")]
    pub cooldown_parameters: ::core::option::Option<CooldownParametersCpv1>,
    /// Current time parameters.
    /// The time parameters indicates the mint rate and the
    /// reward period length, i.e. the time between paydays.
    #[prost(message, optional, tag = "5")]
    pub time_parameters: ::core::option::Option<TimeParametersCpv1>,
    /// The limit for the number of account creations in a block.
    #[prost(message, optional, tag = "6")]
    pub account_creation_limit: ::core::option::Option<CredentialsPerBlockLimit>,
    /// Current mint distribution
    #[prost(message, optional, tag = "7")]
    pub mint_distribution: ::core::option::Option<MintDistributionCpv1>,
    /// Current transaction fee distribution.
    #[prost(message, optional, tag = "8")]
    pub transaction_fee_distribution: ::core::option::Option<TransactionFeeDistribution>,
    /// Current gas reward parameters.
    #[prost(message, optional, tag = "9")]
    pub gas_rewards: ::core::option::Option<GasRewardsCpv2>,
    /// The foundation account.
    #[prost(message, optional, tag = "10")]
    pub foundation_account: ::core::option::Option<AccountAddress>,
    /// Parameters governing baking pools and their commissions.
    #[prost(message, optional, tag = "11")]
    pub pool_parameters: ::core::option::Option<PoolParametersCpv1>,
    /// Keys allowed to do root updates.
    #[prost(message, optional, tag = "12")]
    pub root_keys: ::core::option::Option<HigherLevelKeys>,
    /// Keys allowed to do level1 updates;
    #[prost(message, optional, tag = "13")]
    pub level1_keys: ::core::option::Option<HigherLevelKeys>,
    /// Keys allowed to do parameter updates.
    #[prost(message, optional, tag = "14")]
    pub level2_keys: ::core::option::Option<AuthorizationsV1>,
    /// Finalization committee parameters
    #[prost(message, optional, tag = "15")]
    pub finalization_committee_parameters: ::core::option::Option<FinalizationCommitteeParameters>,
}
/// Chain parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainParameters {
    #[prost(oneof = "chain_parameters::Parameters", tags = "1, 2, 3")]
    pub parameters: ::core::option::Option<chain_parameters::Parameters>,
}
/// Nested message and enum types in `ChainParameters`.
pub mod chain_parameters {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Parameters {
        /// Chain parameters that apply when the block is a protocol version 1-3
        /// block.
        #[prost(message, tag = "1")]
        V0(super::ChainParametersV0),
        /// Chain parameters that apply when the block is a protocol version 4-5
        /// block.
        #[prost(message, tag = "2")]
        V1(super::ChainParametersV1),
        /// Chain parameters that apply when the block is a protocol version 6-
        /// block.
        #[prost(message, tag = "3")]
        V2(super::ChainParametersV2),
    }
}
/// Details about a finalizer for the finalization round.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizationSummaryParty {
    /// Baker ID. Every finalizer is in particular a baker.
    #[prost(message, optional, tag = "1")]
    pub baker:  ::core::option::Option<BakerId>,
    /// The weight of the finalizer in the committee. This is an "absolute"
    /// weight.
    #[prost(uint64, tag = "2")]
    pub weight: u64,
    /// Whether the finalizer's signature was present on the particular
    /// finalization record.
    #[prost(bool, tag = "3")]
    pub signed: bool,
}
/// Index of the finalization round. This increases on each successfully
/// completed finalization.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizationIndex {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// Details about a finalization record included in a block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizationSummary {
    /// Block that was finalized by the finalization record.
    #[prost(message, optional, tag = "1")]
    pub block:      ::core::option::Option<BlockHash>,
    /// Index of the finalization round that finalized the block.
    #[prost(message, optional, tag = "2")]
    pub index:      ::core::option::Option<FinalizationIndex>,
    /// Finalization delay used for the finalization round.
    #[prost(message, optional, tag = "3")]
    pub delay:      ::core::option::Option<BlockHeight>,
    /// List of all finalizers with information about whether they signed the
    /// finalization record or not.
    #[prost(message, repeated, tag = "4")]
    pub finalizers: ::prost::alloc::vec::Vec<FinalizationSummaryParty>,
}
/// Finalization summary that may or may not be part of the block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockFinalizationSummary {
    #[prost(oneof = "block_finalization_summary::Summary", tags = "1, 2")]
    pub summary: ::core::option::Option<block_finalization_summary::Summary>,
}
/// Nested message and enum types in `BlockFinalizationSummary`.
pub mod block_finalization_summary {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Summary {
        /// There is no finalization data in the block.
        #[prost(message, tag = "1")]
        None(super::Empty),
        /// There is a single finalization record with the block.
        #[prost(message, tag = "2")]
        Record(super::FinalizationSummary),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockItem {
    /// The hash of the block item that identifies it to the chain.
    #[prost(message, optional, tag = "1")]
    pub hash:       ::core::option::Option<TransactionHash>,
    #[prost(oneof = "block_item::BlockItem", tags = "2, 3, 4")]
    pub block_item: ::core::option::Option<block_item::BlockItem>,
}
/// Nested message and enum types in `BlockItem`.
pub mod block_item {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum BlockItem {
        /// Account transactions are messages which are signed and paid for by
        /// an account.
        #[prost(message, tag = "2")]
        AccountTransaction(super::AccountTransaction),
        /// Credential deployments create new accounts. They are not paid for
        /// directly by the sender. Instead, bakers are rewarded by the protocol
        /// for including them.
        #[prost(message, tag = "3")]
        CredentialDeployment(super::CredentialDeployment),
        /// Update instructions are messages which can update the chain
        /// parameters. Including which keys are allowed to make future
        /// update instructions.
        #[prost(message, tag = "4")]
        UpdateInstruction(super::UpdateInstruction),
    }
}
/// Information about how open the pool is to new delegators.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum OpenStatus {
    OpenForAll   = 0,
    ClosedForNew = 1,
    ClosedForAll = 2,
}
impl OpenStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic
    /// use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            OpenStatus::OpenForAll => "OPEN_STATUS_OPEN_FOR_ALL",
            OpenStatus::ClosedForNew => "OPEN_STATUS_CLOSED_FOR_NEW",
            OpenStatus::ClosedForAll => "OPEN_STATUS_CLOSED_FOR_ALL",
        }
    }

    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "OPEN_STATUS_OPEN_FOR_ALL" => Some(Self::OpenForAll),
            "OPEN_STATUS_CLOSED_FOR_NEW" => Some(Self::ClosedForNew),
            "OPEN_STATUS_CLOSED_FOR_ALL" => Some(Self::ClosedForAll),
            _ => None,
        }
    }
}
/// Version of smart contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ContractVersion {
    V0 = 0,
    V1 = 1,
}
impl ContractVersion {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic
    /// use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ContractVersion::V0 => "V0",
            ContractVersion::V1 => "V1",
        }
    }

    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "V0" => Some(Self::V0),
            "V1" => Some(Self::V1),
            _ => None,
        }
    }
}
/// The type of a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CredentialType {
    /// An initial credential created by the identity provider.
    Initial = 0,
    /// A normal credential type created by the account.
    Normal  = 1,
}
impl CredentialType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic
    /// use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CredentialType::Initial => "CREDENTIAL_TYPE_INITIAL",
            CredentialType::Normal => "CREDENTIAL_TYPE_NORMAL",
        }
    }

    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CREDENTIAL_TYPE_INITIAL" => Some(Self::Initial),
            "CREDENTIAL_TYPE_NORMAL" => Some(Self::Normal),
            _ => None,
        }
    }
}
/// The type of chain update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum UpdateType {
    UpdateProtocol       = 0,
    UpdateElectionDifficulty = 1,
    UpdateEuroPerEnergy  = 2,
    UpdateMicroCcdPerEuro = 3,
    UpdateFoundationAccount = 4,
    UpdateMintDistribution = 5,
    UpdateTransactionFeeDistribution = 6,
    UpdateGasRewards     = 7,
    UpdatePoolParameters = 8,
    AddAnonymityRevoker  = 9,
    AddIdentityProvider  = 10,
    UpdateRootKeys       = 11,
    UpdateLevel1Keys     = 12,
    UpdateLevel2Keys     = 13,
    UpdateCooldownParameters = 14,
    UpdateTimeParameters = 15,
    UpdateTimeoutParameters = 16,
    UpdateMinBlockTime   = 17,
    UpdateBlockEnergyLimit = 18,
    UpdateFinalizationCommitteeParameters = 19,
}
impl UpdateType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic
    /// use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            UpdateType::UpdateProtocol => "UPDATE_PROTOCOL",
            UpdateType::UpdateElectionDifficulty => "UPDATE_ELECTION_DIFFICULTY",
            UpdateType::UpdateEuroPerEnergy => "UPDATE_EURO_PER_ENERGY",
            UpdateType::UpdateMicroCcdPerEuro => "UPDATE_MICRO_CCD_PER_EURO",
            UpdateType::UpdateFoundationAccount => "UPDATE_FOUNDATION_ACCOUNT",
            UpdateType::UpdateMintDistribution => "UPDATE_MINT_DISTRIBUTION",
            UpdateType::UpdateTransactionFeeDistribution => "UPDATE_TRANSACTION_FEE_DISTRIBUTION",
            UpdateType::UpdateGasRewards => "UPDATE_GAS_REWARDS",
            UpdateType::UpdatePoolParameters => "UPDATE_POOL_PARAMETERS",
            UpdateType::AddAnonymityRevoker => "ADD_ANONYMITY_REVOKER",
            UpdateType::AddIdentityProvider => "ADD_IDENTITY_PROVIDER",
            UpdateType::UpdateRootKeys => "UPDATE_ROOT_KEYS",
            UpdateType::UpdateLevel1Keys => "UPDATE_LEVEL1_KEYS",
            UpdateType::UpdateLevel2Keys => "UPDATE_LEVEL2_KEYS",
            UpdateType::UpdateCooldownParameters => "UPDATE_COOLDOWN_PARAMETERS",
            UpdateType::UpdateTimeParameters => "UPDATE_TIME_PARAMETERS",
            UpdateType::UpdateTimeoutParameters => "UPDATE_TIMEOUT_PARAMETERS",
            UpdateType::UpdateMinBlockTime => "UPDATE_MIN_BLOCK_TIME",
            UpdateType::UpdateBlockEnergyLimit => "UPDATE_BLOCK_ENERGY_LIMIT",
            UpdateType::UpdateFinalizationCommitteeParameters => {
                "UPDATE_FINALIZATION_COMMITTEE_PARAMETERS"
            }
        }
    }

    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UPDATE_PROTOCOL" => Some(Self::UpdateProtocol),
            "UPDATE_ELECTION_DIFFICULTY" => Some(Self::UpdateElectionDifficulty),
            "UPDATE_EURO_PER_ENERGY" => Some(Self::UpdateEuroPerEnergy),
            "UPDATE_MICRO_CCD_PER_EURO" => Some(Self::UpdateMicroCcdPerEuro),
            "UPDATE_FOUNDATION_ACCOUNT" => Some(Self::UpdateFoundationAccount),
            "UPDATE_MINT_DISTRIBUTION" => Some(Self::UpdateMintDistribution),
            "UPDATE_TRANSACTION_FEE_DISTRIBUTION" => Some(Self::UpdateTransactionFeeDistribution),
            "UPDATE_GAS_REWARDS" => Some(Self::UpdateGasRewards),
            "UPDATE_POOL_PARAMETERS" => Some(Self::UpdatePoolParameters),
            "ADD_ANONYMITY_REVOKER" => Some(Self::AddAnonymityRevoker),
            "ADD_IDENTITY_PROVIDER" => Some(Self::AddIdentityProvider),
            "UPDATE_ROOT_KEYS" => Some(Self::UpdateRootKeys),
            "UPDATE_LEVEL1_KEYS" => Some(Self::UpdateLevel1Keys),
            "UPDATE_LEVEL2_KEYS" => Some(Self::UpdateLevel2Keys),
            "UPDATE_COOLDOWN_PARAMETERS" => Some(Self::UpdateCooldownParameters),
            "UPDATE_TIME_PARAMETERS" => Some(Self::UpdateTimeParameters),
            "UPDATE_TIMEOUT_PARAMETERS" => Some(Self::UpdateTimeoutParameters),
            "UPDATE_MIN_BLOCK_TIME" => Some(Self::UpdateMinBlockTime),
            "UPDATE_BLOCK_ENERGY_LIMIT" => Some(Self::UpdateBlockEnergyLimit),
            "UPDATE_FINALIZATION_COMMITTEE_PARAMETERS" => {
                Some(Self::UpdateFinalizationCommitteeParameters)
            }
            _ => None,
        }
    }
}
/// The type of transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum TransactionType {
    DeployModule         = 0,
    InitContract         = 1,
    Update               = 2,
    Transfer             = 3,
    AddBaker             = 4,
    RemoveBaker          = 5,
    UpdateBakerStake     = 6,
    UpdateBakerRestakeEarnings = 7,
    UpdateBakerKeys      = 8,
    UpdateCredentialKeys = 9,
    EncryptedAmountTransfer = 10,
    TransferToEncrypted  = 11,
    TransferToPublic     = 12,
    TransferWithSchedule = 13,
    UpdateCredentials    = 14,
    RegisterData         = 15,
    TransferWithMemo     = 16,
    EncryptedAmountTransferWithMemo = 17,
    TransferWithScheduleAndMemo = 18,
    ConfigureBaker       = 19,
    ConfigureDelegation  = 20,
}
impl TransactionType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic
    /// use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            TransactionType::DeployModule => "DEPLOY_MODULE",
            TransactionType::InitContract => "INIT_CONTRACT",
            TransactionType::Update => "UPDATE",
            TransactionType::Transfer => "TRANSFER",
            TransactionType::AddBaker => "ADD_BAKER",
            TransactionType::RemoveBaker => "REMOVE_BAKER",
            TransactionType::UpdateBakerStake => "UPDATE_BAKER_STAKE",
            TransactionType::UpdateBakerRestakeEarnings => "UPDATE_BAKER_RESTAKE_EARNINGS",
            TransactionType::UpdateBakerKeys => "UPDATE_BAKER_KEYS",
            TransactionType::UpdateCredentialKeys => "UPDATE_CREDENTIAL_KEYS",
            TransactionType::EncryptedAmountTransfer => "ENCRYPTED_AMOUNT_TRANSFER",
            TransactionType::TransferToEncrypted => "TRANSFER_TO_ENCRYPTED",
            TransactionType::TransferToPublic => "TRANSFER_TO_PUBLIC",
            TransactionType::TransferWithSchedule => "TRANSFER_WITH_SCHEDULE",
            TransactionType::UpdateCredentials => "UPDATE_CREDENTIALS",
            TransactionType::RegisterData => "REGISTER_DATA",
            TransactionType::TransferWithMemo => "TRANSFER_WITH_MEMO",
            TransactionType::EncryptedAmountTransferWithMemo => {
                "ENCRYPTED_AMOUNT_TRANSFER_WITH_MEMO"
            }
            TransactionType::TransferWithScheduleAndMemo => "TRANSFER_WITH_SCHEDULE_AND_MEMO",
            TransactionType::ConfigureBaker => "CONFIGURE_BAKER",
            TransactionType::ConfigureDelegation => "CONFIGURE_DELEGATION",
        }
    }

    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "DEPLOY_MODULE" => Some(Self::DeployModule),
            "INIT_CONTRACT" => Some(Self::InitContract),
            "UPDATE" => Some(Self::Update),
            "TRANSFER" => Some(Self::Transfer),
            "ADD_BAKER" => Some(Self::AddBaker),
            "REMOVE_BAKER" => Some(Self::RemoveBaker),
            "UPDATE_BAKER_STAKE" => Some(Self::UpdateBakerStake),
            "UPDATE_BAKER_RESTAKE_EARNINGS" => Some(Self::UpdateBakerRestakeEarnings),
            "UPDATE_BAKER_KEYS" => Some(Self::UpdateBakerKeys),
            "UPDATE_CREDENTIAL_KEYS" => Some(Self::UpdateCredentialKeys),
            "ENCRYPTED_AMOUNT_TRANSFER" => Some(Self::EncryptedAmountTransfer),
            "TRANSFER_TO_ENCRYPTED" => Some(Self::TransferToEncrypted),
            "TRANSFER_TO_PUBLIC" => Some(Self::TransferToPublic),
            "TRANSFER_WITH_SCHEDULE" => Some(Self::TransferWithSchedule),
            "UPDATE_CREDENTIALS" => Some(Self::UpdateCredentials),
            "REGISTER_DATA" => Some(Self::RegisterData),
            "TRANSFER_WITH_MEMO" => Some(Self::TransferWithMemo),
            "ENCRYPTED_AMOUNT_TRANSFER_WITH_MEMO" => Some(Self::EncryptedAmountTransferWithMemo),
            "TRANSFER_WITH_SCHEDULE_AND_MEMO" => Some(Self::TransferWithScheduleAndMemo),
            "CONFIGURE_BAKER" => Some(Self::ConfigureBaker),
            "CONFIGURE_DELEGATION" => Some(Self::ConfigureDelegation),
            _ => None,
        }
    }
}
/// The different versions of the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ProtocolVersion {
    ProtocolVersion1 = 0,
    ProtocolVersion2 = 1,
    ProtocolVersion3 = 2,
    ProtocolVersion4 = 3,
    ProtocolVersion5 = 4,
    ProtocolVersion6 = 5,
}
impl ProtocolVersion {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic
    /// use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ProtocolVersion::ProtocolVersion1 => "PROTOCOL_VERSION_1",
            ProtocolVersion::ProtocolVersion2 => "PROTOCOL_VERSION_2",
            ProtocolVersion::ProtocolVersion3 => "PROTOCOL_VERSION_3",
            ProtocolVersion::ProtocolVersion4 => "PROTOCOL_VERSION_4",
            ProtocolVersion::ProtocolVersion5 => "PROTOCOL_VERSION_5",
            ProtocolVersion::ProtocolVersion6 => "PROTOCOL_VERSION_6",
        }
    }

    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PROTOCOL_VERSION_1" => Some(Self::ProtocolVersion1),
            "PROTOCOL_VERSION_2" => Some(Self::ProtocolVersion2),
            "PROTOCOL_VERSION_3" => Some(Self::ProtocolVersion3),
            "PROTOCOL_VERSION_4" => Some(Self::ProtocolVersion4),
            "PROTOCOL_VERSION_5" => Some(Self::ProtocolVersion5),
            "PROTOCOL_VERSION_6" => Some(Self::ProtocolVersion6),
            _ => None,
        }
    }
}
/// Generated client implementations.
pub mod queries_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::{http::Uri, *};
    #[derive(Debug, Clone)]
    pub struct QueriesClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl QueriesClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>, {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> QueriesClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }

        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> QueriesClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync, {
            QueriesClient::new(InterceptedService::new(inner, interceptor))
        }

        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond
        /// with an error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }

        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }

        /// Return a stream of blocks that arrive from the time the query is
        /// made onward. This can be used to listen for incoming blocks.
        pub async fn get_blocks(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::ArrivedBlockInfo>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetBlocks");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Return a stream of blocks that are finalized from the time the query
        /// is made onward. This can be used to listen for newly
        /// finalized blocks. Note that there is no guarantee that
        /// blocks will not be skipped if the client is too slow in
        /// processing the stream, however blocks will always be sent by
        /// increasing block height.
        pub async fn get_finalized_blocks(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<
            tonic::Response<tonic::codec::Streaming<super::FinalizedBlockInfo>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetFinalizedBlocks");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Retrieve the information about the given account in the given block.
        pub async fn get_account_info(
            &mut self,
            request: impl tonic::IntoRequest<super::AccountInfoRequest>,
        ) -> Result<tonic::Response<super::AccountInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetAccountInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Retrieve the list of accounts that exist at the end of the given
        /// block.
        pub async fn get_account_list(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::AccountAddress>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetAccountList");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get a list of all smart contract modules. The stream will end
        /// when all modules that exist in the state at the end of the given
        /// block have been returned.
        pub async fn get_module_list(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::ModuleRef>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetModuleList");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get a stream of ancestors for the provided block.
        /// Starting with the provided block itself, moving backwards until no
        /// more ancestors or the requested number of ancestors has been
        /// returned.
        pub async fn get_ancestors(
            &mut self,
            request: impl tonic::IntoRequest<super::AncestorsRequest>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::BlockHash>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetAncestors");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get the source of a smart contract module.
        pub async fn get_module_source(
            &mut self,
            request: impl tonic::IntoRequest<super::ModuleSourceRequest>,
        ) -> Result<tonic::Response<super::VersionedModuleSource>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetModuleSource");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of addresses for all smart contract instances. The stream
        /// will end when all instances that exist in the state at the end of
        /// the given block has been returned.
        pub async fn get_instance_list(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::ContractAddress>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetInstanceList");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get info about a smart contract instance as it appears at the end of
        /// the given block.
        pub async fn get_instance_info(
            &mut self,
            request: impl tonic::IntoRequest<super::InstanceInfoRequest>,
        ) -> Result<tonic::Response<super::InstanceInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetInstanceInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the exact state of a specific contract instance, streamed as a
        /// list of key-value pairs. The list is streamed in
        /// lexicographic order of keys.
        pub async fn get_instance_state(
            &mut self,
            request: impl tonic::IntoRequest<super::InstanceInfoRequest>,
        ) -> Result<
            tonic::Response<tonic::codec::Streaming<super::InstanceStateKvPair>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetInstanceState");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get the value at a specific key of a contract state. In contrast to
        /// `GetInstanceState` this is more efficient, but requires the user to
        /// know the specific key to look for.
        pub async fn instance_state_lookup(
            &mut self,
            request: impl tonic::IntoRequest<super::InstanceStateLookupRequest>,
        ) -> Result<tonic::Response<super::InstanceStateValueAtKey>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/InstanceStateLookup");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the best guess as to what the next account sequence number
        /// should be. If all account transactions are finalized then
        /// this information is reliable. Otherwise this is the best
        /// guess, assuming all other transactions will be committed to
        /// blocks and eventually finalized.
        pub async fn get_next_account_sequence_number(
            &mut self,
            request: impl tonic::IntoRequest<super::AccountAddress>,
        ) -> Result<tonic::Response<super::NextAccountSequenceNumber>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetNextAccountSequenceNumber",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about the current state of consensus.
        pub async fn get_consensus_info(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::ConsensusInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetConsensusInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the status of and information about a specific block item
        /// (transaction).
        pub async fn get_block_item_status(
            &mut self,
            request: impl tonic::IntoRequest<super::TransactionHash>,
        ) -> Result<tonic::Response<super::BlockItemStatus>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetBlockItemStatus");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the cryptographic parameters in a given block.
        pub async fn get_cryptographic_parameters(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<super::CryptographicParameters>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetCryptographicParameters",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information, such as height, timings, and transaction counts for
        /// the given block.
        pub async fn get_block_info(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<super::BlockInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetBlockInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get all the bakers at the end of the given block.
        pub async fn get_baker_list(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::BakerId>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetBakerList");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get information about a given pool at the end of a given block.
        pub async fn get_pool_info(
            &mut self,
            request: impl tonic::IntoRequest<super::PoolInfoRequest>,
        ) -> Result<tonic::Response<super::PoolInfoResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetPoolInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about the passive delegators at the end of a given
        /// block.
        pub async fn get_passive_delegation_info(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<super::PassiveDelegationInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetPassiveDelegationInfo",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of live blocks at a given height.
        pub async fn get_blocks_at_height(
            &mut self,
            request: impl tonic::IntoRequest<super::BlocksAtHeightRequest>,
        ) -> Result<tonic::Response<super::BlocksAtHeightResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetBlocksAtHeight");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about tokenomics at the end of a given block.
        pub async fn get_tokenomics_info(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<super::TokenomicsInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetTokenomicsInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Run the smart contract entrypoint in a given context and in the
        /// state at the end of the given block.
        pub async fn invoke_instance(
            &mut self,
            request: impl tonic::IntoRequest<super::InvokeInstanceRequest>,
        ) -> Result<tonic::Response<super::InvokeInstanceResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/InvokeInstance");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the registered delegators of a given pool at the end of a given
        /// block. In contrast to the `GetPoolDelegatorsRewardPeriod`
        /// which returns delegators that are fixed for the reward
        /// period of the block, this endpoint returns the
        /// list of delegators that are registered in the block. Any changes to
        /// delegators are immediately visible in this list.
        /// The stream will end when all the delegators has been returned.
        pub async fn get_pool_delegators(
            &mut self,
            request: impl tonic::IntoRequest<super::GetPoolDelegatorsRequest>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::DelegatorInfo>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetPoolDelegators");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get the fixed delegators of a given pool for the reward period of
        /// the given block. In contracts to the `GetPoolDelegators`
        /// which returns delegators registered for the given block,
        /// this endpoint returns the fixed delegators contributing
        /// stake in the reward period containing the given block.
        /// The stream will end when all the delegators has been returned.
        pub async fn get_pool_delegators_reward_period(
            &mut self,
            request: impl tonic::IntoRequest<super::GetPoolDelegatorsRequest>,
        ) -> Result<
            tonic::Response<tonic::codec::Streaming<super::DelegatorRewardPeriodInfo>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetPoolDelegatorsRewardPeriod",
            );
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get the registered passive delegators at the end of a given block.
        /// In contrast to the `GetPassiveDelegatorsRewardPeriod` which returns
        /// delegators that are fixed for the reward period of the
        /// block, this endpoint returns the list of delegators that are
        /// registered in the block. Any changes to delegators
        /// are immediately visible in this list.
        /// The stream will end when all the delegators has been returned.
        pub async fn get_passive_delegators(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::DelegatorInfo>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetPassiveDelegators");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get the fixed passive delegators for the reward period of the given
        /// block. In contracts to the `GetPassiveDelegators` which
        /// returns delegators registered for the given block, this
        /// endpoint returns the fixed delegators contributing
        /// stake in the reward period containing the given block.
        /// The stream will end when all the delegators has been returned.
        pub async fn get_passive_delegators_reward_period(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<
            tonic::Response<tonic::codec::Streaming<super::DelegatorRewardPeriodInfo>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetPassiveDelegatorsRewardPeriod",
            );
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get the current branches of blocks starting from and including the
        /// last finalized block.
        pub async fn get_branches(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::Branch>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetBranches");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information related to the baker election for a particular
        /// block.
        pub async fn get_election_info(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<super::ElectionInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetElectionInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the identity providers registered as of the end of a given
        /// block. The stream will end when all the identity providers
        /// have been returned.
        pub async fn get_identity_providers(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::IpInfo>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetIdentityProviders");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get the anonymity revokers registered as of the end of a given
        /// block. The stream will end when all the anonymity revokers
        /// have been returned.
        pub async fn get_anonymity_revokers(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::ArInfo>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetAnonymityRevokers");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get a list of non-finalized transaction hashes for a given account.
        /// This endpoint is not expected to return a large amount of
        /// data in most cases, but in bad network condtions it might.
        /// The stream will end when all the non-finalized transaction
        /// hashes have been returned.
        pub async fn get_account_non_finalized_transactions(
            &mut self,
            request: impl tonic::IntoRequest<super::AccountAddress>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::TransactionHash>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetAccountNonFinalizedTransactions",
            );
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get a list of transaction events in a given block.
        /// The stream will end when all the transaction events for a given
        /// block have been returned.
        pub async fn get_block_transaction_events(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::BlockItemSummary>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetBlockTransactionEvents",
            );
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get a list of special events in a given block. These are events
        /// generated by the protocol, such as minting and reward
        /// payouts. They are not directly generated by any transaction.
        /// The stream will end when all the special events for a given
        /// block have been returned.
        pub async fn get_block_special_events(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::BlockSpecialEvent>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetBlockSpecialEvents",
            );
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get the pending updates to chain parameters at the end of a given
        /// block. The stream will end when all the pending updates for
        /// a given block have been returned.
        pub async fn get_block_pending_updates(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::PendingUpdate>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetBlockPendingUpdates",
            );
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }

        /// Get next available sequence numbers for updating chain parameters
        /// after a given block.
        pub async fn get_next_update_sequence_numbers(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<super::NextUpdateSequenceNumbers>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetNextUpdateSequenceNumbers",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Shut down the node.
        /// Return a GRPC error if the shutdown failed.
        pub async fn shutdown(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/Shutdown");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Suggest to a peer to connect to the submitted peer details.
        /// This, if successful, adds the peer to the list of given addresses.
        /// Otherwise return a GRPC error.
        /// Note. The peer might not be connected to instantly, in that case
        /// the node will try to establish the connection in near future. This
        /// function returns a GRPC status 'Ok' in this case.
        pub async fn peer_connect(
            &mut self,
            request: impl tonic::IntoRequest<super::IpSocketAddress>,
        ) -> Result<tonic::Response<super::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/PeerConnect");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Disconnect from the peer and remove them from the given addresses
        /// list if they are on it. Return if the request was processed
        /// successfully. Otherwise return a GRPC error.
        pub async fn peer_disconnect(
            &mut self,
            request: impl tonic::IntoRequest<super::IpSocketAddress>,
        ) -> Result<tonic::Response<super::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/PeerDisconnect");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of banned peers.
        pub async fn get_banned_peers(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::BannedPeers>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetBannedPeers");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Ban the given peer.
        /// Returns a GRPC error if the action failed.
        pub async fn ban_peer(
            &mut self,
            request: impl tonic::IntoRequest<super::PeerToBan>,
        ) -> Result<tonic::Response<super::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/BanPeer");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Unban the banned peer.
        /// Returns a GRPC error if the action failed.
        pub async fn unban_peer(
            &mut self,
            request: impl tonic::IntoRequest<super::BannedPeer>,
        ) -> Result<tonic::Response<super::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/UnbanPeer");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Start dumping packages into the specified file.
        /// Only enabled if the node was built with the `network_dump` feature.
        /// Returns a GRPC error if the network dump failed to start.
        pub async fn dump_start(
            &mut self,
            request: impl tonic::IntoRequest<super::DumpRequest>,
        ) -> Result<tonic::Response<super::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/DumpStart");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Stop dumping packages.
        /// Only enabled if the node was built with the `network_dump` feature.
        /// Returns a GRPC error if the network dump failed to be stopped.
        pub async fn dump_stop(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/DumpStop");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// / Get a list of the peers that the node is connected to
        /// / and assoicated network related information for each peer.
        pub async fn get_peers_info(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::PeersInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetPeersInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about the node.
        /// The `NodeInfo` includes information of
        /// * Meta information such as the, version of the node, type of the
        ///   node, uptime and the local time of the node.
        /// * NetworkInfo which yields data such as the node id, packets
        ///   sent/received, average bytes per second sent/received.
        /// * ConsensusInfo. The `ConsensusInfo` returned depends on if the node
        ///   supports the protocol on chain and whether the node is configured
        ///   as a baker or not.
        pub async fn get_node_info(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::NodeInfo>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetNodeInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Send a block item. A block item is either an `AccountTransaction`,
        /// which is a transaction signed and paid for by an account, a
        /// `CredentialDeployment`, which creates a new account, or
        /// `UpdateInstruction`, which is an instruction to change some
        /// parameters of the chain. Update instructions can
        /// only be sent by the governance committee.
        ///
        /// Returns a hash of the block item, which can be used with
        /// `GetBlockItemStatus`.
        pub async fn send_block_item(
            &mut self,
            request: impl tonic::IntoRequest<super::SendBlockItemRequest>,
        ) -> Result<tonic::Response<super::TransactionHash>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/SendBlockItem");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the hash to be signed for an account transaction. The hash
        /// returned should be signed and the signatures included as an
        /// AccountTransactionSignature when calling `SendBlockItem`. This is
        /// provided as a convenience to support cases where the right
        /// SDK is not available for interacting with the node. If an
        /// SDK is available then it is strongly recommended to compute
        /// this hash off-line using it. That reduces the trust
        /// in the node, removes networking failure modes, and will perform
        /// better.
        pub async fn get_account_transaction_sign_hash(
            &mut self,
            request: impl tonic::IntoRequest<super::PreAccountTransaction>,
        ) -> Result<tonic::Response<super::AccountTransactionSignHash>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetAccountTransactionSignHash",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the values of chain parameters in effect in the given block.
        pub async fn get_block_chain_parameters(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<super::ChainParameters>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetBlockChainParameters",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the summary of the finalization data in a given block.
        pub async fn get_block_finalization_summary(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<super::BlockFinalizationSummary>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.v2.Queries/GetBlockFinalizationSummary",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the items of a block.
        pub async fn get_block_items(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashInput>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<super::BlockItem>>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.v2.Queries/GetBlockItems");
            self.inner
                .server_streaming(request.into_request(), path, codec)
                .await
        }
    }
}
