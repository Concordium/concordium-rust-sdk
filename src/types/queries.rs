//! Types that appear in various queries of the node.

use super::{hashes::*, network::RemotePeerId, *};
use crate::id;
use block_certificates::raw;
use concordium_base::{
    base::*,
    common::{types::TransactionTime, SerdeDeserialize, SerdeSerialize},
};
use std::net::IpAddr;

/// Integer representation of the protocol version.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    SerdeSerialize,
    SerdeDeserialize,
    Hash,
    derive_more::Display,
)]
#[display(fmt = "P{_0}")]
#[serde(transparent)]
#[repr(transparent)]
pub struct ProtocolVersionInt(pub u64);

/// from ProtocolVersion enum conversion to ProtocolVersionInt
impl ProtocolVersionInt {
    pub const fn from_enum(protocol_version: ProtocolVersion) -> Self {
        match protocol_version {
            ProtocolVersion::P1 => Self(1),
            ProtocolVersion::P2 => Self(2),
            ProtocolVersion::P3 => Self(3),
            ProtocolVersion::P4 => Self(4),
            ProtocolVersion::P5 => Self(5),
            ProtocolVersion::P6 => Self(6),
            ProtocolVersion::P7 => Self(7),
            ProtocolVersion::P8 => Self(8),
            ProtocolVersion::P9 => Self(9),
        }
    }
}

impl TryFrom<ProtocolVersionInt> for ProtocolVersion {
    type Error = UnknownProtocolVersion;

    fn try_from(value: ProtocolVersionInt) -> Result<Self, Self::Error> {
        ProtocolVersion::try_from(value.0)
    }
}

impl From<ProtocolVersion> for ProtocolVersionInt {
    fn from(value: ProtocolVersion) -> Self {
        Self(value.into())
    }
}

#[derive(SerdeDeserialize, Debug, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Metadata about a given block.
pub struct BlockInfo {
    /// Size of all the transactions in the block in bytes.
    pub transactions_size: u64,
    /// Parent block pointer.
    pub block_parent: BlockHash,
    /// Hash of the block.
    pub block_hash: BlockHash,
    /// Whether the block is finalized or not.
    pub finalized: bool,
    /// Hash of the block state at the end of the given block.
    pub block_state_hash: StateHash,
    /// Time when the block was added to the node's tree. This is a subjective
    /// (i.e., node specific) value.
    pub block_arrive_time: chrono::DateTime<chrono::Utc>,
    /// Time when the block was first received by the node. This can be in
    /// principle quite different from the arrive time if, e.g., block execution
    /// takes a long time, or the block must wait for the arrival of its parent.
    pub block_receive_time: chrono::DateTime<chrono::Utc>,
    /// The number of transactions in the block.
    pub transaction_count: u64,
    /// The total energy consumption of transactions in the block.
    pub transaction_energy_cost: Energy,
    /// Slot number of the slot the block is in.
    /// This is only present up to protocol 5.
    pub block_slot: Option<Slot>,
    /// Pointer to the last finalized block. Each block has a pointer to a
    /// specific finalized block that existed at the time the block was
    /// produced.
    pub block_last_finalized: BlockHash,
    /// Slot time of the slot the block is in. In contrast to
    /// [BlockInfo::block_arrive_time] this is an objective value, all nodes
    /// agree on it.
    pub block_slot_time: chrono::DateTime<chrono::Utc>,
    /// Height of the block from genesis.
    pub block_height: AbsoluteBlockHeight,
    /// The height of this block relative to the (re)genesis block of its era.
    pub era_block_height: BlockHeight,
    /// The genesis index for this block. This counts the number of protocol
    /// updates that have preceded this block, and defines the era of the
    /// block.
    pub genesis_index: GenesisIndex,
    /// Identity of the baker of the block. For non-genesis blocks the value is
    /// going to always be `Some`.
    pub block_baker: Option<BakerId>,
    /// Protocol version to which the block belongs.
    pub protocol_version: ProtocolVersionInt,
    /// The round of the block. Present from protocol version 6.
    pub round: Option<Round>,
    /// The epoch of the block. Present from protocol version 6.
    pub epoch: Option<Epoch>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Summary of the current state of consensus.
pub struct ConsensusInfo {
    /// Height of the last finalized block. Genesis block has height 0.
    pub last_finalized_block_height: AbsoluteBlockHeight,
    /// The exponential moving average standard deviation of the time between a
    /// block's nominal slot time, and the time at which it is verified.
    pub block_arrive_latency_e_m_s_d: f64,
    /// Exponential moving average standard deviation of block receive latency
    /// (in seconds), i.e. the time between a block's nominal slot time, and
    /// the time at which is received.
    pub block_receive_latency_e_m_s_d: f64,
    /// Hash of the last, i.e., most recent, finalized block.
    pub last_finalized_block: BlockHash,
    /// Exponential moving average standard deviation of the time between
    /// receiving blocks (in seconds).
    pub block_receive_period_e_m_s_d: Option<f64>,
    /// Exponential moving average standard deviation of the time between blocks
    /// being verified.
    pub block_arrive_period_e_m_s_d: Option<f64>,
    /// The number of blocks that have been received.
    pub blocks_received_count: u64,
    /// Exponential moving average standard deviation of the number of
    /// transactions per block.
    pub transactions_per_block_e_m_s_d: f64,
    /// Exponential moving average of the time between finalizations. Will be
    /// `None` if there are no finalizations yet since the node start.
    pub finalization_period_e_m_a: Option<f64>,
    /// Height of the best block. See [ConsensusInfo::best_block].
    pub best_block_height: AbsoluteBlockHeight,
    /// Time at which a block last became finalized. Note that this is the local
    /// time of the node at the time the block was finalized.
    pub last_finalized_time: Option<chrono::DateTime<chrono::Utc>>,
    /// The number of completed finalizations.
    pub finalization_count: u64,
    #[serde(with = "crate::internal::duration_millis")]
    /// Duration of an epoch.
    pub epoch_duration: chrono::Duration,
    /// Number of blocks that arrived, i.e., were added to the tree. Note that
    /// in some cases this can be more than
    /// [ConsensusInfo::blocks_received_count] since blocks that the node itself
    /// produces count towards this, but are not received.
    pub blocks_verified_count: u64,
    /// Duration of a slot.
    pub slot_duration: Option<SlotDuration>,
    /// Slot time of the genesis block.
    pub genesis_time: chrono::DateTime<chrono::Utc>,
    /// Exponential moving average standard deviation of the time between
    /// finalizations. Will be `None` if there are no finalizations yet
    /// since the node start.
    pub finalization_period_e_m_s_d: Option<f64>,
    /// Exponential moving average of the number of
    /// transactions per block.
    pub transactions_per_block_e_m_a: f64,
    /// The exponential moving average of the time between a block's nominal
    /// slot time, and the time at which it is verified.
    pub block_arrive_latency_e_m_a: f64,
    /// Exponential moving average of block receive latency (in seconds), i.e.
    /// the time between a block's nominal slot time, and the time at which is
    /// received.
    pub block_receive_latency_e_m_a: f64,
    /// Exponential moving average of the time between receiving blocks (in
    /// seconds).
    pub block_arrive_period_e_m_a: Option<f64>,
    /// Exponential moving average of the time between receiving blocks (in
    /// seconds).
    pub block_receive_period_e_m_a: Option<f64>,
    /// The time (local time of the node) that a block last arrived, i.e., was
    /// verified and added to the node's tree.
    pub block_last_arrived_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Hash of the current best block. The best block is a protocol defined
    /// block that the node must use a parent block to build the chain on.
    /// Note that this is subjective, in the sense that it is only the best
    /// block among the blocks the node knows about.
    pub best_block: BlockHash,
    /// Hash of the genesis block.
    pub genesis_block: BlockHash,
    /// The time (local time of the node) that a block was last received.
    pub block_last_received_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Currently active protocol version.
    pub protocol_version: ProtocolVersionInt,
    /// The number of chain restarts via a protocol update. An effected
    /// protocol update instruction might not change the protocol version
    /// specified in the previous field, but it always increments the genesis
    /// index.
    pub genesis_index: GenesisIndex,
    /// Block hash of the genesis block of current era, i.e., since the last
    /// protocol update. Initially this is equal to
    /// [`genesis_block`](Self::genesis_block)'.
    pub current_era_genesis_block: BlockHash,
    /// Time when the current era started.
    pub current_era_genesis_time: chrono::DateTime<chrono::Utc>,
    /// Parameters that apply from protocol 6 onward. This is present if and
    /// only if the `protocol_version` is [`ProtocolVersion::P6`] or later.
    #[serde(rename = "concordiumBFTStatus")]
    pub concordium_bft_status: Option<ConcordiumBFTDetails>,
}

/// Parameters pertaining to the Concordium BFT consensus.
#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ConcordiumBFTDetails {
    /// The current duration to wait before a round times out.
    #[serde(with = "crate::internal::duration_millis")]
    pub current_timeout_duration: chrono::Duration,
    /// The current round.
    pub current_round: Round,
    /// The current epoch.
    pub current_epoch: Epoch,
    /// The first block in the epoch with timestamp at least this is considered
    /// to be the trigger block for the epoch transition.
    pub trigger_block_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
/// Branches of the tree. This is the part of the tree above the last finalized
/// block.
pub struct Branch {
    /// Root of the tree.
    pub block_hash: BlockHash,
    /// And children.
    pub children: Vec<Branch>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// Best guess about the current account nonce, with information about
/// reliability.
pub struct AccountNonceResponse {
    /// The nonce that should be used.
    pub nonce: Nonce,
    /// A flag indicating whether all known transactions are finalized. This can
    /// be used as an indicator of how reliable the `nonce` value is.
    pub all_final: bool,
}

//

#[derive(Debug)]
/// Brief information about the node.
pub struct NodeInfo {
    /// Node ID. This is only used for reporting to the network dashboard, and
    /// has no protocol meaning.
    pub node_id: String,
    /// Current local time of the node.
    pub local_time: chrono::DateTime<chrono::Utc>,
    /// Details of the node configuration.
    pub peer_details: PeerDetails,
}

#[derive(Debug)]
/// Details about the node kind.
pub enum PeerDetails {
    /// The node is a bootstrapper.
    Bootstrapper,
    /// The node is not a bootstrapper, it is running consensus.
    Node { consensus_state: ConsensusState },
}

#[derive(Debug)]
/// Configuration of the node's consensus.
pub enum ConsensusState {
    /// Consensus is not running.
    NotRunning,
    /// Consensus is running in passive configuration. The node does not have
    /// baker credentials and cannot act as a baker.
    Passive,
    /// Consensus is running in an active configuration. The inner state has
    /// details on whether it is currently an active baker and finalizer or not.
    Active { active_state: ActiveConsensusState },
}

#[derive(Debug)]
/// State of the running node's consensus when running with baker credentials.
pub enum ActiveConsensusState {
    /// The baker is not in committee.
    NotInCommittee,
    /// The node is started with incorrect keys from the perspective of the
    /// current epoch.
    IncorrectKeys,
    /// The baker is registered, but it is not yet active in the current epoch.
    /// Wait up to two epochs for the baker to become active.
    NotYetActive,
    /// The baker is active as a baker with the given ID. The baker might also
    /// be a finalizer.
    Active { baker_id: BakerId, finalizer: bool },
}

#[derive(Debug)]
/// Ways to ban a node, either by IP address or by a peer id.
pub enum BanMethod {
    Ip(IpAddr),
    Id(RemotePeerId),
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// A scheduled pending update.
pub struct PendingUpdate {
    /// Time when it will become effective.
    pub effective_time: TransactionTime,
    /// The effect the update will have.
    pub effect: Upward<PendingUpdateEffect>,
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(tag = "updateType", content = "update")]
pub enum PendingUpdateEffect {
    #[serde(rename = "root")]
    RootKeys(HigherLevelAccessStructure<RootKeysKind>),
    #[serde(rename = "level1")]
    Level1Keys(HigherLevelAccessStructure<Level1KeysKind>),
    #[serde(rename = "level2V0")]
    Level2KeysCPV0(AuthorizationsV0),
    #[serde(rename = "level2V1")]
    Level2KeysCPV1(AuthorizationsV1),
    #[serde(rename = "protocol")]
    Protocol(ProtocolUpdate),
    #[serde(rename = "electionDifficulty")]
    ElectionDifficulty(ElectionDifficulty),
    #[serde(rename = "euroPerEnergy")]
    EuroPerEnergy(ExchangeRate),
    #[serde(rename = "microCCDPerEuro")]
    MicroCcdPerEnergy(ExchangeRate),
    #[serde(rename = "foundationAccount")]
    FoundationAccount(AccountAddress),
    #[serde(rename = "mintDistributionV0")]
    MintDistributionV0(MintDistributionV0),
    #[serde(rename = "mintDistributionV1")]
    MintDistributionV1(MintDistributionV1),
    #[serde(rename = "transactionFeeDistribution")]
    TransactionFeeDistribution(TransactionFeeDistribution),
    #[serde(rename = "gasRewards")]
    GasRewards(GASRewards),
    #[serde(rename = "poolParametersV0")]
    PoolParametersV0(BakerParameters),
    #[serde(rename = "poolParametersV1")]
    PoolParametersV1(PoolParameters),
    #[serde(rename = "addAnonymityRevoker")]
    AddAnonymityRevoker(Box<id::types::ArInfo<id::constants::ArCurve>>),
    #[serde(rename = "addIdentityProvider")]
    AddIdentityProvider(Box<id::types::IpInfo<id::constants::IpPairing>>),
    #[serde(rename = "cooldownParametersV1")]
    CooldownParameters(CooldownParameters),
    #[serde(rename = "timeParametersV1")]
    TimeParameters(TimeParameters),
    #[serde(rename = "gasRewardsV1")]
    GasRewardsV1(GASRewardsV1),
    #[serde(rename = "timeoutParameters")]
    TimeoutParameters(TimeoutParameters),
    #[serde(rename = "minBlockTime")]
    MinBlockTime(Duration),
    #[serde(rename = "blockEnergyLimit")]
    BlockEnergyLimit(Energy),
    #[serde(rename = "finalizationCommitteeParameters")]
    FinalizationCommitteeParameters(FinalizationCommitteeParameters),
    #[serde(rename = "validatorScoreParameters")]
    ValidatorScoreParameters(ValidatorScoreParameters),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NextUpdateSequenceNumbers {
    /// Updates to the root keys.
    pub root_keys: UpdateSequenceNumber,
    /// Updates to the level 1 keys.
    pub level_1_keys: UpdateSequenceNumber,
    /// Updates to the level 2 keys.
    pub level_2_keys: UpdateSequenceNumber,
    /// Protocol updates.
    pub protocol: UpdateSequenceNumber,
    /// Updates to the election difficulty parameter.
    pub election_difficulty: UpdateSequenceNumber,
    /// Updates to the euro:energy exchange rate.
    pub euro_per_energy: UpdateSequenceNumber,
    /// Updates to the CCD:euro exchange rate.
    pub micro_ccd_per_euro: UpdateSequenceNumber,
    /// Updates to the foundation account.
    pub foundation_account: UpdateSequenceNumber,
    /// Updates to the mint distribution.
    pub mint_distribution: UpdateSequenceNumber,
    /// Updates to the transaction fee distribution.
    pub transaction_fee_distribution: UpdateSequenceNumber,
    /// Updates to the GAS rewards.
    pub gas_rewards: UpdateSequenceNumber,
    /// Updates pool parameters.
    pub pool_parameters: UpdateSequenceNumber,
    /// Add a new anonymity revoker.
    pub add_anonymity_revoker: UpdateSequenceNumber,
    /// Add a new identity provider.
    pub add_identity_provider: UpdateSequenceNumber,
    /// Updates to cooldown parameters for chain parameters version 1 onwards.
    pub cooldown_parameters: UpdateSequenceNumber,
    /// Updates to time parameters for chain parameters version 1 onwards.
    pub time_parameters: UpdateSequenceNumber,
    /// Updates to the consensus version 2 timeout parameters.
    pub timeout_parameters: UpdateSequenceNumber,
    /// Updates to the consensus version 2 minimum time between blocks.
    pub min_block_time: UpdateSequenceNumber,
    /// Updates to the consensus version 2 block energy limit.
    pub block_energy_limit: UpdateSequenceNumber,
    /// Updates to the consensus version 2 finalization committee parameters
    pub finalization_committee_parameters: UpdateSequenceNumber,
    /// Updates to the validator score parameters for chain parameters version 3
    /// onwards.
    pub validator_score_parameters: UpdateSequenceNumber,
    // Updates to the protocol level tokens. Introduced in protocol version 9.
    pub protocol_level_tokens: UpdateSequenceNumber,
}

/// The status of the node with respect to its participation in the consensus
/// protocol. The node persists this information to its local storage to ensure
/// that it does not roll back and violate the consensus protocol in the event
/// of a restart.
#[derive(Debug, Clone)]
pub struct PersistentRoundStatus {
    /// The last signed quorum message by the node.
    pub last_signed_quorum_message: Option<raw::QuorumMessage>,
    /// The last signed timeout message by the node.
    pub last_signed_timeout_message: Option<raw::TimeoutMessage>,
    /// The last round the node baked in.
    pub last_baked_round: Round,
    /// The latest timeout certificate seen by the node. May be absent if the
    /// node has seen a quorum certificate for a more recent round.
    pub latest_timeout: Option<raw::TimeoutCertificate>,
}

/// Details of a round timeout.
#[derive(Debug, Clone)]
pub struct RoundTimeout {
    /// Timeout certificate for the round that timed out.
    pub timeout_certificate: raw::TimeoutCertificate,
    /// The highest known quorum certificate when the round timed out.
    pub quorum_certificate: raw::QuorumCertificate,
}

/// The current round status.
#[derive(Debug, Clone)]
pub struct RoundStatus {
    /// The current round from the perspective of the node.
    /// This should always be higher than the round of the highest certified
    /// block. If the previous round did not timeout, it should be one more
    /// than the round of the `highest_certified_block`. Otherwise, it
    /// should be one more than the round of the `previous_round_timeout`.
    pub current_round: Round,
    /// The quorum certificate for the highest certified block.
    pub highest_certified_block: raw::QuorumCertificate,
    /// If the last round timed out, this is the timeout certificate for that
    /// round and the highest quorum certificate at the time the round timed
    /// out.
    pub previous_round_timeout: Option<RoundTimeout>,
    /// Flag indicating whether the node should attempt to bake in the current
    /// round. This is set to `true` when the round is advanced, and set to
    /// `false` once the node has attempted to bake for the round.
    pub round_eligible_to_bake: bool,
    /// The current epoch. This should either be the same as the epoch of the
    /// last finalized block (if its timestamp is before the trigger block
    /// time) or the next epoch from the last finalized block (if its
    /// timestamp is at least the trigger block time).
    pub current_epoch: Epoch,
    /// If present, an epoch finalization entry for the epoch before
    /// `current_epoch`. An entry must be present if the current epoch is
    /// greater than the epoch of the last finalized block.
    pub last_epoch_finalization_entry: Option<raw::FinalizationEntry>,
    /// The current duration the node will wait before a round times out.
    pub current_timeout: Duration,
}

/// Summary of the block table in the node.
#[derive(Debug, Clone)]
pub struct BlockTableSummary {
    /// The number of blocks in the dead block cache.
    pub dead_block_cache_size: u64,
    /// The blocks that are currently live (not dead and not finalized).
    pub live_blocks: Vec<BlockHash>,
}

/// Details of a round for which a node has seen a block.
#[derive(Debug, Clone, Copy)]
pub struct RoundExistingBlock {
    /// The round for which the node saw a block.
    pub round: Round,
    /// The baker that baked the block.
    pub baker: BakerId,
    /// The hash of the block.
    pub block: BlockHash,
}

/// Details of a round for which a node has seen a quorum certificate.
#[derive(Debug, Clone, Copy)]
pub struct RoundExistingQC {
    /// The round for which a QC was seen.
    pub round: Round,
    /// The epoch of the QC.
    pub epoch: Epoch,
}

/// The public keys and stake of a specific validator.
#[derive(Debug, Clone)]
pub struct FullBakerInfo {
    /// The validator's identity.
    pub baker_identity: BakerId,
    /// The validator's election verify key.
    pub election_verify_key: BakerElectionVerifyKey,
    /// The validator's signature verify key.
    pub signature_verify_key: BakerSignatureVerifyKey,
    /// The validator's aggregation verify key.
    pub aggregation_verify_key: BakerAggregationVerifyKey,
    /// The stake of the validator.
    pub stake: Amount,
}

/// The validator committee for a particular epoch.
#[derive(Debug, Clone)]
pub struct BakersAndFinalizers {
    /// The set of validators.
    pub bakers: Vec<FullBakerInfo>,
    /// The IDs of the validator that are finalizers.
    /// The order determines the finalizer index.
    pub finalizers: Vec<BakerId>,
    /// The total effective stake of the validators.
    pub baker_total_stake: Amount,
    /// The total effective stake of the finalizers.
    pub finalizer_total_stake: Amount,
    /// The hash of the finalization committee.
    pub finalization_committee_hash: FinalizationCommitteeHash,
}

/// The validator committees for the previous, current and next epoch.
#[derive(Debug, Clone)]
pub struct EpochBakers {
    /// The bakers and finalizers for the previous epoch.
    /// If the current epoch is 0, then this is the same as the bakers for the
    /// current epoch.
    pub previous_epoch_bakers: BakersAndFinalizers,
    /// The bakers and finalizers for the current epoch.
    /// If this is absent, it should be treated as the same as the bakers for
    /// the previous epoch.
    pub current_epoch_bakers: Option<BakersAndFinalizers>,
    /// The bakers and finalizers for the next epoch.
    /// If this is absent, it should be treated as the same as the bakers for
    /// the current epoch.
    pub next_epoch_bakers: Option<BakersAndFinalizers>,
    /// The first epoch of the next payday.
    pub next_payday: Epoch,
}

impl EpochBakers {
    /// Get the bakers and finalizers for the previous epoch.
    pub fn previous_epoch_bakers(&self) -> &BakersAndFinalizers {
        &self.previous_epoch_bakers
    }

    /// Get the bakers and finalizers for the current epoch.
    pub fn current_epoch_bakers(&self) -> &BakersAndFinalizers {
        self.current_epoch_bakers
            .as_ref()
            .unwrap_or(&self.previous_epoch_bakers)
    }

    /// Get the bakers and finalizers for the next epoch.
    pub fn next_epoch_bakers(&self) -> &BakersAndFinalizers {
        self.next_epoch_bakers
            .as_ref()
            .unwrap_or_else(|| self.current_epoch_bakers())
    }
}

/// Details of the consensus state of a node. This is primarily useful for
/// diagnostic purposes.
#[derive(Debug, Clone)]
pub struct ConsensusDetailedStatus {
    /// The hash of the genesis block.
    pub genesis_block: BlockHash,
    /// The persisted elements of the round status.
    pub persistent_round_status: PersistentRoundStatus,
    /// The status of the current round.
    pub round_status: RoundStatus,
    /// The number of non-finalized transactions.
    pub non_finalized_transaction_count: u64,
    /// The purge counter for the transaction table.
    pub transaction_table_purge_counter: i64,
    /// Summary of the block table.
    pub block_table: BlockTableSummary,
    /// The live blocks organized by height after the last finalized block.
    pub branches: Vec<Vec<BlockHash>>,
    /// Which bakers the node has seen legally-signed blocks with live parents
    /// from in non-finalized rounds.
    pub round_existing_blocks: Vec<RoundExistingBlock>,
    /// Which non-finalized rounds the node has seen quorum certificates for.
    pub round_existing_qcs: Vec<RoundExistingQC>,
    /// The absolute block height of the genesis block of the era.
    pub genesis_block_height: AbsoluteBlockHeight,
    /// The hash of the last finalized block.
    pub last_finalized_block: BlockHash,
    /// The height of the last finalized block.
    pub last_finalized_block_height: BlockHeight,
    /// Unless the last finalized block is the genesis block, this should be a
    /// finalization entry for the last finalized block.
    /// As this includes a quorum certificate for the last finalized block, that
    /// can be used to determine the epoch and round of the last finalized
    /// block.
    pub latest_finalization_entry: Option<raw::FinalizationEntry>,
    /// The bakers and finalizers for the previous, current and next epoch,
    /// relative to the last finalized block.
    pub epoch_bakers: EpochBakers,
    /// The timeout messages collected by the node for the current round.
    pub timeout_messages: Option<raw::TimeoutMessages>,
    /// If a protocol update has occurred, this is the hash of the terminal
    /// block.
    pub terminal_block: Option<BlockHash>,
}
