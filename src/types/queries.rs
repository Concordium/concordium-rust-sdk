//! Types that appear in various queries of the node.

use super::{hashes::*, network::RemotePeerId, *};
use crate::id;
use concordium_base::{
    base::*,
    common::{types::TransactionTime, SerdeDeserialize, SerdeSerialize},
};
use std::net::IpAddr;

#[derive(SerdeDeserialize, Debug, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Metadata about a given block.
pub struct BlockInfo {
    /// Size of all the transactions in the block in bytes.
    pub transactions_size:       u64,
    /// Parent block pointer.
    pub block_parent:            BlockHash,
    /// Hash of the block.
    pub block_hash:              BlockHash,
    /// Whether the block is finalized or not.
    pub finalized:               bool,
    /// Hash of the block state at the end of the given block.
    pub block_state_hash:        StateHash,
    /// Time when the block was added to the node's tree. This is a subjective
    /// (i.e., node specific) value.
    pub block_arrive_time:       chrono::DateTime<chrono::Utc>,
    /// Time when the block was first received by the node. This can be in
    /// principle quite different from the arrive time if, e.g., block execution
    /// takes a long time, or the block must wait for the arrival of its parent.
    pub block_receive_time:      chrono::DateTime<chrono::Utc>,
    /// The number of transactions in the block.
    pub transaction_count:       u64,
    /// The total energy consumption of transactions in the block.
    pub transaction_energy_cost: Energy,
    /// Slot number of the slot the block is in.
    pub block_slot:              Slot,
    /// Pointer to the last finalized block. Each block has a pointer to a
    /// specific finalized block that existed at the time the block was
    /// produced.
    pub block_last_finalized:    BlockHash,
    /// Slot time of the slot the block is in. In contrast to
    /// [BlockInfo::block_arrive_time] this is an objective value, all nodes
    /// agree on it.
    pub block_slot_time:         chrono::DateTime<chrono::Utc>,
    /// Height of the block from genesis.
    pub block_height:            AbsoluteBlockHeight,
    /// The height of this block relative to the (re)genesis block of its era.
    pub era_block_height:        BlockHeight,
    /// The genesis index for this block. This counts the number of protocol
    /// updates that have preceded this block, and defines the era of the
    /// block.
    pub genesis_index:           GenesisIndex,
    /// Identity of the baker of the block. For non-genesis blocks the value is
    /// going to always be `Some`.
    pub block_baker:             Option<BakerId>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Summary of the current state of consensus.
pub struct ConsensusInfo {
    /// Height of the last finalized block. Genesis block has height 0.
    pub last_finalized_block_height:    AbsoluteBlockHeight,
    /// The exponential moving average standard deviation of the time between a
    /// block's nominal slot time, and the time at which it is verified.
    pub block_arrive_latency_e_m_s_d:   f64,
    /// Exponential moving average standard deviation of block receive latency
    /// (in seconds), i.e. the time between a block's nominal slot time, and
    /// the time at which is received.
    pub block_receive_latency_e_m_s_d:  f64,
    /// Hash of the last, i.e., most recent, finalized block.
    pub last_finalized_block:           BlockHash,
    /// Exponential moving average standard deviation of the time between
    /// receiving blocks (in seconds).
    pub block_receive_period_e_m_s_d:   Option<f64>,
    /// Exponential moving average standard deviation of the time between blocks
    /// being verified.
    pub block_arrive_period_e_m_s_d:    Option<f64>,
    /// The number of blocks that have been received.
    pub blocks_received_count:          u64,
    /// Exponential moving average standard deviation of the number of
    /// transactions per block.
    pub transactions_per_block_e_m_s_d: f64,
    /// Exponential moving average of the time between finalizations. Will be
    /// `None` if there are no finalizations yet since the node start.
    pub finalization_period_e_m_a:      Option<f64>,
    /// Height of the best block. See [ConsensusInfo::best_block].
    pub best_block_height:              AbsoluteBlockHeight,
    /// Time at which a block last became finalized. Note that this is the local
    /// time of the node at the time the block was finalized.
    pub last_finalized_time:            Option<chrono::DateTime<chrono::Utc>>,
    /// The number of completed finalizations.
    pub finalization_count:             u64,
    #[serde(with = "crate::internal::duration_millis")]
    /// Duration of an epoch.
    pub epoch_duration:                 chrono::Duration,
    /// Number of blocks that arrived, i.e., were added to the tree. Note that
    /// in some cases this can be more than
    /// [ConsensusInfo::blocks_received_count] since blocks that the node itself
    /// produces count towards this, but are not received.
    pub blocks_verified_count:          u64,
    /// Duration of a slot.
    pub slot_duration:                  SlotDuration,
    /// Slot time of the genesis block.
    pub genesis_time:                   chrono::DateTime<chrono::Utc>,
    /// Exponential moving average standard deviation of the time between
    /// finalizations. Will be `None` if there are no finalizations yet
    /// since the node start.
    pub finalization_period_e_m_s_d:    Option<f64>,
    /// Exponential moving average of the number of
    /// transactions per block.
    pub transactions_per_block_e_m_a:   f64,
    /// The exponential moving average of the time between a block's nominal
    /// slot time, and the time at which it is verified.
    pub block_arrive_latency_e_m_a:     f64,
    /// Exponential moving average of block receive latency (in seconds), i.e.
    /// the time between a block's nominal slot time, and the time at which is
    /// received.
    pub block_receive_latency_e_m_a:    f64,
    /// Exponential moving average of the time between receiving blocks (in
    /// seconds).
    pub block_arrive_period_e_m_a:      Option<f64>,
    /// Exponential moving average of the time between receiving blocks (in
    /// seconds).
    pub block_receive_period_e_m_a:     Option<f64>,
    /// The time (local time of the node) that a block last arrived, i.e., was
    /// verified and added to the node's tree.
    pub block_last_arrived_time:        Option<chrono::DateTime<chrono::Utc>>,
    /// Hash of the current best block. The best block is a protocol defined
    /// block that the node must use a parent block to build the chain on.
    /// Note that this is subjective, in the sense that it is only the best
    /// block among the blocks the node knows about.
    pub best_block:                     BlockHash,
    /// Hash of the genesis block.
    pub genesis_block:                  BlockHash,
    /// The time (local time of the node) that a block was last received.
    pub block_last_received_time:       Option<chrono::DateTime<chrono::Utc>>,
    /// Currently active protocol version.
    pub protocol_version:               ProtocolVersion,
    /// The number of chain restarts via a protocol update. An effected
    /// protocol update instruction might not change the protocol version
    /// specified in the previous field, but it always increments the genesis
    /// index.
    pub genesis_index:                  GenesisIndex,
    /// Block hash of the genesis block of current era, i.e., since the last
    /// protocol update. Initially this is equal to
    /// [`genesis_block`](Self::genesis_block)'.
    pub current_era_genesis_block:      BlockHash,
    /// Time when the current era started.
    pub current_era_genesis_time:       chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
/// Branches of the tree. This is the part of the tree above the last finalized
/// block.
pub struct Branch {
    /// Root of the tree.
    pub block_hash: BlockHash,
    /// And children.
    pub children:   Vec<Branch>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// Best guess about the current account nonce, with information about
/// reliability.
pub struct AccountNonceResponse {
    /// The nonce that should be used.
    pub nonce:     Nonce,
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
    pub node_id:      String,
    /// Current local time of the node.
    pub local_time:   chrono::DateTime<chrono::Utc>,
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

#[derive(Debug, Clone)]
/// A scheduled pending update.
pub struct PendingUpdate {
    /// Time when it will become effective.
    pub effective_time: TransactionTime,
    /// The effect the udpate will have.
    pub effect:         PendingUpdateEffect,
}

#[derive(Debug, Clone)]
pub enum PendingUpdateEffect {
    RootKeys(HigherLevelAccessStructure<RootKeysKind>),
    Level1Keys(HigherLevelAccessStructure<Level1KeysKind>),
    Level2KeysCPV0(Authorizations<ChainParameterVersion0>),
    Level2KeysCPV1(Authorizations<ChainParameterVersion1>),
    Protocol(ProtocolUpdate),
    ElectionDifficulty(ElectionDifficulty),
    EuroPerEnergy(ExchangeRate),
    MicroCcdPerEnergy(ExchangeRate),
    FoundationAccount(AccountAddress),
    MintDistributionV0(MintDistribution<ChainParameterVersion0>),
    MintDistributionV1(MintDistribution<ChainParameterVersion1>),
    TransactionFeeDistribution(TransactionFeeDistribution),
    GasRewards(GASRewards),
    PoolParametersV0(BakerParameters),
    PoolParametersV1(PoolParameters),
    AddAnonymityRevoker(id::types::ArInfo<id::constants::ArCurve>),
    AddIdentityProvider(Box<id::types::IpInfo<id::constants::IpPairing>>),
    CooldownParameters(CooldownParameters),
    TimeParameters(TimeParameters),
}

#[derive(Debug, Copy, Clone)]
pub struct NextUpdateSequenceNumbers {
    pub root_keys:                    UpdateSequenceNumber,
    pub level_1_keys:                 UpdateSequenceNumber,
    pub level_2_keys:                 UpdateSequenceNumber,
    pub protocol:                     UpdateSequenceNumber,
    pub election_difficulty:          UpdateSequenceNumber,
    pub euro_per_energy:              UpdateSequenceNumber,
    pub micro_ccd_per_euro:           UpdateSequenceNumber,
    pub foundation_account:           UpdateSequenceNumber,
    pub mint_distribution:            UpdateSequenceNumber,
    pub transaction_fee_distribution: UpdateSequenceNumber,
    pub gas_rewards:                  UpdateSequenceNumber,
    pub pool_parameters:              UpdateSequenceNumber,
    pub add_anonymity_revoker:        UpdateSequenceNumber,
    pub add_identity_provider:        UpdateSequenceNumber,
    pub cooldown_parameters:          UpdateSequenceNumber,
    pub time_parameters:              UpdateSequenceNumber,
}
