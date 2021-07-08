//! Types that appear in various queries of the node.

use super::{basic::*, hashes::*, network::RemotePeerId};
use crypto_common::{SerdeDeserialize, SerdeSerialize};
use std::net::IpAddr;

#[derive(SerdeDeserialize, Debug, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Metadata about a given block.
pub struct BlockInfo {
    /// Size of all the transactions in the block in bytes.
    pub transactions_size:       u64,
    /// Parent block pointer.
    pub block_parent:            BlockHash,
    /// Hashe of the block.
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
    /// Height of the block.
    pub block_height:            BlockHeight,
    /// Identity of the baker of the block. For non-genesis blocks the value is
    /// going to always be `Some`.
    pub block_baker:             Option<BakerId>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Summary of the current state of consensus.
pub struct ConsensusInfo {
    pub last_finalized_block_height:    BlockHeight,
    pub block_arrive_latency_e_m_s_d:   f64,
    pub block_receive_latency_e_m_s_d:  f64,
    pub last_finalized_block:           BlockHash,
    pub block_receive_period_e_m_s_d:   Option<f64>,
    pub block_arrive_period_e_m_s_d:    Option<f64>,
    pub blocks_received_count:          u64,
    pub transactions_per_block_e_m_s_d: f64,
    pub finalization_period_e_m_a:      Option<f64>,
    pub best_block_height:              BlockHeight,
    pub last_finalized_time:            Option<chrono::DateTime<chrono::Utc>>,
    pub finalization_count:             u64,
    #[serde(with = "crate::internal::duration_millis")]
    pub epoch_duration:                 chrono::Duration,
    pub blocks_verified_count:          u64,
    pub slot_duration:                  SlotDuration,
    pub genesis_time:                   chrono::DateTime<chrono::Utc>,
    pub finalization_period_e_m_s_d:    Option<f64>,
    pub transactions_per_block_e_m_a:   f64,
    pub block_arrive_latency_e_m_a:     f64,
    pub block_receive_latency_e_m_a:    f64,
    pub block_arrive_period_e_m_a:      Option<f64>,
    pub block_receive_period_e_m_a:     Option<f64>,
    pub block_last_arrived_time:        Option<chrono::DateTime<chrono::Utc>>,
    pub best_block:                     BlockHash,
    pub genesis_block:                  BlockHash,
    pub block_last_received_time:       Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Branches of the tree. This is the part of the tree above the last finalized
/// block.
pub struct Branch {
    /// Root of the tree.
    pub block_hash: BlockHash,
    /// And children.
    pub branches:   Vec<Branch>,
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
