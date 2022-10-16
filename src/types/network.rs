//! Network related types.

use crate::generated_types::peer_element::CatchupStatus;
use concordium_base::common::{SerdeDeserialize, SerdeSerialize};
use derive_more::{Display, From, FromStr, Into};
use std::{fmt, net::IpAddr, num::ParseIntError};

#[derive(Debug)]
pub struct PeerElement {
    pub node_id:        String,
    pub port:           u16,
    pub ip:             IpAddr,
    pub catchup_status: CatchupStatus,
}

#[repr(transparent)]
#[derive(Debug)]
pub struct RemotePeerId {
    id: u64,
}

/// Parse from a (possibly 0 padded) hex value.
impl std::str::FromStr for RemotePeerId {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, ParseIntError> {
        let id = u64::from_str_radix(s, 16)?;
        Ok(RemotePeerId { id })
    }
}

/// Display as a 0-padded hex value.
impl std::fmt::Display for RemotePeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:016x}", self.id) }
}

#[repr(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct NetworkId {
    pub(crate) network_id: u16,
}

/// A banned peer identified by its IP address.
#[derive(Debug)]
pub struct BannedPeer(pub std::net::IpAddr);

/// A peer to ban identified by its IP address.
#[derive(Debug)]
pub enum PeerToBan {
    IpAddr(IpAddr),
}

/// A vector of the peers that
/// the node is connected to.
#[derive(Debug)]
pub struct PeersInfo {
    pub peers: Vec<Peer>,
}

/// A peer id
#[derive(Debug)]
pub struct PeerId(pub String);

/// A peer that the node is connected to
#[derive(Debug)]
pub struct Peer {
    /// The id of the peer.
    pub peer_id:        PeerId,
    /// Catchup status of the peer.
    pub consensus_info: PeerConsensusInfo,
    /// Network statistics for the peer.
    pub network_stats:  NetworkStats,
    /// The address of the peer
    pub addr:           std::net::SocketAddr,
}

/// Consensus info related to a peer.
#[derive(Debug)]
pub enum PeerConsensusInfo {
    /// Bootstrappers do not run consensus thus
    /// no catchup status.
    Bootstrapper,
    /// Regular nodes do have a catchup status.
    Node(PeerCatchupStatus),
}

/// The catch up status of the peer.
#[derive(Debug)]
pub enum PeerCatchupStatus {
    /// The peer is up to date.
    UpToDate,
    /// We do not know the status of the peer,
    /// e.g. the node just established a connection with
    /// the peer.
    Pending,
    /// The peer is catching up on the chain.
    CatchingUp,
}

/// Network statistics for the peer.
#[derive(Debug)]
pub struct NetworkStats {
    /// How many packets the peer has sent to the node.
    pub packets_sent:     u64,
    /// How many packets the peer has received from the node.
    pub packets_received: u64,
    /// The connection latency aka. 'ping' time (measured in milliseconds).
    pub latency:          u64,
}
