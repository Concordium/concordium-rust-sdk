use chrono::TimeZone;
use thiserror::Error;
use crate::endpoints::QueryError;

#[derive(Debug)]
/// TODO: Someone remind me to doc this type.
pub struct NetworkStatus {
    pub node_id:             String,
    pub peer_total_sent:     u64,
    pub peer_total_received: u64,
    pub avg_bps_in:          u64,
    pub avg_bps_out:         u64,
}

#[derive(Debug)]
pub enum NodeType {
    Bootstrapper, 
    Node,
}

#[derive(Debug)]
/// TODO: Someone remind me to doc this type.
pub struct NodeInfo {
    pub node_version: semver::Version,
    pub node_type: NodeType,
    pub local_time:   chrono::DateTime<chrono::Utc>,
    pub node_uptime:  chrono::Duration,
}

#[derive(Debug)]
/// TODO: Someone remind me to doc this type.
pub enum BakingStatus {
    NotInCommittee,
    AddedButNotActiveInCommittee,
    AddedButWrongKeys,
    Baker(crate::types::BakerId),
    Finalizer(crate::types::BakerId),
}

#[derive(Debug)]
/// TODO: Someone remind me to doc this type.
pub enum ConsensusStatus {
    ConsensusNotRunning,
    ConsensusPassive,
    ConsensusBaking(BakingStatus),
}

#[derive(Debug)]
/// TODO: Someone remind me to doc this type.
pub struct NodeStatus {
    pub node_info:        NodeInfo,
    pub network_status:   NetworkStatus,
    pub consensus_status: ConsensusStatus,
}

#[derive(Error, Debug)]
pub enum NodeStatusError {
    #[error("Missing NetworkStatus")]
    MissingNetworkStatus,
    #[error("Missing ConsensusStatus")]
    MissingConsensusStatus,
    #[error("Missing NodeInfo.")]
    MissingNodeInfo,
    #[error("Missing localtime.")]
    MissingLocaltime,
    #[error("Missing uptime.")]
    MissingUptime,
    #[error("Malformed 'Node' type. Must be either 'Bootstrapper' or 'Node'")]
    MalformedNodeType,
    #[error("Malformed 'CommitteeStatus")]
    MalformedCommitteeStatus,
    #[error("The version of the node did not conform to a semantic version: {0}")]
    MalFormedNodeVersion(String),
}

impl From<NodeStatusError> for QueryError {
    fn from(e: NodeStatusError) -> Self {
        QueryError::RPCError(crate::endpoints::RPCError::ParseError(anyhow::anyhow!(e)))
    }
}

impl TryFrom<super::generated::NodeStatus> for NodeStatus {
    type Error = NodeStatusError;

    fn try_from(node_status: super::generated::NodeStatus) -> Result<Self, Self::Error> {
        // Parse the `NetworkStatus` and bail out if it is not present.
        let network_status = if let Some(network_status) = node_status.network_status {
            Ok(NetworkStatus {
                node_id: network_status.node_id,
                peer_total_sent: network_status.peer_total_sent,
                peer_total_received: network_status.peer_total_received,
                avg_bps_in: network_status.avg_bps_in,
                avg_bps_out: network_status.avg_bps_out,
                
            })          
        } else {
            Err(NodeStatusError::MissingNetworkStatus)
        }?;

        // Parse the node type.
        // The node type is specified via an enum:
        // * 0 => The node is a bootstrapper and is simply relaying peers.
        // * 1 => The node is participating in consensus either actively (baking) or passively (solely processing blocks).
        // If the result is none of the above we return an [NodeStatusError::MalformedNodeType].
        let node_type = match node_status.node_type {
            0 => Ok(NodeType::Bootstrapper),
            1 => Ok(NodeType::Node),
            _ => Err(NodeStatusError::MalformedNodeType),
        }?;
        
        let extract_node_info_with_node_type = |node_info| {
            extract_node_info(node_info, node_type)
        };

        let (node_info, consensus_status) = match node_status.consensus_status {
                // The node is a passive member of the consensus. This means: 
                // * The node is processing blocks.
                // * The node is relaying transactions and blocks onto the network.
                // * The node is responding to catch up messages from its peers.
                // * In particular this means that the node is __not__ baking blocks.
                Some(super::generated::node_status::ConsensusStatus::PassiveConsensusStatus(status)) => {                           
                    Ok((extract_node_info_with_node_type(status.node_info)?, ConsensusStatus::ConsensusPassive))
                },
                // The consensus protocol is not running on the node.
                // This only occurs when the node does not support the protocol on the chain or the node is a 'Bootstrapper'.
                Some(super::generated::node_status::ConsensusStatus::ConsensusNotRunningStatus(status)) => Ok((extract_node_info_with_node_type(status.node_info)?, ConsensusStatus::ConsensusNotRunning)),
                // The node has been configured with baker keys.
                Some(super::generated::node_status::ConsensusStatus::BakerConsensusStatus(status)) => {
                    let baking_status = match status.committee_status {
                        // The node has been configured with baker keys however it is not currently baking and possilby never will.
                        0 => Ok(BakingStatus::NotInCommittee),
                        // The baker keys are registered however the baker is not in the committee 
                        // for the current 'Epoch'.
                        1 => Ok(BakingStatus::AddedButNotActiveInCommittee),
                        // The node has been configured with baker keys that does not match the account.
                        2 => Ok(BakingStatus::AddedButWrongKeys),
                        // The node is member of the baking committee.
                        3 => {
                            let account_index = crate::types::AccountIndex::from(status.baker_id);
                            let baker_id = crate::types::BakerId::from(account_index);                        
                            if !status.is_finalizer {
                                Ok(BakingStatus::Baker(baker_id))
                            } else {
                                Ok(BakingStatus::Finalizer(baker_id))
                            }
                        },
                        _ => Err(NodeStatusError::MalformedCommitteeStatus),
                    };                    
                    Ok((extract_node_info_with_node_type(status.node_info)?, ConsensusStatus::ConsensusBaking(baking_status?)))
                },
                _ => Err(NodeStatusError::MissingConsensusStatus),
            }?;

        Ok(NodeStatus{
            network_status,
            node_info,
            consensus_status,
        })
    }
}

fn extract_node_info(node_info: Option<super::generated::NodeInfo>, node_type: NodeType) -> Result<NodeInfo, NodeStatusError> {
    if let Some(node_info) = node_info {    
        // Parse the local time of the node. 
        // The local time is provided as a UNIX timestamp with millisecond precision.    
        let local_time = chrono::Utc.timestamp_millis(node_info.local_time.ok_or(NodeStatusError::MissingLocaltime)?.timestamp as i64); // todo: proper error handling
        // Parse the upime of the node. 
        // The uptime is provided in seconds.
        let node_uptime = chrono::Duration::seconds(node_info.peer_uptime.ok_or(NodeStatusError::MissingUptime)?.value as i64); // todo: proper error handling.   
        let node_version = semver::Version::parse(&node_info.peer_version)?; 
        Ok(NodeInfo { 
            node_version,
            node_type,
            local_time, 
            node_uptime,
    })} else {
        Err(NodeStatusError::MissingNodeInfo)
    }
}

impl From<semver::Error> for NodeStatusError {
    fn from(e: semver::Error) -> Self {
        NodeStatusError::MalFormedNodeVersion(e.to_string())
    }
}
