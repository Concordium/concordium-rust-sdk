/// An empty message.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {}
/// A numeric response.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NumberResponse {
    #[prost(uint64, tag = "1")]
    pub value: u64,
}
/// A response consisting of a boolean.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BoolResponse {
    #[prost(bool, tag = "1")]
    pub value: bool,
}
/// A response in string format.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringResponse {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
/// A response that is encoded in JSON.
/// JSON schemas are available at <https://developer.concordium.software/en/mainnet/net/references/grpc.html.>
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JsonResponse {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
/// A response in binary format.
/// The encoding of the data is dependent on the endpoint.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BytesResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// A request that suggests the node to connect to the specified peer.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeerConnectRequest {
    /// The IP of the peer.
    #[prost(message, optional, tag = "1")]
    pub ip:   ::core::option::Option<::prost::alloc::string::String>,
    /// The port of the peer.
    #[prost(message, optional, tag = "2")]
    pub port: ::core::option::Option<i32>,
}
/// A peer node.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeerElement {
    /// The id of the node.
    #[prost(message, optional, tag = "1")]
    pub node_id:        ::core::option::Option<::prost::alloc::string::String>,
    /// The port of the node.
    #[prost(message, optional, tag = "2")]
    pub port:           ::core::option::Option<u32>,
    /// The IP of the node.
    #[prost(message, optional, tag = "3")]
    pub ip:             ::core::option::Option<::prost::alloc::string::String>,
    /// The current status of the peer.
    #[prost(enumeration = "peer_element::CatchupStatus", tag = "4")]
    pub catchup_status: i32,
}
/// Nested message and enum types in `PeerElement`.
pub mod peer_element {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum CatchupStatus {
        /// The peer does not have any data unknown to us. If we receive a
        /// message from the peer that refers to unknown data (e.g., an
        /// unknown block) the peer is marked as pending.
        Uptodate   = 0,
        /// The peer might have some data unknown to us. A peer can be in this
        /// state either because it sent a message that refers to data
        /// unknown to us, or before we have established a baseline with it.
        /// The latter happens during node startup, as well as upon protocol
        /// updates until the initial catchup handshake completes.
        Pending    = 1,
        /// The node is currently catching up by requesting blocks from this
        /// peer. There will be at most one peer with this status at a
        /// time. Once the peer has responded to the request, its status
        /// will be changed to:
        /// - 'UPTODATE' if the peer has no more data that is not known to us
        /// - 'PENDING' if the node has more data that is unknown to us.
        Catchingup = 2,
    }
    impl CatchupStatus {
        /// String value of the enum field names used in the ProtoBuf
        /// definition.
        ///
        /// The values are not transformed in any way and thus are considered
        /// stable (if the ProtoBuf definition does not change) and safe
        /// for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                CatchupStatus::Uptodate => "UPTODATE",
                CatchupStatus::Pending => "PENDING",
                CatchupStatus::Catchingup => "CATCHINGUP",
            }
        }
    }
}
/// A response containing a list of peers.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeerListResponse {
    /// The type of the queried node.
    /// Possible values: "Node" or "Bootstrapper".
    #[prost(string, tag = "1")]
    pub peer_type: ::prost::alloc::string::String,
    /// A list of peers.
    #[prost(message, repeated, tag = "2")]
    pub peers:     ::prost::alloc::vec::Vec<PeerElement>,
}
/// A response containing information about a peer.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeerStatsResponse {
    /// A list of stats for the peers.
    #[prost(message, repeated, tag = "1")]
    pub peerstats:   ::prost::alloc::vec::Vec<peer_stats_response::PeerStats>,
    /// Average outbound throughput in bytes per second.
    #[prost(uint64, tag = "2")]
    pub avg_bps_in:  u64,
    /// Average inbound throughput in bytes per second.
    #[prost(uint64, tag = "3")]
    pub avg_bps_out: u64,
}
/// Nested message and enum types in `PeerStatsResponse`.
pub mod peer_stats_response {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PeerStats {
        /// The node id.
        #[prost(string, tag = "1")]
        pub node_id:          ::prost::alloc::string::String,
        /// The number of messages sent to the peer.
        #[prost(uint64, tag = "2")]
        pub packets_sent:     u64,
        /// The number of messages received from the peer.
        #[prost(uint64, tag = "3")]
        pub packets_received: u64,
        /// The connection latency (i.e., ping time) in milliseconds.
        #[prost(uint64, tag = "4")]
        pub latency:          u64,
    }
}
/// A request to change the network.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkChangeRequest {
    /// The identifier for the network.
    #[prost(message, optional, tag = "1")]
    pub network_id: ::core::option::Option<i32>,
}
/// A response containing information about the node.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeInfoResponse {
    /// The unique node identifier.
    #[prost(message, optional, tag = "1")]
    pub node_id: ::core::option::Option<::prost::alloc::string::String>,
    /// The local time of the node represented as a unix timestamp in seconds.
    #[prost(uint64, tag = "2")]
    pub current_localtime: u64,
    /// The node type. Either "Node" or "Bootstrapper".
    #[prost(string, tag = "3")]
    pub peer_type: ::prost::alloc::string::String,
    /// Whether the node is a baker.
    #[prost(bool, tag = "4")]
    pub consensus_baker_running: bool,
    /// Whether consensus is running.
    /// This is only false if the protocol was updated to a version which the
    /// node software does not support.
    #[prost(bool, tag = "5")]
    pub consensus_running: bool,
    /// Whether the node is "Active" or "Passive".
    /// - "Active": the node has baker credentials and can thus potentially
    ///   participate in baking and finalization.
    /// - "Passive": the node has no baker credentials is thus only an observer
    ///   of the consensus protocol.
    #[prost(string, tag = "6")]
    pub consensus_type: ::prost::alloc::string::String,
    /// The baking status of the node.
    #[prost(enumeration = "node_info_response::IsInBakingCommittee", tag = "7")]
    pub consensus_baker_committee: i32,
    /// Whether the node is part of the finalization committee.
    #[prost(bool, tag = "8")]
    pub consensus_finalizer_committee: bool,
    /// The baker id. This will be `null` if the node is not a baker.
    #[prost(message, optional, tag = "9")]
    pub consensus_baker_id: ::core::option::Option<u64>,
    /// Deprecated.
    #[deprecated]
    #[prost(message, optional, tag = "50")]
    pub staging_net_username: ::core::option::Option<::prost::alloc::string::String>,
}
/// Nested message and enum types in `NodeInfoResponse`.
pub mod node_info_response {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum IsInBakingCommittee {
        /// The node is not the baking committee.
        NotInCommittee    = 0,
        /// The node has baker keys, but the account is not currently a baker
        /// (and possibly never will be).
        AddedButNotActiveInCommittee = 1,
        /// The node has baker keys, but they don't match the current keys on
        /// the baker account.
        AddedButWrongKeys = 2,
        /// The node has valid baker keys and is active in the baker committee.
        ActiveInCommittee = 3,
    }
    impl IsInBakingCommittee {
        /// String value of the enum field names used in the ProtoBuf
        /// definition.
        ///
        /// The values are not transformed in any way and thus are considered
        /// stable (if the ProtoBuf definition does not change) and safe
        /// for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                IsInBakingCommittee::NotInCommittee => "NOT_IN_COMMITTEE",
                IsInBakingCommittee::AddedButNotActiveInCommittee => {
                    "ADDED_BUT_NOT_ACTIVE_IN_COMMITTEE"
                }
                IsInBakingCommittee::AddedButWrongKeys => "ADDED_BUT_WRONG_KEYS",
                IsInBakingCommittee::ActiveInCommittee => "ACTIVE_IN_COMMITTEE",
            }
        }
    }
}
/// Hash of a block (encoded in hex). Is always 64 characters long.
/// Example: "987d6c06256fbf874d6ba14f19baee4390a31c6ee58edd9cc4efef62e89d22d7"
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHash {
    #[prost(string, tag = "1")]
    pub block_hash: ::prost::alloc::string::String,
}
/// An account address. Uses a base58-check encoding with a version byte set to
/// 1. Is always 50 characters long.
/// Example: "3DJoe7aUwMwVmdFdRU2QsnJfsBbCmQu1QHvEg7YtWFZWmsoBXe"
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountAddress {
    #[prost(string, tag = "1")]
    pub account_address: ::prost::alloc::string::String,
}
/// Hash of a transaction (encoded in hex). Is always 64 characters long.
/// Example: "987d6c06256fbf874d6ba14f19baee4390a31c6ee58edd9cc4efef62e89d22d7"
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionHash {
    #[prost(string, tag = "1")]
    pub transaction_hash: ::prost::alloc::string::String,
}
/// Request for getting the ancestors of a block.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHashAndAmount {
    /// The block to get ancestors of.
    #[prost(string, tag = "1")]
    pub block_hash: ::prost::alloc::string::String,
    /// The maximum amount of ancestors that will be returned.
    #[prost(uint64, tag = "2")]
    pub amount:     u64,
}
/// Submit a transaction to the node. The transaction is subject to basic
/// validation and is then relayed to all the peers.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendTransactionRequest {
    /// The network id (currently not used in this request).
    #[prost(uint32, tag = "1")]
    pub network_id: u32,
    /// The transaction payload in binary encoding.
    /// The encoding of certain transaction types, along with the general
    /// payload structure, is described at: <https://developer.concordium.software/en/mainnet/net/references/grpc.html.>
    #[prost(bytes = "vec", tag = "2")]
    pub payload:    ::prost::alloc::vec::Vec<u8>,
}
/// Request for getting information about an account address.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAddressInfoRequest {
    /// Hash of the block (encoded in hex) at which the information should be
    /// gathered.
    #[prost(string, tag = "1")]
    pub block_hash: ::prost::alloc::string::String,
    /// The account address to request information about.
    #[prost(string, tag = "2")]
    pub address:    ::prost::alloc::string::String,
}
/// Request for invoking a contract without a transaction.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvokeContractRequest {
    /// Hash of the block (encoded in hex) at which to invoke the contract.
    #[prost(string, tag = "1")]
    pub block_hash: ::prost::alloc::string::String,
    /// A JSON object that specifies which contract to invoke, and how.
    /// A JSON schema for the context is provided at: <https://developer.concordium.software/en/mainnet/net/references/grpc.html.>
    #[prost(string, tag = "2")]
    pub context:    ::prost::alloc::string::String,
}
/// Request for getting the source of a smart contract module.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetModuleSourceRequest {
    /// The block to be used for the query.
    #[prost(string, tag = "1")]
    pub block_hash: ::prost::alloc::string::String,
    /// The reference (hash) of the module.
    #[prost(string, tag = "2")]
    pub module_ref: ::prost::alloc::string::String,
}
/// Request to enable dumping of network packages.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DumpRequest {
    /// Which file to dump the packages into.
    #[prost(string, tag = "1")]
    pub file: ::prost::alloc::string::String,
    /// Whether the node should dump raw packages.
    #[prost(bool, tag = "2")]
    pub raw:  bool,
}
/// Request for getting (information about) the peers.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeersRequest {
    /// Whether bootstrapper nodes should be included in the result.
    #[prost(bool, tag = "1")]
    pub include_bootstrappers: bool,
}
/// Request for getting the status of a transaction in a given block.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetTransactionStatusInBlockRequest {
    /// The transaction hash.
    #[prost(string, tag = "1")]
    pub transaction_hash: ::prost::alloc::string::String,
    /// The block hash.
    #[prost(string, tag = "2")]
    pub block_hash:       ::prost::alloc::string::String,
}
/// Request for getting the status of a pool.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPoolStatusRequest {
    /// The block from which the query should be processed.
    #[prost(string, tag = "1")]
    pub block_hash:         ::prost::alloc::string::String,
    /// Whether the request is for passive delegation or a specific baker.
    #[prost(bool, tag = "2")]
    pub passive_delegation: bool,
    /// The baker id to get the status of. This will be ignored if
    /// 'passive_delegation' is 'true'.
    #[prost(uint64, tag = "3")]
    pub baker_id:           u64,
}
/// Request for gettings the blocks at a specific height.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHeight {
    /// The block height.
    #[prost(uint64, tag = "1")]
    pub block_height:              u64,
    /// The block height is relative to the genesis block at this index.
    #[prost(uint32, tag = "2")]
    pub from_genesis_index:        u32,
    /// If true, only return results from the specified genesis index.
    #[prost(bool, tag = "3")]
    pub restrict_to_genesis_index: bool,
}
/// Generated client implementations.
pub mod p2p_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::{http::Uri, *};
    #[derive(Debug, Clone)]
    pub struct P2pClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl P2pClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>, {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> P2pClient<T>
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
        ) -> P2pClient<InterceptedService<T, F>>
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
            P2pClient::new(InterceptedService::new(inner, interceptor))
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

        /// Suggest to a peer to connect to the submitted peer details.
        /// This, if successful, adds the peer to the list of given addresses.
        pub async fn peer_connect(
            &mut self,
            request: impl tonic::IntoRequest<super::PeerConnectRequest>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/PeerConnect");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Disconnect from the peer and remove them from the given addresses
        /// list if they are on it. Return if the request was processed
        /// successfully.
        pub async fn peer_disconnect(
            &mut self,
            request: impl tonic::IntoRequest<super::PeerConnectRequest>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/PeerDisconnect");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Uptime of the *node* in milliseconds.
        pub async fn peer_uptime(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::NumberResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/PeerUptime");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Total number of sent packets by the node.
        pub async fn peer_total_sent(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::NumberResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/PeerTotalSent");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Total number of received packets by the node.
        pub async fn peer_total_received(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::NumberResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/PeerTotalReceived");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Node software version.
        pub async fn peer_version(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::StringResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/PeerVersion");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Stats for connected peers.
        pub async fn peer_stats(
            &mut self,
            request: impl tonic::IntoRequest<super::PeersRequest>,
        ) -> Result<tonic::Response<super::PeerStatsResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/PeerStats");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// List of connected peers.
        pub async fn peer_list(
            &mut self,
            request: impl tonic::IntoRequest<super::PeersRequest>,
        ) -> Result<tonic::Response<super::PeerListResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/PeerList");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Ban a the given peer.
        pub async fn ban_node(
            &mut self,
            request: impl tonic::IntoRequest<super::PeerElement>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/BanNode");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Unban the given peer.
        pub async fn unban_node(
            &mut self,
            request: impl tonic::IntoRequest<super::PeerElement>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/UnbanNode");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Join the provided network.
        pub async fn join_network(
            &mut self,
            request: impl tonic::IntoRequest<super::NetworkChangeRequest>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/JoinNetwork");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Leave the provided network.
        pub async fn leave_network(
            &mut self,
            request: impl tonic::IntoRequest<super::NetworkChangeRequest>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/LeaveNetwork");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about the running node.
        pub async fn node_info(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::NodeInfoResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/NodeInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about the consensus.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_consensus_status(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetConsensusStatus");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about the block.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_block_info(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetBlockInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get ancestors for the provided block.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_ancestors(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHashAndAmount>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetAncestors");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the current branches.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_branches(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetBranches");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the blocks at the given height.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_blocks_at_height(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHeight>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetBlocksAtHeight");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Submit a transaction.
        pub async fn send_transaction(
            &mut self,
            request: impl tonic::IntoRequest<super::SendTransactionRequest>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/SendTransaction");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Start the baker in the consensus module.
        pub async fn start_baker(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/StartBaker");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Stop the baker in the consensus module.
        pub async fn stop_baker(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/StopBaker");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of accounts that exist in the state after the given
        /// block. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_account_list(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetAccountList");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get all smart contract instances that exist in the state after the
        /// given block. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_instances(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetInstances");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about an account.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_account_info(
            &mut self,
            request: impl tonic::IntoRequest<super::GetAddressInfoRequest>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetAccountInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get information about a smart contract instance.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_instance_info(
            &mut self,
            request: impl tonic::IntoRequest<super::GetAddressInfoRequest>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetInstanceInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Invoke a smart contract instance and view the result *as if* it had
        /// been updated at the end of the provided block. This is *not*
        /// a transaction. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn invoke_contract(
            &mut self,
            request: impl tonic::IntoRequest<super::InvokeContractRequest>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/InvokeContract");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get an overview of the balance of special accounts in the given
        /// block. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_reward_status(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetRewardStatus");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get an overview of the parameters used for baking.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_birk_parameters(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetBirkParameters");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of smart contract modules that exist in the state after
        /// the given block. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_module_list(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetModuleList");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the source of a smart contract module.
        pub async fn get_module_source(
            &mut self,
            request: impl tonic::IntoRequest<super::GetModuleSourceRequest>,
        ) -> Result<tonic::Response<super::BytesResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetModuleSource");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of all identity providers that exist in the state after
        /// the given block. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_identity_providers(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetIdentityProviders");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of all anonymity revokers that exist in the state after
        /// the given block. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_anonymity_revokers(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetAnonymityRevokers");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the cryptographic parameters used in the given block.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_cryptographic_parameters(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.P2P/GetCryptographicParameters");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of all baker IDs registered at that block in ascending
        /// order. Or null, if the block is invalid. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_baker_list(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetBakerList");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get the status of a pool. If passiveDelegation == true, this returns
        /// the status for the passive delegators. Otherwise, it returns
        /// the status for the baker with the specified ID (if it exists). A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_pool_status(
            &mut self,
            request: impl tonic::IntoRequest<super::GetPoolStatusRequest>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetPoolStatus");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Get a list of banned peers.
        pub async fn get_banned_peers(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::PeerListResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetBannedPeers");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Shut down the node.
        pub async fn shutdown(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/Shutdown");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Start dumping packages into the specified file.
        /// Only enabled if the node was built with the `network_dump` feature.
        pub async fn dump_start(
            &mut self,
            request: impl tonic::IntoRequest<super::DumpRequest>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/DumpStart");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Stop dumping packages.
        /// Only enabled if the node was built with the `network_dump` feature.
        pub async fn dump_stop(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> Result<tonic::Response<super::BoolResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/DumpStop");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Query for the status of a transaction by its hash.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_transaction_status(
            &mut self,
            request: impl tonic::IntoRequest<super::TransactionHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetTransactionStatus");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Query for transactions in a block by its hash.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_transaction_status_in_block(
            &mut self,
            request: impl tonic::IntoRequest<super::GetTransactionStatusInBlockRequest>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/concordium.P2P/GetTransactionStatusInBlock");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Query for non-finalized transactions present on an account by the
        /// account address. A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_account_non_finalized_transactions(
            &mut self,
            request: impl tonic::IntoRequest<super::AccountAddress>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.P2P/GetAccountNonFinalizedTransactions",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Request a summary for a block by its hash.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_block_summary(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockHash>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetBlockSummary");
            self.inner.unary(request.into_request(), path, codec).await
        }

        /// Request next nonce information for an account.
        /// A JSON schema for the return type is provided at: https://developer.concordium.software/en/mainnet/net/references/grpc.html.
        pub async fn get_next_account_nonce(
            &mut self,
            request: impl tonic::IntoRequest<super::AccountAddress>,
        ) -> Result<tonic::Response<super::JsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/concordium.P2P/GetNextAccountNonce");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
