use crate::{
    endpoints,
    types::{
        self, hashes,
        hashes::{BlockHash, TransactionHash},
        smart_contracts::{ContractContext, InstanceInfo, InvokeContractResult, ModuleRef},
        AbsoluteBlockHeight, AccountInfo, CredentialRegistrationID, TransactionStatus,
    },
};
use concordium_base::contracts_common::{AccountAddress, Amount, ContractAddress, ReceiveName};
use futures::{Stream, StreamExt};
use tonic::IntoRequest;

mod generated;

#[derive(Clone, Debug)]
/// Client that can perform queries.
/// All endpoints take a `&mut self` as an argument which means that a single
/// instance cannot be used concurrently. However instead of putting the Client
/// behind a Mutex, the intended way to use it is to clone it. Cloning is very
/// cheap and will reuse the underlying connection.
pub struct Client {
    client: generated::queries_client::QueriesClient<tonic::transport::Channel>,
}

#[derive(Clone, Copy, Debug)]
pub struct QueryResponse<A> {
    /// Block hash for which the query applies.
    pub block_hash: BlockHash,
    pub response:   A,
}

/// A block identifier used in queries.
#[derive(Copy, Clone, Debug, derive_more::From)]
pub enum BlockIdentifier {
    /// Query in the context of the best block.
    Best,
    /// Query in the context of the last finalized block at the time of the
    /// query.
    LastFinal,
    /// Query in the context of a specific block hash.
    Given(BlockHash),
}

#[derive(Copy, Clone, Debug, derive_more::From)]
pub enum AccountIdentifier {
    /// Identify an account by an address.
    Address(AccountAddress),
    /// Identify an account by the credential registration id.
    CredId(CredentialRegistrationID),
    /// Identify an account by its account index.
    Index(crate::types::AccountIndex),
}

#[derive(Copy, Clone, Debug)]
pub struct FinalizedBlockInfo {
    pub block_hash: BlockHash,
    pub height:     AbsoluteBlockHeight,
}

impl From<&BlockIdentifier> for generated::BlockHashInput {
    fn from(bi: &BlockIdentifier) -> Self {
        let block_hash_input = match bi {
            BlockIdentifier::Best => {
                generated::block_hash_input::BlockHashInput::Best(Default::default())
            }
            BlockIdentifier::LastFinal => {
                generated::block_hash_input::BlockHashInput::LastFinal(Default::default())
            }
            BlockIdentifier::Given(h) => {
                generated::block_hash_input::BlockHashInput::Given(generated::BlockHash {
                    value: h.as_ref().to_vec(),
                })
            }
        };
        generated::BlockHashInput {
            block_hash_input: Some(block_hash_input),
        }
    }
}

impl IntoRequest<generated::BlockHashInput> for &BlockIdentifier {
    fn into_request(self) -> tonic::Request<generated::BlockHashInput> {
        tonic::Request::new(self.into())
    }
}

impl From<&AccountAddress> for generated::AccountAddress {
    fn from(addr: &AccountAddress) -> Self {
        generated::AccountAddress {
            value: concordium_base::common::to_bytes(addr),
        }
    }
}

impl From<&super::types::Address> for generated::Address {
    fn from(addr: &super::types::Address) -> Self {
        let ty = match addr {
            super::types::Address::Account(account) => {
                generated::address::Type::Account(account.into())
            }
            super::types::Address::Contract(contract) => {
                generated::address::Type::Contract(contract.into())
            }
        };
        generated::Address { r#type: Some(ty) }
    }
}

impl From<&ModuleRef> for generated::ModuleRef {
    fn from(mr: &ModuleRef) -> Self { generated::ModuleRef { value: mr.to_vec() } }
}

impl From<Amount> for generated::Amount {
    fn from(a: Amount) -> Self {
        generated::Amount {
            value: a.micro_ccd(),
        }
    }
}

impl<'a> From<ReceiveName<'a>> for generated::ReceiveName {
    fn from(a: ReceiveName<'a>) -> Self {
        generated::ReceiveName {
            value: a.get_chain_name().to_string(),
        }
    }
}

impl From<&[u8]> for generated::Parameter {
    fn from(a: &[u8]) -> Self { generated::Parameter { value: a.to_vec() } }
}

impl From<types::Energy> for generated::Energy {
    fn from(a: types::Energy) -> Self { generated::Energy { value: a.into() } }
}

impl From<&TransactionHash> for generated::TransactionHash {
    fn from(th: &TransactionHash) -> Self { generated::TransactionHash { value: th.to_vec() } }
}

impl From<&ContractAddress> for generated::ContractAddress {
    fn from(ca: &ContractAddress) -> Self {
        generated::ContractAddress {
            index:    ca.index,
            subindex: ca.subindex,
        }
    }
}

impl From<&AccountIdentifier> for generated::AccountIdentifierInput {
    fn from(ai: &AccountIdentifier) -> Self {
        let account_identifier_input = match ai {
            AccountIdentifier::Address(addr) => {
                generated::account_identifier_input::AccountIdentifierInput::Address(addr.into())
            }
            AccountIdentifier::CredId(credid) => {
                let credid = generated::CredentialRegistrationId {
                    value: concordium_base::common::to_bytes(credid),
                };
                generated::account_identifier_input::AccountIdentifierInput::CredId(credid)
            }
            AccountIdentifier::Index(index) => {
                generated::account_identifier_input::AccountIdentifierInput::AccountIndex(
                    (*index).into(),
                )
            }
        };
        generated::AccountIdentifierInput {
            account_identifier_input: Some(account_identifier_input),
        }
    }
}

impl IntoRequest<generated::AccountInfoRequest> for (&AccountIdentifier, &BlockIdentifier) {
    fn into_request(self) -> tonic::Request<generated::AccountInfoRequest> {
        let ai = generated::AccountInfoRequest {
            block_hash:         Some(self.1.into()),
            account_identifier: Some(self.0.into()),
        };
        tonic::Request::new(ai)
    }
}

impl IntoRequest<generated::AncestorsRequest> for (&BlockIdentifier, u64) {
    fn into_request(self) -> tonic::Request<generated::AncestorsRequest> {
        let ar = generated::AncestorsRequest {
            block_hash: Some(self.0.into()),
            amount:     self.1,
        };
        tonic::Request::new(ar)
    }
}

impl IntoRequest<generated::ModuleSourceRequest> for (&ModuleRef, &BlockIdentifier) {
    fn into_request(self) -> tonic::Request<generated::ModuleSourceRequest> {
        let r = generated::ModuleSourceRequest {
            block_hash: Some(self.1.into()),
            module_ref: Some(self.0.into()),
        };
        tonic::Request::new(r)
    }
}

impl IntoRequest<generated::InstanceInfoRequest> for (ContractAddress, &BlockIdentifier) {
    fn into_request(self) -> tonic::Request<generated::InstanceInfoRequest> {
        let r = generated::InstanceInfoRequest {
            block_hash: Some(self.1.into()),
            address:    Some(self.0.into()),
        };
        tonic::Request::new(r)
    }
}

impl<V: Into<Vec<u8>>> IntoRequest<generated::InstanceStateLookupRequest>
    for (ContractAddress, &BlockIdentifier, V)
{
    fn into_request(self) -> tonic::Request<generated::InstanceStateLookupRequest> {
        let r = generated::InstanceStateLookupRequest {
            block_hash: Some(self.1.into()),
            address:    Some(self.0.into()),
            key:        self.2.into(),
        };
        tonic::Request::new(r)
    }
}

impl IntoRequest<generated::TransactionHash> for &TransactionHash {
    fn into_request(self) -> tonic::Request<generated::TransactionHash> {
        tonic::Request::new(self.into())
    }
}

impl IntoRequest<generated::AccountIdentifierInput> for &AccountIdentifier {
    fn into_request(self) -> tonic::Request<generated::AccountIdentifierInput> {
        tonic::Request::new(self.into())
    }
}

impl IntoRequest<generated::AccountAddress> for &AccountAddress {
    fn into_request(self) -> tonic::Request<generated::AccountAddress> {
        tonic::Request::new(self.into())
    }
}

impl IntoRequest<generated::InvokeInstanceRequest> for (&BlockIdentifier, &ContractContext) {
    fn into_request(self) -> tonic::Request<generated::InvokeInstanceRequest> {
        let (block, context) = self;
        tonic::Request::new(generated::InvokeInstanceRequest {
            block_hash: Some(block.into()),
            invoker:    context.invoker.as_ref().map(|a| a.into()),
            instance:   Some((&context.contract).into()),
            amount:     Some(context.amount.into()),
            entrypoint: Some(context.method.as_receive_name().into()),
            parameter:  Some(context.parameter.as_ref().as_slice().into()),
            energy:     Some(context.energy.into()),
        })
    }
}

impl IntoRequest<generated::PoolInfoRequest> for (&BlockIdentifier, types::BakerId) {
    fn into_request(self) -> tonic::Request<generated::PoolInfoRequest> {
        let req = generated::PoolInfoRequest {
            block_hash: Some(self.0.into()),
            baker:      Some(self.1.into()),
        };
        tonic::Request::new(req)
    }
}

impl IntoRequest<generated::BlocksAtHeightRequest> for &endpoints::BlocksAtHeightInput {
    fn into_request(self) -> tonic::Request<generated::BlocksAtHeightRequest> {
        tonic::Request::new(self.into())
    }
}

impl IntoRequest<generated::GetPoolDelegatorsRequest> for (&BlockIdentifier, types::BakerId) {
    fn into_request(self) -> tonic::Request<generated::GetPoolDelegatorsRequest> {
        let req = generated::GetPoolDelegatorsRequest {
            block_hash: Some(self.0.into()),
            baker:      Some(self.1.into()),
        };
        tonic::Request::new(req)
    }
}

impl TryFrom<crate::v2::generated::BannedPeer> for types::network::BannedPeer {
    type Error = anyhow::Error;

    fn try_from(value: crate::v2::generated::BannedPeer) -> Result<Self, Self::Error> {
        Ok(types::network::BannedPeer(
            <std::net::IpAddr as std::str::FromStr>::from_str(&value.ip_address.require()?.value)?,
        ))
    }
}

impl TryFrom<generated::IpSocketAddress> for std::net::SocketAddr {
    type Error = anyhow::Error;

    fn try_from(value: generated::IpSocketAddress) -> Result<Self, Self::Error> {
        Ok(std::net::SocketAddr::new(
            <std::net::IpAddr as std::str::FromStr>::from_str(&value.ip.require()?.value)?,
            value.port.require()?.value as u16,
        ))
    }
}

impl IntoRequest<crate::v2::generated::BannedPeer> for &types::network::BannedPeer {
    fn into_request(self) -> tonic::Request<crate::v2::generated::BannedPeer> {
        tonic::Request::new(crate::v2::generated::BannedPeer {
            ip_address: Some(crate::v2::generated::IpAddress {
                value: self.0.to_string(),
            }),
        })
    }
}

impl From<generated::PeerId> for types::network::PeerId {
    fn from(value: generated::PeerId) -> Self { types::network::PeerId(value.value) }
}

impl TryFrom<generated::PeersInfo> for types::network::PeersInfo {
    type Error = anyhow::Error;

    fn try_from(peers_info: generated::PeersInfo) -> Result<Self, Self::Error> {
        // Get information of the peers that the node is connected to.
        // Note. If one peer contains malformed data then this function does not
        // return any information about the others.
        // This should only happen in cases where the sdk and node is not on the same
        // major version.
        let peers = peers_info
            .peers
            .into_iter()
            .map(|peer| {
                // Parse the catchup status of the peer.
                let peer_consensus_info = match peer.consensus_info.require()? {
                    generated::peers_info::peer::ConsensusInfo::Bootstrapper(_) => {
                        types::network::PeerConsensusInfo::Bootstrapper
                    }
                    generated::peers_info::peer::ConsensusInfo::NodeCatchupStatus(0) => {
                        types::network::PeerConsensusInfo::Node(
                            types::network::PeerCatchupStatus::UpToDate,
                        )
                    }
                    generated::peers_info::peer::ConsensusInfo::NodeCatchupStatus(1) => {
                        types::network::PeerConsensusInfo::Node(
                            types::network::PeerCatchupStatus::Pending,
                        )
                    }
                    generated::peers_info::peer::ConsensusInfo::NodeCatchupStatus(2) => {
                        types::network::PeerConsensusInfo::Node(
                            types::network::PeerCatchupStatus::CatchingUp,
                        )
                    }
                    _ => anyhow::bail!("Malformed catchup status from peer."),
                };
                // Parse the network statistics for the peer.
                let stats = peer.network_stats.require()?;
                let network_stats = types::network::NetworkStats {
                    packets_sent:     stats.packets_sent,
                    packets_received: stats.packets_received,
                    latency:          stats.latency,
                };
                Ok(types::network::Peer {
                    peer_id: peer.peer_id.require()?.into(),
                    consensus_info: peer_consensus_info,
                    network_stats,
                    addr: peer.socket_address.require()?.try_into()?,
                })
            })
            .collect::<anyhow::Result<Vec<types::network::Peer>>>()?;
        Ok(types::network::PeersInfo { peers })
    }
}

impl TryFrom<generated::node_info::NetworkInfo> for types::NetworkInfo {
    type Error = anyhow::Error;

    fn try_from(network_info: generated::node_info::NetworkInfo) -> Result<Self, Self::Error> {
        Ok(types::NetworkInfo {
            node_id:             network_info.node_id.require()?.value,
            peer_total_sent:     network_info.peer_total_sent,
            peer_total_received: network_info.peer_total_received,
            avg_bps_in:          network_info.avg_bps_in,
            avg_bps_out:         network_info.avg_bps_out,
        })
    }
}

impl IntoRequest<crate::v2::generated::PeerToBan> for types::network::PeerToBan {
    fn into_request(self) -> tonic::Request<crate::v2::generated::PeerToBan> {
        tonic::Request::new(match self {
            types::network::PeerToBan::IpAddr(ip_addr) => crate::v2::generated::PeerToBan {
                ip_address: Some(crate::v2::generated::IpAddress {
                    value: ip_addr.to_string(),
                }),
            },
        })
    }
}

impl TryFrom<generated::NodeInfo> for types::NodeInfo {
    type Error = anyhow::Error;

    fn try_from(node_info: generated::NodeInfo) -> Result<Self, Self::Error> {
        let version = semver::Version::parse(&node_info.peer_version)?;
        let local_time = chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH)
            + chrono::Duration::milliseconds(node_info.local_time.require()?.value as i64);
        let uptime = types::DurationSeconds::from(node_info.peer_uptime.require()?.value).into();
        let network_info = node_info.network_info.require()?.try_into()?;
        let details = match node_info.details.require()? {
            generated::node_info::Details::Bootstrapper(_) => types::NodeDetails::Bootstrapper,
            generated::node_info::Details::Node(status) => {
                let consensus_status = match status.consensus_status.require()? {
                    generated::node_info::node::ConsensusStatus::NotRunning(_) => {
                        types::NodeConsensusStatus::ConsensusNotRunning
                    }
                    generated::node_info::node::ConsensusStatus::Passive(_) => {
                        types::NodeConsensusStatus::ConsensusPassive
                    }
                    generated::node_info::node::ConsensusStatus::Active(baker) => {
                        let baker_id = baker.baker_id.require()?.into();
                        match baker.status.require()? {
                            generated::node_info::baker_consensus_info::Status::PassiveCommitteeInfo(0) => types::NodeConsensusStatus::NotInCommittee(baker_id),
                            generated::node_info::baker_consensus_info::Status::PassiveCommitteeInfo(1) => types::NodeConsensusStatus::AddedButNotActiveInCommittee(baker_id),
                            generated::node_info::baker_consensus_info::Status::PassiveCommitteeInfo(2) => types::NodeConsensusStatus::AddedButWrongKeys(baker_id),
                            generated::node_info::baker_consensus_info::Status::ActiveBakerCommitteeInfo(_) => types::NodeConsensusStatus::Baker(baker_id),
                            generated::node_info::baker_consensus_info::Status::ActiveFinalizerCommitteeInfo(_) => types::NodeConsensusStatus::Finalizer(baker_id),
                            _ => anyhow::bail!("Malformed baker status")
                        }
                    }
                };
                types::NodeDetails::Node(consensus_status)
            }
        };
        Ok(types::NodeInfo {
            version,
            local_time,
            uptime,
            network_info,
            details,
        })
    }
}

impl Client {
    pub async fn new<E: Into<tonic::transport::Endpoint>>(
        endpoint: E,
    ) -> Result<Self, tonic::transport::Error> {
        let client = generated::queries_client::QueriesClient::connect(endpoint).await?;
        Ok(Self { client })
    }

    pub async fn get_account_info(
        &mut self,
        acc: &AccountIdentifier,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<AccountInfo>> {
        let response = self.client.get_account_info((acc, bi)).await?;
        let block_hash = extract_metadata(&response)?;
        let response = AccountInfo::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_next_account_sequence_number(
        &mut self,
        account_address: &AccountAddress,
    ) -> endpoints::QueryResult<types::queries::AccountNonceResponse> {
        let response = self
            .client
            .get_next_account_sequence_number(account_address)
            .await?;
        let response = types::queries::AccountNonceResponse::try_from(response.into_inner())?;
        Ok(response)
    }

    pub async fn get_consensus_info(
        &mut self,
    ) -> endpoints::QueryResult<types::queries::ConsensusInfo> {
        let response = self
            .client
            .get_consensus_info(generated::Empty::default())
            .await?;
        let response = types::queries::ConsensusInfo::try_from(response.into_inner())?;
        Ok(response)
    }

    pub async fn get_cryptographic_parameters(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::CryptographicParameters>> {
        let response = self.client.get_cryptographic_parameters(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::CryptographicParameters::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_account_list(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<AccountAddress, tonic::Status>>>,
    > {
        let response = self.client.get_account_list(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.and_then(TryFrom::try_from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_module_list(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<impl Stream<Item = Result<ModuleRef, tonic::Status>>>>
    {
        let response = self.client.get_module_list(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.and_then(TryFrom::try_from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_module_source(
        &mut self,
        module_ref: &ModuleRef,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::smart_contracts::WasmModule>> {
        let response = self.client.get_module_source((module_ref, bi)).await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::smart_contracts::WasmModule::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_instance_list(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<ContractAddress, tonic::Status>>>,
    > {
        let response = self.client.get_instance_list(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.map(From::from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_instance_info(
        &mut self,
        address: ContractAddress,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<InstanceInfo>> {
        let response = self.client.get_instance_info((address, bi)).await?;
        let block_hash = extract_metadata(&response)?;
        let response = InstanceInfo::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_ancestors(
        &mut self,
        bi: &BlockIdentifier,
        amount: u64,
    ) -> endpoints::QueryResult<QueryResponse<impl Stream<Item = Result<BlockHash, tonic::Status>>>>
    {
        let response = self.client.get_ancestors((bi, amount)).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.and_then(TryFrom::try_from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_finalized_blocks(
        &mut self,
    ) -> endpoints::QueryResult<impl Stream<Item = Result<FinalizedBlockInfo, tonic::Status>>> {
        let response = self
            .client
            .get_finalized_blocks(generated::Empty::default())
            .await?;
        let stream = response.into_inner().map(|x| match x {
            Ok(v) => {
                let block_hash = v.hash.require().and_then(TryFrom::try_from)?;
                let height = v.height.require()?.into();
                Ok(FinalizedBlockInfo { block_hash, height })
            }
            Err(x) => Err(x),
        });
        Ok(stream)
    }

    pub async fn get_instance_state(
        &mut self,
        ca: ContractAddress,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<(Vec<u8>, Vec<u8>), tonic::Status>>>,
    > {
        let response = self.client.get_instance_state((ca, bi)).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| match x {
            Ok(v) => {
                let key = v.key;
                let value = v.value;
                Ok((key, value))
            }
            Err(x) => Err(x),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn instance_state_lookup(
        &mut self,
        ca: ContractAddress,
        key: impl Into<Vec<u8>>,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<Vec<u8>>> {
        let response = self.client.instance_state_lookup((ca, bi, key)).await?;
        let block_hash = extract_metadata(&response)?;
        Ok(QueryResponse {
            block_hash,
            response: response.into_inner().value,
        })
    }

    pub async fn get_block_item_status(
        &mut self,
        th: &TransactionHash,
    ) -> endpoints::QueryResult<TransactionStatus> {
        let response = self.client.get_block_item_status(th).await?;
        let response = TransactionStatus::try_from(response.into_inner())?;
        Ok(response)
    }

    pub async fn invoke_instance(
        &mut self,
        bi: &BlockIdentifier,
        context: &ContractContext,
    ) -> endpoints::QueryResult<QueryResponse<InvokeContractResult>> {
        let response = self.client.invoke_instance((bi, context)).await?;
        let block_hash = extract_metadata(&response)?;
        let response = InvokeContractResult::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_block_info(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::queries::BlockInfo>> {
        let response = self.client.get_block_info(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::queries::BlockInfo::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_baker_list(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::BakerId, tonic::Status>>>,
    > {
        let response = self.client.get_baker_list(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.map(From::from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_pool_info(
        &mut self,
        block_id: &BlockIdentifier,
        baker_id: types::BakerId,
    ) -> endpoints::QueryResult<QueryResponse<types::BakerPoolStatus>> {
        let response = self.client.get_pool_info((block_id, baker_id)).await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::BakerPoolStatus::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_passive_delegation_info(
        &mut self,
        block_id: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::PassiveDelegationStatus>> {
        let response = self.client.get_passive_delegation_info(block_id).await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::PassiveDelegationStatus::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_blocks_at_height(
        &mut self,
        blocks_at_height_input: &endpoints::BlocksAtHeightInput,
    ) -> endpoints::QueryResult<Vec<BlockHash>> {
        let response = self
            .client
            .get_blocks_at_height(blocks_at_height_input)
            .await?;
        let blocks = response
            .into_inner()
            .blocks
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<_, tonic::Status>>()?;
        Ok(blocks)
    }

    pub async fn get_tokenomics_info(
        &mut self,
        block_id: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::RewardsOverview>> {
        let response = self.client.get_tokenomics_info(block_id).await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::RewardsOverview::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_pool_delegators(
        &mut self,
        bi: &BlockIdentifier,
        baker_id: types::BakerId,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::DelegatorInfo, tonic::Status>>>,
    > {
        let response = self.client.get_pool_delegators((bi, baker_id)).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(delegator) => delegator.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_pool_delegators_reward_period(
        &mut self,
        bi: &BlockIdentifier,
        baker_id: types::BakerId,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::DelegatorRewardPeriodInfo, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_pool_delegators_reward_period((bi, baker_id))
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(delegator) => delegator.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_passive_delegators(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::DelegatorInfo, tonic::Status>>>,
    > {
        let response = self.client.get_passive_delegators(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(delegator) => delegator.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_passive_delegators_reward_period(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::DelegatorRewardPeriodInfo, tonic::Status>>>,
    > {
        let response = self.client.get_passive_delegators_reward_period(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(delegator) => delegator.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_branches(&mut self) -> endpoints::QueryResult<types::queries::Branch> {
        let response = self
            .client
            .get_branches(generated::Empty::default())
            .await?;
        let response = types::queries::Branch::try_from(response.into_inner())?;
        Ok(response)
    }

    pub async fn get_election_info(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::BirkParameters>> {
        let response = self.client.get_election_info(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::BirkParameters::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    pub async fn get_identity_providers(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<
            impl Stream<
                Item = Result<
                    crate::id::types::IpInfo<crate::id::constants::IpPairing>,
                    tonic::Status,
                >,
            >,
        >,
    > {
        let response = self.client.get_identity_providers(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(ip_info) => ip_info.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_anonymity_revokers(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<
            impl Stream<
                Item = Result<
                    crate::id::types::ArInfo<crate::id::constants::ArCurve>,
                    tonic::Status,
                >,
            >,
        >,
    > {
        let response = self.client.get_anonymity_revokers(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(ar_info) => ar_info.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_account_non_finalized_transactions(
        &mut self,
        account_address: &AccountAddress,
    ) -> endpoints::QueryResult<impl Stream<Item = Result<TransactionHash, tonic::Status>>> {
        let response = self
            .client
            .get_account_non_finalized_transactions(account_address)
            .await?;
        let stream = response.into_inner().map(|result| match result {
            Ok(transaction_hash) => transaction_hash.try_into(),
            Err(err) => Err(err),
        });
        Ok(stream)
    }

    pub async fn shutdown(&mut self) -> endpoints::RPCResult<()> {
        self.client.shutdown(generated::Empty::default()).await?;
        Ok(())
    }

    // Try connect to a peer with the provided address.
    pub async fn peer_connect(&mut self, addr: std::net::SocketAddr) -> endpoints::RPCResult<()> {
        let peer_connection = generated::IpSocketAddress {
            ip:   Some(generated::IpAddress {
                value: addr.ip().to_string(),
            }),
            port: Some(generated::Port {
                value: addr.port() as u32,
            }),
        };
        self.client.peer_connect(peer_connection).await?;
        Ok(())
    }

    // Disconnect a peer at the given address.
    pub async fn peer_disconnect(
        &mut self,
        addr: std::net::SocketAddr,
    ) -> endpoints::RPCResult<()> {
        let peer_connection = generated::IpSocketAddress {
            ip:   Some(generated::IpAddress {
                value: addr.ip().to_string(),
            }),
            port: Some(generated::Port {
                value: addr.port() as u32,
            }),
        };
        self.client.peer_disconnect(peer_connection).await?;
        Ok(())
    }

    /// Get a vector of the banned peers.
    pub async fn get_banned_peers(
        &mut self,
    ) -> endpoints::RPCResult<Vec<super::types::network::BannedPeer>> {
        Ok(self
            .client
            .get_banned_peers(generated::Empty::default())
            .await?
            .into_inner()
            .peers
            .into_iter()
            .map(super::types::network::BannedPeer::try_from)
            .collect::<anyhow::Result<Vec<super::types::network::BannedPeer>>>()?)
    }

    /// Ban a peer
    /// Returns whether the peer was banned or not.
    pub async fn ban_peer(
        &mut self,
        peer_to_ban: super::types::network::PeerToBan,
    ) -> endpoints::RPCResult<()> {
        self.client.ban_peer(peer_to_ban).await?;
        Ok(())
    }

    /// Unban a peer
    /// Returns whether the peer was unbanned or not.
    pub async fn unban_peer(
        &mut self,
        banned_peer: &super::types::network::BannedPeer,
    ) -> endpoints::RPCResult<()> {
        self.client.unban_peer(banned_peer).await?;
        Ok(())
    }

    /// Start a network dump if the feature is enabled on the node.
    /// Return true if a network dump has been initiated.
    ///
    /// * file - The file to write to.
    /// * raw - Whether raw packets should be included in the dump or not.
    ///
    /// Note. If the feature 'network_dump' is not enabled on the node then this
    /// will return a 'Precondition failed' error.
    pub async fn dump_start(&mut self, file: String, raw: bool) -> endpoints::RPCResult<()> {
        self.client
            .dump_start(generated::DumpRequest { file, raw })
            .await?;
        Ok(())
    }

    /// Stop an ongoing network dump.
    /// Return true if it was successfully stopped otherwise false.
    ///
    /// Note. If the feature 'network_dump' is not enabled on the node then this
    /// will return a 'Precondition failed' error.
    pub async fn dump_stop(&mut self) -> endpoints::RPCResult<()> {
        self.client.dump_stop(generated::Empty::default()).await?;
        Ok(())
    }

    /// Retrieve information about the peers that the node is connected to.
    pub async fn get_peers_info(&mut self) -> endpoints::RPCResult<types::network::PeersInfo> {
        let response = self
            .client
            .get_peers_info(generated::Empty::default())
            .await?;
        let peers_info = types::network::PeersInfo::try_from(response.into_inner())?;
        Ok(peers_info)
    }

    /// Retrieve [types::NodeInfo] from the node.
    pub async fn get_node_info(&mut self) -> endpoints::RPCResult<types::NodeInfo> {
        let response = self
            .client
            .get_node_info(generated::Empty::default())
            .await?;
        let node_info = types::NodeInfo::try_from(response.into_inner())?;
        Ok(node_info)
    }
}

fn extract_metadata<T>(response: &tonic::Response<T>) -> endpoints::RPCResult<BlockHash> {
    match response.metadata().get("blockhash") {
        Some(bytes) => {
            let bytes = bytes.as_bytes();
            if bytes.len() == 64 {
                let mut hash = [0u8; 32];
                if hex::decode_to_slice(bytes, &mut hash).is_err() {
                    tonic::Status::unknown("Response does correctly encode the block hash.");
                }
                Ok(hash.into())
            } else {
                Err(endpoints::RPCError::CallError(tonic::Status::unknown(
                    "Response does not include the expected metadata.",
                )))
            }
        }
        None => Err(endpoints::RPCError::CallError(tonic::Status::unknown(
            "Response does not include the expected metadata.",
        ))),
    }
}

/// A helper trait to make it simpler to require specific fields when parsing a
/// protobuf message by allowing us to use method calling syntax and
/// constructing responses that match the calling context, allowing us to use
/// the `?` syntax.
///
/// The main reason for needing this is that in proto3 all fields are optional,
/// so it is up to the application to validate inputs if they are required.
trait Require<E> {
    type A;
    fn require(self) -> Result<Self::A, E>;
}

impl<A> Require<tonic::Status> for Option<A> {
    type A = A;

    fn require(self) -> Result<Self::A, tonic::Status> {
        match self {
            Some(v) => Ok(v),
            None => Err(tonic::Status::invalid_argument("missing field in response")),
        }
    }
}
