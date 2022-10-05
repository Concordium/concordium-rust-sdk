use crate::{
    endpoints,
    types::{
        self,
        bans::BannedPeer,
        hashes,
        hashes::{BlockHash, TransactionHash},
        smart_contracts::{ContractContext, InstanceInfo, InvokeContractResult, ModuleRef},
        AbsoluteBlockHeight, AccountInfo, CredentialRegistrationID, TransactionStatus,
    },
};
use concordium_contracts_common::{AccountAddress, Amount, ContractAddress, ReceiveName};
use futures::{Stream, StreamExt};
use tonic::IntoRequest;

pub mod generated;

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
            value: crypto_common::to_bytes(addr),
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
                    value: crypto_common::to_bytes(credid),
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
            impl Stream<Item = Result<id::types::IpInfo<id::constants::IpPairing>, tonic::Status>>,
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
            impl Stream<Item = Result<id::types::ArInfo<id::constants::ArCurve>, tonic::Status>>,
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

    /// Get a vector of the banned peers.
    pub async fn get_banned_peers(
        &mut self,
    ) -> endpoints::RPCResult<Vec<super::types::bans::BannedPeer>> {
        Ok(self
            .client
            .get_banned_peers(generated::Empty::default())
            .await?
            .into_inner()
            .peers
            .into_iter()
            .map(super::types::bans::BannedPeer::try_from)
            .collect::<anyhow::Result<Vec<BannedPeer>>>()?)
    }

    /// Ban a peer
    /// Returns whether the peer was banned or not.
    pub async fn ban_peer(
        &mut self,
        peer_to_ban: super::types::bans::PeerToBan,
    ) -> endpoints::RPCResult<bool> {
        Ok(self.client.ban_peer(peer_to_ban).await?.into_inner().value)
    }

    /// Unban a peer
    /// Returns whether the peer was unbanned or not.
    pub async fn unban_peer(
        &mut self,
        banned_peer: super::types::bans::BannedPeer,
    ) -> endpoints::RPCResult<bool> {
        Ok(self
            .client
            .unban_peer(banned_peer)
            .await?
            .into_inner()
            .value)
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
