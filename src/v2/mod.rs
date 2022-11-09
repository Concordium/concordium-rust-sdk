//! This module exposes [Client](v2::Client) which is a wrapper around the
//! generated gRPC rust client, providing a more ergonomic interface than the
//! generated client. See [Client](v2::Client) for documentation of how to use.

use crate::{
    endpoints, id,
    id::types::AccountCredentialMessage,
    types::{
        self, hashes,
        hashes::{BlockHash, TransactionHash, TransactionSignHash},
        smart_contracts::{
            ContractContext, InstanceInfo, InvokeContractResult, ModuleRef, Parameter, WasmModule,
        },
        transactions::{self, InitContractPayload, UpdateContractPayload, UpdateInstruction},
        AbsoluteBlockHeight, AccountInfo, CredentialRegistrationID, Energy, Memo, Nonce,
        RegisteredData, TransactionStatus, UpdateSequenceNumber,
    },
};
use concordium_base::{
    base::{
        ChainParameterVersion0, ChainParameterVersion1, CredentialsPerBlockLimit,
        ElectionDifficulty, Epoch, ExchangeRate, MintDistributionV0, MintDistributionV1,
    },
    common::{
        self,
        types::{TransactionSignature, TransactionTime},
    },
    contracts_common::{
        AccountAddress, Amount, ContractAddress, OwnedContractName, OwnedReceiveName, ReceiveName,
    },
    transactions::{BlockItem, EncodedPayload, PayloadLike},
    updates::{
        AuthorizationsV0, CooldownParameters, GASRewards, PoolParameters, TimeParameters,
        TransactionFeeDistribution,
    },
};
pub use endpoints::{QueryError, QueryResult, RPCError, RPCResult};
use futures::{Stream, StreamExt};
use std::collections::HashMap;
use tonic::IntoRequest;
pub use tonic::{transport::Endpoint, Status};

mod conversions;
mod generated;

/// A client for gRPC API v2 of the Concordium node. Can be used to control the
/// node, send transactions and query information about the node and the state
/// of the chain.
///
/// # Connecting to a Concordium node
///
/// Creates a new client connection to a Concordium node.
/// Make sure to have access to the gRPC API v2 endpoint of a running node.
///
/// ```no_run
/// # tokio_test::block_on(async {
/// use concordium_rust_sdk::v2::{Client, Endpoint};
/// use std::str::FromStr;
///
/// // Assumes the node is running locally and gRPC API v2 can be accessed on port 20001.
/// let node_endpoint = Endpoint::from_str("http://localhost:20001")?;
/// let mut client = Client::new(node_endpoint).await?;
///
/// // Verify the connection to the node by printing node information.
/// let node_info = client.get_node_info().await?;
/// println!("{:#?}", node_info);
/// # Ok::<(), anyhow::Error>(())
/// # });
/// ```
///
/// # Concurrent use of the client
///
/// All endpoints take a `&mut self` as an argument which means that a single
/// instance cannot be used concurrently. However instead of putting the Client
/// behind a Mutex, the intended way to use it is to clone it. Cloning is very
/// cheap and will reuse the underlying connection.
#[derive(Clone, Debug)]
pub struct Client {
    client: generated::queries_client::QueriesClient<tonic::transport::Channel>,
}

/// A query response with the addition of the block hash used by the query.
/// The block hash used for querying might be unknown when providing the block
/// as [BlockIdentifier::Best] or [BlockIdentifier::LastFinal].
#[derive(Clone, Copy, Debug)]
pub struct QueryResponse<A> {
    /// Block hash for which the query applies.
    pub block_hash: BlockHash,
    /// The result of the query.
    pub response:   A,
}

impl<A> AsRef<A> for QueryResponse<A> {
    fn as_ref(&self) -> &A { &self.response }
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

/// An account identifier used in queries.
#[derive(Copy, Clone, Debug, derive_more::From)]
pub enum AccountIdentifier {
    /// Identify an account by an address.
    Address(AccountAddress),
    /// Identify an account by the credential registration id.
    CredId(CredentialRegistrationID),
    /// Identify an account by its account index.
    Index(crate::types::AccountIndex),
}

/// Information of a finalized block.
#[derive(Copy, Clone, Debug)]
pub struct FinalizedBlockInfo {
    /// The block hash for the finalized block.
    pub block_hash: BlockHash,
    /// The absolute block height for the finalized block.
    pub height:     AbsoluteBlockHeight,
}

#[derive(Debug, Clone)]
/// Values of chain parameters that can be updated via chain updates.
/// This applies to protocol version 1-3.
pub struct ChainParametersV0 {
    /// Election difficulty for consensus lottery.
    pub election_difficulty: ElectionDifficulty,
    /// Euro per energy exchange rate.
    pub euro_per_energy: ExchangeRate,
    /// Micro ccd per euro exchange rate.
    pub micro_ccd_per_euro: ExchangeRate,
    /// Extra number of epochs before reduction in stake, or baker
    /// deregistration is completed.
    pub baker_cooldown_epochs: Epoch,
    /// The limit for the number of account creations in a block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Parameters related to the distribution of newly minted CCD.
    pub mint_distribution: MintDistributionV0,
    /// Parameters related to the distribution of transaction fees.
    pub transaction_fee_distribution: TransactionFeeDistribution,
    /// Parameters related to the distribution of the GAS account.
    pub gas_rewards: GASRewards,
    /// Address of the foundation account.
    pub foundation_account: AccountAddress,
    /// Minimum threshold for becoming a baker.
    pub minimum_threshold_for_baking: Amount,
    /// Keys allowed to do updates.
    pub keys: types::UpdateKeysCollection<ChainParameterVersion0>,
}

#[derive(Debug, Clone)]
/// Values of chain parameters that can be updated via chain updates.
/// This applies to protocol version 4 and up.
pub struct ChainParametersV1 {
    /// Election difficulty for consensus lottery.
    pub election_difficulty: ElectionDifficulty,
    /// Euro per energy exchange rate.
    pub euro_per_energy: ExchangeRate,
    /// Micro ccd per euro exchange rate.
    pub micro_ccd_per_euro: ExchangeRate,
    pub cooldown_parameters: CooldownParameters,
    pub time_parameters: TimeParameters,
    /// The limit for the number of account creations in a block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Parameters related to the distribution of newly minted CCD.
    pub mint_distribution: MintDistributionV1,
    /// Parameters related to the distribution of transaction fees.
    pub transaction_fee_distribution: TransactionFeeDistribution,
    /// Parameters related to the distribution of the GAS account.
    pub gas_rewards: GASRewards,
    /// Address of the foundation account.
    pub foundation_account: AccountAddress,
    /// Parameters for baker pools.
    pub pool_parameters: PoolParameters,
    /// Keys allowed to do updates.
    pub keys: types::UpdateKeysCollection<ChainParameterVersion1>,
}

/// Chain parameters. See [`ChainParametersV0`] and [`ChainParametersV1`] for
/// details. `V0` parameters apply to protocol version `1..=3`, and `V1`
/// parameters apply to protocol versions `4` and up.
#[derive(Debug, Clone)]
pub enum ChainParameters {
    V0(ChainParametersV0),
    V1(ChainParametersV1),
}

impl ChainParameters {
    /// Get the keys for parameter updates that are common to all versions.
    pub fn common_update_keys(&self) -> &AuthorizationsV0 {
        match self {
            Self::V0(data) => &data.keys.level_2_keys,
            Self::V1(data) => &data.keys.level_2_keys.v0,
        }
    }
}

impl ChainParameters {
    /// Compute the exchange rate between `microCCD` and `NRG`.
    pub fn micro_ccd_per_energy(&self) -> num::rational::Ratio<u128> {
        let (num, denom) = match self {
            ChainParameters::V0(v0) => {
                let x = v0.micro_ccd_per_euro;
                let y = v0.euro_per_energy;
                (
                    u128::from(x.numerator()) * u128::from(y.numerator()),
                    u128::from(y.denominator()) * u128::from(y.denominator()),
                )
            }
            ChainParameters::V1(v1) => {
                let x = v1.micro_ccd_per_euro;
                let y = v1.euro_per_energy;
                (
                    u128::from(x.numerator()) * u128::from(y.numerator()),
                    u128::from(y.denominator()) * u128::from(y.denominator()),
                )
            }
        };
        num::rational::Ratio::new(num, denom)
    }

    /// The foundation account that gets the foundation tax.
    pub fn foundation_account(&self) -> AccountAddress {
        match self {
            ChainParameters::V0(v0) => v0.foundation_account,
            ChainParameters::V1(v1) => v1.foundation_account,
        }
    }
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

impl From<AccountAddress> for generated::AccountAddress {
    fn from(addr: AccountAddress) -> Self {
        generated::AccountAddress {
            value: common::to_bytes(&addr),
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

impl From<&Memo> for generated::Memo {
    fn from(v: &Memo) -> Self {
        Self {
            value: v.as_ref().clone(),
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

impl From<&RegisteredData> for generated::RegisteredData {
    fn from(v: &RegisteredData) -> Self {
        Self {
            value: v.as_ref().clone(),
        }
    }
}
impl From<&[u8]> for generated::Parameter {
    fn from(a: &[u8]) -> Self { generated::Parameter { value: a.to_vec() } }
}

impl From<&TransactionHash> for generated::TransactionHash {
    fn from(th: &TransactionHash) -> Self { generated::TransactionHash { value: th.to_vec() } }
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

impl From<&ModuleRef> for generated::ModuleRef {
    fn from(mr: &ModuleRef) -> Self { Self { value: mr.to_vec() } }
}

impl From<ModuleRef> for generated::ModuleRef {
    fn from(mr: ModuleRef) -> Self { Self { value: mr.to_vec() } }
}

impl From<&WasmModule> for generated::VersionedModuleSource {
    fn from(v: &WasmModule) -> Self {
        Self {
            module: Some(match v.version {
                types::smart_contracts::WasmVersion::V0 => {
                    generated::versioned_module_source::Module::V0(
                        generated::versioned_module_source::ModuleSourceV0 {
                            value: v.source.as_ref().clone(),
                        },
                    )
                }
                types::smart_contracts::WasmVersion::V1 => {
                    generated::versioned_module_source::Module::V1(
                        generated::versioned_module_source::ModuleSourceV1 {
                            value: v.source.as_ref().clone(),
                        },
                    )
                }
            }),
        }
    }
}

impl From<&OwnedContractName> for generated::InitName {
    fn from(v: &OwnedContractName) -> Self {
        Self {
            value: v.as_contract_name().get_chain_name().to_string(),
        }
    }
}

impl From<&OwnedReceiveName> for generated::ReceiveName {
    fn from(v: &OwnedReceiveName) -> Self {
        Self {
            value: v.as_receive_name().get_chain_name().to_string(),
        }
    }
}

impl From<&Parameter> for generated::Parameter {
    fn from(v: &Parameter) -> Self {
        Self {
            value: v.as_ref().clone(),
        }
    }
}

impl From<&InitContractPayload> for generated::InitContractPayload {
    fn from(v: &InitContractPayload) -> Self {
        Self {
            amount:     Some(v.amount.into()),
            module_ref: Some(v.mod_ref.into()),
            init_name:  Some((&v.init_name).into()),
            parameter:  Some((&v.param).into()),
        }
    }
}

impl From<&UpdateContractPayload> for generated::UpdateContractPayload {
    fn from(v: &UpdateContractPayload) -> Self {
        Self {
            amount:       Some(v.amount.into()),
            address:      Some(v.address.into()),
            receive_name: Some((&v.receive_name).into()),
            parameter:    Some((&v.message).into()),
        }
    }
}

impl From<&ContractAddress> for generated::ContractAddress {
    fn from(ca: &ContractAddress) -> Self {
        Self {
            index:    ca.index,
            subindex: ca.subindex,
        }
    }
}

impl From<Nonce> for generated::SequenceNumber {
    fn from(v: Nonce) -> Self { generated::SequenceNumber { value: v.nonce } }
}

impl From<UpdateSequenceNumber> for generated::UpdateSequenceNumber {
    fn from(v: UpdateSequenceNumber) -> Self { generated::UpdateSequenceNumber { value: v.number } }
}

impl From<Energy> for generated::Energy {
    fn from(v: Energy) -> Self { generated::Energy { value: v.energy } }
}

impl From<TransactionTime> for generated::TransactionTime {
    fn from(v: TransactionTime) -> Self { generated::TransactionTime { value: v.seconds } }
}

impl From<&Amount> for generated::Amount {
    fn from(v: &Amount) -> Self { Self { value: v.micro_ccd } }
}

impl From<Amount> for generated::Amount {
    fn from(v: Amount) -> Self { Self { value: v.micro_ccd } }
}

impl
    From<
        &AccountCredentialMessage<
            id::constants::IpPairing,
            id::constants::ArCurve,
            id::constants::AttributeKind,
        >,
    > for generated::CredentialDeployment
{
    fn from(
        v: &AccountCredentialMessage<
            id::constants::IpPairing,
            id::constants::ArCurve,
            id::constants::AttributeKind,
        >,
    ) -> Self {
        Self {
            message_expiry: Some(v.message_expiry.into()),
            payload:        Some(generated::credential_deployment::Payload::RawPayload(
                common::to_bytes(&v.credential),
            )),
        }
    }
}

impl From<&UpdateInstruction> for generated::UpdateInstruction {
    fn from(v: &UpdateInstruction) -> Self {
        Self {
            signatures: Some(generated::SignatureMap {
                signatures: {
                    let mut hm = HashMap::new();
                    for (key_idx, sig) in v.signatures.signatures.iter() {
                        hm.insert(key_idx.index.into(), generated::Signature {
                            value: sig.sig.to_owned(),
                        });
                    }
                    hm
                },
            }),
            header:     Some(generated::UpdateInstructionHeader {
                sequence_number: Some(v.header.seq_number.into()),
                effective_time:  Some(v.header.effective_time.into()),
                timeout:         Some(v.header.timeout.into()),
            }),
            payload:    Some(generated::UpdateInstructionPayload {
                payload: Some(generated::update_instruction_payload::Payload::RawPayload(
                    common::to_bytes(&v.payload),
                )),
            }),
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

impl From<transactions::TransactionHeader> for generated::AccountTransactionHeader {
    fn from(v: transactions::TransactionHeader) -> Self { (&v).into() }
}

impl From<&transactions::TransactionHeader> for generated::AccountTransactionHeader {
    fn from(v: &transactions::TransactionHeader) -> Self {
        Self {
            sender:          Some(generated::AccountAddress::from(v.sender)),
            sequence_number: Some(v.nonce.into()),
            energy_amount:   Some(v.energy_amount.into()),
            expiry:          Some(v.expiry.into()),
        }
    }
}

impl From<TransactionSignature> for generated::AccountTransactionSignature {
    fn from(v: TransactionSignature) -> Self { (&v).into() }
}

impl From<&TransactionSignature> for generated::AccountTransactionSignature {
    fn from(v: &TransactionSignature) -> Self {
        Self {
            signatures: {
                let mut cred_map: HashMap<u32, generated::AccountSignatureMap> = HashMap::new();
                for (cred_idx, sig_map) in v.signatures.iter() {
                    let mut acc_sig_map: HashMap<u32, generated::Signature> = HashMap::new();
                    for (key_idx, sig) in sig_map.iter() {
                        acc_sig_map.insert(key_idx.0.into(), generated::Signature {
                            value: sig.sig.to_owned(),
                        });
                    }
                    cred_map.insert(cred_idx.index.into(), generated::AccountSignatureMap {
                        signatures: acc_sig_map,
                    });
                }
                cred_map
            },
        }
    }
}

impl IntoRequest<generated::PreAccountTransaction>
    for (&transactions::TransactionHeader, &transactions::Payload)
{
    fn into_request(self) -> tonic::Request<generated::PreAccountTransaction> {
        let request = generated::PreAccountTransaction {
            header:  Some(self.0.into()),
            payload: Some(generated::AccountTransactionPayload {
                payload: Some(generated::account_transaction_payload::Payload::RawPayload(
                    self.1.encode().into(),
                )),
            }),
        };
        tonic::Request::new(request)
    }
}

impl<P: PayloadLike> IntoRequest<generated::SendBlockItemRequest> for &transactions::BlockItem<P> {
    fn into_request(self) -> tonic::Request<generated::SendBlockItemRequest> {
        let request = match self {
            transactions::BlockItem::AccountTransaction(v) => {
                generated::SendBlockItemRequest {
                    block_item: Some(
                        generated::send_block_item_request::BlockItem::AccountTransaction(
                            generated::AccountTransaction {
                                signature: Some((&v.signature).into()),
                                header:    Some((&v.header).into()),
                                payload:   {
                                    let atp = generated::AccountTransactionPayload{
                                    payload: Some(generated::account_transaction_payload::Payload::RawPayload(v.payload.encode().into())),
                                };
                                    Some(atp)
                                },
                            },
                        ),
                    ),
                }
            }
            transactions::BlockItem::CredentialDeployment(v) => generated::SendBlockItemRequest {
                block_item: Some(
                    generated::send_block_item_request::BlockItem::CredentialDeployment(
                        v.as_ref().into(),
                    ),
                ),
            },
            transactions::BlockItem::UpdateInstruction(v) => generated::SendBlockItemRequest {
                block_item: Some(
                    generated::send_block_item_request::BlockItem::UpdateInstruction(v.into()),
                ),
            },
        };
        tonic::Request::new(request)
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

/// A helper trait that is implemented by types that can be cheaply converted to
/// a [`BlockIdentifier`]. This is esentially [`Into<BlockIdentifier>`] but
/// orphan rules prevent using that exactly.
///
/// This trait makes it convenient to use block hashes as input to functions
/// that take a block identifier.
pub trait IntoBlockIdentifier {
    fn into_block_identifier(self) -> BlockIdentifier;
}

impl IntoBlockIdentifier for BlockIdentifier {
    fn into_block_identifier(self) -> BlockIdentifier { self }
}

impl<X: IntoBlockIdentifier + Copy> IntoBlockIdentifier for &X {
    fn into_block_identifier(self) -> BlockIdentifier { (*self).into_block_identifier() }
}

impl IntoBlockIdentifier for BlockHash {
    fn into_block_identifier(self) -> BlockIdentifier { BlockIdentifier::Given(self) }
}

impl Client {
    /// Construct a new client connection to a concordium node.
    ///
    /// # Example
    /// Creates a new client. Note the example assumes access to a local running
    /// node.
    ///
    /// ```no_run
    /// # tokio_test::block_on(async {
    /// use concordium_rust_sdk::{endpoints::Endpoint, v2::Client};
    /// use std::str::FromStr;
    ///
    /// let node_endpoint = Endpoint::from_str("http://localhost:20001")?;
    /// let mut client = Client::new(node_endpoint).await?;
    ///
    /// # Ok::<(), anyhow::Error>(())
    /// # });
    /// ```
    pub async fn new<E: Into<tonic::transport::Endpoint>>(
        endpoint: E,
    ) -> Result<Self, tonic::transport::Error> {
        let client = generated::queries_client::QueriesClient::connect(endpoint).await?;
        Ok(Self { client })
    }

    /// Get the information for the given account in the given block. If either
    /// the block or the account do not exist [`QueryError::NotFound`] is
    /// returned.
    pub async fn get_account_info(
        &mut self,
        acc: &AccountIdentifier,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<AccountInfo>> {
        let response = self
            .client
            .get_account_info((acc, &bi.into_block_identifier()))
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = AccountInfo::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get the next sequence number for the account, with information on how
    /// reliable the information is.
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

    /// Get information about the current state of consensus. This is an
    /// overview of the node's current view of the chain.
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

    /// Get the currently used cryptographic parameters. If the block does
    /// not exist [`QueryError::NotFound`] is returned.
    pub async fn get_cryptographic_parameters(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::CryptographicParameters>> {
        let response = self
            .client
            .get_cryptographic_parameters(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::CryptographicParameters::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get the list of accounts in the given block.
    /// The stream will end when all accounts that exist in the state at the end
    /// of the given block have been returned. If the block does not exist
    /// [`QueryError::NotFound`] is returned.
    pub async fn get_account_list(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<AccountAddress, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_account_list(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.and_then(TryFrom::try_from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Get a list of all smart contract modules. The stream will end
    /// when all modules that exist in the state at the end of the given
    /// block have been returned.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    pub async fn get_module_list(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<impl Stream<Item = Result<ModuleRef, tonic::Status>>>>
    {
        let response = self
            .client
            .get_module_list(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.and_then(TryFrom::try_from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Get the source of a smart contract module.
    /// If the block or module does not exist [`QueryError::NotFound`] is
    /// returned.
    pub async fn get_module_source(
        &mut self,
        module_ref: &ModuleRef,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::smart_contracts::WasmModule>> {
        let response = self
            .client
            .get_module_source((module_ref, &bi.into_block_identifier()))
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::smart_contracts::WasmModule::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get the list of smart contract instances in a given block.
    /// The stream will end when all instances that exist in the state at the
    /// end of the given block have been returned. If the block does not
    /// exist [`QueryError::NotFound`] is returned.
    pub async fn get_instance_list(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<ContractAddress, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_instance_list(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.map(From::from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Get information about a smart contract instance as it appears at the end
    /// of the given block. If the block or instance does not exist
    /// [`QueryError::NotFound`] is returned.
    pub async fn get_instance_info(
        &mut self,
        address: ContractAddress,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<InstanceInfo>> {
        let response = self
            .client
            .get_instance_info((address, &bi.into_block_identifier()))
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = InstanceInfo::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get a stream of ancestors for the provided block.
    /// Starting with the provided block itself, moving backwards until no more
    /// ancestors or the requested number of ancestors have been returned.
    pub async fn get_ancestors(
        &mut self,
        bi: impl IntoBlockIdentifier,
        limit: u64,
    ) -> endpoints::QueryResult<QueryResponse<impl Stream<Item = Result<BlockHash, tonic::Status>>>>
    {
        let response = self
            .client
            .get_ancestors((&bi.into_block_identifier(), limit))
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.and_then(TryFrom::try_from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Return a stream of blocks that are finalized from the time the query is
    /// made onward.
    /// This can be used to listen for newly finalized blocks.
    ///
    /// Note: There is no guarantee that blocks will not be skipped if the
    /// client is too slow in processing the stream, however blocks will
    /// always be sent by increasing block height.
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

    /// Get the exact state of a specific contract instance, streamed as a list
    /// of key-value pairs. The list is streamed in lexicographic order of
    /// keys.
    /// If the block or instance does not exist [`QueryError::NotFound`] is
    /// returned.
    pub async fn get_instance_state(
        &mut self,
        ca: ContractAddress,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<(Vec<u8>, Vec<u8>), tonic::Status>>>,
    > {
        let response = self
            .client
            .get_instance_state((ca, &bi.into_block_identifier()))
            .await?;
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

    /// Get the value at a specific key of a contract state. In contrast to
    /// [`get_instance_state`](Self::get_instance_state) this is more efficient,
    /// but requires the user to know the specific key to look for.
    /// If the block or instance does not exist [`QueryError::NotFound`] is
    /// returned.
    pub async fn instance_state_lookup(
        &mut self,
        ca: ContractAddress,
        key: impl Into<Vec<u8>>,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<Vec<u8>>> {
        let response = self
            .client
            .instance_state_lookup((ca, &bi.into_block_identifier(), key))
            .await?;
        let block_hash = extract_metadata(&response)?;
        Ok(QueryResponse {
            block_hash,
            response: response.into_inner().value,
        })
    }

    /// Get the status of and information about a specific block item
    /// (transaction). If the block item does not exist
    /// [`QueryError::NotFound`] is returned.
    pub async fn get_block_item_status(
        &mut self,
        th: &TransactionHash,
    ) -> endpoints::QueryResult<TransactionStatus> {
        let response = self.client.get_block_item_status(th).await?;
        let response = TransactionStatus::try_from(response.into_inner())?;
        Ok(response)
    }

    /// Send a block item. A block item is either an `AccountTransaction`, which
    /// is a transaction signed and paid for by an account, a
    /// `CredentialDeployment`, which creates a new account, or
    /// `UpdateInstruction`, which is an instruction to change some
    /// parameters of the chain. Update instructions can only be sent by the
    /// governance committee.
    pub async fn send_block_item<P: PayloadLike>(
        &mut self,
        bi: &transactions::BlockItem<P>,
    ) -> endpoints::RPCResult<TransactionHash> {
        let response = self.client.send_block_item(bi).await?;
        let response = TransactionHash::try_from(response.into_inner())?;
        Ok(response)
    }

    /// Send an account transaction. This is just a helper around
    /// [`send_block_item`](Self::send_block_item) block item for convenience.
    pub async fn send_account_transaction<P: PayloadLike>(
        &mut self,
        at: transactions::AccountTransaction<P>,
    ) -> endpoints::RPCResult<TransactionHash> {
        self.send_block_item(&at.into()).await
    }

    /// Get the hash to be signed for an account transaction from the node. The
    /// hash returned can then be used for signing when constructing
    /// [`TransactionSignature`] as part of calling [`Client::send_block_item`].
    ///
    /// This is provided as a convenience to support cases where the right SDK
    /// is not available for interacting with the node.
    ///
    /// This SDK can compute the hash off-line and it is not recommended to use
    /// this endpoint, instead use [`compute_transaction_sign_hash`].
    ///
    /// [`compute_transaction_sign_hash`]:
    /// types::transactions::compute_transaction_sign_hash
    pub async fn get_account_transaction_sign_hash(
        &mut self,
        header: &transactions::TransactionHeader,
        payload: &transactions::Payload,
    ) -> endpoints::RPCResult<TransactionSignHash> {
        let response = self
            .client
            .get_account_transaction_sign_hash((header, payload))
            .await?;
        let response = TransactionSignHash::try_from(response.into_inner())?;
        Ok(response)
    }

    /// Wait until the transaction is finalized. Returns
    /// [`NotFound`](QueryError::NotFound) in case the transaction is not
    /// known to the node. In case of success, the return value is a pair of the
    /// block hash of the block that contains the transactions, and its
    /// outcome in the block.
    ///
    /// Since this can take an indefinite amount of time in general, users of
    /// this function might wish to wrap it inside
    /// [`timeout`](tokio::time::timeout) handler and handle the resulting
    /// failure.
    pub async fn wait_until_finalized(
        &mut self,
        hash: &types::hashes::TransactionHash,
    ) -> endpoints::QueryResult<(types::hashes::BlockHash, types::BlockItemSummary)> {
        let hash = *hash;
        let process_response = |response| {
            if let types::TransactionStatus::Finalized(blocks) = response {
                let mut iter = blocks.into_iter();
                if let Some(rv) = iter.next() {
                    if iter.next().is_some() {
                        Err(tonic::Status::internal(
                            "Finalized transaction finalized into multiple blocks. This cannot \
                             happen.",
                        )
                        .into())
                    } else {
                        Ok::<_, QueryError>(Some(rv))
                    }
                } else {
                    Err(tonic::Status::internal(
                        "Finalized transaction finalized into no blocks. This cannot happen.",
                    )
                    .into())
                }
            } else {
                Ok(None)
            }
        };

        match process_response(self.get_block_item_status(&hash).await?)? {
            Some(rv) => Ok(rv),
            None => {
                // if the first query did not succeed then start listening for finalized blocks.
                // and on each new block try to query the status.
                let mut blocks = self.get_finalized_blocks().await?;
                while blocks.next().await.transpose()?.is_some() {
                    if let Some(rv) = process_response(self.get_block_item_status(&hash).await?)? {
                        return Ok(rv);
                    }
                }
                Err(QueryError::NotFound)
            }
        }
    }

    /// Run the smart contract instance entrypoint in a given context and in the
    /// state at the end of the given block and return the results.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    pub async fn invoke_instance(
        &mut self,
        bi: impl IntoBlockIdentifier,
        context: &ContractContext,
    ) -> endpoints::QueryResult<QueryResponse<InvokeContractResult>> {
        let response = self
            .client
            .invoke_instance((&bi.into_block_identifier(), context))
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = InvokeContractResult::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get information, such as height, timings, and transaction counts for the
    /// given block. If the block does not exist [`QueryError::NotFound`] is
    /// returned.
    pub async fn get_block_info(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::queries::BlockInfo>> {
        let response = self
            .client
            .get_block_info(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::queries::BlockInfo::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get all the bakers at the end of the given block.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    pub async fn get_baker_list(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::BakerId, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_baker_list(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.map(From::from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Get information about a given pool at the end of a given block.
    /// If the block or baker ID does not exist [`QueryError::NotFound`] is
    /// returned.
    pub async fn get_pool_info(
        &mut self,
        block_id: impl IntoBlockIdentifier,
        baker_id: types::BakerId,
    ) -> endpoints::QueryResult<QueryResponse<types::BakerPoolStatus>> {
        let response = self
            .client
            .get_pool_info((&block_id.into_block_identifier(), baker_id))
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::BakerPoolStatus::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get information about the passive delegators at the end of a given
    /// block. If the block does not exist [`QueryError::NotFound`] is
    /// returned.
    pub async fn get_passive_delegation_info(
        &mut self,
        block_id: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::PassiveDelegationStatus>> {
        let response = self
            .client
            .get_passive_delegation_info(&block_id.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::PassiveDelegationStatus::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get a list of live blocks at a given height.
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

    /// Get information about tokenomics at the end of a given block.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    pub async fn get_tokenomics_info(
        &mut self,
        block_id: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::RewardsOverview>> {
        let response = self
            .client
            .get_tokenomics_info(&block_id.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::RewardsOverview::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get the registered delegators of a given pool at the end of a given
    /// block. If the block or baker ID does not exist [`QueryError::NotFound`]
    /// is returned. The stream will end when all the delegators have been
    /// returned for the given block.
    ///
    /// In contrast to the [Client::get_pool_delegators_reward_period] which
    /// returns delegators that are fixed for the reward period of the
    /// block, this endpoint returns the list of delegators that are
    /// registered in the block. Any changes to delegators are immediately
    /// visible in this list.
    pub async fn get_pool_delegators(
        &mut self,
        bi: impl IntoBlockIdentifier,
        baker_id: types::BakerId,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::DelegatorInfo, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_pool_delegators((&bi.into_block_identifier(), baker_id))
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

    /// Get the fixed delegators of a given pool for the reward period of the
    /// given block. If the block or baker ID does not exist
    /// [`QueryError::NotFound`] is returned. The stream will end when all the
    /// delegators have been returned.
    ///
    /// In contracts to the [Client::get_pool_delegators] which
    /// returns delegators registered for the given block, this endpoint
    /// returns the fixed delegators contributing stake in the reward period
    /// containing the given block.
    pub async fn get_pool_delegators_reward_period(
        &mut self,
        bi: impl IntoBlockIdentifier,
        baker_id: types::BakerId,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::DelegatorRewardPeriodInfo, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_pool_delegators_reward_period((&bi.into_block_identifier(), baker_id))
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

    /// Get the registered passive delegators at the end of a given block. If
    /// the block does not exist [`QueryError::NotFound`] is returned. The
    /// stream will end when all the delegators have been returned.
    ///
    /// In contrast to the [`Client::get_passive_delegators_reward_period`]
    /// which returns delegators that are fixed for the reward period of the
    /// block, this endpoint returns the list of delegators that are
    /// registered in the block. Any changes to delegators are immediately
    /// visible in this list.
    pub async fn get_passive_delegators(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::DelegatorInfo, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_passive_delegators(&bi.into_block_identifier())
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

    /// Get the fixed passive delegators for the reward period of the given
    /// block. If the block does not exist [`QueryError::NotFound`] is
    /// returned. The stream will end when all the delegators have been
    /// returned.
    ///
    /// In contracts to the `GetPassiveDelegators` which returns delegators
    /// registered for the given block, this endpoint returns the fixed
    /// delegators contributing stake in the reward period containing the
    /// given block.
    pub async fn get_passive_delegators_reward_period(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::DelegatorRewardPeriodInfo, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_passive_delegators_reward_period(&bi.into_block_identifier())
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

    /// Get the current branches of blocks starting from and including the last
    /// finalized block.
    ///
    /// Branches are all live blocks that are successors of the last finalized
    /// block. In particular this means that blocks which do not have a
    /// parent are not included in this response.
    pub async fn get_branches(&mut self) -> endpoints::QueryResult<types::queries::Branch> {
        let response = self
            .client
            .get_branches(generated::Empty::default())
            .await?;
        let response = types::queries::Branch::try_from(response.into_inner())?;
        Ok(response)
    }

    /// Get information related to the baker election for a particular block.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    pub async fn get_election_info(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::BirkParameters>> {
        let response = self
            .client
            .get_election_info(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::BirkParameters::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get the identity providers registered as of the end of a given block.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    /// The stream will end when all the identity providers have been returned.
    pub async fn get_identity_providers(
        &mut self,
        bi: impl IntoBlockIdentifier,
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
        let response = self
            .client
            .get_identity_providers(&bi.into_block_identifier())
            .await?;
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

    /// Get the list of anonymity revokers in the given block.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    /// The stream will end when all the anonymity revokers have been returned.
    pub async fn get_anonymity_revokers(
        &mut self,
        bi: impl IntoBlockIdentifier,
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
        let response = self
            .client
            .get_anonymity_revokers(&bi.into_block_identifier())
            .await?;
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

    /// Get the list of transactions hashes for transactions that claim to be
    /// from the given account, but which are not yet finalized.
    /// They are either committed to a block or still pending.
    /// The stream will end when all the non-finalized transaction hashes have
    /// been returned. If the account does not exist an empty list will be
    /// returned.
    ///
    /// This endpoint is not expected to return a large amount of data in most
    /// cases, but in bad network condtions it might.
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

    /// Get the block items included in a given block.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    /// The stream will end when all the block items in the given block have
    /// been returned.
    pub async fn get_block_items(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<BlockItem<EncodedPayload>, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_block_items(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(summary) => summary.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Shut down the node.
    /// Return a GRPC error if the shutdown failed.
    pub async fn shutdown(&mut self) -> endpoints::RPCResult<()> {
        self.client.shutdown(generated::Empty::default()).await?;
        Ok(())
    }

    /// Suggest a peer to connect to the submitted peer details.
    /// This, if successful, adds the peer to the list of given addresses.
    /// Otherwise return a GRPC error.
    ///
    /// Note: The peer might not be connected to instantly, in that case
    /// the node will try to establish the connection in near future. This
    /// function returns a GRPC status 'Ok' in this case.
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

    /// Disconnect from the peer and remove them from the given addresses list
    /// if they are on it. Return if the request was processed successfully.
    /// Otherwise return a GRPC error.
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

    /// Ban a peer.
    /// When successful return `Ok(())`, and otherwise return an error
    /// describing the issue.
    pub async fn ban_peer(
        &mut self,
        peer_to_ban: super::types::network::PeerToBan,
    ) -> endpoints::RPCResult<()> {
        self.client.ban_peer(peer_to_ban).await?;
        Ok(())
    }

    /// Unban a peer.
    /// When successful return `Ok(())`, and otherwise return an error
    /// describing the issue.
    pub async fn unban_peer(
        &mut self,
        banned_peer: &super::types::network::BannedPeer,
    ) -> endpoints::RPCResult<()> {
        self.client.unban_peer(banned_peer).await?;
        Ok(())
    }

    /// Start a network dump if the feature is enabled on the node.
    /// This writes all the network packets into the given file.
    /// Return `Ok(())` if a network dump has been initiated, and an error
    /// otherwise.
    ///
    /// * file - The file to write to.
    /// * raw - Whether raw packets should be included in the dump or not.
    ///
    /// Note. If the feature 'network_dump' is not enabled on the node then this
    /// will return a 'Precondition failed' error.
    pub async fn dump_start(
        &mut self,
        file: &std::path::Path,
        raw: bool,
    ) -> endpoints::RPCResult<()> {
        let file_str = file.to_str().ok_or_else(|| {
            tonic::Status::invalid_argument(
                "The provided path cannot is not a valid UTF8 string, so cannot be used.",
            )
        })?;

        self.client
            .dump_start(generated::DumpRequest {
                file: file_str.to_string(),
                raw,
            })
            .await?;
        Ok(())
    }

    /// Stop an ongoing network dump.
    /// Return nothing if it was successfully stopped, and otherwise return an
    /// error.
    ///
    /// Note. If the feature 'network_dump' is not enabled on the node then this
    /// will return a 'Precondition failed' error.
    pub async fn dump_stop(&mut self) -> endpoints::RPCResult<()> {
        self.client.dump_stop(generated::Empty::default()).await?;
        Ok(())
    }

    /// Get a list of the peers that the node is connected to and associated
    /// network related information for each peer.
    pub async fn get_peers_info(&mut self) -> endpoints::RPCResult<types::network::PeersInfo> {
        let response = self
            .client
            .get_peers_info(generated::Empty::default())
            .await?;
        let peers_info = types::network::PeersInfo::try_from(response.into_inner())?;
        Ok(peers_info)
    }

    /// Retrieve information about the node.
    /// The response contains meta information about the node
    /// such as the version of the software, the local time of the node etc.
    ///
    /// The response also yields network related information such as the node
    /// ID, bytes sent/received etc.
    ///
    /// Finally depending on the type of the node (regular node or
    /// 'bootstrapper') the response also yields baking information if
    /// the node is configured with baker credentials.
    ///
    /// Bootstrappers do no reveal any consensus information as they do not run
    /// the consensus protocol.
    pub async fn get_node_info(&mut self) -> endpoints::RPCResult<types::NodeInfo> {
        let response = self
            .client
            .get_node_info(generated::Empty::default())
            .await?;
        let node_info = types::NodeInfo::try_from(response.into_inner())?;
        Ok(node_info)
    }

    /// Get the transaction events in a given block. If the block does not exist
    /// [`QueryError::NotFound`] is returned. The stream will end when all the
    /// transaction events for a given block have been returned.
    pub async fn get_block_transaction_events(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::BlockItemSummary, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_block_transaction_events(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(summary) => summary.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Get a the special events in a given block. If the block does not exist
    /// [`QueryError::NotFound`] is returned. The stream will end when all the
    /// special events for a given block have been returned.
    ///
    /// These are events generated by the protocol, such as minting and reward
    /// payouts. They are not directly generated by any transaction.
    pub async fn get_block_special_events(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::SpecialTransactionOutcome, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_block_special_events(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(summary) => summary.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Get the pending updates to chain parameters at the end of a given block.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    /// The stream will end when all the pending updates for a given block have
    /// been returned.
    pub async fn get_block_pending_updates(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<types::queries::PendingUpdate, tonic::Status>>>,
    > {
        let response = self
            .client
            .get_block_pending_updates(&bi.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|result| match result {
            Ok(update) => update.try_into(),
            Err(err) => Err(err),
        });
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    /// Get next available sequence numbers for updating chain parameters after
    /// a given block. If the block does not exist then [`QueryError::NotFound`]
    /// is returned.
    pub async fn get_next_update_sequence_numbers(
        &mut self,
        block_id: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<types::queries::NextUpdateSequenceNumbers>> {
        let response = self
            .client
            .get_next_update_sequence_numbers(&block_id.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = types::queries::NextUpdateSequenceNumbers::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get the chain parameters in effect after a given block.
    /// If the block does not exist [`QueryError::NotFound`] is returned.
    pub async fn get_block_chain_parameters(
        &mut self,
        block_id: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<ChainParameters>> {
        let response = self
            .client
            .get_block_chain_parameters(&block_id.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = ChainParameters::try_from(response.into_inner())?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get the information about a finalization record in a block.
    /// A block can contain zero or one finalization record. If a record is
    /// contained then this query will return information about the finalization
    /// session that produced it, including the finalizers eligible for the
    /// session, their power, and whether they signed this particular record. If
    /// the block does not exist [`QueryError::NotFound`] is returned.
    pub async fn get_block_finalization_summary(
        &mut self,
        block_id: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<Option<types::FinalizationSummary>>> {
        let response = self
            .client
            .get_block_finalization_summary(&block_id.into_block_identifier())
            .await?;
        let block_hash = extract_metadata(&response)?;
        let response = response.into_inner().try_into()?;
        Ok(QueryResponse {
            block_hash,
            response,
        })
    }

    /// Get a continous stream of finalized blocks starting from a given height.
    /// This function starts a background task (a `tokio` task) that listens for
    /// new finalized blocks. This task is killed when the
    /// [`FinalizedBlocksStream`] is dropped.
    pub async fn get_finalized_blocks_from(
        &mut self,
        start_height: AbsoluteBlockHeight,
    ) -> endpoints::QueryResult<FinalizedBlocksStream> {
        let mut fin_height = self.get_consensus_info().await?.last_finalized_block_height;
        let (sender, receiver) = tokio::sync::mpsc::channel(100);
        let mut client = self.clone();
        let handle = tokio::spawn(async move {
            let mut height = start_height;
            loop {
                if height > fin_height {
                    fin_height = client
                        .get_consensus_info()
                        .await?
                        .last_finalized_block_height;
                    if height > fin_height {
                        break;
                    }
                } else {
                    let mut bi = client.get_blocks_at_height(&height.into()).await?;
                    let block_hash = bi.pop().ok_or(endpoints::QueryError::NotFound)?;
                    let info = FinalizedBlockInfo { block_hash, height };
                    if sender.send(info).await.is_err() {
                        return Ok(());
                    }
                    height = height.next();
                }
            }
            let mut stream = client.get_finalized_blocks().await?;
            while let Some(fbi) = stream.next().await.transpose()? {
                // recover missed blocks.
                while height < fbi.height {
                    let mut bi = client.get_blocks_at_height(&height.into()).await?;
                    let block_hash = bi.pop().ok_or(endpoints::QueryError::NotFound)?;
                    let info = FinalizedBlockInfo { block_hash, height };
                    if sender.send(info).await.is_err() {
                        return Ok(());
                    }
                    height = height.next();
                }
                if sender.send(fbi).await.is_err() {
                    return Ok(());
                }
                height = height.next();
            }
            Ok(())
        });
        Ok(FinalizedBlocksStream { handle, receiver })
    }
}

/// A stream of finalized blocks. This contains a background task that polls
/// for new finalized blocks indefinitely. The task can be stopped by dropping
/// the object.
pub struct FinalizedBlocksStream {
    handle:   tokio::task::JoinHandle<endpoints::QueryResult<()>>,
    receiver: tokio::sync::mpsc::Receiver<FinalizedBlockInfo>,
}

// Make sure to abort the background task so that those resources are cleaned up
// before we drop the handle.
impl Drop for FinalizedBlocksStream {
    fn drop(&mut self) { self.handle.abort(); }
}

impl FinalizedBlocksStream {
    /// Get the next finalized block in the stream. Or [`None`] if the there are
    /// no more. This function blocks until a finalized block becomes available,
    /// so in general it is a good idea to c
    pub async fn next(&mut self) -> Option<FinalizedBlockInfo> { self.receiver.recv().await }

    /// Like [`FinalizedBlocksStream::next`], but only waits at most the
    /// specified duration.
    pub async fn next_timeout(
        &mut self,
        duration: std::time::Duration,
    ) -> Result<Option<FinalizedBlockInfo>, tokio::time::error::Elapsed> {
        tokio::time::timeout(duration, async move { self.next().await }).await
    }

    /// Get the next chunk of blocks. If the finalized block poller has been
    /// disconnected this will return `Err(blocks)` where `blocks` are the
    /// finalized blocks that were retrieved before closure. In that case
    /// all further calls will return `Err(Vec::new())`.
    ///
    /// In case of success up to `max(1, n)` elements will be returned. This
    /// function will block so it always returns at least one element, and
    /// will retrieve up to `n` elements without blocking further once at least
    /// one element has been acquired.
    pub async fn next_chunk(
        &mut self,
        n: usize,
    ) -> Result<Vec<FinalizedBlockInfo>, Vec<FinalizedBlockInfo>> {
        let mut out = Vec::with_capacity(n);
        let first = self.receiver.recv().await;
        match first {
            Some(v) => out.push(v),
            None => {
                return Err(out);
            }
        }
        for _ in 1..n {
            match self.receiver.try_recv() {
                Ok(v) => {
                    out.push(v);
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    break;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return Err(out),
            }
        }
        Ok(out)
    }

    /// Like [`next_chunk`](Self::next_chunk), but waits no more than the given
    /// duration for the block. The boolean signifies whether an error
    /// occurred (it is `true` if an error occurred) while getting blocks.
    /// If that is the case further calls will always yield an error.
    ///
    /// If no blocks are available in time an `Err` is returned.
    pub async fn next_chunk_timeout(
        &mut self,
        n: usize,
        duration: std::time::Duration,
    ) -> Result<(bool, Vec<FinalizedBlockInfo>), tokio::time::error::Elapsed> {
        let mut out = Vec::with_capacity(n);
        let first = self.next_timeout(duration).await?;
        match first {
            Some(v) => out.push(v),
            None => return Ok((true, out)),
        }
        for _ in 1..n {
            match self.receiver.try_recv() {
                Ok(v) => {
                    out.push(v);
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    break;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    return Ok((true, out))
                }
            }
        }
        Ok((false, out))
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
