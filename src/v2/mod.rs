use std::collections::HashMap;

use crate::{
    endpoints, id,
    id::types::AccountCredentialMessage,
    types::{
        self, hashes,
        hashes::{BlockHash, TransactionHash, TransactionSignHash},
        smart_contracts::{
            ContractContext, InstanceInfo, InvokeContractResult, ModuleRef, Parameter, WasmModule,
        },
        transactions::{
            self, InitContractPayload, UpdateContractPayload, UpdateInstruction,
        },
        AbsoluteBlockHeight, AccountInfo, CredentialRegistrationID, Energy, Memo, Nonce,
        RegisteredData, TransactionStatus, UpdateSequenceNumber,
    },
};
use concordium_base::{
    common::{
        self,
        types::{TransactionSignature, TransactionTime},
    },
    contracts_common::{
        AccountAddress, Amount, ContractAddress, OwnedContractName, OwnedReceiveName, ReceiveName,
    },
    transactions::PayloadLike,
};
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

    pub async fn send_block_item<P: PayloadLike>(
        &mut self,
        bi: &transactions::BlockItem<P>,
    ) -> endpoints::RPCResult<TransactionHash> {
        let response = self.client.send_block_item(bi).await?;
        let response = TransactionHash::try_from(response.into_inner())?;
        Ok(response)
    }

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
    /// TODO: Make use of get_finalized_blocks.
    pub async fn wait_until_finalized(
        &mut self,
        hash: &types::hashes::TransactionHash,
    ) -> endpoints::QueryResult<(types::hashes::BlockHash, types::BlockItemSummary)> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let types::TransactionStatus::Finalized(blocks) =
                self.get_block_item_status(hash).await?
            {
                let mut iter = blocks.into_iter();
                if let Some(rv) = iter.next() {
                    if iter.next().is_some() {
                        return Err(tonic::Status::internal(
                            "Finalized transaction finalized into multiple blocks. This cannot \
                             happen.",
                        )
                        .into());
                    } else {
                        return Ok(rv);
                    }
                } else {
                    return Err(tonic::Status::internal(
                        "Finalized transaction finalized into no blocks. This cannot happen.",
                    )
                    .into());
                }
            }
        }
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
