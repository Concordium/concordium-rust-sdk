use concordium_base::{
    base::{Energy, ProtocolVersion},
    common::types::{CredentialIndex, KeyIndex, Timestamp},
    contracts_common::{AccountAddress, Amount, ContractAddress},
    hashes::BlockHash,
    smart_contracts::ContractTraceElement,
    transactions::{EncodedPayload, PayloadLike},
};
use queues::{IsQueue, Queue};
use std::{mem, sync::Arc};

use futures::{lock::Mutex, stream::FusedStream, *};

use crate::{
    endpoints,
    types::{
        smart_contracts::{ContractContext, InstanceInfo, ReturnValue},
        AccountInfo, AccountTransactionDetails, RejectReason,
    },
    v2::{generated::DryRunStateQuery, Require},
};

use super::{
    generated::{
        self, account_transaction_payload, dry_run_error_response, dry_run_request,
        DryRunInvokeInstance, DryRunMintToAccount, DryRunSignature, DryRunStateOperation,
    },
    AccountIdentifier, IntoBlockIdentifier,
};

/// A stream together with a queue of pending requests for items from the
/// stream that have not yet been polled. This is used to allow multiple
/// readers of the stream to be sequenced.
struct InnerSharedReceiver<S>
where
    S: Stream, {
    /// The underlying stream.
    src:     S,
    /// The queue of pending receivers.
    pending: Queue<Arc<Mutex<Option<S::Item>>>>,
}

struct SharedReceiverItem<S>
where
    S: Stream, {
    value:    Arc<Mutex<Option<S::Item>>>,
    receiver: Arc<Mutex<InnerSharedReceiver<S>>>,
}

struct SharedReceiver<S>
where
    S: Stream, {
    inner: Arc<Mutex<InnerSharedReceiver<S>>>,
}

impl<S: Stream> SharedReceiver<S> {
    /// Construct a shared receiver from a stream.
    fn new(stream: S) -> Self {
        let inner = InnerSharedReceiver {
            src:     stream,
            pending: Queue::new(),
        };
        SharedReceiver {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Get a [SharedReceiverItem] that can be used to get the next item from
    /// the stream.
    async fn next(&self) -> SharedReceiverItem<S> {
        let new_item = Arc::new(Mutex::new(None));
        self.inner
            .lock()
            .await
            .pending
            .add(new_item.clone())
            .unwrap();
        SharedReceiverItem {
            value:    new_item,
            receiver: self.inner.clone(),
        }
    }
}

impl<S: Stream + Unpin + FusedStream> SharedReceiverItem<S> {
    async fn receive(self) -> Option<S::Item> {
        let mut receiver = self.receiver.lock().await;
        {
            let out = {
                let mut value = self.value.lock().await;
                mem::replace(&mut *value, None)
            };
            if let Some(v) = out {
                return Some(v);
            }
        }
        {
            loop {
                let val = receiver.src.next().await;
                let next_item = receiver.pending.remove().unwrap();
                if Arc::ptr_eq(&next_item, &self.value) {
                    return val;
                } else {
                    let mut other = next_item.lock().await;
                    *other = val;
                }
            }
        }
    }
}

pub struct DryRun {
    request_send:  channel::mpsc::Sender<generated::DryRunRequest>,
    response_recv:
        SharedReceiver<futures::stream::Fuse<tonic::Streaming<generated::DryRunResponse>>>,
}

#[derive(thiserror::Error, Debug)]
pub enum ErrorResult {
    #[error("block state not loaded")]
    NoState(),
    #[error("block not found")]
    BlockNotFound(),
    #[error("account not found")]
    AccountNotFound(),
    #[error("contract instance not found")]
    InstanceNotFound(),
    #[error("mint amount exceeds limit")]
    AmountOverLimit { amount_limit: Amount },
    #[error("account balance insufficient")]
    BalanceInsufficient {
        required_amount:  Amount,
        available_amount: Amount,
    },
    #[error("energy insufficient")]
    EnergyInsufficient { energy_required: Energy },
    #[error("invoke instance failed")]
    InvokeFailure {
        return_value: Option<Vec<u8>>,
        used_energy:  Energy,
        reason:       RejectReason,
    },
}

impl TryFrom<dry_run_error_response::Error> for ErrorResult {
    type Error = tonic::Status;

    fn try_from(value: dry_run_error_response::Error) -> Result<Self, Self::Error> {
        use dry_run_error_response::Error;
        let res = match value {
            Error::NoState(_) => Self::NoState(),
            Error::BlockNotFound(_) => Self::BlockNotFound(),
            Error::AccountNotFound(_) => Self::AccountNotFound(),
            Error::InstanceNotFound(_) => Self::InstanceNotFound(),
            Error::AmountOverLimit(e) => Self::AmountOverLimit {
                amount_limit: e.amount_limit.require()?.into(),
            },
            Error::BalanceInsufficient(e) => Self::BalanceInsufficient {
                required_amount:  e.required_amount.require()?.into(),
                available_amount: e.available_amount.require()?.into(),
            },
            Error::EnergyInsufficient(e) => Self::EnergyInsufficient {
                energy_required: e.energy_required.require()?.into(),
            },
            Error::InvokeFailed(e) => Self::InvokeFailure {
                return_value: e.return_value,
                used_energy:  e.used_energy.require()?.into(),
                reason:       e.reason.require()?.try_into()?,
            },
        };
        Ok(res)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum DryRunError {
    #[error("{0}")]
    QueryError(#[from] endpoints::QueryError),
    #[error("dry-run operation failed: {result}")]
    OperationFailed {
        #[source]
        result:          ErrorResult,
        quota_remaining: Energy,
    },
}

impl From<tonic::Status> for DryRunError {
    fn from(s: tonic::Status) -> Self { Self::QueryError(s.into()) }
}

#[derive(Debug, Clone)]
pub struct WithRemainingQuota<T> {
    pub inner:           T,
    pub quota_remaining: Energy,
}

#[derive(Debug, Clone)]
pub struct BlockStateLoaded {
    pub current_timestamp: Timestamp,
    pub block_hash:        BlockHash,
    pub protocol_version:  ProtocolVersion,
}

impl TryFrom<Option<Result<generated::DryRunResponse, tonic::Status>>>
    for WithRemainingQuota<BlockStateLoaded>
{
    type Error = DryRunError;

    fn try_from(
        value: Option<Result<generated::DryRunResponse, tonic::Status>>,
    ) -> Result<Self, Self::Error> {
        let response =
            value.ok_or_else(|| tonic::Status::cancelled("server closed dry run stream"))??;
        let quota_remaining = response.quota_remaining.require()?.into();
        use generated::dry_run_response::*;
        match response.response.require()? {
            Response::Error(e) => {
                let result = e.error.require()?.try_into()?;
                if !matches!(result, ErrorResult::BlockNotFound()) {
                    Err(tonic::Status::unknown("unexpected error response type"))?
                }
                Err(DryRunError::OperationFailed {
                    result,
                    quota_remaining,
                })
            }
            Response::Success(s) => {
                let response = s.response.require()?;
                use generated::dry_run_success_response::*;
                match response {
                    Response::BlockStateLoaded(loaded) => {
                        let protocol_version =
                            generated::ProtocolVersion::from_i32(loaded.protocol_version)
                                .ok_or_else(|| tonic::Status::unknown("Unknown protocol version"))?
                                .into();
                        let loaded = BlockStateLoaded {
                            current_timestamp: loaded.current_timestamp.require()?.into(),
                            block_hash: loaded.block_hash.require()?.try_into()?,
                            protocol_version,
                        };
                        Ok(WithRemainingQuota {
                            inner: loaded,
                            quota_remaining,
                        })
                    }
                    _ => Err(tonic::Status::unknown("unexpected success response type"))?,
                }
            }
        }
    }
}

impl TryFrom<Option<Result<generated::DryRunResponse, tonic::Status>>>
    for WithRemainingQuota<AccountInfo>
{
    type Error = DryRunError;

    fn try_from(
        value: Option<Result<generated::DryRunResponse, tonic::Status>>,
    ) -> Result<Self, Self::Error> {
        let response =
            value.ok_or_else(|| tonic::Status::cancelled("server closed dry run stream"))??;
        let quota_remaining = response.quota_remaining.require()?.into();
        use generated::dry_run_response::*;
        match response.response.require()? {
            Response::Error(e) => {
                let result = e.error.require()?.try_into()?;
                if !matches!(
                    result,
                    ErrorResult::NoState() | ErrorResult::AccountNotFound()
                ) {
                    Err(tonic::Status::unknown("unexpected error response type"))?
                }
                Err(DryRunError::OperationFailed {
                    result,
                    quota_remaining,
                })
            }
            Response::Success(s) => {
                let response = s.response.require()?;
                use generated::dry_run_success_response::*;
                match response {
                    Response::AccountInfo(info) => Ok(WithRemainingQuota {
                        inner: info.try_into()?,
                        quota_remaining,
                    }),
                    _ => Err(tonic::Status::unknown("unexpected success response type"))?,
                }
            }
        }
    }
}

impl TryFrom<Option<Result<generated::DryRunResponse, tonic::Status>>>
    for WithRemainingQuota<InstanceInfo>
{
    type Error = DryRunError;

    fn try_from(
        value: Option<Result<generated::DryRunResponse, tonic::Status>>,
    ) -> Result<Self, Self::Error> {
        let response =
            value.ok_or_else(|| tonic::Status::cancelled("server closed dry run stream"))??;
        let quota_remaining = response.quota_remaining.require()?.into();
        use generated::dry_run_response::*;
        match response.response.require()? {
            Response::Error(e) => {
                let result = e.error.require()?.try_into()?;
                if !matches!(
                    result,
                    ErrorResult::NoState() | ErrorResult::InstanceNotFound()
                ) {
                    Err(tonic::Status::unknown("unexpected error response type"))?
                }
                Err(DryRunError::OperationFailed {
                    result,
                    quota_remaining,
                })
            }
            Response::Success(s) => {
                let response = s.response.require()?;
                use generated::dry_run_success_response::*;
                match response {
                    Response::InstanceInfo(info) => Ok(WithRemainingQuota {
                        inner: info.try_into()?,
                        quota_remaining,
                    }),
                    _ => Err(tonic::Status::unknown("unexpected success response type"))?,
                }
            }
        }
    }
}

impl From<&ContractContext> for DryRunInvokeInstance {
    fn from(context: &ContractContext) -> Self {
        DryRunInvokeInstance {
            invoker:    context.invoker.as_ref().map(|a| a.into()),
            instance:   Some((&context.contract).into()),
            amount:     Some(context.amount.into()),
            entrypoint: Some(context.method.as_receive_name().into()),
            parameter:  Some(context.parameter.as_ref().into()),
            energy:     Some(context.energy.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvokeContractSuccess {
    pub return_value: Option<ReturnValue>,
    pub events:       Vec<ContractTraceElement>,
    pub used_energy:  Energy,
}

impl TryFrom<Option<Result<generated::DryRunResponse, tonic::Status>>>
    for WithRemainingQuota<InvokeContractSuccess>
{
    type Error = DryRunError;

    fn try_from(
        value: Option<Result<generated::DryRunResponse, tonic::Status>>,
    ) -> Result<Self, Self::Error> {
        let response =
            value.ok_or_else(|| tonic::Status::cancelled("server closed dry run stream"))??;
        let quota_remaining = response.quota_remaining.require()?.into();
        use generated::dry_run_response::*;
        match response.response.require()? {
            Response::Error(e) => {
                let result = e.error.require()?.try_into()?;
                if !matches!(
                    result,
                    ErrorResult::NoState()
                        | ErrorResult::InvokeFailure {
                            return_value: _,
                            used_energy:  _,
                            reason:       _,
                        }
                ) {
                    Err(tonic::Status::unknown("unexpected error response type"))?
                }
                Err(DryRunError::OperationFailed {
                    result,
                    quota_remaining,
                })
            }
            Response::Success(s) => {
                let response = s.response.require()?;
                use generated::dry_run_success_response::*;
                match response {
                    Response::InvokeSucceeded(result) => {
                        let inner = InvokeContractSuccess {
                            return_value: result.return_value.map(|a| ReturnValue { value: a }),
                            events:       result
                                .effects
                                .into_iter()
                                .map(TryFrom::try_from)
                                .collect::<Result<_, tonic::Status>>()?,
                            used_energy:  result.used_energy.require()?.into(),
                        };
                        Ok(WithRemainingQuota {
                            inner,
                            quota_remaining,
                        })
                    }
                    _ => Err(tonic::Status::unknown("unexpected success response type"))?,
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct TimestampSet {}

impl TryFrom<Option<Result<generated::DryRunResponse, tonic::Status>>>
    for WithRemainingQuota<TimestampSet>
{
    type Error = DryRunError;

    fn try_from(
        value: Option<Result<generated::DryRunResponse, tonic::Status>>,
    ) -> Result<Self, Self::Error> {
        let response =
            value.ok_or_else(|| tonic::Status::cancelled("server closed dry run stream"))??;
        let quota_remaining = response.quota_remaining.require()?.into();
        use generated::dry_run_response::*;
        match response.response.require()? {
            Response::Error(e) => {
                let result = e.error.require()?.try_into()?;
                if !matches!(result, ErrorResult::NoState()) {
                    Err(tonic::Status::unknown("unexpected error response type"))?
                }
                Err(DryRunError::OperationFailed {
                    result,
                    quota_remaining,
                })
            }
            Response::Success(s) => {
                let response = s.response.require()?;
                use generated::dry_run_success_response::*;
                match response {
                    Response::TimestampSet(_) => {
                        let inner = TimestampSet {};
                        Ok(WithRemainingQuota {
                            inner,
                            quota_remaining,
                        })
                    }
                    _ => Err(tonic::Status::unknown("unexpected success response type"))?,
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct MintedToAccount {}

impl TryFrom<Option<Result<generated::DryRunResponse, tonic::Status>>>
    for WithRemainingQuota<MintedToAccount>
{
    type Error = DryRunError;

    fn try_from(
        value: Option<Result<generated::DryRunResponse, tonic::Status>>,
    ) -> Result<Self, Self::Error> {
        let response =
            value.ok_or_else(|| tonic::Status::cancelled("server closed dry run stream"))??;
        let quota_remaining = response.quota_remaining.require()?.into();
        use generated::dry_run_response::*;
        match response.response.require()? {
            Response::Error(e) => {
                let result = e.error.require()?.try_into()?;
                if !matches!(
                    result,
                    ErrorResult::NoState() | ErrorResult::AmountOverLimit { amount_limit: _ }
                ) {
                    Err(tonic::Status::unknown("unexpected error response type"))?
                }
                Err(DryRunError::OperationFailed {
                    result,
                    quota_remaining,
                })
            }
            Response::Success(s) => {
                let response = s.response.require()?;
                use generated::dry_run_success_response::*;
                match response {
                    Response::MintedToAccount(_) => {
                        let inner = MintedToAccount {};
                        Ok(WithRemainingQuota {
                            inner,
                            quota_remaining,
                        })
                    }
                    _ => Err(tonic::Status::unknown("unexpected success response type"))?,
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DryRunTransaction {
    /// The account originating the transaction.
    pub sender:        AccountAddress,
    /// The limit on the energy that may be used by the transaction.
    pub energy_amount: Energy,
    /// The transaction payload to execute.
    pub payload:       EncodedPayload,
    /// The credential-keys that are treated as signing the transaction.
    /// If this is the empty vector, it is treated as the single key (0,0)
    /// signing.
    pub signatures:    Vec<(CredentialIndex, KeyIndex)>,
}

impl DryRunTransaction {
    /// Create a [DryRunTransaction] given the sender address, energy limit and
    /// payload. The empty list is used for the signatures, meaning that it
    /// will be treated as though key 0 of credential 0 is the sole
    /// signature on the transaction. For most purposes, this is sufficient.
    pub fn new(sender: AccountAddress, energy_amount: Energy, payload: &impl PayloadLike) -> Self {
        DryRunTransaction {
            sender,
            energy_amount,
            payload: payload.encode(),
            signatures: vec![],
        }
    }
}

impl From<DryRunTransaction> for generated::DryRunTransaction {
    fn from(transaction: DryRunTransaction) -> Self {
        let payload = account_transaction_payload::Payload::RawPayload(transaction.payload.into());
        generated::DryRunTransaction {
            sender:        Some(transaction.sender.into()),
            energy_amount: Some(transaction.energy_amount.into()),
            payload:       Some(generated::AccountTransactionPayload {
                payload: Some(payload),
            }),
            signatures:    transaction
                .signatures
                .into_iter()
                .map(|(cred, key)| DryRunSignature {
                    credential: cred.index as u32,
                    key:        key.0 as u32,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransactionExecuted {
    pub energy_cost:  Energy,
    pub details:      AccountTransactionDetails,
    pub return_value: Option<Vec<u8>>,
}

impl TryFrom<Option<Result<generated::DryRunResponse, tonic::Status>>>
    for WithRemainingQuota<TransactionExecuted>
{
    type Error = DryRunError;

    fn try_from(
        value: Option<Result<generated::DryRunResponse, tonic::Status>>,
    ) -> Result<Self, Self::Error> {
        let response =
            value.ok_or_else(|| tonic::Status::cancelled("server closed dry run stream"))??;
        let quota_remaining = response.quota_remaining.require()?.into();
        use generated::dry_run_response::*;
        match response.response.require()? {
            Response::Error(e) => {
                let result = e.error.require()?.try_into()?;
                if !matches!(
                    result,
                    ErrorResult::NoState()
                        | ErrorResult::AccountNotFound()
                        | ErrorResult::BalanceInsufficient {
                            required_amount:  _,
                            available_amount: _,
                        }
                        | ErrorResult::EnergyInsufficient { energy_required: _ }
                ) {
                    Err(tonic::Status::unknown("unexpected error response type"))?
                }
                Err(DryRunError::OperationFailed {
                    result,
                    quota_remaining,
                })
            }
            Response::Success(s) => {
                let response = s.response.require()?;
                use generated::dry_run_success_response::*;
                match response {
                    Response::TransactionExecuted(res) => {
                        let inner = TransactionExecuted {
                            energy_cost:  res.energy_cost.require()?.into(),
                            details:      res.details.require()?.try_into()?,
                            return_value: res.return_value,
                        };
                        Ok(WithRemainingQuota {
                            inner,
                            quota_remaining,
                        })
                    }
                    _ => Err(tonic::Status::unknown("unexpected success response type"))?,
                }
            }
        }
    }
}

type DryRunResult<T> = Result<WithRemainingQuota<T>, DryRunError>;

impl DryRun {
    pub(crate) async fn new(
        client: &mut generated::queries_client::QueriesClient<tonic::transport::Channel>,
    ) -> endpoints::QueryResult<Self> {
        let (request_send, request_recv) = channel::mpsc::channel(10);
        let response = client.dry_run(request_recv).await?;
        let response_stream = response.into_inner();
        let response_recv = SharedReceiver::new(futures::stream::StreamExt::fuse(response_stream));
        Ok(DryRun {
            request_send,
            response_recv,
        })
    }

    pub async fn load_block_state(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> endpoints::QueryResult<impl Future<Output = DryRunResult<BlockStateLoaded>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::LoadBlockState(
                (&bi.into_block_identifier()).into(),
            )),
        };
        self.request_send
            .send(request)
            .await
            // If an error occurs, it will be because the stream has been closed, which
            // means that no more requests can be sent.
            .map_err(|_| tonic::Status::cancelled("dry run already completed"))?;
        let result_future = self
            .response_recv
            .next()
            .await
            .receive()
            .map(|z| z.try_into());

        Ok(result_future)
    }

    pub async fn get_account_info(
        &mut self,
        acc: &AccountIdentifier,
    ) -> endpoints::QueryResult<impl Future<Output = DryRunResult<AccountInfo>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateQuery(DryRunStateQuery {
                query: Some(generated::dry_run_state_query::Query::GetAccountInfo(
                    acc.into(),
                )),
            })),
        };
        self.request_send.send(request)
        .await
        // If an error occurs, it will be because the stream has been closed, which
        // means that no more requests can be sent.
        .map_err(|_| tonic::Status::cancelled("dry run already completed"))?;
        let result_future = self
            .response_recv
            .next()
            .await
            .receive()
            .map(|z| z.try_into());

        Ok(result_future)
    }

    pub async fn get_instance_info(
        &mut self,
        address: &ContractAddress,
    ) -> endpoints::QueryResult<impl Future<Output = DryRunResult<InstanceInfo>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateQuery(DryRunStateQuery {
                query: Some(generated::dry_run_state_query::Query::GetInstanceInfo(
                    address.into(),
                )),
            })),
        };
        self.request_send.send(request)
        .await
        // If an error occurs, it will be because the stream has been closed, which
        // means that no more requests can be sent.
        .map_err(|_| tonic::Status::cancelled("dry run already completed"))?;
        let result_future = self
            .response_recv
            .next()
            .await
            .receive()
            .map(|z| z.try_into());

        Ok(result_future)
    }

    pub async fn invoke_instance(
        &mut self,
        context: &ContractContext,
    ) -> endpoints::QueryResult<impl Future<Output = DryRunResult<InvokeContractSuccess>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateQuery(DryRunStateQuery {
                query: Some(generated::dry_run_state_query::Query::InvokeInstance(
                    context.into(),
                )),
            })),
        };
        self.request_send.send(request)
        .await
        // If an error occurs, it will be because the stream has been closed, which
        // means that no more requests can be sent.
        .map_err(|_| tonic::Status::cancelled("dry run already completed"))?;
        let result_future = self
            .response_recv
            .next()
            .await
            .receive()
            .map(|z| z.try_into());

        Ok(result_future)
    }

    pub async fn set_timestamp(
        &mut self,
        timestamp: Timestamp,
    ) -> endpoints::QueryResult<impl Future<Output = DryRunResult<TimestampSet>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateOperation(
                DryRunStateOperation {
                    operation: Some(generated::dry_run_state_operation::Operation::SetTimestamp(
                        timestamp.into(),
                    )),
                },
            )),
        };
        self.request_send.send(request)
        .await
        // If an error occurs, it will be because the stream has been closed, which
        // means that no more requests can be sent.
        .map_err(|_| tonic::Status::cancelled("dry run already completed"))?;
        let result_future = self
            .response_recv
            .next()
            .await
            .receive()
            .map(|z| z.try_into());

        Ok(result_future)
    }

    pub async fn mint_to_account(
        &mut self,
        account_address: &AccountAddress,
        mint_amount: Amount,
    ) -> endpoints::QueryResult<impl Future<Output = DryRunResult<MintedToAccount>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateOperation(
                DryRunStateOperation {
                    operation: Some(
                        generated::dry_run_state_operation::Operation::MintToAccount(
                            DryRunMintToAccount {
                                account: Some(account_address.into()),
                                amount:  Some(mint_amount.into()),
                            },
                        ),
                    ),
                },
            )),
        };
        self.request_send.send(request)
        .await
        // If an error occurs, it will be because the stream has been closed, which
        // means that no more requests can be sent.
        .map_err(|_| tonic::Status::cancelled("dry run already completed"))?;
        let result_future = self
            .response_recv
            .next()
            .await
            .receive()
            .map(|z| z.try_into());

        Ok(result_future)
    }

    pub async fn run_transaction(
        &mut self,
        transaction: DryRunTransaction,
    ) -> endpoints::QueryResult<impl Future<Output = DryRunResult<TransactionExecuted>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateOperation(
                DryRunStateOperation {
                    operation: Some(
                        generated::dry_run_state_operation::Operation::RunTransaction(
                            transaction.into(),
                        ),
                    ),
                },
            )),
        };
        self.request_send.send(request)
        .await
        // If an error occurs, it will be because the stream has been closed, which
        // means that no more requests can be sent.
        .map_err(|_| tonic::Status::cancelled("dry run already completed"))?;
        let result_future = self
            .response_recv
            .next()
            .await
            .receive()
            .map(|z| z.try_into());

        Ok(result_future)
    }
}
