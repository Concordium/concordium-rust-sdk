use concordium_base::{
    base::{Energy, ProtocolVersion},
    common::types::{CredentialIndex, KeyIndex, Timestamp},
    contracts_common::{AccountAddress, Amount, ContractAddress},
    hashes::BlockHash,
    smart_contracts::ContractTraceElement,
    transactions::{EncodedPayload, PayloadLike},
};

use futures::*;
use tonic::metadata::MetadataValue;

use crate::{
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

mod shared_receiver {

    use std::{collections::LinkedList, sync::Arc};

    use futures::{lock::Mutex, stream::FusedStream, *};

    /// A stream together with a queue of pending requests for items from the
    /// stream that have not yet been polled. This is used to allow multiple
    /// readers of the stream to be sequenced.
    struct InnerSharedReceiver<S>
    where
        S: Stream, {
        /// The underlying stream.
        src:     S,
        /// The queue of pending receivers.
        pending: LinkedList<oneshot::Sender<Option<S::Item>>>,
    }

    /// A pending item to be received from a [SharedReceiver].
    pub struct SharedReceiverItem<S>
    where
        S: Stream, {
        /// The item, if it has already been read from the stream.
        value:    oneshot::Receiver<Option<S::Item>>,
        /// The shared receiver.
        receiver: Arc<Mutex<InnerSharedReceiver<S>>>,
    }

    /// A `SharedReceiver` wraps an underlying stream so that multiple clients
    /// can queue to receive items from the queue.
    pub struct SharedReceiver<S>
    where
        S: Stream, {
        inner: Arc<Mutex<InnerSharedReceiver<S>>>,
    }

    impl<S: Stream> SharedReceiver<S> {
        /// Construct a shared receiver from a stream.
        pub fn new(stream: S) -> Self {
            let inner = InnerSharedReceiver {
                src:     stream,
                pending: LinkedList::new(),
            };
            SharedReceiver {
                inner: Arc::new(Mutex::new(inner)),
            }
        }

        /// Get a [SharedReceiverItem] that can be used to receive the next item
        /// from the stream. This can be thought of as reserving a place in the
        /// queue to receive an item from the stream.
        pub async fn next(&self) -> SharedReceiverItem<S> {
            let (item_sender, item_receiver) = oneshot::channel();
            self.inner.lock().await.pending.push_back(item_sender);
            SharedReceiverItem {
                value:    item_receiver,
                receiver: self.inner.clone(),
            }
        }
    }

    impl<S: Stream + Unpin + FusedStream> SharedReceiverItem<S> {
        /// Receive an item from the stream. Since the `SharedReceiverItem` is
        /// consumed in the process, this can only occur once. Receiving
        /// is cooperative in that we receive items from the stream on behalf of
        /// other `SharedReceiveItem`s until we have received our own.
        pub async fn receive(self) -> Option<S::Item> {
            use oneshot::TryRecvError::*;
            // Check if we have already received our item. If so, we are done.
            match self.value.try_recv() {
                Ok(v) => return v,
                Err(Disconnected) => return None,
                Err(Empty) => {}
            }
            let mut receiver = self.receiver.lock().await;
            loop {
                // We check at the start of the loop since it is possible that another thread
                // received for us since we acquired the lock.
                match self.value.try_recv() {
                    Ok(v) => return v,
                    Err(Disconnected) => return None,
                    Err(Empty) => {}
                }
                // Receive the next item from the stream to send to the next waiting receiver.
                let val = receiver.src.next().await;
                // Since we have not received our value, the pending queue cannot be empty.
                let next_item = receiver.pending.pop_front().unwrap();
                // We discard the result because we do not care if the receiver has already been
                // dropped.
                let _ = next_item.send(val);
            }
        }
    }
}

/// An error response to a dry-run request.
#[derive(thiserror::Error, Debug)]
pub enum ErrorResult {
    /// The current block state is undefined. It should be initialized with a
    /// `load_block_state` request before any other operations.
    #[error("block state not loaded")]
    NoState(),
    /// The requested block was not found, so its state could not be loaded.
    /// Response to `load_block_state`.
    #[error("block not found")]
    BlockNotFound(),
    /// The specified account was not found.
    /// Response to `get_account_info`, `mint_to_account` and `run_transaction`.
    #[error("account not found")]
    AccountNotFound(),
    /// The specified instance was not found.
    /// Response to `get_instance_info`.
    #[error("contract instance not found")]
    InstanceNotFound(),
    /// The amount to mint would overflow the total CCD supply.
    /// Response to `mint_to_account`.
    #[error("mint amount exceeds limit")]
    AmountOverLimit {
        /// The maximum amount that can be minted.
        amount_limit: Amount,
    },
    /// The balance of the sender account is not sufficient to pay for the
    /// operation. Response to `run_transaction`.
    #[error("account balance insufficient")]
    BalanceInsufficient {
        /// The balance required to pay for the operation.
        required_amount:  Amount,
        /// The actual amount available on the account to pay for the operation.
        available_amount: Amount,
    },
    /// The energy supplied for the transaction was not sufficient to perform
    /// the basic checks. Response to `run_transaction`.
    #[error("energy insufficient")]
    EnergyInsufficient {
        /// The energy required to perform the basic checks on the transaction.
        /// Note that this may not be sufficient to also execute the
        /// transaction.
        energy_required: Energy,
    },
    /// The contract invocation failed.
    /// Response to `invoke_instance`.
    #[error("invoke instance failed")]
    InvokeFailure {
        /// If invoking a V0 contract this is not provided, otherwise it is
        /// the return value produced by the call unless the call failed
        /// with out of energy or runtime error. If the V1 contract
        /// terminated with a logic error then the return value is
        /// present.
        return_value: Option<Vec<u8>>,
        /// Energy used by the execution.
        used_energy:  Energy,
        /// Contract execution failed for the given reason.
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

/// An error resulting from a dry-run operation.
#[derive(thiserror::Error, Debug)]
pub enum DryRunError {
    /// The server responded with an error code.
    /// In this case, no futher requests will be acceped in the dry-run session.
    #[error("{0}")]
    CallError(#[from] tonic::Status),
    /// The dry-run operation failed.
    /// In this case, further dry-run requests are possible in the same session.
    #[error("dry-run operation failed: {result}")]
    OperationFailed {
        /// The error result.
        #[source]
        result:          ErrorResult,
        /// The energy quota remaining for subsequent dry-run requests in the
        /// session.
        quota_remaining: Energy,
    },
}

/// A result value together with the remaining energy quota at the completion of
/// the operation.
#[derive(Debug, Clone)]
pub struct WithRemainingQuota<T> {
    /// The result valule.
    pub inner:           T,
    /// The remaining energy quota.
    pub quota_remaining: Energy,
}

/// The successful result of [DryRun::load_block_state].
#[derive(Debug, Clone)]
pub struct BlockStateLoaded {
    /// The timestamp of the block, taken to be the current timestamp when
    /// executing transactions.
    pub current_timestamp: Timestamp,
    /// The hash of the block that was loaded.
    pub block_hash:        BlockHash,
    /// The protocol version at the specified block. The behavior of operations
    /// can vary across protocol version.
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

/// The successful result of [DryRun::invoke_instance].
#[derive(Debug, Clone)]
pub struct InvokeInstanceSuccess {
    /// The return value for a V1 contract call. Absent for a V0 contract call.
    pub return_value: Option<ReturnValue>,
    /// The effects produced by contract execution.
    pub events:       Vec<ContractTraceElement>,
    /// The energy used by the execution.
    pub used_energy:  Energy,
}

impl TryFrom<Option<Result<generated::DryRunResponse, tonic::Status>>>
    for WithRemainingQuota<InvokeInstanceSuccess>
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
                        let inner = InvokeInstanceSuccess {
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

/// The successful result of [DryRun::set_timestamp].
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

/// The successful result of [DryRun::mint_to_account].
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

/// Representation of a transaction for the purposes of dry-running it.
/// Compared to a genuine transaction, this does not include an expiry time or
/// signatures. It is possible to specify which credentials and keys are assumed
/// to sign the transaction. This is only useful for transactions from
/// multi-signature accounts. In particular, it can ensure that the calculated
/// cost is correct when multiple signatures are used. For transactions that
/// update the keys on a multi-credential account, the transaction must be
/// signed by the credential whose keys are updated, so specifying which keys
/// sign is required here.
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

/// The successful result of [DryRun::transaction].
/// Note that a transaction can still be rejected (i.e. produce no effect beyond
/// charging the sender) even if it is executed.
#[derive(Clone, Debug)]
pub struct TransactionExecuted {
    /// The actual energy cost of executing the transaction.
    pub energy_cost:  Energy,
    /// Detailed result of the transaction execution.
    pub details:      AccountTransactionDetails,
    /// For V1 contract update transactions, the return value.
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

/// A dry-run session.
pub struct DryRun {
    /// The channel used for sending requests to the server.
    /// This is `None` if the session has been closed.
    request_send:  Option<channel::mpsc::Sender<generated::DryRunRequest>>,
    /// The channel used for receiving responses from the server.
    response_recv: shared_receiver::SharedReceiver<
        futures::stream::Fuse<tonic::Streaming<generated::DryRunResponse>>,
    >,
    /// The timeout in milliseconds for the dry-run session to complete.
    timeout:       Option<u64>,
    /// The energy quota for the dry-run session as a whole.
    energy_quota:  Option<u64>,
}

impl DryRun {
    /// Start a new dry-run session.
    /// This may return `UNIMPLEMENTED` if the endpoint is not available on the
    /// server. It may return `UNAVAILABLE` if the endpoint is not currently
    /// available to due resource limitations.
    pub(crate) async fn new(
        client: &mut generated::queries_client::QueriesClient<tonic::transport::Channel>,
    ) -> tonic::Result<Self> {
        let (request_send, request_recv) = channel::mpsc::channel(10);
        let response = client.dry_run(request_recv).await?;
        fn parse_meta_u64(meta: Option<&MetadataValue<tonic::metadata::Ascii>>) -> Option<u64> {
            meta?.to_str().ok()?.parse().ok()
        }
        let timeout: Option<u64> = parse_meta_u64(response.metadata().get("timeout"));
        let energy_quota: Option<u64> = parse_meta_u64(response.metadata().get("quota"));
        let response_stream = response.into_inner();
        let response_recv =
            shared_receiver::SharedReceiver::new(futures::stream::StreamExt::fuse(response_stream));
        Ok(DryRun {
            request_send: Some(request_send),
            response_recv,
            timeout,
            energy_quota,
        })
    }

    /// Get the timeout for the dry-run session set by the server.
    /// Returns `None` if the initial metadata did not include the timeout, or
    /// it could not be parsed.
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.timeout.map(std::time::Duration::from_millis)
    }

    /// Get the total energy quota set for the dry-run session.
    /// Returns `None` if the initial metadata did not include the quota, or it
    /// could not be parsed.
    pub fn energy_quota(&self) -> Option<Energy> { self.energy_quota.map(Energy::from) }

    /// Load the state from a specified block.
    /// This can result in an error if the dry-run session has already been
    /// closed, either by [DryRun::close] or by the server closing the session.
    /// In this case, the response code indicates the cause.
    /// If successful, this returns a future that can be used to wait for the
    /// result of the operation. The following results are possible:
    ///
    ///  * [BlockStateLoaded] if the operation is successful.
    ///  * [DryRunError::OperationFailed] if the operation failed, with one of
    ///    the following results:
    ///    - [ErrorResult::BlockNotFound] if the block could not be found.
    ///  * [DryRunError::CallError] if the server produced an error code, or if
    ///    the server's response was unexpected.
    ///    - If the server's response could not be interpreted, the result code
    ///      `INVALID_ARGUMENT` or `UNKNOWN` is returned.
    ///    - If the execution of the query would exceed the energy quota,
    ///      `RESOURCE_EXHAUSETED` is returned.
    ///    - If the timeout for the dry-run session has expired,
    ///      `DEADLINE_EXCEEDED` is returned.
    ///    - `INVALID_ARGUMENT` or `INTERNAL` could occur as a result of bugs.
    ///
    /// The energy cost of this operation is 2000.
    pub async fn load_block_state(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> tonic::Result<impl Future<Output = DryRunResult<BlockStateLoaded>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::LoadBlockState(
                (&bi.into_block_identifier()).into(),
            )),
        };
        Ok(self.request(request).await?.map(|z| z.try_into()))
    }

    /// Get the account information for a specified account in the current
    /// state. This can result in an error if the dry-run session has
    /// already been closed, either by [DryRun::close] or by the server
    /// closing the session. In this case, the response code indicates the
    /// cause. If successful, this returns a future that can be used to wait
    /// for the result of the operation. The following results are possible:
    ///
    ///  * [AccountInfo] if the operation is successful.
    ///  * [DryRunError::OperationFailed] if the operation failed, with one of
    ///    the following results:
    ///    - [ErrorResult::NoState] if no block state has been loaded.
    ///    - [ErrorResult::AccountNotFound] if the account could not be found.
    ///  * [DryRunError::CallError] if the server produced an error code, or if
    ///    the server's response was unexpected.
    ///    - If the server's response could not be interpreted, the result code
    ///      `INVALID_ARGUMENT` or `UNKNOWN` is returned.
    ///    - If the execution of the query would exceed the energy quota,
    ///      `RESOURCE_EXHAUSETED` is returned.
    ///    - If the timeout for the dry-run session has expired,
    ///      `DEADLINE_EXCEEDED` is returned.
    ///    - `INVALID_ARGUMENT` or `INTERNAL` could occur as a result of bugs.
    ///
    /// The energy cost of this operation is 200.
    pub async fn get_account_info(
        &mut self,
        acc: &AccountIdentifier,
    ) -> tonic::Result<impl Future<Output = DryRunResult<AccountInfo>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateQuery(DryRunStateQuery {
                query: Some(generated::dry_run_state_query::Query::GetAccountInfo(
                    acc.into(),
                )),
            })),
        };
        Ok(self.request(request).await?.map(|z| z.try_into()))
    }

    /// Get the details of a specified smart contract instance in the current
    /// state. This operation can result in an error if the dry-run session has
    /// already been closed, either by [DryRun::close] or by the server
    /// closing the session. In this case, the response code indicates the
    /// cause. If successful, this returns a future that can be used to wait
    /// for the result of the operation. The following results are possible:
    ///
    ///  * [InstanceInfo] if the operation is successful.
    ///  * [DryRunError::OperationFailed] if the operation failed, with one of
    ///    the following results:
    ///    - [ErrorResult::NoState] if no block state has been loaded.
    ///    - [ErrorResult::AccountNotFound] if the account could not be found.
    ///  * [DryRunError::CallError] if the server produced an error code, or if
    ///    the server's response was unexpected.
    ///    - If the server's response could not be interpreted, the result code
    ///      `INVALID_ARGUMENT` or `UNKNOWN` is returned.
    ///    - If the execution of the query would exceed the energy quota,
    ///      `RESOURCE_EXHAUSETED` is returned.
    ///    - If the timeout for the dry-run session has expired,
    ///      `DEADLINE_EXCEEDED` is returned.
    ///    - `INVALID_ARGUMENT` or `INTERNAL` could occur as a result of bugs.
    ///
    /// The energy cost of this operation is 200.
    pub async fn get_instance_info(
        &mut self,
        address: &ContractAddress,
    ) -> tonic::Result<impl Future<Output = DryRunResult<InstanceInfo>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateQuery(DryRunStateQuery {
                query: Some(generated::dry_run_state_query::Query::GetInstanceInfo(
                    address.into(),
                )),
            })),
        };
        Ok(self.request(request).await?.map(|z| z.try_into()))
    }

    /// Invoke an entrypoint on a smart contract instance in the current state.
    /// Any changes this would make to the state will be rolled back so they are
    /// not observable by subsequent operations in the dry-run session. (To make
    /// updates that are observable within the dry-run session, use
    /// [DryRun::run_transaction] instead.) This operation can result in an
    /// error if the dry-run session has already been closed, either by
    /// [DryRun::close] or by the server closing the session. In this case,
    /// the response code indicates the cause. If successful, this returns a
    /// future that can be used to wait for the result of the operation. The
    /// following results are possible:
    ///
    ///  * [InvokeInstanceSuccess] if the operation is successful.
    ///  * [DryRunError::OperationFailed] if the operation failed, with one of
    ///    the following results:
    ///    - [ErrorResult::NoState] if no block state has been loaded.
    ///    - [ErrorResult::InvokeFailure] if the invocation failed. (This can be
    ///      because the contract logic produced a reject, or a number of other
    ///      reasons, such as the endpoint not existing.)
    ///  * [DryRunError::CallError] if the server produced an error code, or if
    ///    the server's response was unexpected.
    ///    - If the server's response could not be interpreted, the result code
    ///      `INVALID_ARGUMENT` or `UNKNOWN` is returned.
    ///    - If the execution of the query would exceed the energy quota,
    ///      `RESOURCE_EXHAUSETED` is returned.
    ///    - If the timeout for the dry-run session has expired,
    ///      `DEADLINE_EXCEEDED` is returned.
    ///    - `INVALID_ARGUMENT` or `INTERNAL` could occur as a result of bugs.
    ///
    /// The energy cost of this operation is 200 plus the energy used by the
    /// execution of the contract endpoint.
    pub async fn invoke_instance(
        &mut self,
        context: &ContractContext,
    ) -> tonic::Result<impl Future<Output = DryRunResult<InvokeInstanceSuccess>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateQuery(DryRunStateQuery {
                query: Some(generated::dry_run_state_query::Query::InvokeInstance(
                    context.into(),
                )),
            })),
        };
        Ok(self.request(request).await?.map(|z| z.try_into()))
    }

    /// Update the current timestamp for subsequent dry-run operations. The
    /// timestamp is automatically set to the timestamp of the block loaded
    /// by [DryRun::load_block_state]. For smart contracts that are time
    /// sensitive, overriding the timestamp can be useful. This operation can
    /// result in an error if the dry-run session has already been closed,
    /// either by [DryRun::close] or by the server closing the session. In
    /// this case, the response code indicates the cause. If successful,
    /// this returns a future that can be used to wait for the result of the
    /// operation. The following results are possible:
    ///
    ///  * [TimestampSet] if the operation is successful.
    ///  * [DryRunError::OperationFailed] if the operation failed, with one of
    ///    the following results:
    ///    - [ErrorResult::NoState] if no block state has been loaded.
    ///  * [DryRunError::CallError] if the server produced an error code, or if
    ///    the server's response was unexpected.
    ///    - If the server's response could not be interpreted, the result code
    ///      `INVALID_ARGUMENT` or `UNKNOWN` is returned.
    ///    - If the execution of the query would exceed the energy quota,
    ///      `RESOURCE_EXHAUSETED` is returned.
    ///    - If the timeout for the dry-run session has expired,
    ///      `DEADLINE_EXCEEDED` is returned.
    ///    - `INVALID_ARGUMENT` or `INTERNAL` could occur as a result of bugs.
    ///
    /// The energy cost of this operation is 50.
    pub async fn set_timestamp(
        &mut self,
        timestamp: Timestamp,
    ) -> tonic::Result<impl Future<Output = DryRunResult<TimestampSet>>> {
        let request = generated::DryRunRequest {
            request: Some(dry_run_request::Request::StateOperation(
                DryRunStateOperation {
                    operation: Some(generated::dry_run_state_operation::Operation::SetTimestamp(
                        timestamp.into(),
                    )),
                },
            )),
        };
        Ok(self.request(request).await?.map(|z| z.try_into()))
    }

    /// Mint a specified amount and award it to a specified account. This
    /// operation can result in an error if the dry-run session has already
    /// been closed, either by [DryRun::close] or by the server closing the
    /// session. In this case, the response code indicates the cause. If
    /// successful, this returns a future that can be used to wait for the
    /// result of the operation. The following results are possible:
    ///
    ///  * [MintedToAccount] if the operation is successful.
    ///  * [DryRunError::OperationFailed] if the operation failed, with one of
    ///    the following results:
    ///    - [ErrorResult::NoState] if no block state has been loaded.
    ///    - [ErrorResult::AmountOverLimit] if the minted amount would overflow
    ///      the total CCD supply.
    ///  * [DryRunError::CallError] if the server produced an error code, or if
    ///    the server's response was unexpected.
    ///    - If the server's response could not be interpreted, the result code
    ///      `INVALID_ARGUMENT` or `UNKNOWN` is returned.
    ///    - If the execution of the query would exceed the energy quota,
    ///      `RESOURCE_EXHAUSETED` is returned.
    ///    - If the timeout for the dry-run session has expired,
    ///      `DEADLINE_EXCEEDED` is returned.
    ///    - `INVALID_ARGUMENT` or `INTERNAL` could occur as a result of bugs.
    ///
    /// The energy cost of this operation is 400.
    pub async fn mint_to_account(
        &mut self,
        account_address: &AccountAddress,
        mint_amount: Amount,
    ) -> tonic::Result<impl Future<Output = DryRunResult<MintedToAccount>>> {
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
        Ok(self.request(request).await?.map(|z| z.try_into()))
    }

    /// Dry-run a transaction, updating the state of the dry-run session
    /// accordingly. This operation can result in an error if the dry-run
    /// session has already been closed, either by [DryRun::close] or by the
    /// server closing the session. In this case, the response code
    /// indicates the cause. If successful, this returns a future that can
    /// be used to wait for the result of the operation. The following
    /// results are possible:
    ///
    ///  * [TransactionExecuted] if the transaction was executed. This case
    ///    applies both if the transaction is rejected or successful.
    ///  * [DryRunError::OperationFailed] if the operation failed, with one of
    ///    the following results:
    ///    - [ErrorResult::NoState] if no block state has been loaded.
    ///    - [ErrorResult::AccountNotFound] if the sender account does not
    ///      exist.
    ///    - [ErrorResult::BalanceInsufficient] if the sender account does not
    ///      have sufficient balance to pay the deposit for the transaction.
    ///    - [ErrorResult::EnergyInsufficient] if the specified energy is not
    ///      sufficient to cover the cost of the basic checks required for a
    ///      transaction to be included in the chain.
    ///  * [DryRunError::CallError] if the server produced an error code, or if
    ///    the server's response was unexpected.
    ///    - If the server's response could not be interpreted, the result code
    ///      `INVALID_ARGUMENT` or `UNKNOWN` is returned.
    ///    - If the execution of the query would exceed the energy quota,
    ///      `RESOURCE_EXHAUSETED` is returned.
    ///    - If the timeout for the dry-run session has expired,
    ///      `DEADLINE_EXCEEDED` is returned.
    ///    - `INVALID_ARGUMENT` or `INTERNAL` could occur as a result of bugs.
    ///
    /// The energy cost of this operation is 400.   
    pub async fn run_transaction(
        &mut self,
        transaction: DryRunTransaction,
    ) -> tonic::Result<impl Future<Output = DryRunResult<TransactionExecuted>>> {
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
        Ok(self.request(request).await?.map(|z| z.try_into()))
    }

    /// Close the request stream. Any subsequent dry-run requests will result in
    /// a `CANCELLED` status code. Closing the request stream allows the
    /// server to free resources associated with the dry-run session. It is
    /// recommended to close the request stream if the [DryRun] object will
    /// be retained for any significant length of time after the last request is
    /// made.
    pub fn close(&mut self) { self.request_send = None; }

    /// Helper function that issues a dry-run request and returns a future for
    /// the corresponding response.
    async fn request(
        &mut self,
        request: generated::DryRunRequest,
    ) -> tonic::Result<impl Future<Output = Option<tonic::Result<generated::DryRunResponse>>>> {
        let sender = self
            .request_send
            .as_mut()
            .ok_or_else(|| tonic::Status::cancelled("dry run already completed"))?;
        match sender.send(request).await {
            Ok(_) => Ok(self.response_recv.next().await.receive()),
            Err(_) => {
                // In this case, the server must have closed the stream. We query the
                // response stream to see if there is an error indicating the reason.
                if let Some(Err(e)) = self.response_recv.next().await.receive().await {
                    Err(e)?
                } else {
                    Err(tonic::Status::cancelled("dry run already completed"))?
                }
            }
        }
    }
}
