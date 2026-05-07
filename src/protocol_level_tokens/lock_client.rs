//! Higher-level abstraction for interactions with protocol-level locks.

use concordium_base::{
    base::Nonce,
    common::{cbor::CborSerializationError, types::TransactionTime},
    contracts_common::AccountAddress,
    hashes::TransactionHash,
    protocol_level_locks::{
        LockConfig, LockController, LockControllerSimpleV0, LockControllerSimpleV0Capability,
        LockId, LockInfo,
    },
    protocol_level_tokens::{
        meta_operations::{self, MetaUpdateOperations},
        CborMemo, TokenAmount, TokenId,
    },
    transactions::{construct, BlockItem, ExactSizeTransactionSigner},
};
use thiserror::Error;
use tonic::async_trait;

use crate::{
    endpoints,
    protocol_level_tokens::{LockInfoResponse, TokenAccountState},
    types::{AccountTransactionEffects, BlockItemSummaryDetails, WalletAccount},
    v2::{BlockIdentifier, Client, QueryError, QueryResponse, RPCError},
};

const DEFAULT_EXPIRY_SECS: u32 = 300;

#[async_trait]
trait LockQuery {
    async fn get_lock_info(
        &mut self,
        lock_id: LockId,
        bi: BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<LockInfoResponse>>;
}

#[async_trait]
impl LockQuery for Client {
    async fn get_lock_info(
        &mut self,
        lock_id: LockId,
        bi: BlockIdentifier,
    ) -> endpoints::QueryResult<QueryResponse<LockInfoResponse>> {
        Client::get_lock_info(self, lock_id, bi).await
    }
}

trait Validate {
    fn validate_fund(&self, sender: AccountAddress, payload: &FundTokens) -> LockResult<()>;
    fn validate_send(&self, sender: AccountAddress, payload: &SendTokens) -> LockResult<()>;
    fn validate_return(&self, sender: AccountAddress, payload: &ReturnTokens) -> LockResult<()>;
    fn validate_cancel(&self, sender: AccountAddress) -> LockResult<()>;
}

/// Optional parameters for a transaction.
#[derive(Debug, Default, Clone)]
pub struct TransactionMetadata {
    /// Optional expiration time for the transaction. If not set, this defaults to 5 minutes in the
    /// future.
    pub expiry: Option<TransactionTime>,
    /// Optional nonce for the transaction. If not set, the next nonce is fetched from the node.
    pub nonce: Option<Nonce>,
}

/// Whether to perform client-side validation before submitting lock
/// operations.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default)]
pub enum Validation {
    /// Do not perform client-side validation.
    #[default]
    NoValidation,
    /// Refresh latest finalized state and validate before submission.
    Validate,
}

/// Details for funding a lock.
#[derive(Debug, Clone)]
pub struct FundTokens {
    /// The token to fund the lock with.
    pub token_id: TokenId,
    /// The amount of tokens to lock.
    pub amount: TokenAmount,
    /// Optional memo to attach to the fund operation.
    pub memo: Option<CborMemo>,
}

/// Details for sending locked funds.
#[derive(Debug, Clone)]
pub struct SendTokens {
    /// The token whose locked funds are being sent.
    pub token_id: TokenId,
    /// The account whose funds are currently locked under the lock.
    pub source: AccountAddress,
    /// The recipient account that must be present in the lock's recipient list.
    pub recipient: AccountAddress,
    /// The amount of locked tokens to send.
    pub amount: TokenAmount,
    /// Optional memo to attach to the send operation.
    pub memo: Option<CborMemo>,
}

/// Details for returning locked funds.
#[derive(Debug, Clone)]
pub struct ReturnTokens {
    /// The token whose locked funds are being returned.
    pub token_id: TokenId,
    /// The account whose funds are currently locked under the lock.
    pub source: AccountAddress,
    /// The amount of locked tokens to return.
    pub amount: TokenAmount,
    /// Optional memo to attach to the return operation.
    pub memo: Option<CborMemo>,
}

/// Result of a lock operation.
pub type LockResult<T> = Result<T, LockError>;

/// Errors that can occur while interacting with locks through the high-level
/// client.
#[derive(Debug, Error)]
pub enum LockError {
    /// Error returned when querying the node fails.
    #[error("query error: {0}.")]
    Query(#[from] QueryError),
    /// Error returned when encoding or decoding CBOR fails.
    #[error("cbor serialization/deserializing error: {0}.")]
    CborSerialization(#[from] CborSerializationError),
    /// Error returned when an RPC call fails.
    #[error("RPC error: {0}.")]
    RPC(#[from] RPCError),
    /// The sender lacks the controller capability required by the operation.
    #[error("the sender does not have the required capability.")]
    MissingCapability,
    /// The lock has expired and can no longer be operated on.
    #[error("the lock has expired.")]
    Expired,
    /// The requested amount exceeds the funds available for the operation.
    #[error("insufficient funds available for the requested operation.")]
    InsufficientFunds,
    /// The token is not configured in the lock controller.
    #[error("the token is not configured for this lock.")]
    TokenNotConfigured,
    /// The recipient is not part of the lock's configured recipient list.
    #[error("the recipient is not configured for this lock.")]
    RecipientNotAllowed,
    /// The submitted lock-creation transaction could not be resolved into a lock.
    #[error("failed to resolve lock creation: {0}")]
    CreationFailed(String),
}

/// A submitted lock creation transaction that can be resolved into a
/// [`LockClient`] once finalized.
#[derive(Debug, Clone)]
pub struct PendingLockCreation {
    client: Client,
    hash: TransactionHash,
}

impl PendingLockCreation {
    /// Get the transaction hash of the submitted lock-creation transaction.
    ///
    /// This can be used to monitor or persist the submitted transaction before
    /// consuming the pending handle with [`PendingLockCreation::wait_for_finalization`].
    pub fn transaction_hash(&self) -> TransactionHash {
        self.hash
    }

    /// Wait for the submitted lock-creation transaction to finalize and
    /// resolve it into a [`LockClient`].
    ///
    /// If `timeout` is `Some`, the wait is bounded to that many seconds.
    /// The pending handle is consumed by this operation.
    pub async fn wait_for_finalization(
        self,
        timeout_seconds: Option<u64>,
    ) -> LockResult<LockClient> {
        let mut client = self.client;
        let (_, summary) = if let Some(timeout_secs) = timeout_seconds {
            tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                client.wait_until_finalized(&self.hash),
            )
            .await
            .map_err(|_| {
                LockError::CreationFailed("timed out while waiting for finalization".into())
            })??
        } else {
            client.wait_until_finalized(&self.hash).await?
        };

        let lock_id = created_lock_id_from_summary(summary)?;

        LockClient::from_lock_id(client, lock_id).await
    }
}

#[derive(Debug, Clone)]
enum PendingOperation {
    Fund(FundTokens),
    Send(SendTokens),
    Return(ReturnTokens),
    Cancel(Option<CborMemo>),
}

/// Builder for composing a lock creation with subsequent operations in a
/// single meta-update transaction.
///
/// The lock identifier is predicted at submission time from the sender's
/// account index and next nonce. This minimises, but does not eliminate, the
/// chance of nonce staleness if another transaction consumes the sender's next
/// nonce concurrently before submission reaches the node.
#[derive(Debug, Clone)]
pub struct LockCreateProposal {
    sender: AccountAddress,
    config: LockConfig,
    operations: Vec<PendingOperation>,
}

impl LockCreateProposal {
    fn new(sender: AccountAddress, config: LockConfig) -> Self {
        Self {
            sender,
            config,
            operations: Vec::new(),
        }
    }

    /// Chain a fund operation onto the lock-creation proposal.
    ///
    /// The fund operation is stored without a lock id and is resolved against
    /// the predicted lock id at submission time.
    pub fn fund(mut self, payload: FundTokens) -> Self {
        self.operations.push(PendingOperation::Fund(payload));
        self
    }

    /// Chain a send operation onto the lock-creation proposal.
    ///
    /// The send operation is stored without a lock id and is resolved against
    /// the predicted lock id at submission time.
    pub fn send(mut self, payload: SendTokens) -> Self {
        self.operations.push(PendingOperation::Send(payload));
        self
    }

    /// Chain a return operation onto the lock-creation proposal.
    ///
    /// The return operation is stored without a lock id and is resolved
    /// against the predicted lock id at submission time.
    pub fn return_funds(mut self, payload: ReturnTokens) -> Self {
        self.operations.push(PendingOperation::Return(payload));
        self
    }

    /// Chain a cancel operation onto the lock-creation proposal.
    ///
    /// The cancel operation is stored without a lock id and is resolved
    /// against the predicted lock id at submission time.
    pub fn cancel(mut self, memo: Option<CborMemo>) -> Self {
        self.operations.push(PendingOperation::Cancel(memo));
        self
    }

    /// Submit the proposal as a single meta-update transaction.
    ///
    /// The lock id is predicted at submission time from the sender's account
    /// index and next nonce, then injected into all chained operations before
    /// submission. The returned [`PendingLockCreation`] can be awaited to
    /// resolve the finalized lock.
    pub async fn submit(
        self,
        client: &mut Client,
        signer: &WalletAccount,
        meta: Option<TransactionMetadata>,
    ) -> LockResult<PendingLockCreation> {
        let lock_id = get_next_lock_id(client, self.sender, 0).await?;

        let operations = resolve_pending_operations(self.config, self.operations, lock_id);
        let hash = sign_and_send_with_client(client, signer, &operations, meta).await?;
        Ok(PendingLockCreation {
            client: client.clone(),
            hash,
        })
    }
}

/// Get the next deterministic lock id for the given account and creation order.
///
/// This queries the account's index and next sequence number from the node and
/// returns the lock id that would be assigned to a `lockCreate` operation with
/// the given `creation_order` in the next transaction from that account.
pub async fn get_next_lock_id(
    client: &mut Client,
    account: AccountAddress,
    creation_order: u64,
) -> LockResult<LockId> {
    let account_index = client
        .get_account_info(&account.into(), BlockIdentifier::LastFinal)
        .await?
        .response
        .account_index;
    let nonce = client
        .get_next_account_sequence_number(&account)
        .await?
        .nonce;
    Ok(LockId::new(account_index, nonce, creation_order))
}

/// Construct a proposal for composing lock creation with additional operations
/// in a single meta-update transaction.
pub fn create_lock_proposal(sender: AccountAddress, config: LockConfig) -> LockCreateProposal {
    LockCreateProposal::new(sender, config)
}

/// Submit a lock-creation transaction and return a pending creation handle.
///
/// This submits only the `lockCreate` operation. Use
/// [`create_lock_proposal`] to compose creation with additional operations in
/// the same transaction.
pub async fn create_lock(
    mut client: Client,
    signer: &WalletAccount,
    config: LockConfig,
    meta: Option<TransactionMetadata>,
) -> LockResult<PendingLockCreation> {
    let operations = MetaUpdateOperations::new(vec![meta_operations::lock_create(config)]);
    let hash = sign_and_send_with_client(&mut client, signer, &operations, meta).await?;
    Ok(PendingLockCreation { client, hash })
}

/// A wrapper around the gRPC client representing a protocol-level lock.
#[derive(Debug, Clone)]
pub struct LockClient {
    client: Client,
    /// Cached lock information.
    info: LockInfo,
}

impl LockClient {
    /// Construct a [`LockClient`] from an existing RPC client and decoded lock
    /// info.
    ///
    /// The default transaction submission expiry is five minutes.
    pub fn new(client: Client, info: LockInfo) -> Self {
        Self { client, info }
    }

    /// Construct a [`LockClient`] by looking up lock information from the
    /// chain.
    ///
    /// The lock info is fetched from the latest finalized block and decoded
    /// from the query response.
    pub async fn from_lock_id(mut client: Client, lock_id: LockId) -> LockResult<Self> {
        let info = from_lock_id_impl(&mut client, lock_id).await?;
        Ok(Self::new(client, info))
    }

    /// Get the cached lock information.
    ///
    /// This does not refresh chain state. Use [`LockClient::update_lock_info`]
    /// to fetch the latest finalized lock info.
    pub fn lock_info(&self) -> &LockInfo {
        &self.info
    }

    /// Refresh the cached lock information to the latest finalized block.
    ///
    /// This replaces the cached [`LockInfo`] with the latest finalized state
    /// fetched from the node.
    pub async fn update_lock_info(&mut self) -> LockResult<()> {
        self.info = query_lock_info_impl(&mut self.client, self.info.lock.clone()).await?;
        Ok(())
    }

    /// Send a set of raw meta-update operations without validation.
    ///
    /// This is the lower-level submission helper for custom pre-built
    /// [`MetaUpdateOperations`] targeting the current lock.
    pub async fn send_operations(
        &mut self,
        signer: &WalletAccount,
        operations: MetaUpdateOperations,
        meta: Option<TransactionMetadata>,
    ) -> LockResult<TransactionHash> {
        self.sign_and_send(signer, &operations, meta).await
    }

    /// Validate that the lock can be funded with the given payload.
    ///
    /// This refreshes the latest finalized lock info, checks expiry,
    /// dispatches controller-specific validation based on the lock
    /// variant, verifies that the token is configured
    /// for the lock, and checks that the sender has enough unencumbered
    /// balance available.
    pub async fn validate_fund(
        &mut self,
        sender: AccountAddress,
        payload: &FundTokens,
    ) -> LockResult<()> {
        self.update_lock_info().await?;
        self.ensure_not_expired()?;
        self.info.controller.validate_fund(sender, payload)?;

        let info = self
            .client
            .get_account_info(&sender.into(), BlockIdentifier::LastFinal)
            .await?
            .response;
        let state = info
            .tokens
            .iter()
            .find(|token| token.token_id == payload.token_id)
            .map(|token| &token.state);
        let available = account_available_balance(state)?;
        if available < payload.amount {
            return Err(LockError::InsufficientFunds);
        }
        Ok(())
    }

    /// Validate that locked funds can be sent with the given payload.
    ///
    /// This refreshes the latest finalized lock info, checks expiry,
    /// dispatches controller-specific validation based on the lock
    /// variant, verifies that the source has
    /// sufficient funds locked under this lock for the requested token, and
    /// checks that the recipient is configured for the lock.
    pub async fn validate_send(
        &mut self,
        sender: AccountAddress,
        payload: &SendTokens,
    ) -> LockResult<()> {
        self.update_lock_info().await?;
        self.ensure_not_expired()?;
        self.info.controller.validate_send(sender, payload)?;
        self.ensure_locked_amount(payload.source, &payload.token_id, payload.amount)?;
        if !self
            .info
            .recipients
            .iter()
            .any(|recipient| recipient.address == payload.recipient)
        {
            return Err(LockError::RecipientNotAllowed);
        }
        Ok(())
    }

    /// Validate that locked funds can be returned with the given payload.
    ///
    /// This refreshes the latest finalized lock info, checks expiry,
    /// dispatches controller-specific validation based on the lock
    /// variant, and verifies that the source has
    /// sufficient funds locked under this lock for the requested token.
    pub async fn validate_return(
        &mut self,
        sender: AccountAddress,
        payload: &ReturnTokens,
    ) -> LockResult<()> {
        self.update_lock_info().await?;
        self.ensure_not_expired()?;
        self.info.controller.validate_return(sender, payload)?;
        self.ensure_locked_amount(payload.source, &payload.token_id, payload.amount)?;
        Ok(())
    }

    /// Validate that the lock can be cancelled by the given sender.
    ///
    /// This refreshes the latest finalized lock info, checks expiry, and
    /// dispatches controller-specific validation based on the lock
    /// variant to verify that the sender has the
    /// cancel capability.
    pub async fn validate_cancel(&mut self, sender: AccountAddress) -> LockResult<()> {
        self.update_lock_info().await?;
        self.ensure_not_expired()?;
        self.info.controller.validate_cancel(sender)
    }

    /// Fund the lock from the sender account.
    ///
    /// If `validation` is [`Validation::Validate`], the operation is validated
    /// against the latest finalized state before submission.
    pub async fn fund(
        &mut self,
        signer: &WalletAccount,
        payload: FundTokens,
        meta: Option<TransactionMetadata>,
        validation: Validation,
    ) -> LockResult<TransactionHash> {
        if validation == Validation::Validate {
            self.validate_fund(signer.address, &payload).await?;
        }
        let operations = MetaUpdateOperations::new(vec![meta_operations::lock_fund(
            payload.token_id,
            self.info.lock.clone(),
            payload.amount,
            payload.memo,
        )]);
        self.sign_and_send(signer, &operations, meta).await
    }

    /// Send locked funds to a recipient.
    ///
    /// If `validation` is [`Validation::Validate`], the operation is validated
    /// against the latest finalized state before submission.
    pub async fn send(
        &mut self,
        signer: &WalletAccount,
        payload: SendTokens,
        meta: Option<TransactionMetadata>,
        validation: Validation,
    ) -> LockResult<TransactionHash> {
        if validation == Validation::Validate {
            self.validate_send(signer.address, &payload).await?;
        }
        let operations = MetaUpdateOperations::new(vec![meta_operations::lock_send(
            payload.token_id,
            self.info.lock.clone(),
            payload.source,
            payload.recipient,
            payload.amount,
            payload.memo,
        )]);
        self.sign_and_send(signer, &operations, meta).await
    }

    /// Return locked funds to the owner.
    ///
    /// If `validation` is [`Validation::Validate`], the operation is validated
    /// against the latest finalized state before submission.
    pub async fn return_funds(
        &mut self,
        signer: &WalletAccount,
        payload: ReturnTokens,
        meta: Option<TransactionMetadata>,
        validation: Validation,
    ) -> LockResult<TransactionHash> {
        if validation == Validation::Validate {
            self.validate_return(signer.address, &payload).await?;
        }
        let operations = MetaUpdateOperations::new(vec![meta_operations::lock_return(
            payload.token_id,
            self.info.lock.clone(),
            payload.source,
            payload.amount,
            payload.memo,
        )]);
        self.sign_and_send(signer, &operations, meta).await
    }

    /// Cancel the lock.
    ///
    /// If `validation` is [`Validation::Validate`], the operation is validated
    /// against the latest finalized state before submission.
    pub async fn cancel(
        &mut self,
        signer: &WalletAccount,
        memo: Option<CborMemo>,
        meta: Option<TransactionMetadata>,
        validation: Validation,
    ) -> LockResult<TransactionHash> {
        if validation == Validation::Validate {
            self.validate_cancel(signer.address).await?;
        }
        let operations = MetaUpdateOperations::new(vec![meta_operations::lock_cancel(
            self.info.lock.clone(),
            memo,
        )]);
        self.sign_and_send(signer, &operations, meta).await
    }

    async fn sign_and_send(
        &mut self,
        signer: &WalletAccount,
        operations: &MetaUpdateOperations,
        meta: Option<TransactionMetadata>,
    ) -> LockResult<TransactionHash> {
        sign_and_send_with_client(&mut self.client, signer, operations, meta).await
    }

    fn ensure_not_expired(&self) -> LockResult<()> {
        ensure_not_expired(&self.info)
    }

    fn ensure_locked_amount(
        &self,
        source: AccountAddress,
        token_id: &TokenId,
        amount: TokenAmount,
    ) -> LockResult<()> {
        ensure_locked_amount(&self.info, source, token_id, amount)
    }
}

fn ensure_not_expired(info: &LockInfo) -> LockResult<()> {
    let now = chrono::Utc::now().timestamp() as u64;
    if info.expiry.seconds <= now {
        Err(LockError::Expired)
    } else {
        Ok(())
    }
}

impl Validate for LockController {
    fn validate_fund(&self, sender: AccountAddress, payload: &FundTokens) -> LockResult<()> {
        match self {
            LockController::SimpleV0(controller) => controller.validate_fund(sender, payload),
        }
    }

    fn validate_send(&self, sender: AccountAddress, payload: &SendTokens) -> LockResult<()> {
        match self {
            LockController::SimpleV0(controller) => controller.validate_send(sender, payload),
        }
    }

    fn validate_return(&self, sender: AccountAddress, payload: &ReturnTokens) -> LockResult<()> {
        match self {
            LockController::SimpleV0(controller) => controller.validate_return(sender, payload),
        }
    }

    fn validate_cancel(&self, sender: AccountAddress) -> LockResult<()> {
        match self {
            LockController::SimpleV0(controller) => controller.validate_cancel(sender),
        }
    }
}

impl Validate for LockControllerSimpleV0 {
    fn validate_fund(&self, sender: AccountAddress, payload: &FundTokens) -> LockResult<()> {
        ensure_capability_simple_v0(self, sender, LockControllerSimpleV0Capability::Fund)?;
        if !self.tokens.iter().any(|token| token == &payload.token_id) {
            return Err(LockError::TokenNotConfigured);
        }
        Ok(())
    }

    fn validate_send(&self, sender: AccountAddress, _payload: &SendTokens) -> LockResult<()> {
        ensure_capability_simple_v0(self, sender, LockControllerSimpleV0Capability::Send)
    }

    fn validate_return(&self, sender: AccountAddress, _payload: &ReturnTokens) -> LockResult<()> {
        ensure_capability_simple_v0(self, sender, LockControllerSimpleV0Capability::Return)
    }

    fn validate_cancel(&self, sender: AccountAddress) -> LockResult<()> {
        ensure_capability_simple_v0(self, sender, LockControllerSimpleV0Capability::Cancel)
    }
}

fn ensure_capability_simple_v0(
    controller: &LockControllerSimpleV0,
    sender: AccountAddress,
    capability: LockControllerSimpleV0Capability,
) -> LockResult<()> {
    if controller
        .grants
        .iter()
        .any(|grant| grant.account.address == sender && grant.roles.contains(&capability))
    {
        Ok(())
    } else {
        Err(LockError::MissingCapability)
    }
}

fn ensure_locked_amount(
    info: &LockInfo,
    source: AccountAddress,
    token_id: &TokenId,
    amount: TokenAmount,
) -> LockResult<()> {
    let Some(account_funds) = info
        .funds
        .iter()
        .find(|funds| funds.account.address == source)
    else {
        return Err(LockError::InsufficientFunds);
    };

    let Some(locked_amount) = account_funds
        .amounts
        .iter()
        .find(|locked| &locked.token == token_id)
    else {
        return Err(LockError::InsufficientFunds);
    };

    if locked_amount.amount < amount {
        Err(LockError::InsufficientFunds)
    } else {
        Ok(())
    }
}

async fn from_lock_id_impl<LQ: LockQuery>(lq: &mut LQ, lock_id: LockId) -> LockResult<LockInfo> {
    query_lock_info_impl(lq, lock_id).await
}

async fn query_lock_info_impl<LQ: LockQuery>(lq: &mut LQ, lock_id: LockId) -> LockResult<LockInfo> {
    Ok(lq
        .get_lock_info(lock_id, BlockIdentifier::LastFinal)
        .await?
        .response
        .decode_lock_info()?)
}

fn created_lock_id_from_summary(summary: crate::types::BlockItemSummary) -> LockResult<LockId> {
    let details = summary.details.known_or(LockError::CreationFailed(
        "unknown block item summary details".into(),
    ))?;
    let account_tx = match details {
        BlockItemSummaryDetails::AccountTransaction(details) => details,
        _ => {
            return Err(LockError::CreationFailed(
                "finalized block item is not an account transaction".into(),
            ))
        }
    };
    let effects = account_tx.effects.known_or(LockError::CreationFailed(
        "unknown account transaction effects".into(),
    ))?;
    let events = match effects {
        AccountTransactionEffects::MetaUpdate { events } => events,
        AccountTransactionEffects::None { .. } => {
            return Err(LockError::CreationFailed(
                "lock creation transaction was rejected".into(),
            ))
        }
        _ => {
            return Err(LockError::CreationFailed(
                "finalized account transaction is not a meta update".into(),
            ))
        }
    };

    events
        .into_iter()
        .find_map(|event| match event {
            super::MetaEvent::LockCreate(event) => Some(event.lock_id),
            _ => None,
        })
        .ok_or_else(|| {
            LockError::CreationFailed("missing lock-created event in finalization".into())
        })
}

fn resolve_pending_operations(
    config: LockConfig,
    operations: Vec<PendingOperation>,
    lock_id: LockId,
) -> MetaUpdateOperations {
    let mut ops = Vec::with_capacity(operations.len() + 1);
    ops.push(meta_operations::lock_create(config));
    for op in operations {
        let op = match op {
            PendingOperation::Fund(payload) => meta_operations::lock_fund(
                payload.token_id,
                lock_id.clone(),
                payload.amount,
                payload.memo,
            ),
            PendingOperation::Send(payload) => meta_operations::lock_send(
                payload.token_id,
                lock_id.clone(),
                payload.source,
                payload.recipient,
                payload.amount,
                payload.memo,
            ),
            PendingOperation::Return(payload) => meta_operations::lock_return(
                payload.token_id,
                lock_id.clone(),
                payload.source,
                payload.amount,
                payload.memo,
            ),
            PendingOperation::Cancel(memo) => meta_operations::lock_cancel(lock_id.clone(), memo),
        };
        ops.push(op);
    }
    MetaUpdateOperations::new(ops)
}

fn account_available_balance(state: Option<&TokenAccountState>) -> LockResult<TokenAmount> {
    let Some(state) = state else {
        return Err(LockError::InsufficientFunds);
    };
    let module_state = state.decode_module_state()?;
    Ok(module_state.available.unwrap_or(state.balance))
}

async fn sign_and_send_with_client(
    client: &mut Client,
    signer: &WalletAccount,
    operations: &MetaUpdateOperations,
    meta: Option<TransactionMetadata>,
) -> LockResult<TransactionHash> {
    let TransactionMetadata { expiry, nonce } = meta.unwrap_or_default();
    let expiry = expiry.unwrap_or(TransactionTime::seconds_after(DEFAULT_EXPIRY_SECS));
    let nonce = match nonce {
        Some(nonce) => nonce,
        None => {
            client
                .get_next_account_sequence_number(&signer.address)
                .await?
                .nonce
        }
    };
    let tx = construct::meta_update_operations(
        signer.num_keys(),
        signer.address,
        nonce,
        expiry,
        operations,
    )
    .sign(signer);
    let block_item = BlockItem::AccountTransaction(tx);
    Ok(client.send_block_item(&block_item).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AccountTransactionDetails, AccountTransactionEffects, BlockItemSummary,
        BlockItemSummaryDetails, RejectReason,
    };
    use crate::{types::hashes::TransactionHash, v2::Upward};
    use concordium_base::{
        base::{Energy, TransactionIndex},
        common::types::TransactionTime,
        protocol_level_locks::{
            LockAccountFunds, LockControllerSimpleV0, LockControllerSimpleV0Grant,
            LockedTokenAmount,
        },
        protocol_level_tokens::{
            meta_operations::MetaUpdateOperation, CborHolderAccount, CoinInfo, RawCbor,
        },
        transactions::TransactionType,
    };

    const ADDRESS: AccountAddress = AccountAddress([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ]);

    fn holder(address: AccountAddress) -> CborHolderAccount {
        CborHolderAccount {
            coin_info: Some(CoinInfo::CCD),
            address,
        }
    }

    fn example_lock_info() -> LockInfo {
        LockInfo {
            lock: LockId::new(10001, 5, 0),
            recipients: vec![holder(ADDRESS)],
            expiry: TransactionTime::seconds_after(3600),
            controller: LockController::SimpleV0(LockControllerSimpleV0 {
                grants: vec![LockControllerSimpleV0Grant {
                    account: holder(ADDRESS),
                    roles: vec![
                        LockControllerSimpleV0Capability::Fund,
                        LockControllerSimpleV0Capability::Send,
                        LockControllerSimpleV0Capability::Return,
                        LockControllerSimpleV0Capability::Cancel,
                    ],
                }],
                tokens: vec!["CCD".parse().unwrap()],
                keep_alive: false,
                memo: None,
            }),
            funds: vec![LockAccountFunds {
                account: holder(ADDRESS),
                amounts: vec![LockedTokenAmount {
                    token: "CCD".parse().unwrap(),
                    amount: TokenAmount::from_raw(100, 0),
                }],
            }],
        }
    }

    #[test]
    fn ensure_not_expired_rejects_expired_locks() {
        let mut info = example_lock_info();
        info.expiry = TransactionTime::from_seconds(1);
        assert!(matches!(ensure_not_expired(&info), Err(LockError::Expired)));
    }

    #[test]
    fn controller_validate_fund_checks_grants_and_tokens() {
        let info = example_lock_info();
        let valid = FundTokens {
            token_id: "CCD".parse().unwrap(),
            amount: TokenAmount::from_raw(1, 0),
            memo: None,
        };
        assert!(info.controller.validate_fund(ADDRESS, &valid).is_ok());

        let other = AccountAddress([9u8; 32]);
        assert!(matches!(
            info.controller.validate_fund(other, &valid),
            Err(LockError::MissingCapability)
        ));

        let wrong_token = FundTokens {
            token_id: "OTHER".parse().unwrap(),
            amount: TokenAmount::from_raw(1, 0),
            memo: None,
        };
        assert!(matches!(
            info.controller.validate_fund(ADDRESS, &wrong_token),
            Err(LockError::TokenNotConfigured)
        ));
    }

    #[test]
    fn ensure_locked_amount_checks_source_and_amount() {
        let info = example_lock_info();
        assert!(ensure_locked_amount(
            &info,
            ADDRESS,
            &"CCD".parse().unwrap(),
            TokenAmount::from_raw(50, 0)
        )
        .is_ok());
        assert!(matches!(
            ensure_locked_amount(
                &info,
                ADDRESS,
                &"CCD".parse().unwrap(),
                TokenAmount::from_raw(200, 0)
            ),
            Err(LockError::InsufficientFunds)
        ));
        let other = AccountAddress([8u8; 32]);
        assert!(matches!(
            ensure_locked_amount(
                &info,
                other,
                &"CCD".parse().unwrap(),
                TokenAmount::from_raw(1, 0)
            ),
            Err(LockError::InsufficientFunds)
        ));
    }

    #[test]
    fn account_available_balance_correctness() {
        let with_available = TokenAccountState {
            balance: TokenAmount::from_raw(100, 0),
            module_state: Some(RawCbor::from(concordium_base::common::cbor::cbor_encode(
                &concordium_base::protocol_level_tokens::TokenModuleAccountState {
                    available: Some(TokenAmount::from_raw(25, 0)),
                    ..Default::default()
                },
            ))),
        };
        assert_eq!(
            account_available_balance(Some(&with_available)).unwrap(),
            TokenAmount::from_raw(25, 0)
        );

        let without_available = TokenAccountState {
            balance: TokenAmount::from_raw(100, 0),
            module_state: Some(RawCbor::from(concordium_base::common::cbor::cbor_encode(
                &concordium_base::protocol_level_tokens::TokenModuleAccountState::default(),
            ))),
        };
        assert_eq!(
            account_available_balance(Some(&without_available)).unwrap(),
            TokenAmount::from_raw(100, 0)
        );
    }

    fn summary_with_effects(effects: AccountTransactionEffects) -> BlockItemSummary {
        BlockItemSummary {
            index: TransactionIndex { index: 0 },
            energy_cost: Energy::from(0),
            hash: TransactionHash::from([0u8; 32]),
            details: Upward::Known(BlockItemSummaryDetails::AccountTransaction(
                AccountTransactionDetails {
                    cost: concordium_base::common::types::Amount::from_micro_ccd(0),
                    sender: ADDRESS,
                    sponsor: None,
                    effects: Upward::Known(effects),
                },
            )),
        }
    }

    struct StubLockQuery {
        result: Option<endpoints::QueryResult<QueryResponse<LockInfoResponse>>>,
    }

    #[async_trait]
    impl LockQuery for StubLockQuery {
        async fn get_lock_info(
            &mut self,
            _lock_id: LockId,
            _bi: BlockIdentifier,
        ) -> endpoints::QueryResult<QueryResponse<LockInfoResponse>> {
            self.result
                .take()
                .expect("stub should only be queried once")
        }
    }

    #[tokio::test]
    async fn from_lock_id_query_error() {
        let mut stub = StubLockQuery {
            result: Some(Err(QueryError::NotFound)),
        };
        let result = from_lock_id_impl(&mut stub, LockId::new(10001, 5, 0)).await;
        assert!(matches!(
            result,
            Err(LockError::Query(QueryError::NotFound))
        ));
    }

    #[test]
    fn created_lock_id_reject_missing_event() {
        let summary =
            summary_with_effects(AccountTransactionEffects::MetaUpdate { events: vec![] });
        assert!(matches!(
            created_lock_id_from_summary(summary),
            Err(LockError::CreationFailed(_))
        ));
    }

    #[test]
    fn created_lock_id_reject_failed_transaction() {
        let summary = summary_with_effects(AccountTransactionEffects::None {
            transaction_type: Some(TransactionType::MetaUpdate),
            reject_reason: Upward::Known(RejectReason::ZeroScheduledAmount),
        });
        assert!(matches!(
            created_lock_id_from_summary(summary),
            Err(LockError::CreationFailed(_))
        ));
    }

    #[test]
    fn pending_operations_order() {
        let operations = vec![
            PendingOperation::Fund(FundTokens {
                token_id: "CCD".parse().unwrap(),
                amount: TokenAmount::from_raw(10, 0),
                memo: None,
            }),
            PendingOperation::Cancel(None),
        ];
        let lock_id = LockId::new(10001, 5, 0);
        let resolved = resolve_pending_operations(
            LockConfig {
                recipients: vec![holder(ADDRESS)],
                expiry: TransactionTime::from_seconds(10_000_000),
                controller: LockController::SimpleV0(LockControllerSimpleV0 {
                    grants: vec![],
                    tokens: vec!["CCD".parse().unwrap()],
                    keep_alive: false,
                    memo: None,
                }),
            },
            operations,
            lock_id.clone(),
        );
        assert_eq!(resolved.operations.len(), 3);
        match &resolved.operations[0] {
            MetaUpdateOperation::LockCreate(_) => {}
            other => panic!("expected lockCreate first, got {other:?}"),
        }
        match &resolved.operations[1] {
            MetaUpdateOperation::LockFund(details) => assert_eq!(details.lock, lock_id),
            other => panic!("expected lockFund second, got {other:?}"),
        }
    }
}
