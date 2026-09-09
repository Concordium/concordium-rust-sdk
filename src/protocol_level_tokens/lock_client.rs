//! Higher-level abstraction for interactions with protocol-level locks.

use concordium_base::{
    base::Nonce,
    common::{cbor::CborSerializationError, types::TransactionTime},
    contracts_common::AccountAddress,
    hashes::TransactionHash,
    protocol_level_locks::{
        LockConfig, LockConfigSimpleV0, LockControllerSimpleV0Capability, LockId, LockInfo,
        LockRecipients,
    },
    protocol_level_tokens::{
        meta_operations::{self, MetaUpdateOperation, MetaUpdateOperations},
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

/// Internal abstraction over the lock-info RPC used by query helpers.
///
/// This exists as a small test seam: production code implements it for
/// [`Client`], while unit tests can provide stubs that return controlled query
/// responses without connecting to a node.
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

/// Internal dispatch trait for lock-configuration-specific client-side validation.
///
/// The high-level lock client validates operations through this trait so each
/// lock configuration variant can implement its own capability and
/// configuration checks while the public API remains independent of the
/// concrete configuration type.
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
    /// The recipient account to receive the locked funds.
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
    /// The sender lacks the required simple-lock capability.
    #[error("the sender does not have the required capability.")]
    MissingCapability,
    /// The lock has expired and can no longer be operated on.
    #[error("the lock has expired.")]
    Expired,
    /// The requested amount exceeds the funds available for the operation.
    #[error("insufficient funds available for the requested operation.")]
    InsufficientFunds,
    /// The token is not configured in the lock configuration.
    #[error("the token is not configured for this lock.")]
    TokenNotConfigured,
    /// The recipient is not part of the lock's configured limited recipient list.
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
enum AppendedOperation {
    Raw(MetaUpdateOperation),
    Fund(FundTokens),
    Send(SendTokens),
    Return(ReturnTokens),
    Cancel(Option<CborMemo>),
}

/// Builder for composing a lock creation with surrounding meta-update
/// operations in a single transaction.
///
/// Prepended operations are emitted before the `lockCreate`. Appended
/// operations are emitted after it. Typed append helpers for lock operations do
/// not require a lock id up front; they are resolved against the predicted lock
/// id at submission time.
///
/// The lock identifier is predicted at submission time from the sender's
/// account index and next nonce. This minimises, but does not eliminate, the
/// chance of nonce staleness if another transaction consumes the sender's next
/// nonce concurrently before submission reaches the node.
#[derive(Debug, Clone)]
pub struct LockCreateProposal {
    sender: AccountAddress,
    config: LockConfig,
    prepended_operations: Vec<MetaUpdateOperation>,
    appended_operations: Vec<AppendedOperation>,
}

impl LockCreateProposal {
    fn new(sender: AccountAddress, config: LockConfig) -> Self {
        Self {
            sender,
            config,
            prepended_operations: Vec::new(),
            appended_operations: Vec::new(),
        }
    }

    /// Prepend a raw meta-update operation before the `lockCreate`.
    ///
    /// # Arguments
    ///
    /// * `operation` - The raw meta-update operation to place before the lock
    ///   creation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let proposal = create_lock_proposal(sender, config)
    ///     .prepend_operation(meta_operations::mint_tokens(token_id.clone(), amount));
    /// ```
    pub fn prepend_operation(mut self, operation: MetaUpdateOperation) -> Self {
        self.prepended_operations.push(operation);
        self
    }

    /// Append a raw meta-update operation after the `lockCreate`.
    ///
    /// # Arguments
    ///
    /// * `operation` - The raw meta-update operation to place after the lock
    ///   creation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let proposal = create_lock_proposal(sender, config)
    ///     .append_operation(meta_operations::mint_tokens(token_id.clone(), amount));
    /// ```
    pub fn append_operation(mut self, operation: MetaUpdateOperation) -> Self {
        self.appended_operations
            .push(AppendedOperation::Raw(operation));
        self
    }

    /// Append a fund operation after the `lockCreate`.
    ///
    /// The fund operation is stored without a lock id and is resolved against
    /// the predicted lock id at submission time.
    ///
    /// # Arguments
    ///
    /// * `payload` - The lock-funding parameters to append after the creation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let proposal = create_lock_proposal(sender, config).append_fund(FundTokens {
    ///     token_id,
    ///     amount,
    ///     memo: None,
    /// });
    /// ```
    pub fn append_fund(mut self, payload: FundTokens) -> Self {
        self.appended_operations
            .push(AppendedOperation::Fund(payload));
        self
    }

    /// Append a send operation after the `lockCreate`.
    ///
    /// The send operation is stored without a lock id and is resolved against
    /// the predicted lock id at submission time.
    ///
    /// # Arguments
    ///
    /// * `payload` - The locked-funds send parameters to append after the
    ///   creation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let proposal = create_lock_proposal(sender, config).append_send(payload);
    /// ```
    pub fn append_send(mut self, payload: SendTokens) -> Self {
        self.appended_operations
            .push(AppendedOperation::Send(payload));
        self
    }

    /// Append a return operation after the `lockCreate`.
    ///
    /// The return operation is stored without a lock id and is resolved against
    /// the predicted lock id at submission time.
    ///
    /// # Arguments
    ///
    /// * `payload` - The locked-funds return parameters to append after the
    ///   creation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let proposal = create_lock_proposal(sender, config).append_return_funds(payload);
    /// ```
    pub fn append_return_funds(mut self, payload: ReturnTokens) -> Self {
        self.appended_operations
            .push(AppendedOperation::Return(payload));
        self
    }

    /// Append a cancel operation after the `lockCreate`.
    ///
    /// The cancel operation is stored without a lock id and is resolved against
    /// the predicted lock id at submission time.
    ///
    /// # Arguments
    ///
    /// * `memo` - The optional memo to attach to the cancel operation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let proposal = create_lock_proposal(sender, config).append_cancel(None);
    /// ```
    pub fn append_cancel(mut self, memo: Option<CborMemo>) -> Self {
        self.appended_operations
            .push(AppendedOperation::Cancel(memo));
        self
    }

    /// Submit the proposal as a single meta-update transaction.
    ///
    /// The lock id is predicted at submission time from the sender's account
    /// index and next nonce, then injected into all typed appended lock
    /// operations before submission. The returned [`PendingLockCreation`] can
    /// be awaited to resolve the finalized lock.
    ///
    /// # Arguments
    ///
    /// * `client` - The node client used to predict the next lock id and submit
    ///   the transaction.
    /// * `signer` - The account keys used to sign the transaction.
    /// * `meta` - Optional transaction metadata overriding the default nonce
    ///   and expiry handling.
    ///
    /// # Errors
    ///
    /// Returns [`LockError`] if lock-id prediction fails, transaction signing
    /// or submission fails, or the provided metadata cannot be used.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let pending = create_lock_proposal(sender, config)
    ///     .append_fund(FundTokens {
    ///         token_id,
    ///         amount,
    ///         memo: None,
    ///     })
    ///     .submit(&mut client, &keys, None)
    ///     .await?;
    /// ```
    pub async fn submit(
        self,
        client: &mut Client,
        signer: &WalletAccount,
        meta: Option<TransactionMetadata>,
    ) -> LockResult<PendingLockCreation> {
        let lock_id = get_next_lock_id(client, self.sender, 0).await?;

        let operations = resolve_pending_operations(
            self.config,
            self.prepended_operations,
            self.appended_operations,
            lock_id,
        );
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

/// Construct a proposal for composing lock creation with additional
/// meta-update operations in a single transaction.
///
/// # Arguments
///
/// * `sender` - The account that will submit the composed transaction.
/// * `config` - The lock configuration to use for the `lockCreate` operation.
///
/// # Examples
///
/// ```ignore
/// let proposal = create_lock_proposal(sender, config)
///     .prepend_operation(meta_operations::mint_tokens(token_id.clone(), amount))
///     .append_fund(FundTokens {
///         token_id,
///         amount,
///         memo: None,
///     });
/// ```
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
        let info = query_lock_info_impl(&mut client, lock_id).await?;
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
    /// dispatches configuration-specific validation based on the lock
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
        self.info.config.validate_fund(sender, payload)?;

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
    /// dispatches configuration-specific validation based on the lock
    /// variant, verifies that the source has
    /// sufficient funds locked under this lock for the requested token, and
    /// checks the recipient against the lock's limited recipient list when
    /// applicable.
    pub async fn validate_send(
        &mut self,
        sender: AccountAddress,
        payload: &SendTokens,
    ) -> LockResult<()> {
        self.update_lock_info().await?;
        self.ensure_not_expired()?;
        self.info.config.validate_send(sender, payload)?;
        self.ensure_locked_amount(payload.source, &payload.token_id, payload.amount)?;
        if !recipient_allowed(&self.info, payload.recipient) {
            return Err(LockError::RecipientNotAllowed);
        }
        Ok(())
    }

    /// Validate that locked funds can be returned with the given payload.
    ///
    /// This refreshes the latest finalized lock info, checks expiry,
    /// dispatches configuration-specific validation based on the lock
    /// variant, and verifies that the source has
    /// sufficient funds locked under this lock for the requested token.
    pub async fn validate_return(
        &mut self,
        sender: AccountAddress,
        payload: &ReturnTokens,
    ) -> LockResult<()> {
        self.update_lock_info().await?;
        self.ensure_not_expired()?;
        self.info.config.validate_return(sender, payload)?;
        self.ensure_locked_amount(payload.source, &payload.token_id, payload.amount)?;
        Ok(())
    }

    /// Validate that the lock can be cancelled by the given sender.
    ///
    /// This refreshes the latest finalized lock info, and
    /// dispatches configuration-specific validation based on the lock
    /// variant to verify that the sender has the cancel capability.
    pub async fn validate_cancel(&mut self, sender: AccountAddress) -> LockResult<()> {
        self.update_lock_info().await?;

        if self.ensure_not_expired().is_err() {
            return Ok(());
        };
        self.info.config.validate_cancel(sender)
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
    let LockConfig::SimpleV0(config) = &info.config;
    if config.expiry.seconds <= now {
        Err(LockError::Expired)
    } else {
        Ok(())
    }
}

impl Validate for LockConfig {
    fn validate_fund(&self, sender: AccountAddress, payload: &FundTokens) -> LockResult<()> {
        match self {
            LockConfig::SimpleV0(config) => config.validate_fund(sender, payload),
        }
    }

    fn validate_send(&self, sender: AccountAddress, payload: &SendTokens) -> LockResult<()> {
        match self {
            LockConfig::SimpleV0(config) => config.validate_send(sender, payload),
        }
    }

    fn validate_return(&self, sender: AccountAddress, payload: &ReturnTokens) -> LockResult<()> {
        match self {
            LockConfig::SimpleV0(config) => config.validate_return(sender, payload),
        }
    }

    fn validate_cancel(&self, sender: AccountAddress) -> LockResult<()> {
        match self {
            LockConfig::SimpleV0(config) => config.validate_cancel(sender),
        }
    }
}

impl Validate for LockConfigSimpleV0 {
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
    config: &LockConfigSimpleV0,
    sender: AccountAddress,
    capability: LockControllerSimpleV0Capability,
) -> LockResult<()> {
    if config
        .grants
        .iter()
        .any(|grant| grant.account.address == sender && grant.roles.contains(&capability))
    {
        Ok(())
    } else {
        Err(LockError::MissingCapability)
    }
}

fn recipient_allowed(info: &LockInfo, recipient: AccountAddress) -> bool {
    let LockConfig::SimpleV0(config) = &info.config;
    match &config.recipients {
        LockRecipients::Any => true,
        LockRecipients::Limited(recipients) => recipients
            .iter()
            .any(|allowed_recipient| allowed_recipient.address == recipient),
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
    prepended_operations: Vec<MetaUpdateOperation>,
    appended_operations: Vec<AppendedOperation>,
    lock_id: LockId,
) -> MetaUpdateOperations {
    let mut ops = Vec::with_capacity(prepended_operations.len() + appended_operations.len() + 1);
    ops.extend(prepended_operations);
    ops.push(meta_operations::lock_create(config));
    for op in appended_operations {
        let op = match op {
            AppendedOperation::Raw(operation) => operation,
            AppendedOperation::Fund(payload) => meta_operations::lock_fund(
                payload.token_id,
                lock_id.clone(),
                payload.amount,
                payload.memo,
            ),
            AppendedOperation::Send(payload) => meta_operations::lock_send(
                payload.token_id,
                lock_id.clone(),
                payload.source,
                payload.recipient,
                payload.amount,
                payload.memo,
            ),
            AppendedOperation::Return(payload) => meta_operations::lock_return(
                payload.token_id,
                lock_id.clone(),
                payload.source,
                payload.amount,
                payload.memo,
            ),
            AppendedOperation::Cancel(memo) => meta_operations::lock_cancel(lock_id.clone(), memo),
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
    use crate::{
        protocol_level_tokens::{
            LockCreateEvent, LockDestroyEvent, MetaEvent, TokenEvent, TokenEventDetails,
        },
        types::hashes::TransactionHash,
        v2::Upward,
    };
    use concordium_base::{
        base::{Energy, TransactionIndex},
        common::{cbor::value::Value, types::TransactionTime},
        protocol_level_locks::{
            LockAccountFunds, LockConfigSimpleV0, LockControllerSimpleV0Grant, LockMetadata,
            LockRecipients, LockedTokenAmount,
        },
        protocol_level_tokens::{
            meta_operations::MetaUpdateOperation, CborHolderAccount, CoinInfo, RawCbor,
            TokenHolder, TokenTransferEvent,
        },
        transactions::TransactionType,
    };
    use std::collections::HashMap;

    const ADDRESS: AccountAddress = AccountAddress([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ]);
    const OTHER_ADDRESS: AccountAddress = AccountAddress([0x21; 32]);
    const THIRD_ADDRESS: AccountAddress = AccountAddress([0x22; 32]);

    fn holder(address: AccountAddress) -> CborHolderAccount {
        CborHolderAccount {
            coin_info: Some(CoinInfo::CCD),
            address,
        }
    }

    fn example_lock_metadata() -> LockMetadata {
        LockMetadata {
            name: Some("SDK test lock".to_string()),
            description: Some("Metadata used by SDK lock tests".to_string()),
            additional: HashMap::from([(
                "issuer".to_string(),
                Value::Text("Concordium".to_string()),
            )]),
        }
    }

    fn example_lock_info() -> LockInfo {
        LockInfo {
            lock: LockId::new(10001, 5, 0),
            config: LockConfig::SimpleV0(LockConfigSimpleV0 {
                recipients: LockRecipients::Limited(vec![holder(ADDRESS)]),
                expiry: TransactionTime::seconds_after(3600),
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
                metadata: Some(example_lock_metadata().encode_raw_cbor()),
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
        let LockConfig::SimpleV0(config) = &mut info.config;
        config.expiry = TransactionTime::from_seconds(1);
        assert!(matches!(ensure_not_expired(&info), Err(LockError::Expired)));
    }

    #[test]
    fn config_validate_fund_checks_grants_and_tokens() {
        let info = example_lock_info();
        let valid = FundTokens {
            token_id: "CCD".parse().unwrap(),
            amount: TokenAmount::from_raw(1, 0),
            memo: None,
        };
        assert!(info.config.validate_fund(ADDRESS, &valid).is_ok());

        let other = AccountAddress([9u8; 32]);
        assert!(matches!(
            info.config.validate_fund(other, &valid),
            Err(LockError::MissingCapability)
        ));

        let wrong_token = FundTokens {
            token_id: "OTHER".parse().unwrap(),
            amount: TokenAmount::from_raw(1, 0),
            memo: None,
        };
        assert!(matches!(
            info.config.validate_fund(ADDRESS, &wrong_token),
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
    fn recipient_allowed_accepts_any_recipients() {
        let mut info = example_lock_info();
        let LockConfig::SimpleV0(config) = &mut info.config;
        config.recipients = LockRecipients::Any;

        assert!(recipient_allowed(&info, ADDRESS));
        assert!(recipient_allowed(&info, OTHER_ADDRESS));
    }

    #[test]
    fn recipient_allowed_rejects_missing_limited_recipient() {
        let info = example_lock_info();

        assert!(recipient_allowed(&info, ADDRESS));
        assert!(!recipient_allowed(&info, OTHER_ADDRESS));
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
    async fn query_lock_info_query_error() {
        let mut stub = StubLockQuery {
            result: Some(Err(QueryError::NotFound)),
        };
        let result = query_lock_info_impl(&mut stub, LockId::new(10001, 5, 0)).await;
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
    fn meta_update_lock_lifecycle_events_affect_sender_only() {
        let lock_id = LockId::new(10001, 5, 0);
        let lock_create = summary_with_effects(AccountTransactionEffects::MetaUpdate {
            events: vec![MetaEvent::LockCreate(LockCreateEvent {
                lock_id: lock_id.clone(),
                lock_config: RawCbor::from(Vec::new()),
            })],
        });
        assert_eq!(
            lock_create.affected_addresses().known().unwrap(),
            vec![ADDRESS]
        );

        let lock_destroy = summary_with_effects(AccountTransactionEffects::MetaUpdate {
            events: vec![MetaEvent::LockDestroy(LockDestroyEvent { lock_id })],
        });
        assert_eq!(
            lock_destroy.affected_addresses().known().unwrap(),
            vec![ADDRESS]
        );
    }

    #[test]
    fn meta_update_token_transfer_with_lock_metadata_affects_token_holders() {
        let summary = summary_with_effects(AccountTransactionEffects::MetaUpdate {
            events: vec![MetaEvent::Token(TokenEvent {
                token_id: "CCD".parse().unwrap(),
                event: TokenEventDetails::Transfer(TokenTransferEvent {
                    from: TokenHolder::Account {
                        address: OTHER_ADDRESS,
                    },
                    to: TokenHolder::Account {
                        address: THIRD_ADDRESS,
                    },
                    amount: TokenAmount::from_raw(10, 0),
                    memo: None,
                    from_lock: Some(LockId::new(10001, 5, 0)),
                    to_lock: Some(LockId::new(10002, 6, 0)),
                }),
            })],
        });

        assert_eq!(
            summary.affected_addresses().known().unwrap(),
            vec![ADDRESS, OTHER_ADDRESS, THIRD_ADDRESS]
        );
    }

    #[test]
    fn meta_update_summary_json_matches_wallet_proxy_contract() {
        let lock_id = LockId::new(10001, 5, 0);
        let summary = summary_with_effects(AccountTransactionEffects::MetaUpdate {
            events: vec![
                MetaEvent::LockCreate(LockCreateEvent {
                    lock_id: lock_id.clone(),
                    lock_config: RawCbor::from(vec![0xa1, 0x64, b't', b'e', b's', b't', 0x01]),
                }),
                MetaEvent::LockDestroy(LockDestroyEvent { lock_id }),
                MetaEvent::Token(TokenEvent {
                    token_id: "CCD".parse().unwrap(),
                    event: TokenEventDetails::Transfer(TokenTransferEvent {
                        from: TokenHolder::Account {
                            address: OTHER_ADDRESS,
                        },
                        to: TokenHolder::Account {
                            address: THIRD_ADDRESS,
                        },
                        amount: TokenAmount::from_raw(10, 0),
                        memo: None,
                        from_lock: Some(LockId::new(10001, 5, 0)),
                        to_lock: Some(LockId::new(10002, 6, 0)),
                    }),
                }),
            ],
        });

        let json = serde_json::to_value(summary).expect("serialize summary");
        assert_eq!(json["type"]["contents"], "metaUpdate");
        assert_eq!(json["result"]["outcome"], "success");
        assert_eq!(json["result"]["events"][0]["tag"], "LockCreated");
        assert_eq!(json["result"]["events"][1]["tag"], "LockDestroyed");
        assert_eq!(json["result"]["events"][2]["tag"], "TokenTransfer");
        assert!(json["result"]["events"][2].get("fromLock").is_some());
        assert!(json["result"]["events"][2].get("toLock").is_some());
    }

    #[test]
    fn pending_operations_order() {
        let prepended_operations = vec![meta_operations::mint_tokens(
            "CCD".parse().unwrap(),
            TokenAmount::from_raw(5, 0),
        )];
        let appended_operations = vec![
            AppendedOperation::Fund(FundTokens {
                token_id: "CCD".parse().unwrap(),
                amount: TokenAmount::from_raw(10, 0),
                memo: None,
            }),
            AppendedOperation::Raw(meta_operations::burn_tokens(
                "CCD".parse().unwrap(),
                TokenAmount::from_raw(3, 0),
            )),
            AppendedOperation::Cancel(None),
        ];
        let lock_id = LockId::new(10001, 5, 0);
        let resolved = resolve_pending_operations(
            LockConfig::SimpleV0(LockConfigSimpleV0 {
                recipients: LockRecipients::Limited(vec![holder(ADDRESS)]),
                expiry: TransactionTime::from_seconds(10_000_000),
                grants: vec![],
                tokens: vec!["CCD".parse().unwrap()],
                keep_alive: false,
                memo: None,
                metadata: Some(example_lock_metadata().encode_raw_cbor()),
            }),
            prepended_operations,
            appended_operations,
            lock_id.clone(),
        );
        assert_eq!(resolved.operations.len(), 5);
        match &resolved.operations[0] {
            MetaUpdateOperation::Mint(_) => {}
            other => panic!("expected mint first, got {other:?}"),
        }
        match &resolved.operations[1] {
            MetaUpdateOperation::LockCreate(_) => {}
            other => panic!("expected lockCreate second, got {other:?}"),
        }
        match &resolved.operations[2] {
            MetaUpdateOperation::LockFund(details) => assert_eq!(details.lock, lock_id),
            other => panic!("expected lockFund third, got {other:?}"),
        }
        match &resolved.operations[3] {
            MetaUpdateOperation::Burn(_) => {}
            other => panic!("expected burn fourth, got {other:?}"),
        }
        match &resolved.operations[4] {
            MetaUpdateOperation::LockCancel(details) => assert_eq!(details.lock, lock_id),
            other => panic!("expected lockCancel fifth, got {other:?}"),
        }
    }
}
