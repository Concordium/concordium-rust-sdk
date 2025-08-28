//! This module contains a generic client that provides conveniences for
//! interacting with any smart contract instance, as well as for creating new
//! ones.
//!
//! The key types in this module are
//! [`ContractClient`],
//! [`ContractInitBuilder`]
//! and [`ModuleDeployBuilder`].
use crate::{
    indexer::ContractUpdateInfo,
    types::{
        smart_contracts::{self, ContractContext, InvokeContractResult, ReturnValue},
        transactions, AccountTransactionEffects, ContractInitializedEvent, RejectReason,
    },
    v2::{
        self,
        dry_run::{self, DryRunTransaction},
        BlockIdentifier, Client, Upward,
    },
};
use concordium_base::{
    base::{Energy, Nonce},
    common::types::{self, TransactionTime},
    contracts_common::{
        self, schema::VersionedModuleSchema, AccountAddress, Address, Amount, ContractAddress,
        Cursor, NewContractNameError, NewReceiveNameError,
    },
    hashes::TransactionHash,
    smart_contracts::{
        ContractEvent, ContractTraceElement, ExceedsParameterSize, ModuleReference,
        OwnedContractName, OwnedParameter, OwnedReceiveName, WasmModule, WasmVersion,
    },
    transactions::{
        construct::TRANSACTION_HEADER_SIZE, AccountTransaction, EncodedPayload,
        InitContractPayload, PayloadLike, UpdateContractPayload,
    },
};
pub use concordium_base::{cis2_types::MetadataUrl, cis4_types::*};
use concordium_smart_contract_engine::utils;
use serde_json::Value;
use std::{fmt, marker::PhantomData, sync::Arc};
use v2::{QueryError, RPCError};

/// A contract client that handles some of the boilerplate such as serialization
/// and parsing of responses when sending transactions, or invoking smart
/// contracts.
///
/// Note that cloning is cheap and is, therefore, the intended way of sharing
/// values of this type between multiple tasks.
#[derive(Debug)]
pub struct ContractClient<Type> {
    /// The underlying network client.
    pub client:        Client,
    /// The address of the instance.
    pub address:       ContractAddress,
    /// The name of the contract at the address.
    pub contract_name: Arc<contracts_common::OwnedContractName>,
    /// The schema of the contract at the address.
    pub schema:        Arc<Option<VersionedModuleSchema>>,
    phantom:           PhantomData<Type>,
}

impl<Type> Clone for ContractClient<Type> {
    fn clone(&self) -> Self {
        Self {
            client:        self.client.clone(),
            address:       self.address,
            contract_name: self.contract_name.clone(),
            phantom:       PhantomData,
            schema:        self.schema.clone(),
        }
    }
}

/// Transaction metadata for CIS-4 update transactions.
#[derive(Debug, Clone, Copy)]
pub struct ContractTransactionMetadata {
    /// The account address sending the transaction.
    pub sender_address: AccountAddress,
    /// The nonce to use for the transaction.
    pub nonce:          Nonce,
    /// Expiry date of the transaction.
    pub expiry:         types::TransactionTime,
    /// The limit on energy to use for the transaction.
    pub energy:         transactions::send::GivenEnergy,
    /// The amount of CCD to include in the transaction.
    pub amount:         types::Amount,
}

#[derive(Debug, thiserror::Error)]
/// An error that can be used as the error for the
/// [`view`](ContractClient::view) family of functions.
pub enum ViewError {
    #[error("Invalid receive name: {0}")]
    InvalidName(#[from] NewReceiveNameError),
    #[error("Node rejected with reason: {0:#?}")]
    QueryFailed(v2::Upward<RejectReason>),
    #[error("Response was not as expected: {0}")]
    InvalidResponse(#[from] contracts_common::ParseError),
    #[error("Network error: {0}")]
    NetworkError(#[from] v2::QueryError),
    #[error("Parameter is too large: {0}")]
    ParameterError(#[from] ExceedsParameterSize),
}

impl From<v2::Upward<RejectReason>> for ViewError {
    fn from(value: v2::Upward<RejectReason>) -> Self { Self::QueryFailed(value) }
}

/// A builder of transactions out of minimal data typically obtained by
/// dry-running.
///
/// The concrete instances of this type, [`ContractInitBuilder`] and
/// [`ContractUpdateBuilder`] have more detailed information on usage.
///
/// The `ADD_ENERGY` constant is used to indicate whether the builder should
/// allow adding extra energy. This is only useful for transactions that have
/// dynamic cost, namely contract initializations and updates.
pub struct TransactionBuilder<const ADD_ENERGY: bool, Inner> {
    client:     v2::Client,
    sender:     AccountAddress,
    energy:     Energy,
    add_energy: Option<Energy>,
    expiry:     Option<TransactionTime>,
    nonce:      Option<Nonce>,
    payload:    transactions::Payload,
    inner:      Inner,
}

impl<const ADD: bool, Inner> TransactionBuilder<ADD, Inner> {
    fn new(
        client: v2::Client,
        sender: AccountAddress,
        energy: Energy,
        payload: transactions::Payload,
        inner: Inner,
    ) -> Self {
        Self {
            client,
            sender,
            energy,
            add_energy: None,
            expiry: None,
            nonce: None,
            payload,
            inner,
        }
    }

    /// Set the expiry time for the transaction. If not set the default is one
    /// hour from the time the transaction is signed.
    pub fn expiry(mut self, expiry: TransactionTime) -> Self {
        self.expiry = Some(expiry);
        self
    }

    /// Set the nonce for the transaction. If not set the default behaviour is
    /// to get the nonce from the connected [`Client`] at the
    /// time the transaction is sent.
    pub fn nonce(mut self, nonce: Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Return the amount of [`Energy`] that will be allowed for the transaction
    /// if the transaction was sent with the current parameters.
    pub fn current_energy(&self) -> Energy {
        if ADD {
            // Add 10% to the call, or at least 50.
            self.energy
                + self
                    .add_energy
                    .unwrap_or_else(|| std::cmp::max(50, self.energy.energy / 10).into())
        } else {
            self.energy
        }
    }

    /// Send the transaction and return a handle that can be queried
    /// for the status.
    pub async fn send_inner<A>(
        mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        k: impl FnOnce(TransactionHash, v2::Client) -> A,
    ) -> v2::QueryResult<A> {
        let nonce = if let Some(nonce) = self.nonce {
            nonce
        } else {
            self.client
                .get_next_account_sequence_number(&self.sender)
                .await?
                .nonce
        };
        let expiry = self
            .expiry
            .unwrap_or_else(|| TransactionTime::hours_after(1));
        let energy = self.current_energy();
        let tx = transactions::send::make_and_sign_transaction(
            signer,
            self.sender,
            nonce,
            expiry,
            transactions::send::GivenEnergy::Add(energy),
            self.payload,
        );
        let tx_hash = self.client.send_account_transaction(tx).await?;
        Ok(k(tx_hash, self.client))
    }
}

impl<Inner> TransactionBuilder<true, Inner> {
    /// Add extra energy to the call.
    /// The default amount is 10%, or at least 50.
    /// This should be sufficient in most cases, but for specific
    /// contracts no extra energy might be needed, or a greater safety margin
    /// could be desired.
    pub fn extra_energy(mut self, energy: Energy) -> Self {
        self.add_energy = Some(energy);
        self
    }
}

/// A helper type to construct [`ContractInitBuilder`].
/// Users do not directly interact with values of this type.
pub struct ContractInitInner<Type> {
    /// The event generated from dry running.
    event:   ContractInitializedEvent,
    phantom: PhantomData<Type>,
}

impl<Type> ContractInitInner<Type> {
    fn new(event: ContractInitializedEvent) -> Self {
        Self {
            event,
            phantom: PhantomData,
        }
    }
}

/// Builder for initializing a new smart contract instance.
///
/// The builder is intended to be constructed using
/// [`dry_run_new_instance`](ContractInitBuilder::dry_run_new_instance)
/// or [`dry_run_new_instance_raw`](ContractInitBuilder::dry_run_new_instance_raw) methods.
/// and the transaction is intended to be sent using the
/// [`send`](ContractInitBuilder::send) method.
pub type ContractInitBuilder<Type> = TransactionBuilder<true, ContractInitInner<Type>>;

/// A handle returned when sending a smart contract init transaction.
/// This can be used to get the response of the initialization.
///
/// Note that this handle retains a connection to the node. So if it is not
/// going to be used it should be dropped.
pub struct ContractInitHandle<Type> {
    tx_hash: TransactionHash,
    client:  v2::Client,
    phantom: PhantomData<Type>,
}

/// The [`Display`](std::fmt::Display) implementation displays the hash of the
/// transaction.
impl<Type> std::fmt::Display for ContractInitHandle<Type> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.tx_hash.fmt(f) }
}

#[derive(Debug, thiserror::Error)]
/// An error that may occur when querying the result of a smart contract update
/// transaction.
pub enum ContractInitError {
    #[error("The status of the transaction could not be ascertained: {0}")]
    Query(#[from] QueryError),
    #[error("Contract update failed with reason: {0:?}")]
    Failed(v2::Upward<RejectReason>),
}

impl<Type> ContractInitHandle<Type> {
    /// Extract the hash of the transaction underlying this handle.
    pub fn hash(&self) -> TransactionHash { self.tx_hash }

    /// Wait until the transaction is finalized and return the client for the
    /// contract together with a list of events generated by the contract
    /// during initialization.
    ///
    /// Note that this can potentially wait indefinitely.
    pub async fn wait_for_finalization(
        mut self,
    ) -> Result<(ContractClient<Type>, Vec<ContractEvent>), ContractInitError> {
        let (_, result) = self.client.wait_until_finalized(&self.tx_hash).await?;

        let mk_error = |msg| {
            Err(ContractInitError::from(QueryError::RPCError(
                RPCError::CallError(tonic::Status::invalid_argument(msg)),
            )))
        };
        let v2::upward::Upward::Known(details) = result.details else {
            return mk_error(
                "Expected smart contract initialization status, but received unknown block item \
                 details.",
            );
        };
        match details {
            crate::types::BlockItemSummaryDetails::AccountTransaction(at) => {
                let v2::upward::Upward::Known(effects) = at.effects else {
                    return mk_error(
                        "Expected smart contract initialization status, but received unknown \
                         block item details.",
                    );
                };
                match effects {
                    AccountTransactionEffects::ContractInitialized { data } => {
                        let contract_client =
                            ContractClient::create(self.client, data.address).await?;
                        Ok((contract_client, data.events))
                    }
                    AccountTransactionEffects::None {
                        transaction_type: _,
                        reject_reason,
                    } => Err(ContractInitError::Failed(reject_reason)),
                    _ => mk_error(
                        "Expected smart contract initialization status, but did not receive it.",
                    ),
                }
            }
            crate::types::BlockItemSummaryDetails::AccountCreation(_) => mk_error(
                "Expected smart contract initialization status, but received account creation.",
            ),
            crate::types::BlockItemSummaryDetails::Update(_) => mk_error(
                "Expected smart contract initialization status, but received chain update \
                 instruction.",
            ),
            crate::types::BlockItemSummaryDetails::TokenCreationDetails(_) => mk_error(
                "Expected smart contract initialization status, but received token creation chain \
                 update instruction.",
            ),
        }
    }

    /// Wait until the transaction is finalized or until the timeout has elapsed
    /// and return the result.
    pub async fn wait_for_finalization_timeout(
        self,
        timeout: std::time::Duration,
    ) -> Result<(ContractClient<Type>, Vec<ContractEvent>), ContractInitError> {
        let result = tokio::time::timeout(timeout, self.wait_for_finalization()).await;
        match result {
            Ok(r) => r,
            Err(_elapsed) => Err(ContractInitError::Query(QueryError::RPCError(
                RPCError::CallError(tonic::Status::deadline_exceeded(
                    "Deadline waiting for result of transaction is exceeded.",
                )),
            ))),
        }
    }
}

#[derive(thiserror::Error, Debug)]
/// An error that may occur when attempting to dry run a new instance creation.
pub enum DryRunNewInstanceError {
    #[error("Dry run succeeded, but contract initialization failed due to {0:#?}.")]
    Failed(v2::Upward<RejectReason>),
    #[error("Dry run failed: {0}")]
    DryRun(#[from] dry_run::DryRunError),
    #[error("Parameter too large: {0}")]
    ExceedsParameterSize(#[from] ExceedsParameterSize),
    #[error("Node query error: {0}")]
    Query(#[from] v2::QueryError),
    #[error("Contract name not valid: {0}")]
    InvalidContractName(#[from] NewContractNameError),
    #[error("The reported energy consumed for the dry run is less than expected ({min}).")]
    InvalidEnergy {
        /// Minimum amount of energy expected
        min: Energy,
    },
}

impl From<v2::Upward<RejectReason>> for DryRunNewInstanceError {
    fn from(value: v2::Upward<RejectReason>) -> Self { Self::Failed(value) }
}

impl<Type> ContractInitBuilder<Type> {
    /// Attempt to dry run a smart contract initialization transaction.
    ///
    /// In contrast to
    /// [`dry_run_new_instance_raw`](Self::dry_run_new_instance_raw) this
    /// automatically serializes the provided parameter.
    pub async fn dry_run_new_instance<P: contracts_common::Serial>(
        client: Client,
        sender: AccountAddress,
        mod_ref: ModuleReference,
        name: &str,
        amount: Amount,
        parameter: &P,
    ) -> Result<Self, DryRunNewInstanceError> {
        let parameter = OwnedParameter::from_serial(parameter)?;
        Self::dry_run_new_instance_raw(client, sender, mod_ref, name, amount, parameter).await
    }

    /// Attempt to dry run a smart contract initialization transaction.
    /// In case of success the resulting value can be used to extract
    /// the generated events from the dry-run, and sign and send the
    /// transaction.
    ///
    /// The arguments are
    /// - `client` - the client to connect to the node
    /// - `sender` - the account that will be sending the transaction
    /// - `mod_ref` - the reference to the module on chain from which the
    ///   instance is to be created
    /// - `name` - the name of the contract (NB: without the `init_` prefix)
    /// - `amount` - the amount of CCD to initialize the instance with
    /// - `parameter` - the parameter to send to the initialization method of
    ///   the contract.
    pub async fn dry_run_new_instance_raw(
        mut client: Client,
        sender: AccountAddress,
        mod_ref: ModuleReference,
        name: &str,
        amount: Amount,
        parameter: OwnedParameter,
    ) -> Result<Self, DryRunNewInstanceError> {
        let name = OwnedContractName::new(format!("init_{name}"))?;
        let mut dr = client.dry_run(BlockIdentifier::LastFinal).await?;
        let payload = InitContractPayload {
            amount,
            mod_ref,
            init_name: name,
            param: parameter,
        };
        let payload = transactions::Payload::InitContract { payload };
        let encoded_payload = payload.encode();
        let payload_size = encoded_payload.size();
        let tx = DryRunTransaction {
            sender,
            energy_amount: dr.inner.0.energy_quota(),
            payload: encoded_payload,
            signatures: Vec::new(),
        };
        let result = dr
            .inner
            .0
            .begin_run_transaction(tx)
            .await
            .map_err(dry_run::DryRunError::from)?
            .await?
            .inner;

        let data = match result.details.effects.known_or_else(|| {
            dry_run::DryRunError::CallError(tonic::Status::invalid_argument(
                "Unexpected response from dry-running a contract initialization.",
            ))
        })? {
            AccountTransactionEffects::None {
                transaction_type: _,
                reject_reason,
            } => return Err(reject_reason.into()),
            AccountTransactionEffects::ContractInitialized { data } => data,
            _ => {
                return Err(
                    dry_run::DryRunError::CallError(tonic::Status::invalid_argument(
                        "Unexpected response from dry-running a contract initialization.",
                    ))
                    .into(),
                )
            }
        };
        let base_cost = transactions::cost::base_cost(
            TRANSACTION_HEADER_SIZE + u64::from(u32::from(payload_size)),
            1,
        );
        let energy = result
            .energy_cost
            .checked_sub(base_cost)
            .ok_or(DryRunNewInstanceError::InvalidEnergy { min: base_cost })?;

        Ok(ContractInitBuilder::new(
            client,
            sender,
            energy,
            payload,
            ContractInitInner::new(data),
        ))
    }

    /// Access to the generated events.
    ///
    /// Note that these are events generated as part of a dry run.
    /// Since time passes between the dry run and the actual transaction
    /// the transaction might behave differently.
    pub fn event(&self) -> &ContractInitializedEvent { &self.inner.event }

    /// Send the transaction and return a handle that can be queried
    /// for the status.
    pub async fn send(
        self,
        signer: &impl transactions::ExactSizeTransactionSigner,
    ) -> v2::QueryResult<ContractInitHandle<Type>> {
        let phantom = self.inner.phantom;
        self.send_inner(signer, |tx_hash, client| ContractInitHandle {
            tx_hash,
            client,
            phantom,
        })
        .await
    }
}

pub type ModuleDeployBuilder = TransactionBuilder<false, ModuleReference>;

#[derive(thiserror::Error, Debug)]
/// An error that may occur when attempting to dry run a smart contract module
/// deployment.
pub enum DryRunModuleDeployError {
    #[error("Dry run succeeded, but module deployment failed due to {0:#?}.")]
    Failed(v2::Upward<RejectReason>),
    #[error("Dry run failed: {0}")]
    DryRun(#[from] dry_run::DryRunError),
    #[error("Node query error: {0}")]
    Query(#[from] v2::QueryError),
    #[error("The reported energy consumed for the dry run is less than expected ({min}).")]
    InvalidEnergy {
        /// Minimum amount of energy expected
        min: Energy,
    },
}

impl DryRunModuleDeployError {
    /// Check whether dry-run failed because the module already exists.
    pub fn already_exists(&self) -> bool {
        let Self::Failed(reason) = self else {
            return false;
        };
        matches!(
            reason,
            v2::Upward::Known(RejectReason::ModuleHashAlreadyExists { .. })
        )
    }
}

impl From<v2::Upward<RejectReason>> for DryRunModuleDeployError {
    fn from(value: v2::Upward<RejectReason>) -> Self { Self::Failed(value) }
}

impl ModuleDeployBuilder {
    /// Attempt to dry run a module deployment transaction.
    ///
    /// In case of success the return value can be used to send the transaction
    /// to affect the module deployment.
    pub async fn dry_run_module_deploy(
        mut client: Client,
        sender: AccountAddress,
        module: WasmModule,
    ) -> Result<Self, DryRunModuleDeployError> {
        let mut dr = client.dry_run(BlockIdentifier::LastFinal).await?;
        let payload = transactions::Payload::DeployModule { module };
        let encoded_payload = payload.encode();
        let payload_size = encoded_payload.size();
        let tx = DryRunTransaction {
            sender,
            energy_amount: dr.inner.0.energy_quota(),
            payload: encoded_payload,
            signatures: Vec::new(),
        };
        let result = dr
            .inner
            .0
            .begin_run_transaction(tx)
            .await
            .map_err(dry_run::DryRunError::from)?
            .await?
            .inner;

        let module_ref = match result.details.effects.known_or_else(|| {
            dry_run::DryRunError::CallError(tonic::Status::invalid_argument(
                "Unexpected response from dry-running a module deployment.",
            ))
        })? {
            AccountTransactionEffects::None {
                transaction_type: _,
                reject_reason,
            } => return Err(reject_reason.into()),
            AccountTransactionEffects::ModuleDeployed { module_ref } => module_ref,
            _ => {
                return Err(
                    dry_run::DryRunError::CallError(tonic::Status::invalid_argument(
                        "Unexpected response from dry-running a module deployment.",
                    ))
                    .into(),
                )
            }
        };
        let base_cost = transactions::cost::base_cost(
            TRANSACTION_HEADER_SIZE + u64::from(u32::from(payload_size)),
            1,
        );
        let energy = result
            .energy_cost
            .checked_sub(base_cost)
            .ok_or(DryRunModuleDeployError::InvalidEnergy { min: base_cost })?;
        Ok(Self::new(client, sender, energy, payload, module_ref))
    }
}

impl ModuleDeployBuilder {
    /// Send the transaction and return a handle that can be queried
    /// for the status.
    pub async fn send(
        self,
        signer: &impl transactions::ExactSizeTransactionSigner,
    ) -> v2::QueryResult<ModuleDeployHandle> {
        self.send_inner(signer, |tx_hash, client| ModuleDeployHandle {
            tx_hash,
            client,
        })
        .await
    }
}

pub struct ModuleDeployHandle {
    tx_hash: TransactionHash,
    client:  v2::Client,
}

/// The [`Display`](std::fmt::Display) implementation displays the hash of the
/// transaction.
impl std::fmt::Display for ModuleDeployHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.tx_hash.fmt(f) }
}

#[derive(Debug, thiserror::Error)]
/// An error that may occur when querying the result of a module deploy
/// transaction.
pub enum ModuleDeployError {
    #[error("The status of the transaction could not be ascertained: {0}")]
    Query(#[from] QueryError),
    #[error("Module deployment failed with reason: {0:?}")]
    Failed(v2::Upward<RejectReason>),
}

#[derive(Debug, Clone, Copy)]
/// Result of successful module deployment.
pub struct ModuleDeployData {
    /// Energy used for the transaction.
    pub energy:           Energy,
    /// The CCD cost of the transaction.
    pub cost:             Amount,
    /// The module reference.
    pub module_reference: ModuleReference,
}

impl ModuleDeployHandle {
    /// Extract the hash of the transaction underlying this handle.
    pub fn hash(&self) -> TransactionHash { self.tx_hash }

    /// Wait until the transaction is finalized and return the result.
    /// Note that this can potentially wait indefinitely.
    pub async fn wait_for_finalization(mut self) -> Result<ModuleDeployData, ModuleDeployError> {
        let (_, result) = self.client.wait_until_finalized(&self.tx_hash).await?;

        let mk_error = |msg| {
            Err(ModuleDeployError::from(QueryError::RPCError(
                RPCError::CallError(tonic::Status::invalid_argument(msg)),
            )))
        };

        let v2::upward::Upward::Known(details) = result.details else {
            return mk_error(
                "Expected  module deploy status, but received unknown block item details.",
            );
        };
        match details {
            crate::types::BlockItemSummaryDetails::AccountTransaction(at) => {
                let v2::upward::Upward::Known(effects) = at.effects else {
                    return mk_error(
                        "Expected  module deploy status, but received unknown block item effect.",
                    );
                };
                match effects {
                    AccountTransactionEffects::ModuleDeployed { module_ref } => {
                        Ok(ModuleDeployData {
                            energy:           result.energy_cost,
                            cost:             at.cost,
                            module_reference: module_ref,
                        })
                    }
                    AccountTransactionEffects::None {
                        transaction_type: _,
                        reject_reason,
                    } => Err(ModuleDeployError::Failed(reject_reason)),
                    _ => mk_error("Expected module deploy status, but did not receive it."),
                }
            }
            crate::types::BlockItemSummaryDetails::AccountCreation(_) => {
                mk_error("Expected module deploy status, but received account creation.")
            }
            crate::types::BlockItemSummaryDetails::Update(_) => {
                mk_error("Expected module deploy status, but received chain update instruction.")
            }
            crate::types::BlockItemSummaryDetails::TokenCreationDetails(_) => mk_error(
                "Expected module deploy status, but received token creation chain update \
                 instruction.",
            ),
        }
    }

    /// Wait until the transaction is finalized or until the timeout has elapsed
    /// and return the result.
    pub async fn wait_for_finalization_timeout(
        self,
        timeout: std::time::Duration,
    ) -> Result<ModuleDeployData, ModuleDeployError> {
        let result = tokio::time::timeout(timeout, self.wait_for_finalization()).await;
        match result {
            Ok(r) => r,
            Err(_elapsed) => Err(ModuleDeployError::Query(QueryError::RPCError(
                RPCError::CallError(tonic::Status::deadline_exceeded(
                    "Deadline waiting for result of transaction is exceeded.",
                )),
            ))),
        }
    }
}

/// Define a newtype wrapper around the error schema type.
#[derive(Debug, Clone)]
pub struct ErrorSchema(pub Value);

/// Write a custom display implementation for the error schema type.
/// This implementation displays nested errors meaningfully.
/// For example the nested error: `Object {\"Custom\": Array
/// [Object {\"Unauthorized\": Array []}]}` is displayed as
/// `Custom::Unauthorized`.
impl std::fmt::Display for ErrorSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Value::Object(map) => {
                if let Some(key) = map.keys().next() {
                    write!(f, "{}", key)?;
                    if let Some(value) = map.values().next() {
                        if value.is_array() {
                            write!(f, "{}", ErrorSchema(value.clone()))?;
                        }
                    }
                }
            }
            Value::Array(arr) => {
                if let Some(value) = arr.iter().next() {
                    write!(f, "::{}", ErrorSchema(value.clone()))?;
                }
            }
            _ => write!(f, "{}", self.0)?,
        }
        Ok(())
    }
}

/// A human-readable decoded error for the reject reason of a reverted
/// transaction.
#[derive(Debug, Clone)]
pub enum DecodedReason {
    Std {
        /// The error code of the transaction.
        reject_reason: i32,
        /// The decoded human-readable error.
        parsed:        ConcordiumStdRejectReason,
    },
    Custom {
        /// The return value of the transaction.
        return_value:  ReturnValue,
        /// The error code of the transaction.
        reject_reason: i32,
        /// The decoded human-readable error.
        /// For example:
        /// Object {\"Unauthorized\": Array []} or
        /// Object {\"Custom\": Array [Object {\"Unauthorized\": Array []}]}
        /// (e.g. the cis2_library error)
        parsed:        ErrorSchema,
    },
}

/// Write a custom display implementation for the decoded human-readable error
/// of the `DecodedReason` type.
impl std::fmt::Display for DecodedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodedReason::Std { parsed, .. } => {
                write!(f, "{}", parsed)
            }
            DecodedReason::Custom { parsed, .. } => {
                write!(f, "{}", parsed)
            }
        }
    }
}

/// The outcome of invoking (dry-running) a transaction to update a smart
/// contract instance. The variants describe the two cases of successfully
/// simulating the transaction and rejecting the transaction due to some
/// reverts.
pub enum InvokeContractOutcome {
    /// The simulation of the transaction was successful.
    Success(SimulatedTransaction),
    /// The transaction was rejected due to some reverts.
    Failure(RejectedTransaction),
}

/// The `SimulatedTransaction` type is an alias for the `ContractUpdateBuilder`
/// type. This type is used when an invoke (dry-run) of a transaction succeeds.
/// This type includes a convenient send method to send and execute the
/// transaction on-chain in a subsequent action. As such, it is a builder to
/// simplify sending smart contract updates.
pub type SimulatedTransaction = ContractUpdateBuilder;

/// This type is used when an invoke (dry-run) of a transaction gets rejected.
#[derive(Debug, Clone)]
pub struct RejectedTransaction {
    /// The return value of the transaction.
    pub return_value:   Option<ReturnValue>,
    /// The reject reason of the transaction.
    pub reason:         Upward<RejectReason>,
    /// An optional human-readable decoded reason for the reject reason.
    /// This is only available if the reject reason is a smart contract logical
    /// revert and a valid error schema is available for decoding, or the
    /// reject reason originates from the `concordium-std` crate.
    pub decoded_reason: Option<DecodedReason>,
    /// The energy used by the transaction.
    pub used_energy:    Energy,
    /// The payload of the transaction.
    pub payload:        transactions::Payload,
}

impl InvokeContractOutcome {
    /// This converts `InvokeContractOutcome` into a result type.
    pub fn success(self) -> Result<SimulatedTransaction, RejectedTransaction> {
        match self {
            InvokeContractOutcome::Success(simulated_transaction) => Ok(simulated_transaction),
            InvokeContractOutcome::Failure(rejected_transaction) => Err(rejected_transaction),
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[repr(i32)]
pub enum ConcordiumStdRejectReason {
    #[error("[Unspecified (Default reject)]")]
    Unspecified          = -2147483648, // i32::MIN
    #[error("[Error ()]")]
    Unit                 = -2147483647, // i32::MIN + 1
    #[error("[ParseError]")]
    Parse                = -2147483646, // ...
    #[error("[LogError::Full]")]
    LogFull              = -2147483645,
    #[error("[LogError::Malformed]")]
    LogMalformed         = -2147483644,
    #[error("[NewContractNameError::MissingInitPrefix]")]
    NewContractNameMissingInitPrefix = -2147483643,
    #[error("[NewContractNameError::TooLong]")]
    NewContractNameTooLong = -2147483642,
    #[error("[NewReceiveNameError::MissingDotSeparator]")]
    NewReceiveNameMissingDotSeparator = -2147483641,
    #[error("[NewReceiveNameError::TooLong]")]
    NewReceiveNameTooLong = -2147483640,
    #[error("[NewContractNameError::ContainsDot]")]
    NewContractNameContainsDot = -2147483639,
    #[error("[NewContractNameError::InvalidCharacters]")]
    NewContractNameInvalidCharacters = -2147483638,
    #[error("[NewReceiveNameError::InvalidCharacters]")]
    NewReceiveNameInvalidCharacters = -2147483637,
    #[error("[NotPayableError]")]
    NotPayableError      = -2147483636,
    #[error("[TransferError::AmountTooLarge]")]
    TransferAmountTooLarge = -2147483635,
    #[error("[TransferError::MissingAccount]")]
    TransferMissingAccount = -2147483634,
    #[error("[CallContractError::AmountTooLarge]")]
    CallContractAmountTooLarge = -2147483633,
    #[error("[CallContractError::MissingAccount]")]
    CallContractMissingAccount = -2147483632,
    #[error("[CallContractError::MissingContract]")]
    CallContractMissingContract = -2147483631,
    #[error("[CallContractError::MissingEntrypoint]")]
    CallContractMissingEntrypoint = -2147483630,
    #[error("[CallContractError::MessageFailed]")]
    CallContractMessageFailed = -2147483629,
    #[error("[CallContractError::LogicReject]")]
    CallContractLogicReject = -2147483628,
    #[error("[CallContractError::Trap]")]
    CallContractTrap     = -2147483627,
    #[error("[UpgradeError::MissingModule]")]
    UpgradeMissingModule = -2147483626,
    #[error("[UpgradeError::MissingContract]")]
    UpgradeMissingContract = -2147483625,
    #[error("[UpgradeError::UnsupportedModuleVersion]")]
    UpgradeUnsupportedModuleVersion = -2147483624,
    #[error("[QueryAccountBalanceError]")]
    QueryAccountBalanceError = -2147483623,
    #[error("[QueryContractBalanceError]")]
    QueryContractBalanceError = -2147483622,
}

/// Decode the `reject_reason` into a human-readable error based on the error
/// code definition in the `concordium-std` crate.
pub fn decode_concordium_std_error(reject_reason: i32) -> Option<ConcordiumStdRejectReason> {
    if (-2147483648..=-2147483622).contains(&reject_reason) {
        let reason: ConcordiumStdRejectReason = unsafe { ::std::mem::transmute(reject_reason) };
        Some(reason)
    } else {
        None
    }
}

/// Decode the smart contract logical revert reason and return a human-readable
/// error.
///
/// If the error is NOT caused by a smart contract logical revert, the
/// `reject_reason` is already a human-readable error. No further decoding of
/// the error is needed and as such this function returns `None`.
/// An example of such a failure (rejected transaction) is the case when the
/// transaction runs out of energy which is represented by the human-readable
/// error variant "OutOfEnergy".
///
/// Step 1: If the error matches a smart contract logical revert code coming
/// from the `concordium-std` crate, this function decodes the error based on
/// the error code definition in the `concordium-std` crate.
///
/// Step 2: If the error is caused by a smart contract logical revert coming
/// from the smart contract itself, this function uses the provided
/// `error_schema` and `return_value` to decode the `reject_reason` into a
/// human-readable error.
///
/// `Return_values` vs. `error_codes` in rejected transactions:
/// Historically, Concordium had smart contracts V0 which had no `retun_value`.
/// Error codes (negative values used commonly in computer science to represent
/// errors) were chosen as a method to report the reject reason. Smart
/// contracts could only revert using one "[Unspecified (Default reject)]" error
/// and the error code (i32::MIN) was used to represent this error. This
/// "[Unspecified (Default reject)]" error definition still exists in the
/// `concordium-std` crate.
///
/// `Return_values` were introduced in smart contracts V1 and smart contracts
/// were fitted with features to revert with different reasons (as defined in
/// the smart contract logic). The `return_value` is used to distinguish between
/// the different reasons for the revert coming from the smart contract logic.
///
/// There are some historical types used by the node which spread into this Rust
/// SDK code base (such as `RejectReason`) that only include the `error_code`
/// but not the `return_value`. The reason can be explained by the historical
/// development of smart contracts on Concordium (types were not expanded to
/// avoid breaking changes) as well as to keep the size of the node as small as
/// possible since the `return_value` does not need to be saved by the node for
/// achieving consensus.
///
/// As a result, this decoding function needs to have access to both the
/// `return_value` and the `error_code` to decode the `reject_reason` of a
/// reverted transaction into a human-readable error.
///
/// How is the `return_value` and `error_code` assigned in rejected
/// transactions:
/// - If the transaction reverts due to an error in the `concordium-std` crate,
///   the `return_value` is None and the `error_code` is assigned as defined in
///   the `concordium-std` crate.
/// - If the transaction reverts due to an error in the smart contract logic:
///   A smart contract V1 needs to implement a conversion to `Reject` for its
///   smart contract errors.
///   `<https://docs.rs/concordium-std/latest/concordium_std/struct.Reject.html>`
///
/// 1. Example: Deriving `Reject` in the smart contract.
///
/// The simplest way to implement `Reject` in the smart contract is by deriving
/// it.
///
/// ```ignore
/// /// The custom errors the contract can produce.
/// #[derive(Serialize, Debug, Reject, SchemaType)]
/// pub enum CustomContractError {
///     /// CustomError1 defined in the smart contract logic.
///     CustomError1, // return_value: 00; error_code: -1
///     /// CustomError2 defined in the smart contract logic.
///     CustomError2, // return_value: 01; error_code: -2
/// }
/// ```
///
/// The `Reject` macro assigns the `error_codes` starting from `-1` to the enum
/// variants and assigns the `return_values` by serializing the enum variants.
/// The `return_values` are equivalent to the enum tags in the above example.
///
/// The JSON value returned by this function for the above `CustomError1` is:
/// ```json
/// {"CustomError1":[]}
/// ```
///
/// 2. Example: Deriving `Reject` in the smart contract with nested errors.
///
/// Nested errors are often used to inherit the errors from a smart
/// contract library such as the cis2-library.
/// `<https://github.com/Concordium/concordium-rust-smart-contracts/blob/dde42fa62254a55b46a4c9c52c32bbe661127001/concordium-cis2/src/lib.rs#L1093>`
///
/// Parent Smart contract:
/// ```ignore
/// /// The custom errors the contract/library can produce.
/// #[derive(Serialize, Debug, Reject, SchemaType)]
/// pub enum ParentError<R> {
///     /// ParentCustomError1 defined in the smart contract logic.
///     ParentCustomError1, // return_value: 00; error_code: -1
///     /// Nested error variant.
///     Custom(R),
///     // ChildCustomError1 -> return_value: 0100; error_code: -1
///     // ChildCustomError2 -> return_value: 0101; error_code: -2
///     // ChildCustomError3 -> return_value: 0102; error_code: -3
///     // ...
///     /// ParentCustomError2 defined in the smart contract logic.
///     ParentCustomError2, // return_value: 02; error_code: -3
/// }
/// ```
///
/// Child Smart contract:
/// ```ignore
/// /// The different errors the contract/library can produce.
/// #[derive(Serialize, Debug, PartialEq, Eq, Reject, SchemaType)]
/// pub enum ChildError {
///     /// ChildCustomError1 defined in the smart contract logic.
///     ChildCustomError1, // return_value: 0100; error_code: -1
///     /// ChildCustomError2 defined in the smart contract logic.
///     ChildCustomError2, // return_value: 0101; error_code: -2
///     /// ChildCustomError3 defined in the smart contract logic.
///     ChildCustomError3, // return_value: 0102; error_code: -2
/// }
///
/// /// Mapping ChildError to ContractError
/// impl From<ChildError> for ContractError {
///     fn from(c: ChildError) -> Self { ParentError::Custom(c) }
/// }
///
/// pub type ContractError = ParentError<ChildError>;
///
/// pub type ContractResult<A> = Result<A, ContractError>;
/// ```
///
/// The `Reject` macro assigns the `error_codes` starting from `-1` to the enum
/// variants and assigns the `return_values` by serializing the enum variants
/// starting with the topmost enum. The `return_values` are equivalent to the
/// enum tags of all enums in the nested chain.
///
/// The JSON value returned by this function for the above `CustomError1` is:
/// ```json
/// {"Custom":[{"CustomError1":[]}]}
/// ```
///
/// 3. Example: `Reject::default()`.
///
/// The historical `Reject::default()` can be used by implementing the
/// conversion to `Reject` manually.
///
/// ```ignore
/// /// The custom errors the contract can produce.
/// #[derive(Serialize, Debug, SchemaType)]
/// pub enum CustomContractError {
///     /// CustomError1 defined in the smart contract logic.
///     CustomError1, // return_value: None; error_code: -2147483648 (i32::MIN)
/// }
///
/// impl From<CustomContractError> for Reject {
///     fn from(error: CustomContractError) -> Self {
///         match error {
///             _ => Reject::default(),
///         }
///     }
/// }
/// ```
///
/// `Reject::default()` assigns `-2147483648` as `error_code` and `None` to the
/// `return_value`.
///
/// The JSON value returned by this function for the above `CustomError1` is:
/// ```json
/// {"[Unspecified (Default reject)]":[]}
/// ```
///
/// 4. Example: Implementing the conversion to `Reject` manually.
///
/// A smart contract can implement the conversion to `Reject` manually and
/// define custom error codes. The convention for the `return_value` is to set
/// the value to the serialization of the enum variants so that decoding of the
/// error is possible.
///
/// ```ignore
/// /// The custom errors the contract can produce.
/// #[derive(Serialize, Debug, SchemaType)]
/// pub enum CustomContractError {
///     /// CustomError1 defined in the smart contract logic.
///     CustomError1, // return_value: 00; error_code: -123
///     /// CustomError2 defined in the smart contract logic.
///     CustomError2, // return_value: 01; error_code: -124
/// }
///
/// impl From<CustomContractError> for Reject {
///     fn from(error: CustomContractError) -> Self {
///         match error {
///             CustomContractError::CustomError1 => Reject {
///                 error_code:   NonZeroI32::new(-123).unwrap(),
///                 return_value: Some(vec![00]),
///             },
///             CustomContractError::CustomError2 => Reject {
///                 error_code:   NonZeroI32::new(-124).unwrap(),
///                 return_value: Some(vec![01]),
///             },
///         }
///     }
/// }
/// ```
///
/// The JSON value returned by this function for the above `CustomError1` is:
/// ```json
/// {"CustomError1":[]}
/// ```
///
/// Disclaimer: A smart contract can have logic to overwrite/change/reuse the
/// meaning of the error codes as defined in the `concordium-std` crate (see
/// Example 4 above). While it is not advised to reuse these error codes and is
/// rather unusual to do so, this function decodes the error codes based on the
/// definitions in the `concordium-std` crate (assuming they have not been
/// reused with other meanings in the smart contract logic). No guarantee
/// are given as such that the meaning of the decoded reject reason hasn't been
/// altered by the smart contract logic. The main reason for setting the
/// `concordium-std` crate errors to `i32::MIN`,`i32::MIN+1`, etc., is to avoid
/// conflicts/reuse of the error codes used in the smart contract logic.
pub fn decode_smart_contract_revert(
    return_value: Option<&ReturnValue>,
    reject_reason: &RejectReason,
    schema: Option<&VersionedModuleSchema>,
) -> Option<DecodedReason> {
    match reject_reason {
        RejectReason::RejectedReceive {
            reject_reason: error_code,
            contract_address: _,
            receive_name,
            parameter: _,
        } => {
            let receive_name = receive_name.as_receive_name();

            // Step 1: Try to decode the `reject_reason` using the `concordium-std`
            // error codes.
            if let Some(decoded_error) = decode_concordium_std_error(*error_code) {
                return Some(DecodedReason::Std {
                    reject_reason: *error_code,
                    parsed:        decoded_error,
                });
            }

            // Step 2: Try to decode the `reject_reason` using the `error_schema` and the
            // `return_value`.

            // If no `schema` is provided, the
            // `reject_reason` can not be decoded further.
            let schema = schema?;

            let (Some(error_schema), Some(return_value)) = (
                schema
                    .get_receive_error_schema(
                        receive_name.contract_name(),
                        receive_name.entrypoint_name().into(),
                    )
                    .ok(),
                return_value,
            ) else {
                // If no `error_schema` and/or `return_value` is provided, the
                // `reject_reason` can not be decoded further.
                return None;
            };

            let mut cursor = Cursor::new(&return_value.value);

            error_schema
                .to_json(&mut cursor)
                .ok()
                .map(|decoded_reason| DecodedReason::Custom {
                    return_value:  return_value.clone(),
                    reject_reason: *error_code,
                    parsed:        ErrorSchema(decoded_reason),
                })
        }
        // If the error is NOT caused by a smart contract logical revert, the
        // `reject_reason` is already a human-readable error. No
        // further decoding of the error is needed. An example of
        // such a transaction is the error variant "OutOfEnergy".
        _ => None,
    }
}

impl<Type> ContractClient<Type> {
    /// Construct a [`ContractClient`] by looking up metadata from the chain
    /// (such as the contract_name and the embedded schema).
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node.
    /// * `address` - The contract address of the smart contract instance.
    pub async fn create(mut client: Client, address: ContractAddress) -> v2::QueryResult<Self> {
        // Get the smart contract instance info.
        let contract_instance_info = client
            .get_instance_info(address, BlockIdentifier::LastFinal)
            .await?
            .response;

        let contract_name = contract_instance_info.name().clone();
        let module_reference = contract_instance_info.source_module();

        // Get the wasm module associated to the contract instance.
        let wasm_module = client
            .get_module_source(&module_reference, BlockIdentifier::LastFinal)
            .await?
            .response;

        // Get the schema associated to the contract instance.
        let schema = match wasm_module.version {
            WasmVersion::V0 => utils::get_embedded_schema_v0(wasm_module.source.as_ref()).ok(),
            WasmVersion::V1 => utils::get_embedded_schema_v1(wasm_module.source.as_ref()).ok(),
        };

        Ok(Self {
            client,
            address,
            contract_name: Arc::new(contract_name),
            phantom: PhantomData,
            schema: Arc::new(schema),
        })
    }

    /// Construct a [`ContractClient`] locally. In comparison to
    /// [`create`](Self::create) this always succeeds and does not check
    /// existence of the contract.
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node. Note that cloning
    ///   [`Client`] is cheap and is therefore the intended way of sharing.
    /// * `address` - The contract address of the smart contract.
    /// * `contract_name` - The name of the contract. This must match the name
    ///   on the chain, otherwise the constructed client will not work.
    pub fn new(client: Client, address: ContractAddress, contract_name: OwnedContractName) -> Self {
        Self {
            client,
            address,
            contract_name: Arc::new(contract_name),
            phantom: PhantomData,
            schema: Arc::new(None),
        }
    }

    /// Construct a [`ContractClient`] locally. In comparison to
    /// [`create`](Self::create) this always succeeds and does not check
    /// existence of the contract and does not look up metadata from the chain
    /// (such as embedded schemas). In comparison to
    /// [`new`](Self::new) this constructor also takes a versioned module
    /// schema.
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node. Note that cloning
    ///   [`Client`] is cheap and is therefore the intended way of sharing.
    /// * `address` - The contract address of the smart contract.
    /// * `contract_name` - The name of the contract. This must match the name
    ///   on the chain, otherwise the constructed client will not work.
    /// * `schema` - A versioned module schema of the contract. It is used by
    ///   the client to decode the error codes in rejected transactions.
    pub fn new_with_schema(
        client: Client,
        address: ContractAddress,
        contract_name: OwnedContractName,
        schema: VersionedModuleSchema,
    ) -> Self {
        Self {
            client,
            address,
            contract_name: Arc::new(contract_name),
            phantom: PhantomData,
            schema: Arc::new(Some(schema)),
        }
    }

    /// Invoke a contract and return the response.
    ///
    /// This will always fail for a V0 contract, and for V1 contracts it will
    /// attempt to deserialize the response into the provided type `A`.
    ///
    /// The error `E` is left generic in order to support specialized errors
    /// such as CIS2 or CIS4 specific errors for more specialized view functions
    /// defined by those standards.
    ///
    /// For a general contract [`ViewError`] can be used as a concrete error
    /// type `E`.
    pub async fn view<P: contracts_common::Serial, A: contracts_common::Deserial, E>(
        &mut self,
        entrypoint: &str,
        parameter: &P,
        bi: impl v2::IntoBlockIdentifier,
    ) -> Result<A, E>
    where
        E: From<NewReceiveNameError>
            + From<v2::Upward<RejectReason>>
            + From<contracts_common::ParseError>
            + From<v2::QueryError>
            + From<ExceedsParameterSize>, {
        let parameter = OwnedParameter::from_serial(parameter)?;
        self.view_raw::<A, E>(entrypoint, parameter, bi).await
    }

    /// Like [`view`](Self::view) but expects an already serialized parameter.
    pub async fn view_raw<A: contracts_common::Deserial, E>(
        &mut self,
        entrypoint: &str,
        parameter: OwnedParameter,
        bi: impl v2::IntoBlockIdentifier,
    ) -> Result<A, E>
    where
        E: From<NewReceiveNameError>
            + From<v2::Upward<RejectReason>>
            + From<contracts_common::ParseError>
            + From<v2::QueryError>, {
        let ir = self
            .invoke_raw::<E>(entrypoint, Amount::zero(), None, parameter, bi)
            .await?;
        match ir {
            smart_contracts::InvokeContractResult::Success { return_value, .. } => {
                let Some(bytes) = return_value else {
                    return Err(contracts_common::ParseError {}.into());
                };
                let response: A = contracts_common::from_bytes(&bytes.value)?;
                Ok(response)
            }
            smart_contracts::InvokeContractResult::Failure { reason, .. } => Err(reason.into()),
        }
    }

    /// Invoke a contract instance and return the response without any
    /// processing.
    pub async fn invoke_raw<E>(
        &mut self,
        entrypoint: &str,
        amount: Amount,
        invoker: Option<Address>,
        parameter: OwnedParameter,
        bi: impl v2::IntoBlockIdentifier,
    ) -> Result<InvokeContractResult, E>
    where
        E: From<NewReceiveNameError> + From<v2::Upward<RejectReason>> + From<v2::QueryError>, {
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let method = OwnedReceiveName::try_from(format!("{contract_name}.{entrypoint}"))?;

        let context = ContractContext {
            invoker,
            contract: self.address,
            amount,
            method,
            parameter,
            energy: None,
        };

        let invoke_result = self.client.invoke_instance(bi, &context).await?.response;
        Ok(invoke_result)
    }

    /// Dry run an update. If the dry run succeeds the return value is an object
    /// that has a send method to send the transaction that was simulated during
    /// the dry run.
    ///
    /// The arguments are
    /// - `entrypoint` the name of the entrypoint to be invoked. Note that this
    ///   is just the entrypoint name without the contract name.
    /// - `amount` the amount of CCD to send to the contract instance
    /// - `sender` the account that will be sending the transaction
    /// - `message` the parameter to the smart contract entrypoint.
    pub async fn dry_run_update<P: contracts_common::Serial, E>(
        &mut self,
        entrypoint: &str,
        amount: Amount,
        sender: AccountAddress,
        message: &P,
    ) -> Result<ContractUpdateBuilder, E>
    where
        E: From<NewReceiveNameError>
            + From<v2::Upward<RejectReason>>
            + From<v2::QueryError>
            + From<ExceedsParameterSize>, {
        let message = OwnedParameter::from_serial(message)?;
        self.dry_run_update_raw(entrypoint, amount, sender, message)
            .await
    }

    /// Dry run an update. In comparison to
    /// [`dry_run_update`](Self::dry_run_update) this function does not throw an
    /// error when the transaction reverts and instead tries to decode the
    /// reject reason into a human-readable error. If the dry run succeeds the
    /// return value is an object that has a send method to send the
    /// transaction that was simulated during the dry run.
    ///
    /// The arguments are
    /// - `entrypoint` the name of the entrypoint to be invoked. Note that this
    ///   is just the entrypoint name without the contract name.
    /// - `amount` the amount of CCD to send to the contract instance
    /// - `sender` the account that will be sending the transaction
    /// - `message` the parameter to the smart contract entrypoint.
    pub async fn dry_run_update_with_reject_reason_info<P: contracts_common::Serial, E>(
        &mut self,
        entrypoint: &str,
        amount: Amount,
        sender: AccountAddress,
        message: &P,
    ) -> Result<InvokeContractOutcome, E>
    where
        E: From<NewReceiveNameError> + From<v2::QueryError> + From<ExceedsParameterSize>, {
        let message = OwnedParameter::from_serial(message)?;
        self.dry_run_update_raw_with_reject_reason_info(entrypoint, amount, sender, message)
            .await
    }

    /// Like [`dry_run_update`](Self::dry_run_update) but expects an already
    /// formed parameter.
    pub async fn dry_run_update_raw<E>(
        &mut self,
        entrypoint: &str,
        amount: Amount,
        sender: AccountAddress,
        message: OwnedParameter,
    ) -> Result<ContractUpdateBuilder, E>
    where
        E: From<NewReceiveNameError> + From<v2::Upward<RejectReason>> + From<v2::QueryError>, {
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let receive_name = OwnedReceiveName::try_from(format!("{contract_name}.{entrypoint}"))?;

        let payload = UpdateContractPayload {
            amount,
            address: self.address,
            receive_name,
            message,
        };

        let context = ContractContext::new_from_payload(sender, None, payload);

        let invoke_result = self
            .client
            .invoke_instance(BlockIdentifier::LastFinal, &context)
            .await?
            .response;
        let payload = UpdateContractPayload {
            amount,
            address: context.contract,
            receive_name: context.method,
            message: context.parameter,
        };

        match invoke_result {
            InvokeContractResult::Success {
                used_energy,
                return_value,
                events,
            } => Ok(ContractUpdateBuilder::new(
                self.client.clone(),
                sender,
                used_energy,
                transactions::Payload::Update { payload },
                ContractUpdateInner {
                    return_value,
                    events,
                },
            )),
            InvokeContractResult::Failure { reason, .. } => Err(reason.into()),
        }
    }

    /// Like [`dry_run_update_with_reject_reason_info`](Self::dry_run_update_with_reject_reason_info) but expects an already
    /// formed parameter.
    pub async fn dry_run_update_raw_with_reject_reason_info<E>(
        &mut self,
        entrypoint: &str,
        amount: Amount,
        sender: AccountAddress,
        message: OwnedParameter,
    ) -> Result<InvokeContractOutcome, E>
    where
        E: From<NewReceiveNameError> + From<v2::QueryError>, {
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let receive_name = OwnedReceiveName::try_from(format!("{contract_name}.{entrypoint}"))?;

        let payload = UpdateContractPayload {
            amount,
            address: self.address,
            receive_name: receive_name.clone(),
            message,
        };

        let context = ContractContext::new_from_payload(sender, None, payload.clone());

        let invoke_result = self
            .client
            .invoke_instance(BlockIdentifier::LastFinal, &context)
            .await?
            .response;

        match invoke_result {
            InvokeContractResult::Success {
                used_energy,
                return_value,
                events,
            } => Ok(InvokeContractOutcome::Success(SimulatedTransaction::new(
                self.client.clone(),
                sender,
                used_energy,
                transactions::Payload::Update { payload },
                ContractUpdateInner {
                    return_value,
                    events,
                },
            ))),
            InvokeContractResult::Failure {
                reason,
                return_value,
                used_energy,
            } => {
                let decoded_reason = reason.as_ref().known().and_then(|reason| {
                    decode_smart_contract_revert(
                        return_value.as_ref(),
                        reason,
                        (*self.schema).as_ref(),
                    )
                });

                Ok(InvokeContractOutcome::Failure(RejectedTransaction {
                    payload: transactions::Payload::Update { payload },
                    return_value,
                    used_energy,
                    reason,
                    decoded_reason,
                }))
            }
        }
    }

    /// Make the payload of a contract update with the specified parameter.
    pub fn make_update<P: contracts_common::Serial, E>(
        &self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &ContractTransactionMetadata,
        entrypoint: &str,
        message: &P,
    ) -> Result<AccountTransaction<EncodedPayload>, E>
    where
        E: From<NewReceiveNameError> + From<ExceedsParameterSize>, {
        let message = OwnedParameter::from_serial(message)?;
        self.make_update_raw::<E>(signer, metadata, entrypoint, message)
    }

    /// Make **and send** a transaction with the specified parameter.
    pub async fn update<P: contracts_common::Serial, E>(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &ContractTransactionMetadata,
        entrypoint: &str,
        message: &P,
    ) -> Result<TransactionHash, E>
    where
        E: From<NewReceiveNameError> + From<v2::RPCError> + From<ExceedsParameterSize>, {
        let message = OwnedParameter::from_serial(message)?;
        self.update_raw::<E>(signer, metadata, entrypoint, message)
            .await
    }

    /// Like [`update`](Self::update) but expects a serialized parameter.
    pub async fn update_raw<E>(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &ContractTransactionMetadata,
        entrypoint: &str,
        message: OwnedParameter,
    ) -> Result<TransactionHash, E>
    where
        E: From<NewReceiveNameError> + From<v2::RPCError>, {
        let tx = self.make_update_raw::<E>(signer, metadata, entrypoint, message)?;
        let hash = self.client.send_account_transaction(tx).await?;
        Ok(hash)
    }

    /// Like [`make_update`](Self::make_update) but expects a serialized
    /// parameter.
    pub fn make_update_raw<E>(
        &self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &ContractTransactionMetadata,
        entrypoint: &str,
        message: OwnedParameter,
    ) -> Result<AccountTransaction<EncodedPayload>, E>
    where
        E: From<NewReceiveNameError>, {
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let receive_name = OwnedReceiveName::try_from(format!("{contract_name}.{entrypoint}"))?;

        let payload = UpdateContractPayload {
            amount: metadata.amount,
            address: self.address,
            receive_name,
            message,
        };

        let tx = transactions::send::make_and_sign_transaction(
            signer,
            metadata.sender_address,
            metadata.nonce,
            metadata.expiry,
            metadata.energy,
            transactions::Payload::Update { payload },
        );
        Ok(tx)
    }
}

/// A helper type to construct [`ContractUpdateBuilder`].
/// Users do not directly interact with values of this type.
pub struct ContractUpdateInner {
    return_value: Option<ReturnValue>,
    events:       Vec<Upward<ContractTraceElement>>,
}

/// A builder to simplify sending smart contract updates.
pub type ContractUpdateBuilder = TransactionBuilder<true, ContractUpdateInner>;

impl ContractUpdateBuilder {
    /// Send the transaction and return a handle that can be queried
    /// for the status.
    pub async fn send(
        self,
        signer: &impl transactions::ExactSizeTransactionSigner,
    ) -> v2::QueryResult<ContractUpdateHandle> {
        self.send_inner(signer, |tx_hash, client| ContractUpdateHandle {
            tx_hash,
            client,
        })
        .await
    }

    /// Get the return value from dry-running.
    pub fn return_value(&self) -> Option<&ReturnValue> { self.inner.return_value.as_ref() }

    /// Get the events generated from the dry-run.
    ///
    /// Since newer versions of the Concordium Node API might introduce new
    /// variants of [`ContractTraceElement`] the result might contain
    /// [`Upward::Unknown`].
    pub fn events(&self) -> &[Upward<ContractTraceElement>] { &self.inner.events }
}

/// A handle returned when sending a smart contract update transaction.
/// This can be used to get the response of the update.
///
/// Note that this handle retains a connection to the node. So if it is not
/// going to be used it should be dropped.
pub struct ContractUpdateHandle {
    tx_hash: TransactionHash,
    client:  v2::Client,
}

/// The [`Display`](std::fmt::Display) implementation displays the hash of the
/// transaction.
impl std::fmt::Display for ContractUpdateHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.tx_hash.fmt(f) }
}

#[derive(Debug, thiserror::Error)]
/// An error that may occur when querying the result of a smart contract update
/// transaction.
pub enum ContractUpdateError {
    #[error("The status of the transaction could not be ascertained: {0}")]
    Query(#[from] QueryError),
    #[error("Contract update failed with reason: {0:?}")]
    Failed(v2::Upward<RejectReason>),
}

impl ContractUpdateHandle {
    /// Extract the hash of the transaction underlying this handle.
    pub fn hash(&self) -> TransactionHash { self.tx_hash }

    /// Wait until the transaction is finalized and return the result.
    /// Note that this can potentially wait indefinitely.
    pub async fn wait_for_finalization(
        mut self,
    ) -> Result<ContractUpdateInfo, ContractUpdateError> {
        let (_, result) = self.client.wait_until_finalized(&self.tx_hash).await?;

        let mk_error = |msg| {
            Err(ContractUpdateError::from(QueryError::RPCError(
                RPCError::CallError(tonic::Status::invalid_argument(msg)),
            )))
        };
        let v2::upward::Upward::Known(details) = result.details else {
            return mk_error(
                "Expected smart contract update status, but received unknown block item details.",
            );
        };
        match details {
            crate::types::BlockItemSummaryDetails::AccountTransaction(at) => {
                let v2::upward::Upward::Known(effects) = at.effects else {
                    return mk_error(
                        "Expected smart contract update status, but received unknown block item \
                         effects.",
                    );
                };
                match effects {
                    AccountTransactionEffects::ContractUpdateIssued { effects } => {
                        let Some(execution_tree) = crate::types::execution_tree(effects) else {
                            return mk_error(
                                "Expected smart contract update, but received invalid execution \
                                 tree.",
                            );
                        };
                        Ok(ContractUpdateInfo {
                            execution_tree,
                            energy_cost: result.energy_cost,
                            cost: at.cost,
                            transaction_hash: self.tx_hash,
                            sender: at.sender,
                        })
                    }
                    AccountTransactionEffects::None {
                        transaction_type: _,
                        reject_reason,
                    } => Err(ContractUpdateError::Failed(reject_reason)),
                    _ => mk_error("Expected smart contract update status, but did not receive it."),
                }
            }
            crate::types::BlockItemSummaryDetails::AccountCreation(_) => {
                mk_error("Expected smart contract update status, but received account creation.")
            }
            crate::types::BlockItemSummaryDetails::Update(_) => mk_error(
                "Expected smart contract update status, but received chain update instruction.",
            ),
            crate::types::BlockItemSummaryDetails::TokenCreationDetails(_) => mk_error(
                "Expected smart contract update status, but received token creation chain update \
                 instruction.",
            ),
        }
    }

    /// Wait until the transaction is finalized or until the timeout has elapsed
    /// and return the result.
    pub async fn wait_for_finalization_timeout(
        self,
        timeout: std::time::Duration,
    ) -> Result<ContractUpdateInfo, ContractUpdateError> {
        let result = tokio::time::timeout(timeout, self.wait_for_finalization()).await;
        match result {
            Ok(r) => r,
            Err(_elapsed) => Err(ContractUpdateError::Query(QueryError::RPCError(
                RPCError::CallError(tonic::Status::deadline_exceeded(
                    "Deadline waiting for result of transaction is exceeded.",
                )),
            ))),
        }
    }
}
