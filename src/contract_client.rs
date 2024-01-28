//! This module contains a generic client that provides conveniences for
//! interacting with any smart contract instance.
use crate::{
    indexer::ContractUpdateInfo,
    types::{
        smart_contracts::{self, ContractContext, InvokeContractResult},
        transactions, AccountTransactionEffects, ContractInitializedEvent, RejectReason,
    },
    v2::{
        self,
        dry_run::{self, DryRunTransaction},
        BlockIdentifier, Client,
    },
};
use concordium_base::{
    base::{Energy, Nonce},
    common::types::{self, TransactionTime},
    contracts_common::{
        self, AccountAddress, Address, Amount, ContractAddress, NewReceiveNameError,
    },
    hashes::TransactionHash,
    smart_contracts::{
        ContractEvent, ExceedsParameterSize, ModuleReference, OwnedContractName, OwnedParameter,
        OwnedReceiveName,
    },
    transactions::{
        AccountTransaction, EncodedPayload, InitContractPayload, PayloadLike, UpdateContractPayload,
    },
};
pub use concordium_base::{cis2_types::MetadataUrl, cis4_types::*};
use std::{marker::PhantomData, sync::Arc};
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
    phantom:           PhantomData<Type>,
}

impl<Type> Clone for ContractClient<Type> {
    fn clone(&self) -> Self {
        Self {
            client:        self.client.clone(),
            address:       self.address,
            contract_name: self.contract_name.clone(),
            phantom:       PhantomData,
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
    QueryFailed(RejectReason),
    #[error("Response was not as expected: {0}")]
    InvalidResponse(#[from] contracts_common::ParseError),
    #[error("Network error: {0}")]
    NetworkError(#[from] v2::QueryError),
    #[error("Parameter is too large: {0}")]
    ParameterError(#[from] ExceedsParameterSize),
}

impl From<RejectReason> for ViewError {
    fn from(value: RejectReason) -> Self { Self::QueryFailed(value) }
}

/// Builder for initializing a new smart contract instance.
/// This is returned from the `dry_run_new_instance` family of methods of the
/// [`ContractClient`].
pub struct ContractInitBuilder<Type> {
    add_energy: Option<Energy>,
    expiry:     Option<TransactionTime>,
    nonce:      Option<Nonce>,
    client:     v2::Client,
    payload:    transactions::Payload,
    sender:     AccountAddress,
    energy:     Energy,
    event:      ContractInitializedEvent,
    phantom:    PhantomData<Type>,
}

impl<Type> ContractInitBuilder<Type> {
    /// Access to the generated events.
    ///
    /// Note that these are events generated as part of a dry run.
    /// Since time passes between the dry run and the actual transaction
    /// the transaction might behave differently.
    pub fn event(&self) -> &ContractInitializedEvent { &self.event }

    fn new(
        client: v2::Client,
        sender: AccountAddress,
        energy: Energy,
        payload: transactions::Payload,
        event: ContractInitializedEvent,
    ) -> Self {
        Self {
            client,
            payload,
            sender,
            energy,
            event,
            add_energy: None,
            expiry: None,
            nonce: None,
            phantom: PhantomData,
        }
    }

    /// Add extra energy to the call.
    /// The default amount is 10%, or at least 50.
    /// This should be sufficient in most cases, but for specific
    /// contracts no extra energy might be needed, or a greater safety margin
    /// could be desired.
    pub fn extra_energy(mut self, energy: Energy) -> Self {
        self.add_energy = Some(energy);
        self
    }

    /// Set the expiry time for the transaction. If not set the default is one
    /// hour from the time the transaction is signed.
    pub fn expiry(mut self, expiry: TransactionTime) -> Self {
        self.expiry = Some(expiry);
        self
    }

    /// Set the nonce for the transaction. If not set the default behaviour is
    /// to get the nonce from the connected [`Client`](v2::Client) at the
    /// time the transaction is sent.
    pub fn nonce(mut self, nonce: Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Return the amount of [`Energy`] that will be allowed for the transaction
    /// if the transaction was sent with the current parameters.
    pub fn current_energy(&self) -> Energy {
        // Add 10% to the call, or at least 50.
        self.energy
            + self
                .add_energy
                .unwrap_or_else(|| std::cmp::max(50, self.energy.energy / 10).into())
    }

    /// Send the transaction and return a handle that can be queried
    /// for the status.
    pub async fn send(
        mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
    ) -> v2::QueryResult<ContractInitHandle<Type>> {
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
            transactions::send::GivenEnergy::Absolute(energy),
            self.payload,
        );
        let tx_hash = self.client.send_account_transaction(tx).await?;
        Ok(ContractInitHandle {
            tx_hash,
            client: self.client,
            phantom: self.phantom,
        })
    }
}

/// A handle returned when sending a smart contract update transaction.
/// This can be used to get the response of the update.
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
    Failed(RejectReason),
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

        match result.details {
            crate::types::BlockItemSummaryDetails::AccountTransaction(at) => match at.effects {
                AccountTransactionEffects::ContractInitialized { data } => {
                    let contract_client =
                        ContractClient::new(self.client, data.address, data.init_name);
                    Ok((contract_client, data.events))
                }
                AccountTransactionEffects::None {
                    transaction_type: _,
                    reject_reason,
                } => Err(ContractInitError::Failed(reject_reason)),
                _ => mk_error(
                    "Expected smart contract initialization status, but did not receive it.",
                ),
            },
            crate::types::BlockItemSummaryDetails::AccountCreation(_) => mk_error(
                "Expected smart contract initialization status, but received account creation.",
            ),
            crate::types::BlockItemSummaryDetails::Update(_) => mk_error(
                "Expected smart contract initialization status, but received chain update \
                 instruction.",
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
    Failed(RejectReason),
    #[error("Dry run failed: {0}")]
    DryRun(#[from] dry_run::DryRunError),
}

impl<Type> ContractClient<Type> {
    /// Initialize a new smart contract instance and create a client as a
    /// result.
    pub async fn dry_run_new_instance_raw(
        mut client: Client,
        sender: AccountAddress,
        mod_ref: ModuleReference,
        name: OwnedContractName,
        amount: Amount,
        parameter: OwnedParameter,
    ) -> Result<ContractInitBuilder<Type>, DryRunNewInstanceError> {
        let mut dr = client.dry_run(BlockIdentifier::LastFinal).await?;
        let payload = InitContractPayload {
            amount,
            mod_ref,
            init_name: name,
            param: parameter,
        };
        let payload = transactions::Payload::InitContract { payload };
        let tx = DryRunTransaction {
            sender,
            energy_amount: dr.inner.0.energy_quota(),
            payload: payload.encode(),
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

        let data = match result.details.effects {
            AccountTransactionEffects::None {
                transaction_type: _,
                reject_reason,
            } => return Err(DryRunNewInstanceError::Failed(reject_reason)),
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
        let energy = result.energy_cost;

        Ok(ContractInitBuilder::new(
            client, sender, energy, payload, data,
        ))
    }

    /// Construct a [`ContractClient`] by looking up metadata from the chain.
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node.
    /// * `address` - The contract address of the smart contract instance.
    pub async fn create(mut client: Client, address: ContractAddress) -> v2::QueryResult<Self> {
        let ci = client
            .get_instance_info(address, BlockIdentifier::LastFinal)
            .await?;
        Ok(Self::new(client, address, ci.response.name().clone()))
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
    ///   on the chain,
    /// otherwise the constructed client will not work.
    pub fn new(client: Client, address: ContractAddress, contract_name: OwnedContractName) -> Self {
        Self {
            client,
            address,
            contract_name: Arc::new(contract_name),
            phantom: PhantomData,
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
            + From<RejectReason>
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
            + From<RejectReason>
            + From<contracts_common::ParseError>
            + From<v2::QueryError>, {
        let ir = self
            .invoke_raw::<E>(entrypoint, Amount::zero(), None, parameter, bi)
            .await?;
        match ir {
            smart_contracts::InvokeContractResult::Success { return_value, .. } => {
                let Some(bytes) = return_value else {return Err(contracts_common::ParseError {}.into()
            )};
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
        E: From<NewReceiveNameError> + From<RejectReason> + From<v2::QueryError>, {
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
            + From<RejectReason>
            + From<v2::QueryError>
            + From<ExceedsParameterSize>, {
        let message = OwnedParameter::from_serial(message)?;
        self.dry_run_update_raw(entrypoint, amount, sender, message)
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
        E: From<NewReceiveNameError> + From<RejectReason> + From<v2::QueryError>, {
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
            InvokeContractResult::Success { used_energy, .. } => Ok(ContractUpdateBuilder::new(
                self.client.clone(),
                sender,
                payload,
                used_energy,
            )),
            InvokeContractResult::Failure { reason, .. } => Err(reason.into()),
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

/// A builder to simplify sending smart contract updates.
pub struct ContractUpdateBuilder {
    payload:    UpdateContractPayload,
    sender:     AccountAddress,
    energy:     Energy,
    expiry:     Option<TransactionTime>,
    add_energy: Option<Energy>,
    nonce:      Option<Nonce>,
    client:     v2::Client,
}

impl ContractUpdateBuilder {
    /// Construct a new builder.
    fn new(
        client: v2::Client,
        sender: AccountAddress,
        payload: UpdateContractPayload,
        energy: Energy,
    ) -> Self {
        Self {
            payload,
            sender,
            energy,
            expiry: None,
            add_energy: None,
            nonce: None,
            client,
        }
    }

    /// Add extra energy to the call.
    /// The default amount is 10%, or at least 50.
    /// This should be sufficient in most cases, but for specific
    /// contracts no extra energy might be needed, or a greater safety margin
    /// could be desired.
    pub fn extra_energy(mut self, energy: Energy) -> Self {
        self.add_energy = Some(energy);
        self
    }

    /// Set the expiry time for the transaction. If not set the default is one
    /// hour from the time the transaction is signed.
    pub fn expiry(mut self, expiry: TransactionTime) -> Self {
        self.expiry = Some(expiry);
        self
    }

    /// Set the nonce for the transaction. If not set the default behaviour is
    /// to get the nonce from the connected [`Client`](v2::Client) at the
    /// time the transaction is sent.
    pub fn nonce(mut self, nonce: Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Return the amount of [`Energy`] allowed for execution if
    /// the transaction was sent with the current parameters.
    pub fn current_energy(&self) -> Energy {
        // Add 10% to the call, or at least 50.
        self.energy
            + self
                .add_energy
                .unwrap_or_else(|| std::cmp::max(50, self.energy.energy / 10).into())
    }

    /// Send the transaction and return a handle that can be queried
    /// for the status.
    pub async fn send(
        mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
    ) -> v2::QueryResult<ContractUpdateHandle> {
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
        let tx = transactions::send::update_contract(
            signer,
            self.sender,
            nonce,
            expiry,
            self.payload,
            energy,
        );
        let tx_hash = self.client.send_account_transaction(tx).await?;
        Ok(ContractUpdateHandle {
            tx_hash,
            client: self.client,
        })
    }
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
    Failed(RejectReason),
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

        match result.details {
            crate::types::BlockItemSummaryDetails::AccountTransaction(at) => match at.effects {
                AccountTransactionEffects::ContractUpdateIssued { effects } => {
                    let Some(execution_tree) = crate::types::execution_tree(effects) else {
                        return mk_error("Expected smart contract update, but received invalid execution tree.");
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
            },
            crate::types::BlockItemSummaryDetails::AccountCreation(_) => {
                mk_error("Expected smart contract update status, but received account creation.")
            }
            crate::types::BlockItemSummaryDetails::Update(_) => mk_error(
                "Expected smart contract update status, but received chain update instruction.",
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
