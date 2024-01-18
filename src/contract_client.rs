//! This module contains a generic client that provides conveniences for
//! interacting with any smart contract instance.
use crate::{
    indexer::ContractUpdateInfo,
    types::{
        smart_contracts::{self, ContractContext, InvokeContractResult},
        transactions, AccountTransactionEffects, RejectReason,
    },
    v2::{self, BlockIdentifier, Client},
};
use concordium_base::{
    base::{Energy, Nonce},
    common::types::{self, TransactionTime},
    contracts_common::{
        self, AccountAddress, Address, Amount, ContractAddress, NewReceiveNameError,
    },
    hashes::TransactionHash,
    smart_contracts::{ExceedsParameterSize, OwnedContractName, OwnedParameter, OwnedReceiveName},
    transactions::{AccountTransaction, EncodedPayload, UpdateContractPayload},
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

impl<Type> ContractClient<Type> {
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

        let context = ContractContext::new_from_payload(sender, Energy::from(10_000_000), payload);

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
    pub fn new(
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

    /// Send the transaction and return its hash.
    pub async fn send(
        mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
    ) -> v2::QueryResult<TransactionHash> {
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
        let energy = self.energy + self.add_energy.unwrap_or(100.into());
        let tx = transactions::send::update_contract(
            signer,
            self.sender,
            nonce,
            expiry,
            self.payload,
            energy,
        );
        let hash = self.client.send_account_transaction(tx).await?;
        Ok(hash)
    }
}

pub struct ContractUpdateHandle {
    tx_hash: TransactionHash,
    client:  v2::Client,
}

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
                _ => mk_error("Expected smart contract update status, but received ."),
            },
            crate::types::BlockItemSummaryDetails::AccountCreation(_) => {
                mk_error("Expected smart contract update status, but received account creation.")
            }
            crate::types::BlockItemSummaryDetails::Update(_) => mk_error(
                "Expected smart contract update status, but received chain update creation.",
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
