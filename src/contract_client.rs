use crate::{
    types::{
        smart_contracts::{self, ContractContext, InvokeContractResult},
        transactions, RejectReason,
    },
    v2::{self, BlockIdentifier, Client},
};
use concordium_base::{
    base::Nonce,
    common::types,
    contracts_common::{
        self, AccountAddress, Address, Amount, ContractAddress, NewReceiveNameError,
    },
    hashes::TransactionHash,
    smart_contracts::{ExceedsParameterSize, OwnedContractName, OwnedParameter, OwnedReceiveName},
    transactions::UpdateContractPayload,
};
pub use concordium_base::{cis2_types::MetadataUrl, cis4_types::*};
use std::{marker::PhantomData, sync::Arc};

/// A CIS4 compatible contract instance.
///
/// Note that cloning is cheap and is, therefore, the intended way of sharing
/// values of this type between multiple tasks.
#[derive(Debug)]
pub struct ContractClient<Type> {
    pub client:        Client,
    pub address:       ContractAddress,
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
#[derive(thiserror::Error, Debug)]
/// An error that can occur when executing CIS4 queries.
pub enum Cis4QueryError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] contracts_common::NewReceiveNameError),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] super::v2::QueryError),

    /// The data returned from q query could not be parsed.
    #[error("Failed parsing the response.")]
    ResponseParseError(#[from] contracts_common::ParseError),

    /// The node rejected the invocation.
    #[error("Rejected by the node: {0:?}.")]
    NodeRejected(crate::types::RejectReason),
}

#[derive(thiserror::Error, Debug)]
/// An error that can occur when sending CIS4 update transactions.
pub enum Cis4TransactionError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] contracts_common::NewReceiveNameError),

    /// The parameter is too large.
    #[error("Parameter is too large: {0}")]
    InvalidParams(#[from] ExceedsParameterSize),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] super::v2::RPCError),

    /// The node rejected the invocation.
    #[error("Rejected by the node: {0:?}.")]
    NodeRejected(crate::types::RejectReason),
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
        Self::new(client, address, ci.response.name().clone())
    }

    /// Construct a [`ContractClient`] locally.
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node. Note that cloning
    ///   [`Client`] is cheap and is therefore the intended way of sharing.
    /// * `address` - The contract address of the CIS4 registry smart contract.
    /// * `contract_name` - The name of the contract. This must match the name
    ///   on the chain,
    /// otherwise the constructed client will not work.
    pub fn new(
        client: Client,
        address: ContractAddress,
        contract_name: OwnedContractName,
    ) -> v2::QueryResult<Self> {
        Ok(Self {
            client,
            address,
            contract_name: Arc::new(contract_name),
            phantom: PhantomData,
        })
    }

    pub async fn view<R: contracts_common::Deserial>(
        &mut self,
        entrypoint: &str,
        input: &impl contracts_common::Serial,
        bi: impl v2::IntoBlockIdentifier,
    ) -> Result<R, ViewError> {
        let parameter = OwnedParameter::from_serial(input)?;
        self.make_query_raw(entrypoint, parameter, bi).await
    }

    pub async fn make_query<P: contracts_common::Serial, A: contracts_common::Deserial, E>(
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
        self.make_query_raw::<A, E>(entrypoint, parameter, bi).await
    }

    pub async fn make_query_raw<A: contracts_common::Deserial, E>(
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
            .make_invoke::<E>(entrypoint, Amount::zero(), None, parameter, bi)
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

    pub async fn make_invoke<E>(
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
            energy: 1_000_000.into(),
        };

        let invoke_result = self.client.invoke_instance(bi, &context).await?.response;
        Ok(invoke_result)
    }

    pub async fn make_call<P: contracts_common::Serial, E>(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &ContractTransactionMetadata,
        entrypoint: &str,
        message: &P,
    ) -> Result<TransactionHash, E>
    where
        E: From<NewReceiveNameError> + From<v2::RPCError> + From<ExceedsParameterSize>, {
        let message = OwnedParameter::from_serial(message)?;
        self.make_call_raw::<E>(signer, metadata, entrypoint, message)
            .await
    }

    pub async fn make_call_raw<E>(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &ContractTransactionMetadata,
        entrypoint: &str,
        message: OwnedParameter,
    ) -> Result<TransactionHash, E>
    where
        E: From<NewReceiveNameError> + From<v2::RPCError>, {
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

        let hash = self.client.send_account_transaction(tx).await?;
        Ok(hash)
    }
}
