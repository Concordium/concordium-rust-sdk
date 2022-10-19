//! This module contains types and functions for interacting with smart
//! contracts following the [CIS-2](https://proposals.concordium.software/CIS/cis-2.html) specification.
//!
//! The type [`Cis2Contract`](crate::cis2::Cis2Contract) act as a wrapper around
//! the [Client](crate::endpoints::Client) and a contract address providing
//! functions for querying and making transactions to smart contract.
mod types;

use crate::{
    common, id, types as sdk_types,
    v2::{BlockIdentifier, Client},
};
use sdk_types::{smart_contracts, transactions, ContractAddress};
use smart_contracts::concordium_contracts_common;
use std::{
    convert::{From, TryFrom},
    sync::Arc,
};
use thiserror::*;
pub use types::*;

/// A wrapper around the client representing a CIS2 token smart contract, which
/// provides functions for interaction.
///
/// Note that cloning is cheap and is, therefore, the intended way of sharing
/// this type between multiple tasks.
#[derive(Debug, Clone)]
pub struct Cis2Contract {
    client:        Client,
    address:       ContractAddress,
    contract_name: Arc<concordium_contracts_common::OwnedContractName>,
}

/// Error which can occur when submitting a transaction such as `transfer` and
/// `updateOperator` to a CIS2 smart contract.
#[derive(Debug, Error)]
pub enum Cis2TransactionError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(concordium_contracts_common::NewReceiveNameError),

    /// The parameter for `transfer` is invalid.
    #[error("Invalid transfer parameter: {0}")]
    InvalidTransferParams(#[from] NewTransferParamsError),

    /// The parameter for `updateOperator` is invalid.
    #[error("Invalid updateOperator parameter: {0}")]
    InvalidUpdateOperatorParams(#[from] NewUpdateOperatorParamsError),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] crate::endpoints::RPCError),
}

// This is implemented manually, since deriving it using thiserror requires
// `concordium_contracts_common::NewReceiveNameError` to implement
// std::error::Error.
impl From<concordium_contracts_common::NewReceiveNameError> for Cis2TransactionError {
    fn from(err: concordium_contracts_common::NewReceiveNameError) -> Self {
        Self::InvalidReceiveName(err)
    }
}

/// Error which can occur when invoking a query such as `balanceOf` and
/// `operatorOf` or `tokenMetadata` to a CIS2 smart contract.
#[derive(Debug, Error)]
pub enum Cis2QueryError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] concordium_contracts_common::NewReceiveNameError),

    /// The parameter for `balanceOf` is invalid.
    #[error("Invalid balanceOf parameter: {0}")]
    InvalidBalanceOfParams(#[from] NewBalanceOfQueryParamsError),

    /// The parameter for `operatorOf` is invalid.
    #[error("Invalid operatorOf parameter: {0}")]
    InvalidOperatorOfParams(#[from] NewOperatorOfQueryParamsError),

    /// The parameter for `tokenMetadata` is invalid.
    #[error("Invalid tokenMetadata parameter: {0}")]
    InvalidTokenMetadataParams(#[from] NewTokenMetadataQueryParamsError),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] super::v2::QueryError),

    /// The returned bytes from invoking the smart contract could not be parsed.
    #[error("Failed parsing the response.")]
    ResponseParseError(#[from] concordium_contracts_common::ParseError),

    /// The node rejected the invocation.
    #[error("Rejected by the node.")]
    NodeRejected(sdk_types::RejectReason),
}

// This is implemented manually, since deriving it using thiserror requires
// `RejectReason` to implement std::error::Error.
impl From<sdk_types::RejectReason> for Cis2QueryError {
    fn from(err: sdk_types::RejectReason) -> Self { Self::NodeRejected(err) }
}

/// Transaction metadata for CIS-2
#[derive(Debug, Clone, Copy)]
pub struct Cis2TransactionMetadata {
    /// The account address sending the transaction.
    pub sender_address: id::types::AccountAddress,
    /// The nonce to use for the transaction.
    pub nonce:          sdk_types::Nonce,
    /// Expiry date of the transaction.
    pub expiry:         common::types::TransactionTime,
    /// The limit on energy to use for the transaction.
    pub energy:         transactions::send::GivenEnergy,
    /// The amount of CCD to include in the transaction.
    pub amount:         common::types::Amount,
}

impl Cis2Contract {
    /// Construct a Cis2Contract.
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node. Note that cloning
    ///   [Client](crate::endpoints::Client) is cheap and is therefore the
    ///   intended way of sharing.
    /// * `address` - The contract address of the CIS2 token smart contract.
    /// * `contract_name` - The name of the contract.
    pub fn new(
        client: Client,
        address: ContractAddress,
        contract_name: concordium_contracts_common::OwnedContractName,
    ) -> Cis2Contract {
        Cis2Contract {
            client,
            address,
            contract_name: Arc::new(contract_name),
        }
    }

    /// Construct and send a CIS2 transfer smart contract update transaction
    /// given a list of CIS2 transfers. Returns a Result with the
    /// transaction hash.
    ///
    /// # Arguments
    ///
    /// * `signer` - The account keys to use for signing the smart contract
    ///   update transaction.
    /// * `transaction_metadata` - Metadata for constructing the transaction.
    /// * `transfers` - A list of CIS2 token transfers to execute.
    pub async fn transfer(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        transaction_metadata: Cis2TransactionMetadata,
        transfers: Vec<Transfer>,
    ) -> Result<sdk_types::hashes::TransactionHash, Cis2TransactionError> {
        let parameter = TransferParams::new(transfers)?;
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let receive_name =
            smart_contracts::OwnedReceiveName::try_from(format!("{}.transfer", contract_name))?;

        let payload = transactions::Payload::Update {
            payload: transactions::UpdateContractPayload {
                amount: transaction_metadata.amount,
                address: self.address,
                receive_name,
                message: smart_contracts::Parameter::try_from(bytes).map_err(|_| {
                    Cis2TransactionError::InvalidTransferParams(NewTransferParamsError)
                })?,
            },
        };
        let tx = transactions::send::make_and_sign_transaction(
            signer,
            transaction_metadata.sender_address,
            transaction_metadata.nonce,
            transaction_metadata.expiry,
            transaction_metadata.energy,
            payload,
        );
        let bi = transactions::BlockItem::AccountTransaction(tx);
        let hash = self.client.send_block_item(&bi).await?;
        Ok(hash)
    }

    /// Send a CIS2 updateOperator transaction.
    /// Construct and send a CIS2 updateOperator smart contract update
    /// transaction given a list of CIS2 UpdateOperators. Returns a Result
    /// with the transaction hash.
    ///
    /// # Arguments
    ///
    /// * `signer` - The account keys to use for signing the smart contract
    ///   update transaction.
    /// * `sender_address` - The account address of the signing keys.
    /// * `transaction_metadata` - Metadata for constructing the transaction.
    /// * `updates` - A list of CIS2 UpdateOperators to update.
    pub async fn update_operator(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        transaction_metadata: Cis2TransactionMetadata,
        updates: Vec<UpdateOperator>,
    ) -> anyhow::Result<sdk_types::hashes::TransactionHash, Cis2TransactionError> {
        let parameter = UpdateOperatorParams::new(updates)?;
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let contract_name = self.contract_name.as_contract_name().contract_name();

        let receive_name = smart_contracts::OwnedReceiveName::try_from(format!(
            "{}.updateOperator",
            contract_name
        ))?;

        let payload = transactions::Payload::Update {
            payload: transactions::UpdateContractPayload {
                amount: transaction_metadata.amount,
                address: self.address,
                receive_name,
                message: smart_contracts::Parameter::try_from(bytes).map_err(|_| {
                    Cis2TransactionError::InvalidUpdateOperatorParams(NewUpdateOperatorParamsError)
                })?,
            },
        };
        let tx = transactions::send::make_and_sign_transaction(
            signer,
            transaction_metadata.sender_address,
            transaction_metadata.nonce,
            transaction_metadata.expiry,
            transaction_metadata.energy,
            payload,
        );
        let bi = transactions::BlockItem::AccountTransaction(tx);
        let hash = self.client.send_block_item(&bi).await?;
        Ok(hash)
    }

    /// Invoke the CIS2 balanceOf query given a list of BalanceOfQuery.
    ///
    /// Note: the query is executed locally by the node and does not produce a
    /// transaction on-chain.
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of a block. The query will be executed in the
    ///   state of the chain at the end of the block.
    /// * `queries` - A list queries to execute.
    pub async fn balance_of(
        &mut self,
        bi: &BlockIdentifier,
        queries: Vec<BalanceOfQuery>,
    ) -> Result<BalanceOfQueryResponse, Cis2QueryError> {
        let parameter = BalanceOfQueryParams::new(queries)?;
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let receive_name =
            smart_contracts::OwnedReceiveName::try_from(format!("{}.balanceOf", contract_name))?;

        let contract_context = smart_contracts::ContractContext {
            invoker:   None,
            contract:  self.address,
            amount:    common::types::Amount::from_micro_ccd(0),
            method:    receive_name,
            parameter: smart_contracts::Parameter::try_from(bytes).map_err(|_| {
                Cis2QueryError::InvalidBalanceOfParams(NewBalanceOfQueryParamsError)
            })?,
            energy:    smart_contracts::MAX_ALLOWED_INVOKE_ENERGY,
        };

        let invoke_result = self.client.invoke_instance(bi, &contract_context).await?;

        match invoke_result.response {
            smart_contracts::InvokeContractResult::Success { return_value, .. } => {
                let bytes: smart_contracts::ReturnValue = return_value.ok_or(
                    Cis2QueryError::ResponseParseError(concordium_contracts_common::ParseError {}),
                )?;
                let response: BalanceOfQueryResponse =
                    concordium_contracts_common::from_bytes(&bytes.value)?;
                Ok(response)
            }
            smart_contracts::InvokeContractResult::Failure { reason, .. } => Err(reason.into()),
        }
    }

    /// Invoke the CIS2 operatorOf query given a list of OperatorOfQuery.
    ///
    /// Note: the query is executed locally by the node and does not produce a
    /// transaction on-chain.
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of a block. The query will be executed in the
    ///   state of the chain at the end of the block.
    /// * `queries` - A list queries to execute.
    pub async fn operator_of(
        &mut self,
        bi: &BlockIdentifier,
        queries: Vec<OperatorOfQuery>,
    ) -> Result<OperatorOfQueryResponse, Cis2QueryError> {
        let parameter = OperatorOfQueryParams::new(queries)?;
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let receive_name =
            smart_contracts::OwnedReceiveName::try_from(format!("{}.operatorOf", contract_name))?;

        let contract_context = smart_contracts::ContractContext {
            invoker:   None,
            contract:  self.address,
            amount:    common::types::Amount::from_micro_ccd(0),
            method:    receive_name,
            parameter: smart_contracts::Parameter::try_from(bytes).map_err(|_| {
                Cis2QueryError::InvalidOperatorOfParams(NewOperatorOfQueryParamsError)
            })?,
            energy:    smart_contracts::MAX_ALLOWED_INVOKE_ENERGY,
        };

        let invoke_result = self.client.invoke_instance(bi, &contract_context).await?;

        match invoke_result.response {
            smart_contracts::InvokeContractResult::Success { return_value, .. } => {
                let bytes: smart_contracts::ReturnValue = return_value.ok_or(
                    Cis2QueryError::ResponseParseError(concordium_contracts_common::ParseError {}),
                )?;
                let response: OperatorOfQueryResponse =
                    concordium_contracts_common::from_bytes(&bytes.value)?;
                Ok(response)
            }
            smart_contracts::InvokeContractResult::Failure { reason, .. } => Err(reason.into()),
        }
    }

    /// Invoke the CIS2 tokenMetadata query given a list of CIS2 TokenIds.
    ///
    /// Note: the query is executed locally by the node and does not produce a
    /// transaction on-chain.
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of a block. The query will be executed in the
    ///   state of the chain at the end of the block.
    /// * `queries` - A list queries to execute.
    pub async fn token_metadata(
        &mut self,
        bi: &BlockIdentifier,
        queries: Vec<TokenId>,
    ) -> Result<TokenMetadataQueryResponse, Cis2QueryError> {
        let parameter = TokenMetadataQueryParams::new(queries)?;
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let receive_name = smart_contracts::OwnedReceiveName::try_from(format!(
            "{}.tokenMetadata",
            contract_name
        ))?;

        let contract_context = smart_contracts::ContractContext {
            invoker:   None,
            contract:  self.address,
            amount:    common::types::Amount::from_micro_ccd(0),
            method:    receive_name,
            parameter: smart_contracts::Parameter::try_from(bytes).map_err(|_| {
                Cis2QueryError::InvalidTokenMetadataParams(NewTokenMetadataQueryParamsError)
            })?,
            energy:    smart_contracts::MAX_ALLOWED_INVOKE_ENERGY,
        };

        let invoke_result = self.client.invoke_instance(bi, &contract_context).await?;

        match invoke_result.response {
            smart_contracts::InvokeContractResult::Success { return_value, .. } => {
                let bytes: smart_contracts::ReturnValue = return_value.ok_or(
                    Cis2QueryError::ResponseParseError(concordium_contracts_common::ParseError {}),
                )?;
                let response: TokenMetadataQueryResponse =
                    concordium_contracts_common::from_bytes(&bytes.value)?;
                Ok(response)
            }
            smart_contracts::InvokeContractResult::Failure { reason, .. } => Err(reason.into()),
        }
    }
}
