mod types;

use std::convert::{From, TryFrom};

pub use types::*;

use crate::{common, endpoints::Client, id, types as sdk_types};
use sdk_types::{smart_contracts, transactions, ContractAddress};
use smart_contracts::concordium_contracts_common;

use thiserror::*;

/// A wrapper around the client representing a CIS2 token smart contract and
/// provides functions for interaction.
pub struct Cis2Contract {
    client:        Client,
    address:       ContractAddress,
    contract_name: String,
}

#[derive(Debug, Error)]
pub enum Cis2TransactionError {
    #[error("Invalid receive name")]
    InvalidContractName(concordium_contracts_common::NewReceiveNameError),

    #[error("Rejected by the node: {0}")]
    NodeRejected(#[from] crate::endpoints::RPCError),
}

impl From<concordium_contracts_common::NewReceiveNameError> for Cis2TransactionError {
    fn from(err: concordium_contracts_common::NewReceiveNameError) -> Self {
        Self::InvalidContractName(err)
    }
}

#[derive(Debug, Error)]
pub enum Cis2QueryError {
    #[error("Invalid receive name")]
    InvalidContractName(concordium_contracts_common::NewReceiveNameError),

    #[error("Rejected by the node: {0}")]
    NodeRejected(#[from] crate::endpoints::RPCError),

    #[error("Failed parsing the response")]
    ResponseParseError(concordium_contracts_common::ParseError),

    #[error("Query failed")]
    QueryFailed(sdk_types::RejectReason),
}

impl From<concordium_contracts_common::NewReceiveNameError> for Cis2QueryError {
    fn from(err: concordium_contracts_common::NewReceiveNameError) -> Self {
        Self::InvalidContractName(err)
    }
}

impl From<concordium_contracts_common::ParseError> for Cis2QueryError {
    fn from(err: concordium_contracts_common::ParseError) -> Self { Self::ResponseParseError(err) }
}

impl From<sdk_types::RejectReason> for Cis2QueryError {
    fn from(err: sdk_types::RejectReason) -> Self { Self::QueryFailed(err) }
}

impl Cis2Contract {
    /// Construct a Cis2Contract
    pub fn new(client: Client, address: ContractAddress, contract_name: String) -> Cis2Contract {
        Cis2Contract {
            client,
            address,
            contract_name,
        }
    }

    /// Send a CIS2 transfer transaction.
    pub async fn transfer(
        mut self,
        sender_keys: &id::types::AccountKeys,
        sender_address: &id::types::AccountAddress,
        nonce: sdk_types::Nonce,
        expiry: common::types::TransactionTime,
        energy: transactions::send::GivenEnergy,
        amount: common::types::Amount,
        transfers: Vec<Transfer>,
    ) -> Result<sdk_types::hashes::TransactionHash, Cis2TransactionError> {
        let parameter = TransferParams::from(transfers);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name =
            smart_contracts::ReceiveName::try_from(format!("{}.transfer", self.contract_name))?;

        let payload = transactions::Payload::Update {
            payload: transactions::UpdateContractPayload {
                amount,
                address: self.address,
                receive_name,
                message: smart_contracts::Parameter::from(bytes),
            },
        };
        let tx = transactions::send::make_and_sign_transaction(
            sender_keys,
            *sender_address,
            nonce,
            expiry,
            energy,
            payload,
        );
        let bi = transactions::BlockItem::AccountTransaction(tx);
        let hash = self.client.send_block_item(&bi).await?;
        Ok(hash)
    }

    /// Send a CIS2 updateOperator transaction.
    pub async fn update_operator(
        mut self,
        sender_keys: &id::types::AccountKeys,
        sender_address: &id::types::AccountAddress,
        nonce: sdk_types::Nonce,
        expiry: common::types::TransactionTime,
        energy: transactions::send::GivenEnergy,
        amount: common::types::Amount,
        updates: Vec<UpdateOperator>,
    ) -> anyhow::Result<sdk_types::hashes::TransactionHash, Cis2TransactionError> {
        let parameter = UpdateOperatorParams::from(updates);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name = smart_contracts::ReceiveName::try_from(format!(
            "{}.updateOperator",
            self.contract_name
        ))?;

        let payload = transactions::Payload::Update {
            payload: transactions::UpdateContractPayload {
                amount,
                address: self.address,
                receive_name,
                message: smart_contracts::Parameter::from(bytes),
            },
        };
        let tx = transactions::send::make_and_sign_transaction(
            sender_keys,
            *sender_address,
            nonce,
            expiry,
            energy,
            payload,
        );
        let bi = transactions::BlockItem::AccountTransaction(tx);
        let hash = self.client.send_block_item(&bi).await?;
        Ok(hash)
    }

    /// Invoke CIS2 balanceOf.
    pub async fn balance_of(
        mut self,
        block_hash: &sdk_types::hashes::BlockHash,
        queries: Vec<BalanceOfQuery>,
    ) -> Result<BalanceOfQueryResponse, Cis2QueryError> {
        let parameter = BalanceOfQueryParams::from(queries);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name =
            smart_contracts::ReceiveName::try_from(format!("{}.balanceOf", self.contract_name))?;

        let contract_context = smart_contracts::ContractContext {
            invoker:   None,
            contract:  self.address,
            amount:    common::types::Amount::from(0),
            method:    receive_name,
            parameter: smart_contracts::Parameter::from(bytes),
            energy:    sdk_types::Energy::from(10_000_000),
        };

        let invoke_result = self
            .client
            .invoke_contract(block_hash, &contract_context)
            .await?;

        match invoke_result {
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

    /// Invoke CIS2 operatorOf.
    pub async fn operator_of(
        mut self,
        block_hash: &sdk_types::hashes::BlockHash,
        queries: Vec<OperatorOfQuery>,
    ) -> Result<OperatorOfQueryResponse, Cis2QueryError> {
        let parameter = OperatorOfQueryParams::from(queries);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name =
            smart_contracts::ReceiveName::try_from(format!("{}.operatorOf", self.contract_name))?;

        let contract_context = smart_contracts::ContractContext {
            invoker:   None,
            contract:  self.address,
            amount:    common::types::Amount::from(0),
            method:    receive_name,
            parameter: smart_contracts::Parameter::from(bytes),
            energy:    sdk_types::Energy::from(10_000_000),
        };

        let invoke_result = self
            .client
            .invoke_contract(block_hash, &contract_context)
            .await?;

        match invoke_result {
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

    /// Invoke CIS2 tokenMetadata.
    pub async fn token_metadata(
        mut self,
        block_hash: &sdk_types::hashes::BlockHash,
        queries: Vec<TokenIdVec>,
    ) -> Result<TokenMetadataQueryResponse, Cis2QueryError> {
        let parameter = TokenMetadataQueryParams::from(queries);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name = smart_contracts::ReceiveName::try_from(format!(
            "{}.tokenMetadata",
            self.contract_name
        ))?;

        let contract_context = smart_contracts::ContractContext {
            invoker:   None,
            contract:  self.address,
            amount:    common::types::Amount::from(0),
            method:    receive_name,
            parameter: smart_contracts::Parameter::from(bytes),
            energy:    sdk_types::Energy::from(10_000_000),
        };

        let invoke_result = self
            .client
            .invoke_contract(block_hash, &contract_context)
            .await?;

        match invoke_result {
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
