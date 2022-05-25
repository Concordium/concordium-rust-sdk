mod types;

use std::convert::TryFrom;

pub use types::*;

use crate::{common, endpoints::Client, id, types as sdk_types};
use sdk_types::{smart_contracts, transactions, ContractAddress};
use smart_contracts::concordium_contracts_common;

/// A wrapper around the client representing a CIS2 token smart contract and
/// provides functions for interaction.
pub struct Cis2Contract {
    client:        Client,
    address:       ContractAddress,
    contract_name: String,
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
    ) -> anyhow::Result<sdk_types::hashes::TransactionHash> {
        let parameter = TransferParams::from(transfers);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name =
            smart_contracts::ReceiveName::try_from(format!("{}.transfer", self.contract_name))
                .map_err(|e| anyhow!("Invalid receive name"))?;

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
        self.client
            .send_block_item(&bi)
            .await
            .context("Transaction was rejected by the node.")
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
    ) -> anyhow::Result<sdk_types::hashes::TransactionHash> {
        let parameter = UpdateOperatorParams::from(updates);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name = smart_contracts::ReceiveName {
            name: "updateOperator",
        };

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
        self.client
            .send_block_item(&bi)
            .await
            .context("Transaction was rejected by the node.")
    }

    /// Invoke CIS2 balanceOf.
    pub async fn balance_of(
        mut self,
        block_hash: &sdk_types::hashes::BlockHash,
        queries: Vec<BalanceOfQuery>,
    ) -> anyhow::Result<BalanceOfQueryResponse> {
        let parameter = BalanceOfQueryParams::from(queries);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name = smart_contracts::ReceiveName { name: "balanceOf" };

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
            .await
            .context("Contract invocation failed.")?;

        if let smart_contracts::InvokeContractResult::Success {
            return_value: Some(bytes),
            ..
        } = invoke_result
        {
            let mut cursor = concordium_contracts_common::Cursor::new(bytes.value);
            let response = BalanceOfQueryResponse::deserial(&mut cursor)
                .map_err(|_| anyhow!("Failed parsing contract state"))?;
            Ok(response)
        } else {
            bail!("balanceOf query was rejected.");
        }
    }

    /// Invoke CIS2 operatorOf.
    pub async fn operator_of(
        mut self,
        block_hash: &sdk_types::hashes::BlockHash,
        queries: Vec<OperatorOfQuery>,
    ) -> anyhow::Result<OperatorOfQueryResponse> {
        let parameter = OperatorOfQueryParams::from(queries);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name = smart_contracts::ReceiveName { name: "operatorOf" };

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
            .await
            .context("Contract invocation failed.")?;

        if let smart_contracts::InvokeContractResult::Success {
            return_value: Some(bytes),
            ..
        } = invoke_result
        {
            let mut cursor = concordium_contracts_common::Cursor::new(bytes.value);
            let response = OperatorOfQueryResponse::deserial(&mut cursor)
                .map_err(|_| anyhow!("Failed parsing contract state"))?;
            Ok(response)
        } else {
            bail!("operatorOf query was rejected.");
        }
    }

    /// Invoke CIS2 tokenMetadata.
    pub async fn token_metadata(
        mut self,
        block_hash: &sdk_types::hashes::BlockHash,
        queries: Vec<TokenIdVec>,
    ) -> anyhow::Result<TokenMetadataQueryResponse> {
        let parameter = TokenMetadataQueryParams::from(queries);
        let bytes = concordium_contracts_common::to_bytes(&parameter);
        let receive_name = smart_contracts::ReceiveName {
            name: "tokenMetadata",
        };

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
            .await
            .context("Contract invocation failed.")?;

        if let smart_contracts::InvokeContractResult::Success {
            return_value: Some(bytes),
            ..
        } = invoke_result
        {
            let mut cursor = concordium_contracts_common::Cursor::new(bytes.value);
            let response = TokenMetadataQueryResponse::deserial(&mut cursor)
                .map_err(|_| anyhow!("Failed parsing contract state"))?;
            Ok(response)
        } else {
            bail!("tokenMetadata query was rejected.");
        }
    }
}
