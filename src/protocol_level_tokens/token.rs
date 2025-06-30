use concordium_base::{
    common::{cbor::CborSerializationError, types::TransactionTime},
    contracts_common::AccountAddress,
    hashes::TransactionHash,
    protocol_level_tokens::{operations, TokenAmount, TokenId, TokenTransfer},
    transactions::{send, BlockItem},
};
use thiserror::Error;

use crate::{
    protocol_level_tokens::TokenInfo,
    types::WalletAccount,
    v2::{AccountIdentifier, BlockIdentifier, Client, IntoBlockIdentifier, QueryError, RPCError},
};

#[derive()]
pub struct Token {
    client: Client,
    info:   TokenInfo,
}

pub type TokenResult<T> = Result<T, TokenError>;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Query error: {0}")]
    Query(#[from] QueryError),
    #[error("CBor serialization error: {0}")]
    CberSeriazation(#[from] CborSerializationError),
    #[error("RPC error: {0}")]
    RPC(#[from] RPCError),
}

impl Token {
    pub fn new(client: Client, info: TokenInfo) -> Self { Self { client, info } }

    pub fn token_info(&self) -> &TokenInfo { &self.info }

    pub async fn create(mut client: Client, token_id: TokenId) -> TokenResult<Self> {
        let info = client
            .get_token_info(token_id, BlockIdentifier::LastFinal)
            .await?
            .response;
        Ok(Self { client, info })
    }

    pub async fn transfer(
        &mut self,
        signer: &WalletAccount,
        receiver: AccountAddress,
        amount: TokenAmount,
        expiry: Option<TransactionTime>,
    ) -> TokenResult<TransactionHash> {
        let expiry = if let Some(trx_time) = expiry {
            trx_time
        } else {
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64)
        };

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operation = operations::transfer_tokens(receiver, amount);

        let transaction = send::token_holder_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            [operation].into_iter().collect(),
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    pub async fn mint(
        &mut self,
        signer: &WalletAccount,
        amount: TokenAmount,
        expiry: Option<TransactionTime>,
    ) -> TokenResult<TransactionHash> {
        let expiry = if let Some(trx_time) = expiry {
            trx_time
        } else {
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64)
        };

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operation = operations::mint_tokens(amount);

        let transaction = send::token_governance_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            [operation].into_iter().collect(),
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    pub async fn burn(
        &mut self,
        signer: &WalletAccount,
        amount: TokenAmount,
        expiry: Option<TransactionTime>,
    ) -> TokenResult<TransactionHash> {
        let expiry = if let Some(trx_time) = expiry {
            trx_time
        } else {
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64)
        };

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operation = operations::burn_tokens(amount);

        let transaction = send::token_governance_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            [operation].into_iter().collect(),
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    pub async fn add_allow_list(
        &mut self,
        signer: &WalletAccount,
        address: AccountAddress,
        expiry: Option<TransactionTime>,
    ) -> TokenResult<TransactionHash> {
        let expiry = if let Some(trx_time) = expiry {
            trx_time
        } else {
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64)
        };

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operation = operations::add_token_allow_list(address);

        let transaction = send::token_governance_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            [operation].into_iter().collect(),
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    pub async fn remove_allow_list(
        &mut self,
        signer: &WalletAccount,
        address: AccountAddress,
        expiry: Option<TransactionTime>,
    ) -> TokenResult<TransactionHash> {
        let expiry = if let Some(trx_time) = expiry {
            trx_time
        } else {
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64)
        };

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operation = operations::remove_token_allow_list(address);

        let transaction = send::token_governance_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            [operation].into_iter().collect(),
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    pub async fn add_deny_list(
        &mut self,
        signer: &WalletAccount,
        address: AccountAddress,
        expiry: Option<TransactionTime>,
    ) -> TokenResult<TransactionHash> {
        let expiry = if let Some(trx_time) = expiry {
            trx_time
        } else {
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64)
        };

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operation = operations::add_token_deny_list(address);

        let transaction = send::token_governance_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            [operation].into_iter().collect(),
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    pub async fn remove_deny_list(
        &mut self,
        signer: &WalletAccount,
        address: AccountAddress,
        expiry: Option<TransactionTime>,
    ) -> TokenResult<TransactionHash> {
        let expiry = if let Some(trx_time) = expiry {
            trx_time
        } else {
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64)
        };

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operation = operations::remove_token_deny_list(address);

        let transaction = send::token_governance_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            [operation].into_iter().collect(),
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    pub async fn balance_of(
        &mut self,
        acc: &AccountIdentifier,
        bi: Option<impl IntoBlockIdentifier>,
    ) -> TokenResult<Option<TokenAmount>> {
        let bi = if let Some(bi) = bi {
            bi.into_block_identifier()
        } else {
            BlockIdentifier::LastFinal
        };
        let account_info = self.client.get_account_info(acc, bi).await?.response;
        Ok(account_info
            .tokens
            .into_iter()
            .find(|at| at.token_id == self.info.token_id)
            .map(|at| at.state.balance))
    }

    pub async fn validate_transfer(
        &mut self,
        sender: AccountAddress,
        payload: Vec<TokenTransfer>,
    ) -> TokenResult<()> {
        
        Ok(())
    }

    // // done before the gov ops
    // pub async fn validate_governance_operation(&self) -> QueryResult<()> { Ok(())
    // }

    // pub async fn raw_operation(&self) -> QueryResult<()> {
    //     Ok(())
    // } // what is the use case?
}
