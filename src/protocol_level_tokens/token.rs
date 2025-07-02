use concordium_base::{
    common::{
        cbor::{CborSerializationError, CborSerialize},
        types::TransactionTime,
    },
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
        sender: AccountAddress,
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

        let transaction = send::token_update_operations(
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

        let transaction = send::token_update_operations(
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

        let transaction = send::token_update_operations(
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

        let transaction = send::token_update_operations(
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

        let transaction = send::token_update_operations(
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

        let transaction = send::token_update_operations(
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

        let transaction = send::token_update_operations(
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
    ) -> TokenResult<bool> {
        let decimals = self.info.token_state.decimals;

        // Validate all amounts
        if payload
            .iter()
            .any(|transfer| transfer.amount.decimals() != decimals)
        {
            return Ok(false);
        }

        // Check the sender ballance
        let sender_balance = self
            .balance_of(&sender.into(), None::<BlockIdentifier>)
            .await?
            .unwrap_or(TokenAmount::from_raw(0, decimals));

        let payload_total = TokenAmount::from_raw(
            payload.iter().fold(0u64, |acc, x| acc + x.amount.value()),
            decimals,
        );

        if payload_total > sender_balance {
            return Ok(false);
        }

        // Check if token has no allow and deny lists
        let module_state = self.info.token_state.decode_module_state()?;
        if !module_state.allow_list.is_none_or(|val| !val)
            && !module_state.deny_list.is_none_or(|val| !val)
        {
            return Ok(true);
        }

        // Check sender and recievers for allow and deny lists
        let mut addresses = Vec::with_capacity(payload.len() + 1);
        addresses.push(sender.clone().into());

        for p in payload {
            let concordium_base::protocol_level_tokens::CborTokenHolder::Account(holder) =
                p.recipient;
            addresses.push(holder.address.into());
        }

        let accounts = futures::future::join_all(addresses.into_iter().map(|address| {
            let mut client = self.client.clone();
            async move {
                client
                    .get_account_info(&address, BlockIdentifier::LastFinal)
                    .await
            }
        }))
        .await;

        for account in accounts {
            let account_info = account?.response;
            let token_state = match account_info
                .tokens
                .into_iter()
                .find(|t| t.token_id == self.info.token_id)
                .map(|t| t.state)
            {
                Some(state) => state,
                None => return Ok(false),
            };

            let module_state = token_state.decode_module_state()?;
            if module_state.allow_list.is_some_and(|val| !val)
                || module_state.deny_list.is_some_and(|val| val)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub async fn validate_governance_operation(&mut self, sender: AccountAddress) -> TokenResult<bool> {
        let governance_account = match self.info.token_state.decode_module_state()?.governance_account {
            concordium_base::protocol_level_tokens::CborTokenHolder::Account(holder) => holder.address,
        };
        Ok(governance_account == sender)
    }

    pub async fn send_raw(&self, _operations: Vec<&impl CborSerialize>) -> TokenResult<()> { 
        Ok(())
    }
}
