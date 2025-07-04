use concordium_base::{
    common::{cbor::CborSerializationError, types::TransactionTime},
    contracts_common::AccountAddress,
    hashes::TransactionHash,
    protocol_level_tokens::{
        operations, TokenAmount, TokenId, TokenOperations, TokenOperationsPayload, TokenTransfer,
    },
    transactions::{send, BlockItem},
};
use thiserror::Error;

use crate::{
    protocol_level_tokens::{CborTokenHolder, TokenInfo},
    types::{AccountInfo, WalletAccount},
    v2::{AccountIdentifier, BlockIdentifier, Client, IntoBlockIdentifier, QueryError, RPCError},
};

/// A wrapper around the gRPC client representing a PLT, which
/// provides functions for interaction with a specific PLT.
///
/// Note that cloning is cheap and is, therefore, the intended way of sharing
/// this type between multiple tasks.
#[derive(Debug)]
pub struct Token {
    /// an actual gRPC client used for fetching data.
    client:         Client,
    /// the state of the token upon initialization for this struct.
    info:           TokenInfo,
    /// default expiration period for transaction set to 5 minues.
    default_expiry: TransactionTime,
}

/// Options for the transfer.
pub struct TranferOptions {
    /// Whether to automatically scale a token amount to the correct number of
    /// decimals as the token.
    pub autoscale: Option<bool>,
    /// Whether to validate the payload before executing it.
    pub validate:  Option<bool>,
}

/// Options for supply update operations.
pub struct SupplyUpdateOptions {
    /// Whether to automatically scale a token amount to the correct number of
    /// decimals as the token.
    pub autoscale: Option<bool>,
    /// Whether to validate the payload before executing it.
    pub validate:  Option<bool>,
}

/// Options for allow and deny list update operations.
pub struct ListUpdateOptions {
    /// Whether to validate the payload before executing it.
    pub validate: Option<bool>,
}

impl Default for TranferOptions {
    fn default() -> Self {
        Self {
            autoscale: Some(true),
            validate:  Some(true),
        }
    }
}

impl Default for SupplyUpdateOptions {
    fn default() -> Self {
        Self {
            autoscale: Some(true),
            validate:  Some(true),
        }
    }
}

impl Default for ListUpdateOptions {
    fn default() -> Self {
        Self {
            validate: Some(true),
        }
    }
}

/// Enum used to represent account info source, who's balance needs to be found.
#[derive(derive_more::From)]
pub enum Account {
    /// An actual type used to find the account balance.
    Info(AccountInfo),
    /// Account identifier used to fetch the account info.
    Address(AccountIdentifier),
}

/// Result of a Token operation.
/// This is an alias for [std::Result](https://doc.rust-lang.org/std/result/enum.Result.html) that fixes the error type to be [`TokenError`].
pub type TokenResult<T> = Result<T, TokenError>;

/// Enum representing the types of errors that can occur when interacting with
/// PLT instances through the client.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Query error: {0}")]
    /// Errors that can occur when making queries.
    Query(#[from] QueryError),
    #[error("CBor serialization error: {0}")]
    /// Error that can occur during serializing or deserializing CBOR
    CberSeriazation(#[from] CborSerializationError),
    #[error("RPC error: {0}")]
    /// Error that can occur over RPC.
    RPC(#[from] RPCError),
    #[error("The token amount supplied cannot be represented as an amount of the token.")]
    /// Error type indicating the supplied token amount is not compatible with
    /// the token.
    InvalidTokenAmount,
    #[error("The sender has insufficient funds.")]
    /// Error representing an attempt to transfer tokens from an account that
    /// does not have enough tokens to cover the amount.
    InsufficientFunds,
    #[error(
        "Transfering funds from or to the account is currently not allowed because of the \
         allow/deny list."
    )]
    /// Error representing an attempt transfer funds to an account which is
    /// either not on the token allow list, or is on the token deny list
    NotAllowed,
    #[error("Unauthorized governance operation attempted")]
    /// Error type indicating an unauthorized governance operation was
    /// attempted.
    UnauthorizedGovernanceOperation,
    #[error("Invalid token ID in the provided payload.")]
    /// Error that indicates that provided payload for raw operations does not
    /// match with the client's token ID.
    InvalidTokenId,
    #[error("Total token amount in the payload exceeds total token supply.")]
    /// Error that indicates there is insufficient total token supply to burn
    /// the total amount in the payload.
    InsufficientSupply,
}

impl Token {
    /// Construct a [`Token`] from existing RPC client and [TokenInfo].
    /// Has a default transaction expiration time set to 5 minutes.
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node.
    /// * `info` - [`TokenInfo`] of an exiting PLT.
    pub fn new(client: Client, info: TokenInfo) -> Self {
        let default_expiry =
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
        Self {
            client,
            info,
            default_expiry,
        }
    }

    /// A helper methods for fetching the token info.
    pub fn token_info(&self) -> &TokenInfo { &self.info }

    /// Construct a [`Token`] by looking up metadata from the chain
    /// (such as the token info). Has a default transaction expiration time set
    /// to 5 minutes.
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node.
    /// * `token_id` - The ID of the token.
    pub async fn create(mut client: Client, token_id: TokenId) -> TokenResult<Self> {
        let info = client
            .get_token_info(token_id, BlockIdentifier::LastFinal)
            .await?
            .response;
        let default_expiry =
            TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);

        Ok(Self {
            client,
            info,
            default_expiry,
        })
    }

    /// Transfers tokens from the sender to the specified recipients.
    ///
    /// # Arguments
    ///
    /// * `signer` - A [`WalletAccount`] who's address is used as a sender and
    ///   keys as a signer.
    /// * `payload` - The transfer payload.
    /// * `expiry` - The optional expiry time for the transaction.
    /// * `opts` - Options for the transfer.
    pub async fn transfer(
        &mut self,
        signer: &WalletAccount,
        payload: Vec<TokenTransfer>,
        expiry: Option<TransactionTime>,
        opts: Option<TranferOptions>,
    ) -> TokenResult<TransactionHash> {
        let expiry = expiry.unwrap_or(self.default_expiry);
        let opts = opts.unwrap_or_default();

        if let Some(validate) = opts.validate {
            if validate {
                self.validate_transfer(signer.address, payload.clone())
                    .await?;
            }
        }

        let transactions = match opts.autoscale {
            Some(true) => self.scale_transfer_amounts(payload),
            Some(false) | None => Ok(payload),
        }?;

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operations: TokenOperations = transactions
            .into_iter()
            .map(|tr| {
                let CborTokenHolder::Account(receiver) = tr.recipient;
                match tr.memo {
                    Some(memo) => {
                        operations::transfer_tokens_with_memo(receiver.address, tr.amount, memo)
                    }
                    None => operations::transfer_tokens(receiver.address, tr.amount),
                }
            })
            .collect();

        let transaction = send::token_update_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            operations,
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    /// Mints a specified amount of tokens.
    ///
    /// # Arguments
    ///
    /// * `signer` - a [`WalletAccount`] who's address is used as a sender and
    ///   keys as a signer.
    /// * `amounts` - The amounts of tokens to mint.
    /// * `expiry` - The optional expiry time for the transaction.
    /// * `opts` - Options for supply update operations.
    pub async fn mint(
        &mut self,
        signer: &WalletAccount,
        amounts: Vec<TokenAmount>,
        expiry: Option<TransactionTime>,
        opts: Option<SupplyUpdateOptions>,
    ) -> TokenResult<TransactionHash> {
        let expiry = expiry.unwrap_or(self.default_expiry);
        let opts = opts.unwrap_or_default();

        if let Some(validate) = opts.validate {
            if validate {
                // check if the signer is authorized to mint tokens.
                self.validate_governance_operation(signer.address)?;

                // check if every amount ot be minted have the same decimals as the token.
                if amounts
                    .iter()
                    .any(|amount| amount.decimals() != self.info.token_state.decimals)
                {
                    return Err(TokenError::InvalidTokenAmount);
                }
            }
        }

        let amounts = match opts.autoscale {
            Some(true) => amounts
                .into_iter()
                .map(|amount| self.scale_amount(amount))
                .collect(),
            Some(false) | None => Ok(amounts),
        }?;

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operations = amounts
            .into_iter()
            .map(operations::mint_tokens)
            .collect();

        let transaction = send::token_update_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            operations,
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    /// Burns a specified amount of tokens.
    ///
    /// # Arguments
    ///
    /// * `signer` - A [`WalletAccount`] who's address is used as a sender and
    ///   keys as a signer.
    /// * `amount` - The amounts of tokens to burn.
    /// * `expiry` - The optional expiry time for the transaction.
    /// * `opts` - Options for supply update operations.
    pub async fn burn(
        &mut self,
        signer: &WalletAccount,
        amounts: Vec<TokenAmount>,
        expiry: Option<TransactionTime>,
        opts: Option<SupplyUpdateOptions>,
    ) -> TokenResult<TransactionHash> {
        let expiry = expiry.unwrap_or(self.default_expiry);
        let opts = opts.unwrap_or_default();

        if let Some(validate) = opts.validate {
            if validate {
                // check if the signer is authorized to burn tokens.
                self.validate_governance_operation(signer.address)?;

                // check if every amount ot be burned have the same decimals as the token.
                if amounts
                    .iter()
                    .any(|amount| amount.decimals() != self.info.token_state.decimals)
                {
                    return Err(TokenError::InvalidTokenAmount);
                }

                // check if total amount to burn exceeds total token supply
                let payload_total = TokenAmount::from_raw(
                    amounts.iter().fold(0u64, |acc, x| acc + x.value()),
                    self.info.token_state.decimals,
                );
                if self.info.token_state.total_supply.value() < payload_total.value() {
                    return Err(TokenError::InsufficientSupply);
                }
            }
        }

        let amounts = match opts.autoscale {
            Some(true) => amounts
                .into_iter()
                .map(|amount| self.scale_amount(amount))
                .collect(),
            Some(false) | None => Ok(amounts),
        }?;

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operations = amounts
            .into_iter()
            .map(operations::burn_tokens)
            .collect();
        let transaction = send::token_update_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            operations,
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    /// Adds accounts to the allow list of a token.
    ///
    /// # Arguments
    ///
    /// * `signer` - A [`WalletAccount`] who's address is used as a sender and
    ///   keys as a signer.
    /// * `targets` - The account addresses to be added to the allow list.
    /// * `expiry` - The optional expiry time for the transaction.
    /// * `opts` - Options for the list update operation.
    pub async fn add_allow_list(
        &mut self,
        signer: &WalletAccount,
        targets: Vec<AccountAddress>,
        expiry: Option<TransactionTime>,
        opts: Option<ListUpdateOptions>,
    ) -> TokenResult<TransactionHash> {
        let expiry = expiry.unwrap_or(self.default_expiry);
        let opts = opts.unwrap_or_default();

        if let Some(validate) = opts.validate {
            if validate {
                // check if the signer is authorized to add to token's allow list.
                self.validate_governance_operation(signer.address)?;
            }
        }

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operations = targets
            .into_iter()
            .map(operations::add_token_allow_list)
            .collect();

        let transaction = send::token_update_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            operations,
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    /// Removes an accounts from the allow list of a token.
    ///     
    /// # Arguments
    ///
    /// * `signer` - A [`WalletAccount`] who's address is used as a sender and
    ///   keys as a signer.
    /// * `targets` - The account addresses to be removed from the allow list.
    /// * `expiry` - The optional expiry time for the transaction.
    /// * `opts` - Options for the list update operation.
    pub async fn remove_allow_list(
        &mut self,
        signer: &WalletAccount,
        targets: Vec<AccountAddress>,
        expiry: Option<TransactionTime>,
        opts: Option<ListUpdateOptions>,
    ) -> TokenResult<TransactionHash> {
        let expiry = expiry.unwrap_or(self.default_expiry);
        let opts = opts.unwrap_or_default();

        if let Some(validate) = opts.validate {
            if validate {
                // check if the signer is authorized to remove from token's allow list.
                self.validate_governance_operation(signer.address)?;
            }
        }

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operations = targets
            .into_iter()
            .map(operations::remove_token_allow_list)
            .collect();

        let transaction = send::token_update_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            operations,
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    /// Adds an accounts to the deny list of a token.
    ///
    /// # Arguments
    ///
    /// * `signer` - A [`WalletAccount`] who's address is used as a sender and
    ///   keys as a signer.
    /// * `targets` - The account addresses to be added to the deny list.
    /// * `expiry` - The optional expiry time for the transaction.
    /// * `opts` - Options for the list update operation.
    pub async fn add_deny_list(
        &mut self,
        signer: &WalletAccount,
        targets: Vec<AccountAddress>,
        expiry: Option<TransactionTime>,
        opts: Option<ListUpdateOptions>,
    ) -> TokenResult<TransactionHash> {
        let expiry = expiry.unwrap_or(self.default_expiry);
        let opts = opts.unwrap_or_default();

        if let Some(validate) = opts.validate {
            if validate {
                // check if the signer is authorized to add to token's deny list.
                self.validate_governance_operation(signer.address)?;
            }
        }

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operations = targets
            .into_iter()
            .map(operations::add_token_deny_list)
            .collect();

        let transaction = send::token_update_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            operations,
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    /// Removes an accounts from the deny list of a token.
    ///
    /// # Arguments
    ///
    /// * `signer` - A [`WalletAccount`] who's address is used as a sender and
    ///   keys as a signer.
    /// * `targets` - The account addresses to be removed from the deny list.
    /// * `expiry` - The optional expiry time for the transaction.
    /// * `opts` - Options for the list update operation.
    pub async fn remove_deny_list(
        &mut self,
        signer: &WalletAccount,
        targets: Vec<AccountAddress>,
        expiry: Option<TransactionTime>,
        opts: Option<ListUpdateOptions>,
    ) -> TokenResult<TransactionHash> {
        let expiry = expiry.unwrap_or(self.default_expiry);
        let opts = opts.unwrap_or_default();

        if let Some(validate) = opts.validate {
            if validate {
                // check if the signer is authorized to remove from token's deny list.
                self.validate_governance_operation(signer.address)?;
            }
        }

        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let operations = targets
            .into_iter()
            .map(operations::remove_token_deny_list)
            .collect();

        let transaction = send::token_update_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            self.info.token_id.clone(),
            operations,
        )?;

        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    /// Retrieves the balance of a token for a given account.
    ///
    /// # Arguments
    ///
    /// * `acc` - The account who's balances must be fetched.
    /// * `bi` - The block identifier. Defaults to Last Final block, if
    ///   [`None`].
    pub async fn balance_of(
        &mut self,
        acc: &Account,
        bi: Option<impl IntoBlockIdentifier>,
    ) -> TokenResult<Option<TokenAmount>> {
        let info = match acc {
            Account::Info(info) => info,
            Account::Address(identifier) => {
                let bi = match bi {
                    Some(bi) => bi.into_block_identifier(),
                    None => BlockIdentifier::LastFinal,
                };
                &self.client.get_account_info(identifier, bi).await?.response
            }
        };
        Ok(self.ballance_from_account_info(info))
    }

    /// Helper method for retrieving the balance of [Token] held by an account .
    ///
    /// # Arguments
    ///
    /// * `info` - [AccountInfo] of the holder of the tokens (if any).
    fn ballance_from_account_info(&self, info: &AccountInfo) -> Option<TokenAmount> {
        info.tokens
            .iter()
            .find(|at| at.token_id == self.info.token_id)
            .map(|at| at.state.balance.to_owned())
    }

    /// Validates a token transfer.
    ///
    /// # Arguments
    ///
    /// * `sender` - The account address of the sender.
    /// * `payload` - The token transfers that are about to be sent.
    pub async fn validate_transfer(
        &mut self,
        sender: AccountAddress,
        payload: Vec<TokenTransfer>,
    ) -> TokenResult<()> {
        let decimals = self.info.token_state.decimals;

        // Validate all amounts
        if payload
            .iter()
            .any(|transfer| transfer.amount.decimals() != decimals)
        {
            return Err(TokenError::InvalidTokenAmount);
        }

        let sender_info = self
            .client
            .get_account_info(&sender.into(), BlockIdentifier::LastFinal)
            .await?
            .response;

        // Check the sender ballance
        let sender_balance = self
            .ballance_from_account_info(&sender_info)
            .unwrap_or(TokenAmount::from_raw(0, decimals));

        let payload_total = TokenAmount::from_raw(
            payload.iter().fold(0u64, |acc, x| acc + x.amount.value()),
            decimals,
        );

        if payload_total > sender_balance {
            return Err(TokenError::InsufficientFunds);
        }

        // Check if token has no allow and deny lists
        let module_state = self.info.token_state.decode_module_state()?;
        if module_state.allow_list.is_none_or(|val| !val)
            && module_state.deny_list.is_none_or(|val| !val)
        {
            return Ok(());
        }

        // Check sender and recievers for allow and deny lists
        let mut accounts = Vec::with_capacity(payload.len() + 1);
        accounts.push(sender_info);

        let futures = payload.into_iter().map(|transfer| {
            let CborTokenHolder::Account(holder) = transfer.recipient;
            let mut client = self.client.clone();
            async move {
                client
                    .get_account_info(&holder.address.into(), BlockIdentifier::LastFinal)
                    .await
            }
        });

        let recepients = futures::future::join_all(futures).await;
        for recepient in recepients {
            let info = recepient?.response;
            accounts.push(info);
        }

        for account in accounts {
            let token_state = match account
                .tokens
                .into_iter()
                .find(|t| t.token_id == self.info.token_id)
                .map(|t| t.state)
            {
                Some(state) => state,
                None => return Err(TokenError::NotAllowed),
            };

            let account_module_state = token_state.decode_module_state()?;
            if module_state.deny_list.is_some_and(|val| val)
                || module_state.deny_list.is_some_and(|val| val)
            {
                return Err(TokenError::NotAllowed);
            }

            if module_state.allow_list.is_some_and(|val| val)
                && !account_module_state.allow_list.is_some_and(|val| val)
            {
                return Err(TokenError::NotAllowed);
            }

        }
        Ok(())
    }

    /// Validates that the sender is authorized to perform governance operations
    /// on the token.
    ///
    /// # Arguments
    ///
    /// * `sender` - The account address of the sender.
    pub fn validate_governance_operation(&mut self, sender: AccountAddress) -> TokenResult<()> {
        let CborTokenHolder::Account(governance_account) = self
            .info
            .token_state
            .decode_module_state()?
            .governance_account;

        if governance_account.address != sender {
            return Err(TokenError::UnauthorizedGovernanceOperation);
        }

        Ok(())
    }

    /// Initiates a transaction for a given token.
    ///
    /// This function creates and sends a transaction of type `TokenUpdate` for
    /// the specified token.
    ///
    /// # Arguments
    ///
    /// * `signer` - A [`WalletAccount`] who's address is used as a sender and
    ///   keys as a signer.
    /// * `expiry` - The optional expiry time for the transaction.
    /// * `payload` - The transaction payload.
    pub async fn send_raw(
        &mut self,
        signer: &WalletAccount,
        expiry: Option<TransactionTime>,
        payload: TokenOperationsPayload,
    ) -> TokenResult<TransactionHash> {
        let expiry = expiry.unwrap_or(self.default_expiry);
        let nonce = self
            .client
            .get_next_account_sequence_number(&signer.address)
            .await?
            .nonce;

        let token_id = payload.token_id.clone();
        if token_id != self.info.token_id {
            return Err(TokenError::InvalidTokenId);
        }

        let operations = payload.decode_operations()?;
        let transaction = send::token_update_operations(
            &signer,
            signer.address,
            nonce,
            expiry,
            token_id,
            operations,
        )?;
        let block_item = BlockItem::AccountTransaction(transaction);
        Ok(self.client.send_block_item(&block_item).await?)
    }

    /// Scales a token amount with fewer decimals to the token's decimal
    /// representation.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount to scale.
    fn scale_amount(&self, amount: TokenAmount) -> TokenResult<TokenAmount> {
        let token_decimals = self.info.token_state.decimals;

        if token_decimals == amount.decimals() {
            return Ok(amount);
        }

        if token_decimals < amount.decimals() {
            return Err(TokenError::InvalidTokenAmount);
        }
        let power = 10u64
            .checked_pow((token_decimals - amount.decimals()).into())
            .ok_or(TokenError::InvalidTokenAmount)?;
        let value = amount
            .value()
            .checked_mul(power)
            .ok_or(TokenError::InvalidTokenAmount)?;

        Ok(TokenAmount::from_raw(value, token_decimals))
    }

    /// A helper method to scale [`TokenAmount`]s inside [`TokenTransfer`]s.
    ///
    /// # Arguments
    ///
    /// * `transfers` - token transfers whos amounts must be scaled.
    fn scale_transfer_amounts(
        &self,
        transfers: Vec<TokenTransfer>,
    ) -> TokenResult<Vec<TokenTransfer>> {
        transfers
            .into_iter()
            .map(|transfer| {
                let amount = self.scale_amount(transfer.amount)?;
                Ok(TokenTransfer { amount, ..transfer })
            })
            .collect()
    }
}
