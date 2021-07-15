mod basic;
pub mod hashes;
pub mod network;
pub mod queries;
pub mod smart_contracts;
pub mod transactions;

use crate::constants::*;
pub use crate::generated_types::PeerStatsResponse;
pub use basic::*;
use crypto_common::{
    derive::Serial,
    types::{Amount, CredentialIndex, Timestamp, TransactionTime},
    Buffer, Deserial, Get, ParseResult, SerdeDeserialize, SerdeSerialize, Serial, Versioned,
};
use id::{
    constants::ArCurve,
    ffi::AttributeKind,
    types::{AccountAddress, AccountCredentialWithoutProofs},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    marker::PhantomData,
};

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// The state of the encrypted balance of an account.
pub struct AccountEncryptedAmount {
    /// Encrypted amount that is a result of this accounts' actions.
    /// In particular this list includes the aggregate of
    ///
    /// - remaining amounts that result when transfering to public balance
    /// - remaining amounts when transfering to another account
    /// - encrypted amounts that are transferred from public balance
    ///
    /// When a transfer is made all of these must always be used.
    pub self_amount:       encrypted_transfers::types::EncryptedAmount<ArCurve>,
    /// Starting index for incoming encrypted amounts. If an aggregated amount
    /// is present then this index is associated with such an amount and the
    /// list of incoming encrypted amounts starts at the index `start_index
    /// + 1`.
    pub start_index:       u64,
    #[serde(default)]
    /// If 'Some', the amount that has resulted from aggregating other amounts
    /// and the number of aggregated amounts (must be at least 2 if
    /// present).
    pub aggregated_amount: Option<(encrypted_transfers::types::EncryptedAmount<ArCurve>, u32)>,
    /// Amounts starting at `start_index` (or at `start_index + 1` if there is
    /// an aggregated amount present). They are assumed to be numbered
    /// sequentially. The length of this list is bounded by the maximum number
    /// of incoming amounts on the accounts, which is currently 32. After
    /// that aggregation kicks in.
    pub incoming_amounts:  Vec<encrypted_transfers::types::EncryptedAmount<ArCurve>>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// State of the account's release schedule. This is the balance of the account
/// that is owned by the account, but cannot be used until the release point.
pub struct AccountReleaseSchedule {
    /// Total amount that is locked up in releases.
    pub total:    Amount,
    /// List of timestamped releases. In increasing order of timestamps.
    pub schedule: Vec<Release>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// An individual release of a locked balance.
pub struct Release {
    #[serde(with = "crate::internal::timestamp_millis")]
    /// Effective time of release.
    pub timestamp:    chrono::DateTime<chrono::Utc>,
    /// Amount to be released.
    pub amount:       Amount,
    /// List of transaction hashes that contribute a balance to this release.
    pub transactions: Vec<hashes::TransactionHash>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// Account information exposed via the node's API. This is always the state of
/// an account in a specific block.
pub struct AccountInfo {
    /// Next nonce to be used for transactions signed from this account.
    pub account_nonce:            Nonce,
    /// Current (unencrypted) balance of the account.
    pub account_amount:           Amount,
    /// Release schedule for any locked up amount. This could be an empty
    /// release schedule.
    pub account_release_schedule: AccountReleaseSchedule,
    /// Map of all currently active credentials on the account.
    /// This includes public keys that can sign for the given credentials, as
    /// well as any revealed attributes.
    pub account_credentials: std::collections::BTreeMap<
        CredentialIndex,
        Versioned<AccountCredentialWithoutProofs<ArCurve, AttributeKind>>,
    >,
    /// Lower bound on how many credentials must sign any given transaction from
    /// this account.
    pub account_threshold:        AccountThreshold,
    /// The encrypted balance of the account.
    pub account_encrypted_amount: AccountEncryptedAmount,
    /// The public key for sending encrypted balances to the account.
    pub account_encryption_key:   elgamal::PublicKey<ArCurve>,
    /// Internal index of the account. Accounts on the chain get sequential
    /// indices. These should generally not be used outside of the chain,
    /// the account address is meant to be used to refer to accounts,
    /// however the account index serves the role of the baker id, if the
    /// account is a baker. Hence it is exposed here as well.
    pub account_index:            AccountIndex,
    #[serde(default)]
    /// `Some` if and only if the account is a baker. In that case it is the
    /// information about the baker.
    pub account_baker:            Option<AccountBaker>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// Information about a baker.
pub struct AccountBaker {
    /// The baker's stake.
    pub staked_amount:                Amount,
    /// Whether the earnings from block, baker, and finalization rewards are
    /// automatically added to the baker's stake.
    pub restake_earnings:             bool,
    /// ID of the baker. This is the same as the index of the account.
    pub baker_id:                     BakerId,
    /// Baker's public key used to check whether they won the lottery or not.
    pub baker_election_verify_key:    BakerElectionVerifyKey,
    /// Baker's public key used to check that they are indeed the ones who
    /// produced the block.
    pub baker_signature_verify_key:   BakerSignVerifyKey,
    /// Baker's public key used to check signatures on finalization records.
    /// This is only used if the baker has sufficient stake to participate in
    /// finalization.
    pub baker_aggregation_verify_key: BakerAggregationVerifyKey,
    #[serde(default)]
    /// Any currently scheduled change in the baker. This is only present if
    /// the baker is being removed, or its stake is being lowered.
    pub pending_change:               Option<BakerPendingChange>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// The state of consensus parameters, and allowed participants (i.e., bakers).
pub struct BirkParameters {
    /// Current election difficulty.
    pub election_difficulty: ElectionDifficulty,
    /// Leadership election nonce for the current epoch.
    pub election_nonce:      hashes::LeadershipElectionNonce,
    /// The list of active bakers.
    pub bakers:              Vec<BirkBaker>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// State of an individual baker.
pub struct BirkBaker {
    /// ID of the baker. Matches their account index.
    pub baker_id:            BakerId,
    /// The lottery power of the baker. This is the baker's stake relative to
    /// the total staked amount.
    pub baker_lottery_power: f64,
    /// Address of the account this baker is associated with.
    pub baker_account:       AccountAddress,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(tag = "pendingChange")]
/// Pending change in the baker's stake.
pub enum BakerPendingChange {
    #[serde(rename = "ReduceStake")]
    #[serde(rename_all = "camelCase")]
    /// The stake is being reduced. The new stake will take affect in the given
    /// epoch.
    ReduceStake { new_stake: Amount, epoch: Epoch },
    #[serde(rename = "ReduceStake")]
    #[serde(rename_all = "camelCase")]
    /// The baker will be removed at the end of the given epoch.
    RemoveBaker { epoch: Epoch },
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// Current balance statistics.
pub struct RewardsOverview {
    #[serde(with = "crate::internal::amounts_as_u64")]
    pub total_amount:                Amount,
    #[serde(with = "crate::internal::amounts_as_u64")]
    pub total_encrypted_amount:      Amount,
    #[serde(with = "crate::internal::amounts_as_u64")]
    pub baking_reward_account:       Amount,
    #[serde(with = "crate::internal::amounts_as_u64")]
    pub finalization_reward_account: Amount,
    #[serde(with = "crate::internal::amounts_as_u64")]
    pub gas_account:                 Amount,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
// Since all variants are fieldless, the default JSON serialization will convert
// all the variants to simple strings.
/// Enumeration of the types of updates that are possible.
pub enum UpdateType {
    /// Update the chain protocol
    UpdateProtocol,
    /// Update the election difficulty
    UpdateElectionDifficulty,
    /// Update the euro per energy exchange rate
    UpdateEuroPerEnergy,
    /// Update the microGTU per euro exchange rate
    UpdateMicroGTUPerEuro,
    /// Update the address of the foundation account
    UpdateFoundationAccount,
    /// Update the distribution of newly minted GTU
    UpdateMintDistribution,
    /// Update the distribution of transaction fees
    UpdateTransactionFeeDistribution,
    /// Update the GAS rewards
    UpdateGASRewards,
    /// Minimum amount to register as a baker
    UpdateBakerStakeThreshold,
    /// Add new anonymity revoker
    UpdateAddAnonymityRevoker,
    /// Add new identity provider
    UpdateAddIdentityProvider,
    /// Update the root keys
    UpdateRootKeys,
    /// Update the level 1 keys
    UpdateLevel1Keys,
    /// Update the level 2 keys
    UpdateLevel2Keys,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
// Since all variants are fieldless, the default JSON serialization will convert
// all the variants to simple strings.
/// Enumeration of the types of credentials.
pub enum CredentialType {
    /// Initial credential is a credential that is submitted by the identity
    /// provider on behalf of the user. There is only one initial credential
    /// per identity.
    Initial,
    /// A normal credential is one where the identity behind it is only known to
    /// the owner of the account, unless the anonymity revocation process was
    /// followed.
    Normal,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
// Since all variants are fieldless, the default JSON serialization will convert
// all the variants to simple strings.
/// Types of account transactions.
pub enum TransactionType {
    /// Deploy a Wasm module.
    DeployModule,
    /// Initialize a smart contract instance.
    InitContract,
    /// Update a smart contract instance.
    Update,
    /// Transfer GTU from an account to another.
    Transfer,
    /// Register an account as a baker.
    AddBaker,
    /// Remove an account as a baker.
    RemoveBaker,
    /// Update the staked amount.
    UpdateBakerStake,
    /// Update whether the baker automatically restakes earnings.
    UpdateBakerRestakeEarnings,
    /// Update baker keys
    UpdateBakerKeys,
    /// Update given credential keys
    UpdateCredentialKeys,
    /// Transfer encrypted amount.
    EncryptedAmountTransfer,
    /// Transfer from public to encrypted balance of the same account.
    TransferToEncrypted,
    /// Transfer from encrypted to public balance of the same account.
    TransferToPublic,
    /// Transfer a GTU with a release schedule.
    TransferWithSchedule,
    /// Update the account's credentials.
    UpdateCredentials,
    /// Register some data on the chain.
    RegisterData,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "type", content = "contents", rename_all = "camelCase")]
/// The type of the block item.
pub enum BlockItemType {
    #[serde(rename = "accountTransaction")]
    /// Account transactions are transactions that are signed by an account.
    /// Most transactions are account transactions.
    AccountTransaction(#[serde(default)] Option<TransactionType>),
    #[serde(rename = "credentialDeploymentTransaction")]
    /// Credential deployments that create accounts are special kinds of
    /// transactions. They are not signed by the account in the usual way,
    /// and they are not paid for directly by the sender.
    CredentialDeploymentTransaction(CredentialType),
    #[serde(rename = "updateTransaction")]
    /// Chain updates are signed by the governance keys. They affect the core
    /// parameters of the chain.
    UpdateTransaction(UpdateType),
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(tag = "status", content = "result", rename_all = "camelCase")]
/// Status of a transaction in a given block.
/// NB: If the transaction is committed or finalized, but not in the given
/// block, then the API response will be `QueryError::NotFound`, hence those
/// cases are not covered by this type.
pub enum TransactionStatusInBlock {
    /// Transaction is received, but is not in any blocks.
    Received,
    /// Transaction is finalized in a block, with the given outcome.
    Finalized(BlockItemSummary),
    /// Transaction is committed, but not yet finalized in a block, with the
    /// given outcome.
    Committed(BlockItemSummary),
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(tag = "status", content = "outcomes", rename_all = "camelCase")]
/// Status of a transaction known to the node.
pub enum TransactionStatus {
    /// Transaction is received, but not yet in any blocks.
    Received,
    /// Transaction is finalized in the given block, with the given summary.
    /// If the finalization committee is not corrupt then this will always
    /// be a singleton map.
    Finalized(BTreeMap<hashes::TransactionHash, BlockItemSummary>),
    /// Transaction is committed to one or more blocks. The outcomes are listed
    /// for each block. Note that in the vast majority of cases the outcome of a
    /// transaction should not be dependent on the block it is in, but this
    /// can in principle happen.
    Committed(BTreeMap<hashes::TransactionHash, BlockItemSummary>),
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "tag")]
/// In addition to the user initiated transactions the protocol generates some
/// events which are deemed "Special outcomes". These are rewards for running
/// the consensus and finalization protocols.
pub enum SpecialTransactionOutcome {
    #[serde(rename_all = "camelCase")]
    /// Reward issued to all the bakers at the end of an epoch for baking blocks
    /// in the epoch.
    BakingRewards {
        #[serde(with = "crate::internal::account_amounts")]
        baker_rewards: BTreeMap<AccountAddress, Amount>,
        /// Remaining balance of the baking account. This will be transfered to
        /// the next epoch's reward account. It exists since it is not possible
        /// to perfectly distribute the accumulated rewards. The reason this is
        /// not possible is that amounts are integers.
        remainder:     Amount,
    },
    #[serde(rename_all = "camelCase")]
    /// Distribution of newly minted GTU.
    Mint {
        /// The portion of the newly minted GTU that goes to the baking reward
        /// account.
        mint_baking_reward:               Amount,
        /// The portion that goes to the finalization reward account.
        mint_finalization_reward:         Amount,
        /// The portion that goes to the foundation, as foundation tax.
        mint_platform_development_charge: Amount,
        /// The address of the foundation account that the newly minted GTU goes
        /// to.
        foundation_account:               AccountAddress,
    },
    #[serde(rename_all = "camelCase")]
    /// Distribution of finalization rewards.
    FinalizationRewards {
        #[serde(with = "crate::internal::account_amounts")]
        finalization_rewards: BTreeMap<AccountAddress, Amount>,
        /// Remaining balance of the finalization reward account. It exists
        /// since it is not possible to perfectly distribute the
        /// accumulated rewards. The reason this is not possible is that
        /// amounts are integers.
        remainder:            Amount,
    },
    #[serde(rename_all = "camelCase")]
    /// Reward for including transactions in a block.
    BlockReward {
        /// Total amount of transaction fees in the block.
        transaction_fees:   Amount,
        #[serde(rename = "oldGASAccount")]
        /// Previous balance of the GAS account.
        old_gas_account:    Amount,
        #[serde(rename = "newGASAccount")]
        /// New balance of the GAS account.
        new_gas_account:    Amount,
        /// The amount of GTU that goes to the baker.
        baker_reward:       Amount,
        /// The amount of GTU that goes to the foundation.
        foundation_charge:  Amount,
        /// The account address where the baker receives the reward.
        baker:              AccountAddress,
        /// The account address where the foundation receives the tax.
        foundation_account: AccountAddress,
    },
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlockSummary {
    transaction_summaries: Vec<BlockItemSummary>,
    special_events:        Vec<SpecialTransactionOutcome>,
    updates:               Updates, // FIXME: Add the finalization data.
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Summary of the outcome of a block item.
pub struct BlockItemSummary {
    #[serde(default)]
    /// Sender, if available. The sender is always available for account
    /// transactions.
    // FIXME: Restructure this type to make the impossible states unrepresentable.
    pub sender:       Option<AccountAddress>,
    /// Hash of the transaction.
    pub hash:         hashes::TransactionHash,
    /// The amount of GTU the transaction was charged to the sender.
    pub cost:         Amount,
    /// The amount of NRG the transaction cost.
    pub energy_cost:  Energy,
    #[serde(rename = "type")]
    /// Which type of block item this is.
    pub summary_type: BlockItemType,
    /// What is the outcome of this particular block item.
    pub result:       BlockItemResult,
    /// Index of the transaction in the block where it is included.
    pub index:        TransactionIndex,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "outcome", rename_all = "camelCase")]
/// Outcome of a block item execution.
pub enum BlockItemResult {
    /// The intended action was completed. The sender was charged, if
    /// applicable. Some events were generated describing the changes that
    /// happened on the chain.
    Success { events: Vec<Event> },
    #[serde(rename_all = "camelCase")]
    /// The intended action was not completed due to an error. The sender was
    /// charged, but no other effect is seen on the chain.
    Reject { reject_reason: Box<RejectReason> },
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Event generated when an account receives a new encrypted amount.
pub struct NewEncryptedAmountEvent {
    /// The account onto which the amount was added.
    account:          AccountAddress,
    /// The index the amount was assigned.
    new_index:        encrypted_transfers::types::EncryptedAmountIndex,
    /// The encrypted amount that was added.
    encrypted_amount: encrypted_transfers::types::EncryptedAmount<id::constants::ArCurve>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Event generated when one or more encrypted amounts are consumed from the
/// account.
pub struct EncryptedAmountRemovedEvent {
    /// The affected account.
    account:      AccountAddress,
    /// The new self encrypted amount on the affected account.
    new_amount:   encrypted_transfers::types::EncryptedAmount<id::constants::ArCurve>,
    /// The input encrypted amount that was removed.
    input_amount: encrypted_transfers::types::EncryptedAmount<id::constants::ArCurve>,
    /// The index indicating which amounts were used.
    up_to_index:  encrypted_transfers::types::EncryptedAmountAggIndex,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BakerAddedEvent {
    #[serde(flatten)]
    /// The keys with which the baker registered.
    keys_event:       BakerKeysEvent,
    /// The amount the account staked to become a baker. This amount is
    /// locked.
    stake:            Amount,
    /// Whether the baker will automatically add earnings to their stake or
    /// not.
    restake_earnings: bool,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BakerKeysEvent {
    baker_id:        BakerId,
    account:         AccountAddress,
    sign_key:        BakerSignVerifyKey,
    election_key:    BakerElectionVerifyKey,
    aggregation_key: BakerAggregationVerifyKey,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedSelfAmountAddedEvent {
    /// The affected account.
    account:    AccountAddress,
    /// The new self encrypted amount of the account.
    new_amount: encrypted_transfers::types::EncryptedAmount<id::constants::ArCurve>,
    /// The amount that was transferred from public to encrypted balance.
    amount:     Amount,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "tag")]
/// An event describing the changes that occurred to the state of the chain.
pub enum Event {
    /// A smart contract module was successfully deployed.
    ModuleDeployed {
        #[serde(rename = "contents")]
        module_ref: smart_contracts::ModuleRef,
    },
    /// A new smart contract instance was created.
    #[serde(rename_all = "camelCase")]
    ContractInitialized {
        #[serde(rename = "ref")]
        /// Module with the source code of the contract.
        origin_ref: smart_contracts::ModuleRef,
        /// The newly assigned address of the contract.
        address:    ContractAddress,
        /// The amount the instance was initialized with.
        amount:     Amount,
        /// The name of the contract.
        init_name:  smart_contracts::InitName,
        /// Any contract events that might have been generated by the contract
        /// initialization.
        events:     Vec<smart_contracts::ContractEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// A smart contract instance was updated.
    Updated {
        address:      ContractAddress,
        /// The origin of the message to the smart contract. This can be either
        /// an account or a smart contract.
        instigator:   Address,
        /// The amount the method was invoked with.
        amount:       Amount,
        /// The message passed to method.
        message:      smart_contracts::Parameter,
        /// The name of the method that was executed.
        receive_name: smart_contracts::ReceiveName,
        /// Any contract events that might have been generated by the contract
        /// execution.
        events:       Vec<smart_contracts::ContractEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// An amount of GTU was transferred.
    Transferred {
        /// Sender, either smart contract instance or account.
        from:   Address,
        /// Amount that was transferred.
        amount: Amount,
        /// Receiver. This will currently always be an account. Transferring to
        /// a smart contract is always an update.
        to:     Address,
    },
    /// An account with the given address was created.
    AccountCreated { contents: AccountAddress },
    #[serde(rename_all = "camelCase")]
    /// A new credential with the given ID was deployed onto an account.
    /// This is used only when a new account is created. See
    /// [Event::CredentialsUpdated] for when an existing account's
    /// credentials are updated.
    CredentialDeployed {
        reg_id:  CredentialRegistrationID,
        account: AccountAddress,
    },
    /// A new baker was registered, with the given ID and keys.
    BakerAdded {
        #[serde(flatten)]
        data: Box<BakerAddedEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// A baker was scheduled to be removed.
    BakerRemoved {
        baker_id: BakerId,
        account:  AccountAddress,
    },
    #[serde(rename_all = "camelCase")]
    /// A baker's stake was increased. This has effect immediately.
    BakerStakeIncreased {
        baker_id:  BakerId,
        account:   AccountAddress,
        new_stake: Amount,
    },
    #[serde(rename_all = "camelCase")]
    /// A baker's stake was scheduled to be decreased. This will have an effect
    /// on the stake after a number of epochs, controlled by the baker
    /// cooldown period.
    BakerStakeDecreased {
        baker_id:  BakerId,
        account:   AccountAddress,
        new_stake: Amount,
    },
    #[serde(rename_all = "camelCase")]
    /// The setting for whether rewards are added to stake immediately or not
    /// was changed to the given value.
    BakerSetRestakeEarnings {
        baker_id:         BakerId,
        account:          AccountAddress,
        /// The new value of the flag.
        restake_earnings: bool,
    },
    /// The baker keys were updated. The new keys are listed.
    BakerKeysUpdated {
        #[serde(flatten)]
        data: Box<BakerKeysEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// Keys of the given credential were updated.
    CredentialKeysUpdated { cred_id: CredentialRegistrationID },
    #[serde(rename_all = "camelCase")]
    /// A new encrypted amount was added to the account.
    NewEncryptedAmount {
        #[serde(flatten)]
        data: Box<NewEncryptedAmountEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// One or more encrypted amounts were removed from an account as part of a
    /// transfer or decryption.
    EncryptedAmountsRemoved {
        #[serde(flatten)]
        data: Box<EncryptedAmountRemovedEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// The public balance of the account was increased via a transfer from
    /// encrypted to public balance.
    AmountAddedByDecryption {
        account: AccountAddress,
        amount:  Amount,
    },
    /// The encrypted balance of the account was updated due to transfer from
    /// public to encrypted balance of the account.
    EncryptedSelfAmountAdded {
        #[serde(flatten)]
        data: Box<EncryptedSelfAmountAddedEvent>,
    },
    #[serde(rename_all = "camelCase")]
    /// An update was enqueued for the given time.
    UpdateEnqueued {
        effective_time: TransactionTime,
        payload:        UpdatePayload,
    },
    #[serde(rename_all = "camelCase")]
    /// A transfer with schedule was enqueued.
    TransferredWithSchedule {
        /// Sender account.
        from:   AccountAddress,
        /// Receiver account.
        to:     AccountAddress,
        /// The list of releases. Ordered by increasing timestamp.
        amount: Vec<(Timestamp, Amount)>,
    },
    #[serde(rename_all = "camelCase")]
    /// The credentials of the account were updated. Either added, removed, or
    /// both.
    CredentialsUpdated {
        /// The affected account.
        account:          AccountAddress,
        /// The credential ids that were added.
        new_cred_ids:     Vec<CredentialRegistrationID>,
        /// The credentials that were removed.
        removed_cred_ids: Vec<CredentialRegistrationID>,
        /// The (possibly) updated account threshold.
        new_threshold:    AccountThreshold,
    },
    #[serde(rename_all = "camelCase")]
    /// Data was registered.
    DataRegistered { data: RegisteredData },
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "updateType", content = "update")]
/// The type of an update payload.
pub enum UpdatePayload {
    #[serde(rename = "protocol")]
    Protocol(ProtocolUpdate),
    #[serde(rename = "electionDifficulty")]
    ElectionDifficulty(ElectionDifficulty),
    #[serde(rename = "euroPerEnergy")]
    EuroPerEnergy(ExchangeRate),
    #[serde(rename = "microGTUPerEuro")]
    MicroGTUPerEuro(ExchangeRate),
    #[serde(rename = "foundationAccount")]
    FoundationAccount(AccountAddress),
    #[serde(rename = "mintDistribution")]
    MintDistribution(MintDistribution),
    #[serde(rename = "transactionFeeDistribution")]
    TransactionFeeDistribution(TransactionFeeDistribution),
    #[serde(rename = "gASRewards")]
    GASRewards(GASRewards),
    #[serde(rename = "bakerStakeThreshold")]
    BakerStakeThreshold(Amount),
    #[serde(rename = "root")]
    Root(RootUpdate),
    #[serde(rename = "level1")]
    Level1(Level1Update),
    #[serde(rename = "addAnonymityRevoker")]
    AddAnonymityRevoker(Box<id::types::ArInfo<id::constants::ArCurve>>),
    #[serde(rename = "addIdentityProvider")]
    AddIdentityProvider(Box<id::types::IpInfo<id::constants::IpPairing>>),
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// A generic protocol update. This is essentially an announcement of the
/// update. The details of the update will be communicated in some off-chain
/// way, and bakers will need to update their node software to support the
/// update.
pub struct ProtocolUpdate {
    message: String,
    #[serde(rename = "specificationURL")]
    specification_url: String,
    specification_hash: hashes::Hash,
    #[serde(with = "crate::internal::byte_array_hex")]
    specification_auxiliary_data: Vec<u8>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(try_from = "transaction_fee_distribution::TransactionFeeDistributionUnchecked")]
/// Update the transaction fee distribution to the specified value.
pub struct TransactionFeeDistribution {
    /// The fraction that goes to the baker of the block.
    baker:       RewardFraction,
    /// The fraction that goes to the gas account. The remaining fraction will
    /// go to the foundation.
    gas_account: RewardFraction,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// The reward fractions related to the gas account and inclusion of special
/// transactions.
pub struct GASRewards {
    /// `BakerPrevTransFrac`: fraction of the previous gas account paid to the
    /// baker.
    baker:              RewardFraction,
    /// `FeeAddFinalisationProof`: fraction paid for including a finalization
    /// proof in a block.
    finalization_proof: RewardFraction,
    /// `FeeAccountCreation`: fraction paid for including each account creation
    /// transaction in a block.
    account_creation:   RewardFraction,
    /// `FeeUpdate`: fraction paid for including an update transaction in a
    /// block.
    chain_update:       RewardFraction,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(tag = "typeOfUpdate", content = "updatePayload")]
#[serde(rename_all = "camelCase")]
/// An update with root keys of some other set of governance keys, or the root
/// keys themselves. Each update is a separate transaction.
pub enum RootUpdate {
    RootKeysUpdate(HigherLevelAccessStructure<RootKeysKind>),
    Level1KeysUpdate(HigherLevelAccessStructure<Level1KeysKind>),
    Level2KeysUpdate(Box<Authorizations>),
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(tag = "typeOfUpdate", content = "updatePayload")]
#[serde(rename_all = "camelCase")]
/// An update with level 1 keys of either level 1 or level 2 keys. Each of the
/// updates must be a separate transaction.
pub enum Level1Update {
    Level1KeysUpdate(HigherLevelAccessStructure<Level1KeysKind>),
    Level2KeysUpdate(Box<Authorizations>),
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[doc(hidden)]
/// A tag for added type safety when using HigherLevelKeys.
/// This type deliberately has no values. It is meant to exist purely as a
/// type-level marker.
pub enum RootKeysKind {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[doc(hidden)]
/// A tag for added type safety when using HigherLevelKeys.
/// This type deliberately has no values. It is meant to exist purely as a
/// type-level marker.
pub enum Level1KeysKind {}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "Kind: Sized")]
/// Either root, level1, or level 2 access structure. They all have the same
/// structure, keys and a threshold. The phantom type parameter is used for
/// added type safety to distinguish different access structures in different
/// contexts.
pub struct HigherLevelAccessStructure<Kind> {
    pub keys:      Vec<UpdatePublicKey>,
    pub threshold: UpdateKeysThreshold,
    #[serde(skip)] // use default when deserializing
    pub _phantom:  PhantomData<Kind>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// And access structure for performing chain updates. The access structure is
/// only meaningful in the context of a list of update keys to which the indices
/// refer to.
pub struct AccessStructure {
    pub authorized_keys: BTreeSet<UpdateKeysIndex>,
    pub threshold:       UpdateKeysThreshold,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Access structures for each of the different possible chain updates, togehter
/// with the context giving all the possible keys.
pub struct Authorizations {
    /// The list of all keys that are currently authorized to perform updates.
    pub keys: Vec<UpdatePublicKey>,
    /// Access structure for emergency updates.
    pub emergency: AccessStructure,
    /// Access structure for protocol updates.
    pub protocol: AccessStructure,
    /// Access structure for updating the election difficulty.
    pub election_difficulty: AccessStructure,
    /// Access structure for updating the euro to energy exchange rate.
    pub euro_per_energy: AccessStructure,
    #[serde(rename = "microGTUPerEuro")]
    /// Access structure for updating the microgtu per euro exchange rate.
    pub micro_gtu_per_euro: AccessStructure,
    /// Access structure for updating the foundation account address.
    pub foundation_account: AccessStructure,
    /// Access structure for updating the mint distribution parameters.
    pub mint_distribution: AccessStructure,
    /// Access structure for updating the transaction fee distribution.
    pub transaction_fee_distribution: AccessStructure,
    #[serde(rename = "paramGASRewards")]
    /// Access structure for updating the gas reward distribution parameters.
    pub param_gas_rewards: AccessStructure,
    /// Access structure for updating the baker stake threshold.
    pub baker_stake_threshold: AccessStructure,
    /// Access structure for adding new anonymity revokers.
    pub add_anonymity_revoker: AccessStructure,
    /// Access structure for adding new identity providers.
    pub add_identity_provider: AccessStructure,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone)]
#[serde(transparent)]
/// A data that was registered on the chain.
pub struct RegisteredData {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 2]
    bytes: Vec<u8>,
}

impl Deserial for RegisteredData {
    fn deserial<R: crypto_common::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        anyhow::ensure!(
            usize::from(len) <= MAX_REGISTERED_DATA_SIZE,
            "Data too big to register."
        );
        let bytes = crypto_common::deserial_bytes(source, len.into())?;
        Ok(RegisteredData { bytes })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// The current collection of keys allowd to do updates.
pub struct UpdateKeysCollection {
    root_keys:    HigherLevelAccessStructure<RootKeysKind>,
    #[serde(rename = "level1Keys")]
    level_1_keys: HigherLevelAccessStructure<Level1KeysKind>,
    #[serde(rename = "level2Keys")]
    level_2_keys: Authorizations,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Values of chain parameters that can be updated via chain updates.
pub struct ChainParameters {
    /// Election difficulty for consensus lottery.
    pub election_difficulty:          ElectionDifficulty,
    /// Euro per energy exchange rate.
    pub euro_per_energy:              ExchangeRate,
    #[serde(rename = "microGTUPerEuro")]
    /// Micro gtu per euro exchange rate.
    pub micro_gtu_per_euro:           ExchangeRate,
    /// Extra number of epochs before reduction in stake, or baker
    /// deregistration is completed.
    pub baker_cooldown_epochs:        Epoch,
    /// The limit for the number of account creations in a block.
    pub account_creation_limit:       CredentialsPerBlockLimit,
    /// Current reward parameters.
    pub reward_parameters:            RewardParameters,
    /// Index of the foundation account.
    pub foundation_account_index:     AccountIndex,
    /// Minimum threshold for becoming a baker.
    pub minimum_threshold_for_baking: Amount,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Values of reward parameters.
pub struct RewardParameters {
    pub mint_distribution:            MintDistribution,
    pub transaction_fee_distribution: TransactionFeeDistribution,
    #[serde(rename = "gASRewards")]
    pub gas_rewards:                  GASRewards,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
/// A scheduled update of a given type.
pub struct ScheduledUpdate<T> {
    pub effective_time: TransactionTime,
    pub update:         T,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// A queue of updates of a given type.
pub struct UpdateQueue<T> {
    /// Next available sequence number for the update type.
    pub next_sequence_number: UpdateSequenceNumber,
    /// Queue of updates, ordered by effective time.
    pub queue:                Vec<ScheduledUpdate<T>>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PendingUpdates {
    pub root_keys:                    UpdateQueue<HigherLevelAccessStructure<RootKeysKind>>,
    pub level_1_keys:                 UpdateQueue<HigherLevelAccessStructure<Level1KeysKind>>,
    pub level_2_keys:                 UpdateQueue<Authorizations>,
    pub protocol:                     UpdateQueue<ProtocolUpdate>,
    pub election_difficulty:          UpdateQueue<ElectionDifficulty>,
    pub euro_per_energy:              UpdateQueue<ExchangeRate>,
    #[serde(rename = "microGTUPerEuro")]
    pub micro_gtu_per_euro:           UpdateQueue<ExchangeRate>,
    pub foundation_account:           UpdateQueue<AccountIndex>,
    pub mint_distribution:            UpdateQueue<MintDistribution>,
    pub transaction_fee_distribution: UpdateQueue<TransactionFeeDistribution>,
    pub gas_rewards:                  UpdateQueue<GASRewards>,
    pub baker_stake_threshold:        UpdateQueue<Amount>,
    pub add_anonymity_revoker:        UpdateQueue<id::types::ArInfo<id::constants::ArCurve>>,
    pub add_identity_provider:        UpdateQueue<id::types::IpInfo<id::constants::IpPairing>>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// State of updates. This includes current values of parameters as well as any
/// scheduled updates.
pub struct Updates {
    /// Keys allowed to perform updates.
    pub keys:             UpdateKeysCollection,
    #[serde(default)]
    /// Possibly pending protocol update.
    pub protocol_update:  Option<ProtocolUpdate>,
    /// Values of chain parameters.
    pub chain_parameters: ChainParameters,
    /// Any scheduled updates.
    pub update_queues:    PendingUpdates,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "tag")]
/// A reason for why a transaction was rejected. Rejected means included in a
/// block, but the desired action was not achieved. The only effect of a
/// rejected transaction is payment.
///
/// NOTE: Some of the variant definitions can look peculiar, but they are
/// made to be compatible with the serialization of the Haskell datatype.
pub enum RejectReason {
    /// Error raised when validating the Wasm module.
    ModuleNotWF,
    /// As the name says.
    ModuleHashAlreadyExists {
        contents: smart_contracts::ModuleRef,
    },
    /// Account does not exist.
    InvalidAccountReference { contents: AccountAddress },
    /// Reference to a non-existing contract init method.
    InvalidInitMethod {
        contents: (smart_contracts::ModuleRef, smart_contracts::InitName),
    },
    /// Reference to a non-existing contract receive method.
    InvalidReceiveMethod {
        contents: (smart_contracts::ModuleRef, smart_contracts::ReceiveName),
    },
    /// Reference to a non-existing module.
    InvalidModuleReference {
        contents: smart_contracts::ModuleRef,
    },
    /// Contract instance does not exist.
    InvalidContractAddress { contents: ContractAddress },
    /// Runtime exception occurred when running either the init or receive
    /// method.
    RuntimeFailure,
    /// When one wishes to transfer an amount from A to B but there
    /// are not enough funds on account/contract A to make this
    /// possible. The data are the from address and the amount to transfer.
    AmountTooLarge { contents: (Address, Amount) },
    /// Serialization of the body failed.
    SerializationFailure,
    /// We ran of out energy to process this transaction.
    OutOfEnergy,
    /// Rejected due to contract logic in init function of a contract.
    #[serde(rename_all = "camelCase")]
    RejectedInit { reject_reason: i32 },
    #[serde(rename_all = "camelCase")]
    RejectedReceive {
        reject_reason:    i32,
        contract_address: ContractAddress,
        receive_name:     smart_contracts::ReceiveName,
        parameter:        smart_contracts::Parameter,
    },
    /// Reward account desired by the baker does not exist.   
    NonExistentRewardAccount { contents: AccountAddress },
    /// Proof that the baker owns relevant private keys is not valid.
    InvalidProof,
    /// Tried to add baker for an account that already has a baker
    AlreadyABaker { contents: BakerId },
    /// Tried to remove a baker for an account that has no baker
    NotABaker { contents: AccountAddress },
    /// The amount on the account was insufficient to cover the proposed stake
    InsufficientBalanceForBakerStake,
    /// The amount provided is under the threshold required for becoming a baker
    StakeUnderMinimumThresholdForBaking,
    /// The change could not be made because the baker is in cooldown for
    /// another change
    BakerInCooldown,
    /// A baker with the given aggregation key already exists
    DuplicateAggregationKey {
        contents: Box<BakerAggregationVerifyKey>,
    },
    /// Encountered credential ID that does not exist
    NonExistentCredentialID,
    /// Attempted to add an account key to a key index already in use
    KeyIndexAlreadyInUse,
    /// When the account threshold is updated, it must not exceed the amount of
    /// existing keys
    InvalidAccountThreshold,
    /// When the credential key threshold is updated, it must not exceed the
    /// amount of existing keys
    InvalidCredentialKeySignThreshold,
    /// Proof for an encrypted amount transfer did not validate.
    InvalidEncryptedAmountTransferProof,
    /// Proof for a secret to public transfer did not validate.
    InvalidTransferToPublicProof,
    /// Account tried to transfer an encrypted amount to itself, that's not
    /// allowed.
    EncryptedAmountSelfTransfer { contents: AccountAddress },
    /// The provided index is below the start index or above `startIndex +
    /// length incomingAmounts`
    InvalidIndexOnEncryptedTransfer,
    /// The transfer with schedule is going to send 0 tokens
    ZeroScheduledAmount,
    /// The transfer with schedule has a non strictly increasing schedule
    NonIncreasingSchedule,
    /// The first scheduled release in a transfer with schedule has already
    /// expired
    FirstScheduledReleaseExpired,
    /// Account tried to transfer with schedule to itself, that's not allowed.
    ScheduledSelfTransfer { contents: AccountAddress },
    /// At least one of the credentials was either malformed or its proof was
    /// incorrect.
    InvalidCredentials,
    /// Some of the credential IDs already exist or are duplicated in the
    /// transaction.
    DuplicateCredIDs {
        contents: Vec<CredentialRegistrationID>,
    },
    /// A credential id that was to be removed is not part of the account.
    NonExistentCredIDs {
        contents: Vec<CredentialRegistrationID>,
    },
    /// Attemp to remove the first credential
    RemoveFirstCredential,
    /// The credential holder of the keys to be updated did not sign the
    /// transaction
    CredentialHolderDidNotSign,
    /// Account is not allowed to have multiple credentials because it contains
    /// a non-zero encrypted transfer.
    NotAllowedMultipleCredentials,
    /// The account is not allowed to receive encrypted transfers because it has
    /// multiple credentials.
    NotAllowedToReceiveEncrypted,
    /// The account is not allowed to send encrypted transfers (or transfer
    /// from/to public to/from encrypted)
    NotAllowedToHandleEncrypted,
}

mod transaction_fee_distribution {
    use super::*;
    #[derive(SerdeDeserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TransactionFeeDistributionUnchecked {
        baker:       RewardFraction,
        gas_account: RewardFraction,
    }

    impl TryFrom<TransactionFeeDistributionUnchecked> for TransactionFeeDistribution {
        type Error = &'static str;

        fn try_from(value: TransactionFeeDistributionUnchecked) -> Result<Self, Self::Error> {
            if (value.baker + value.gas_account).is_some() {
                Ok(TransactionFeeDistribution {
                    baker:       value.baker,
                    gas_account: value.gas_account,
                })
            } else {
                Err("Transaction fee fractions exceed 100%.")
            }
        }
    }
}
