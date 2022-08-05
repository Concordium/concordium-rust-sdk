mod basic;
pub mod hashes;
pub mod network;
pub mod queries;
pub mod smart_contracts;
mod summary_helper;
pub mod transactions;

use crate::constants::*;
pub use crate::generated_types::PeerStatsResponse;
pub use basic::*;
use crypto_common::{
    derive::{Serial, Serialize},
    deserial_bytes, deserial_set_no_length, deserial_string, deserial_vector_no_length,
    types::{Amount, CredentialIndex, Timestamp, TransactionTime},
    Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
    Versioned,
};
use derive_more::*;
use id::{
    constants::{ArCurve, AttributeKind},
    elgamal,
    types::{AccountAddress, AccountCredentialWithoutProofs},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    convert::TryFrom,
    io::Read,
    marker::PhantomData,
};
use thiserror::Error;

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
    /// If ['Some'], the amount that has resulted from aggregating other amounts
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Information about a baker.
pub struct BakerInfo {
    /// Identity of the baker. This is actually the account index of
    /// the account controlling the baker.
    pub baker_id:                     BakerId,
    /// Baker's public key used to check whether they won the lottery or not.
    pub baker_election_verify_key:    BakerElectionVerifyKey,
    /// Baker's public key used to check that they are indeed the ones who
    /// produced the block.
    pub baker_signature_verify_key:   BakerSignatureVerifyKey,
    /// Baker's public key used to check signatures on finalization records.
    /// This is only used if the baker has sufficient stake to participate in
    /// finalization.
    pub baker_aggregation_verify_key: BakerAggregationVerifyKey,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(untagged)]
pub enum AccountStakingInfo {
    #[serde(rename_all = "camelCase")]
    /// The account is a baker.
    Baker {
        staked_amount:    Amount,
        restake_earnings: bool,
        #[serde(flatten)]
        baker_info:       BakerInfo,
        pending_change:   Option<StakePendingChange>,
        pool_info:        Option<BakerPoolInfo>,
    },
    /// The account is delegating stake to a baker.
    #[serde(rename_all = "camelCase")]
    Delegated {
        staked_amount:     Amount,
        restake_earnings:  bool,
        delegation_target: DelegationTarget,
        pending_change:    Option<StakePendingChange>,
    },
}

impl AccountStakingInfo {
    /// Return the amount that is staked, either as a baker or delegator.
    pub fn staked_amount(&self) -> Amount {
        match self {
            AccountStakingInfo::Baker { staked_amount, .. } => *staked_amount,
            AccountStakingInfo::Delegated { staked_amount, .. } => *staked_amount,
        }
    }
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
    /// well as any revealed attributes. This map always contains a credential
    /// with index 0.
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
    /// `Some` if and only if the account is a baker or delegator. In that case
    /// it is the information about the baker or delegator.
    // this is a bit of a hacky way of JSON parsing, and **relies** on
    // the account staking info serde instance being "untagged"
    #[serde(rename = "accountBaker", alias = "accountDelegation")]
    pub account_stake:            Option<AccountStakingInfo>,
    /// Canonical address of the account.
    pub account_address:          AccountAddress,
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(tag = "change")]
/// Pending change in the baker's stake.
pub enum StakePendingChange {
    #[serde(rename = "ReduceStake")]
    #[serde(rename_all = "camelCase")]
    /// The stake is being reduced. The new stake will take affect in the given
    /// epoch.
    ReduceStake {
        new_stake:      Amount,
        effective_time: chrono::DateTime<chrono::Utc>,
    },
    #[serde(rename = "RemoveStake")]
    #[serde(rename_all = "camelCase")]
    /// The baker will be removed at the end of the given epoch.
    RemoveStake {
        effective_time: chrono::DateTime<chrono::Utc>,
    },
}

impl StakePendingChange {
    /// Effective time of the pending change.
    pub fn effective_time(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            StakePendingChange::ReduceStake { effective_time, .. } => *effective_time,
            StakePendingChange::RemoveStake { effective_time } => *effective_time,
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(
    rename_all = "camelCase",
    untagged,
    try_from = "rewards_overview::RewardsDataRaw"
)]
/// Information about the state of the CCD distribution at a particular time.
pub enum RewardsOverview {
    #[serde(rename_all = "camelCase")]
    V0 {
        #[serde(flatten)]
        data: CommonRewardData,
    },
    #[serde(rename_all = "camelCase")]
    V1 {
        #[serde(flatten)]
        common: CommonRewardData,
        /// The transaction reward fraction accruing to the foundation (to be
        /// paid at next payday).
        foundation_transaction_rewards: Amount,
        /// The time of the next payday.
        next_payday_time: chrono::DateTime<chrono::Utc>,
        /// The rate at which CCD will be minted (as a proportion of the total
        /// supply) at the next payday
        next_payday_mint_rate: MintRate,
        /// The total capital put up as stake by bakers and delegators
        total_staked_capital: Amount,
    },
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
/// Reward data common to both V0 and V1 rewards.
pub struct CommonRewardData {
    /// Protocol version that applies to these rewards. V0 variant
    /// only exists for protocol versions 1, 2, and 3.
    pub protocol_version:            ProtocolVersion,
    /// The total CCD in existence.
    pub total_amount:                Amount,
    /// The total CCD in encrypted balances.
    pub total_encrypted_amount:      Amount,
    /// The amount in the baking reward account.
    pub baking_reward_account:       Amount,
    /// The amount in the finalization reward account.
    pub finalization_reward_account: Amount,
    /// The amount in the GAS account.
    pub gas_account:                 Amount,
}

mod rewards_overview {
    use super::*;
    #[derive(SerdeDeserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct RewardsDataRaw {
        #[serde(flatten)]
        common: CommonRewardData,
        /// The transaction reward fraction accruing to the foundation (to be
        /// paid at next payday).
        foundation_transaction_rewards: Option<Amount>,
        /// The time of the next payday.
        next_payday_time: Option<chrono::DateTime<chrono::Utc>>,
        /// The rate at which CCD will be minted (as a proportion of the total
        /// supply) at the next payday
        next_payday_mint_rate: Option<MintRate>,
        /// The total capital put up as stake by bakers and delegators
        total_staked_capital: Option<Amount>,
    }

    impl TryFrom<RewardsDataRaw> for RewardsOverview {
        type Error = anyhow::Error;

        fn try_from(value: RewardsDataRaw) -> Result<Self, Self::Error> {
            if value.common.protocol_version <= ProtocolVersion::P3 {
                Ok(Self::V0 { data: value.common })
            } else {
                let foundation_transaction_rewards =
                    value.foundation_transaction_rewards.ok_or_else(|| {
                        anyhow::anyhow!("Missing 'foundationTransactionRewards' field.")
                    })?;
                let next_payday_time = value
                    .next_payday_time
                    .ok_or_else(|| anyhow::anyhow!("Missing 'nextPaydayTime' field."))?;
                let next_payday_mint_rate = value
                    .next_payday_mint_rate
                    .ok_or_else(|| anyhow::anyhow!("Missing 'nextPaydayMintRate' field."))?;
                let total_staked_capital = value
                    .total_staked_capital
                    .ok_or_else(|| anyhow::anyhow!("Missing 'totalStakedCapital' field."))?;
                Ok(Self::V1 {
                    common: value.common,
                    foundation_transaction_rewards,
                    next_payday_time,
                    next_payday_mint_rate,
                    total_staked_capital,
                })
            }
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(tag = "pendingChangeType")]
pub enum PoolPendingChange {
    NoChange,
    #[serde(rename_all = "camelCase")]
    ReduceBakerCapital {
        /// New baker equity capital.
        baker_equity_capital: Amount,
        /// Effective time of the change.
        effective_time:       chrono::DateTime<chrono::Utc>,
    },
    #[serde(rename_all = "camelCase")]
    RemovePool {
        /// Effective time of the change.
        effective_time: chrono::DateTime<chrono::Utc>,
    },
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CurrentPaydayBakerPoolStatus {
    /// The number of blocks baked in the current reward period.
    pub blocks_baked:            u64,
    /// Whether the baker has contributed a finalization proof in the current
    /// reward period.
    pub finalization_live:       bool,
    /// The transaction fees accruing to the pool in the current reward period.
    pub transaction_fees_earned: Amount,
    /// The effective stake of the baker in the current reward period.
    pub effective_stake:         Amount,
    /// The lottery power of the baker in the current reward period.
    #[serde(deserialize_with = "lottery_power_parser::deserialize")]
    pub lottery_power:           f64,
    /// The effective equity capital of the baker for the current reward period.
    pub baker_equity_capital:    Amount,
    /// The effective delegated capital to the pool for the current reward
    /// period.
    pub delegated_capital:       Amount,
}

// hack due to a bug in Serde that is caused by the combination of
// the tag attribute, and the arbitrary_precision feature.
mod lottery_power_parser {
    use super::SerdeDeserialize;
    /// Deserialize (via Serde) chrono::Duration in milliseconds as an i64.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(des: D) -> Result<f64, D::Error> {
        let v = serde_json::Value::deserialize(des)?;
        if let Some(n) = v.as_f64() {
            Ok(n)
        } else {
            Err(serde::de::Error::custom("Expected a number."))
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "poolType")]
pub enum PoolStatus {
    #[serde(rename_all = "camelCase")]
    BakerPool {
        /// The 'BakerId' of the pool owner.
        baker_id:                   BakerId,
        /// The account address of the pool owner.
        baker_address:              AccountAddress,
        /// The equity capital provided by the pool owner.
        baker_equity_capital:       Amount,
        /// The capital delegated to the pool by other accounts.
        delegated_capital:          Amount,
        /// The maximum amount that may be delegated to the pool, accounting for
        /// leverage and stake limits.
        delegated_capital_cap:      Amount,
        /// The pool info associated with the pool: open status, metadata URL
        /// and commission rates.
        pool_info:                  BakerPoolInfo,
        /// Any pending change to the baker's stake.
        baker_stake_pending_change: PoolPendingChange,
        /// Status of the pool in the current reward period. This will be [None]
        /// if the pool is not a
        current_payday_status:      Option<CurrentPaydayBakerPoolStatus>,
        /// Total capital staked across all pools.
        all_pool_total_capital:     Amount,
    },
    #[serde(rename_all = "camelCase")]
    PassiveDelegation {
        /// The total capital delegated passively.
        delegated_capital: Amount,
        /// The passive delegation commission rates.
        commission_rates: CommissionRates,
        /// The transaction fees accruing to the passive delegators in the
        /// current reward period.
        current_payday_transaction_fees_earned: Amount,
        /// The effective delegated capital to the passive delegators for the
        /// current reward period.
        current_payday_delegated_capital: Amount,
        /// Total capital staked across all pools, including passive delegation.
        all_pool_total_capital: Amount,
    },
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
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
    /// Transfer CCD from an account to another.
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
    /// Transfer a CCD with a release schedule.
    TransferWithSchedule,
    /// Update the account's credentials.
    UpdateCredentials,
    /// Register some data on the chain.
    RegisterData,
    /// Same as transfer but with a memo field.
    TransferWithMemo,
    /// Same as encrypted transfer, but with a memo.
    EncryptedAmountTransferWithMemo,
    /// Same as transfer with schedule, but with an added memo.
    TransferWithScheduleAndMemo,
    ///  Configure an account's baker.
    ConfigureBaker,
    ///  Configure an account's stake delegation.
    ConfigureDelegation,
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
    Finalized(BTreeMap<hashes::BlockHash, BlockItemSummary>),
    /// Transaction is committed to one or more blocks. The outcomes are listed
    /// for each block. Note that in the vast majority of cases the outcome of a
    /// transaction should not be dependent on the block it is in, but this
    /// can in principle happen.
    Committed(BTreeMap<hashes::BlockHash, BlockItemSummary>),
}

impl TransactionStatus {
    /// If the transaction is finalized return the block hash in which it is
    /// contained, and the result.
    pub fn is_finalized(&self) -> Option<(&hashes::BlockHash, &BlockItemSummary)> {
        match self {
            TransactionStatus::Received => None,
            TransactionStatus::Finalized(e) => {
                if e.len() == 1 {
                    e.iter().next()
                } else {
                    None
                }
            }
            TransactionStatus::Committed(_) => None,
        }
    }
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
    /// Distribution of newly minted CCD.
    Mint {
        /// The portion of the newly minted CCD that goes to the baking reward
        /// account.
        mint_baking_reward:               Amount,
        /// The portion that goes to the finalization reward account.
        mint_finalization_reward:         Amount,
        /// The portion that goes to the foundation, as foundation tax.
        mint_platform_development_charge: Amount,
        /// The address of the foundation account that the newly minted CCD goes
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
        /// The amount of CCD that goes to the baker.
        baker_reward:       Amount,
        /// The amount of CCD that goes to the foundation.
        foundation_charge:  Amount,
        /// The account address where the baker receives the reward.
        baker:              AccountAddress,
        /// The account address where the foundation receives the tax.
        foundation_account: AccountAddress,
    },
    #[serde(rename_all = "camelCase")]
    /// Payment for the foundation.
    PaydayFoundationReward {
        /// Address of the foundation account.
        foundation_account: AccountAddress,
        /// Amount rewarded.
        development_charge: Amount,
    },
    /// Payment for a particular account.
    /// When listed in a block summary, the delegated pool of the account is
    /// given by the last PaydayPoolReward outcome included before this outcome.
    #[serde(rename_all = "camelCase")]
    PaydayAccountReward {
        /// The account that got rewarded.
        account:             AccountAddress,
        /// The transaction fee reward at payday to the account.
        transaction_fees:    Amount,
        /// The baking reward at payday to the account.
        baker_reward:        Amount,
        /// The finalization reward at payday to the account.
        finalization_reward: Amount,
    },
    /// Amounts accrued to accounts for each baked block.
    #[serde(rename_all = "camelCase")]
    BlockAccrueReward {
        /// The total fees paid for transactions in the block.
        transaction_fees:  Amount,
        /// The old balance of the GAS account.
        #[serde(rename = "oldGASAccount")]
        old_gas_account:   Amount,
        /// The new balance of the GAS account.
        #[serde(rename = "newGASAccount")]
        new_gas_account:   Amount,
        /// The amount awarded to the baker.
        baker_reward:      Amount,
        /// The amount awarded to the passive delegators.
        passive_reward:    Amount,
        /// The amount awarded to the foundation.
        foundation_charge: Amount,
        /// The baker of the block, who will receive the award.
        baker_id:          BakerId,
    },
    /// Payment distributed to a pool or passive delegators.
    #[serde(rename_all = "camelCase")]
    PaydayPoolReward {
        /// The pool owner (passive delegators when 'None').
        pool_owner:          Option<BakerId>,
        /// Accrued transaction fees for pool.
        transaction_fees:    Amount,
        /// Accrued baking rewards for pool.
        baker_reward:        Amount,
        /// Accrued finalization rewards for pool.
        finalization_reward: Amount,
    },
}

impl SpecialTransactionOutcome {
    pub fn affected_addresses(&self) -> Vec<AccountAddress> {
        match self {
            SpecialTransactionOutcome::BakingRewards { baker_rewards, .. } => {
                baker_rewards.keys().copied().collect()
            }
            SpecialTransactionOutcome::Mint {
                foundation_account, ..
            } => vec![*foundation_account],
            SpecialTransactionOutcome::FinalizationRewards {
                finalization_rewards,
                ..
            } => finalization_rewards.keys().copied().collect(),
            SpecialTransactionOutcome::BlockReward {
                baker,
                foundation_account,
                ..
            } => {
                if baker == foundation_account {
                    vec![*baker]
                } else {
                    vec![*baker, *foundation_account]
                }
            }
            SpecialTransactionOutcome::PaydayFoundationReward {
                foundation_account, ..
            } => vec![*foundation_account],
            SpecialTransactionOutcome::PaydayAccountReward { account, .. } => vec![*account],
            SpecialTransactionOutcome::BlockAccrueReward { .. } => Vec::new(),
            SpecialTransactionOutcome::PaydayPoolReward { .. } => Vec::new(),
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockSummaryData<Upd> {
    /// Outcomes of transactions in this block, ordered as in the block.
    pub transaction_summaries: Vec<BlockItemSummary>,
    /// Any special events generated as part of this block. Special events
    /// are protocol defined transfers, e.g., rewards, minting.
    pub special_events:        Vec<SpecialTransactionOutcome>,
    /// Chain parameters, and any scheduled updates to chain parameters or
    /// the protocol.
    pub updates:               Upd,
    /// If the block contains a finalization record this contains its
    /// summary. Otherwise [None].
    pub finalization_data:     Option<FinalizationSummary>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
// serialize as untagged, deserialization is custom, looking at the protocol version.
#[serde(untagged, try_from = "block_summary_parser::BlockSummaryRaw")]
/// Summary of transactions, protocol generated transfers, and chain parameters
/// in a given block.
pub enum BlockSummary {
    #[serde(rename_all = "camelCase")]
    V0 {
        /// Protocol version at which this block was baked. This is no more than
        /// [ProtocolVersion::P3]
        protocol_version: ProtocolVersion,
        #[serde(flatten)]
        data:             BlockSummaryData<Updates<ChainParameterVersion0>>,
    },
    #[serde(rename_all = "camelCase")]
    V1 {
        /// Protocol version at which this block was baked. This is at least
        /// [ProtocolVersion::P4]
        protocol_version: ProtocolVersion,
        #[serde(flatten)]
        data:             BlockSummaryData<Updates<ChainParameterVersion1>>,
    },
}

mod block_summary_parser {
    #[derive(super::SerdeDeserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BlockSummaryRaw {
        protocol_version: super::ProtocolVersion,
        #[serde(flatten)]
        // parse first into a value
        data: super::BlockSummaryData<serde_json::Value>,
    }

    impl std::convert::TryFrom<BlockSummaryRaw> for super::BlockSummary {
        type Error = anyhow::Error;

        fn try_from(value: BlockSummaryRaw) -> Result<Self, Self::Error> {
            use super::ProtocolVersion::*;
            match value.protocol_version {
                P1 | P2 | P3 => {
                    let updates: super::Updates<super::ChainParameterVersion0> =
                        serde_json::from_value(value.data.updates)?;
                    let data = super::BlockSummaryData {
                        updates,
                        transaction_summaries: value.data.transaction_summaries,
                        special_events: value.data.special_events,
                        finalization_data: value.data.finalization_data,
                    };
                    Ok(Self::V0 {
                        protocol_version: value.protocol_version,
                        data,
                    })
                }
                P4 => {
                    let updates: super::Updates<super::ChainParameterVersion1> =
                        serde_json::from_value(value.data.updates)?;
                    let data = super::BlockSummaryData {
                        updates,
                        transaction_summaries: value.data.transaction_summaries,
                        special_events: value.data.special_events,
                        finalization_data: value.data.finalization_data,
                    };
                    Ok(Self::V1 {
                        protocol_version: value.protocol_version,
                        data,
                    })
                }
            }
        }
    }
}

impl BlockSummary {
    /// Protocol version of the block.
    pub fn protocol_version(&self) -> ProtocolVersion {
        match self {
            BlockSummary::V0 {
                protocol_version, ..
            } => *protocol_version,
            BlockSummary::V1 {
                protocol_version, ..
            } => *protocol_version,
        }
    }

    /// Outcomes of transactions in this block, ordered as in the block.
    pub fn transaction_summaries(&self) -> &[BlockItemSummary] {
        match self {
            BlockSummary::V0 { data, .. } => &data.transaction_summaries,
            BlockSummary::V1 { data, .. } => &data.transaction_summaries,
        }
    }

    /// Any special events generated as part of this block. Special events
    /// are protocol defined transfers, e.g., rewards, minting.
    pub fn special_events(&self) -> &[SpecialTransactionOutcome] {
        match self {
            BlockSummary::V0 { data, .. } => &data.special_events,
            BlockSummary::V1 { data, .. } => &data.special_events,
        }
    }

    /// Return whether the block is a payday block. This is always false for
    /// protocol versions before P4. In protocol version 4 and up this is the
    /// block where all the rewards are paid out.
    pub fn is_payday_block(&self) -> bool {
        match self {
            BlockSummary::V0 { .. } => false,
            BlockSummary::V1 { data, .. } => data.special_events.iter().any(|ev| {
                matches!(
                    ev,
                    SpecialTransactionOutcome::PaydayFoundationReward { .. }
                        | SpecialTransactionOutcome::PaydayAccountReward { .. }
                        | SpecialTransactionOutcome::PaydayPoolReward { .. }
                )
            }),
        }
    }

    /// If the block contains a finalization record this contains its
    /// summary. Otherwise [`None`].
    pub fn finalization_data(&self) -> Option<&FinalizationSummary> {
        match self {
            BlockSummary::V0 { data, .. } => data.finalization_data.as_ref(),
            BlockSummary::V1 { data, .. } => data.finalization_data.as_ref(),
        }
    }

    /// Get the keys for parameter updates that are common to all versions of
    /// the summary.
    pub fn common_update_keys(&self) -> &AuthorizationsV0 {
        match self {
            BlockSummary::V0 { data, .. } => &data.updates.keys.level_2_keys,
            BlockSummary::V1 { data, .. } => &data.updates.keys.level_2_keys.v0,
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
/// Summary of the finalization record in a block, if any.
pub struct FinalizationSummary {
    #[serde(rename = "finalizationBlockPointer")]
    pub block_pointer: hashes::BlockHash,
    #[serde(rename = "finalizationIndex")]
    pub index:         FinalizationIndex,
    #[serde(rename = "finalizationDelay")]
    pub delay:         BlockHeight,
    #[serde(rename = "finalizers")]
    pub finalizers:    Vec<FinalizationSummaryParty>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
/// Details of a party in a finalization.
pub struct FinalizationSummaryParty {
    /// The identity of the baker.
    pub baker_id: BakerId,
    /// The party's relative weight in the committee
    pub weight:   u64,
    /// Whether the party's signature is present
    pub signed:   bool,
}

#[derive(SerdeDeserialize, SerdeSerialize, Debug, Clone)]
#[serde(
    try_from = "summary_helper::BlockItemSummary",
    into = "summary_helper::BlockItemSummary"
)]
/// Summary of the outcome of a block item in structured form.
/// The summary determines which transaction type it was.
pub struct BlockItemSummary {
    /// Index of the transaction in the block where it is included.
    pub index:       TransactionIndex,
    /// The amount of NRG the transaction cost.
    pub energy_cost: Energy,
    /// Hash of the transaction.
    pub hash:        hashes::TransactionHash,
    /// Details that are specific to different transaction types.
    /// For successful transactions there is a one to one mapping of transaction
    /// types and variants (together with subvariants) of this type.
    pub details:     BlockItemSummaryDetails,
}

impl BlockItemSummary {
    pub fn sender_account(&self) -> Option<AccountAddress> {
        match &self.details {
            BlockItemSummaryDetails::AccountTransaction(at) => Some(at.sender),
            BlockItemSummaryDetails::AccountCreation(_) => None,
            BlockItemSummaryDetails::Update(_) => None,
        }
    }

    pub fn affected_contracts(&self) -> Vec<ContractAddress> {
        if let BlockItemSummaryDetails::AccountTransaction(at) = &self.details {
            match &at.effects {
                AccountTransactionEffects::ContractInitialized { data } => vec![data.address],
                AccountTransactionEffects::ContractUpdateIssued { effects } => {
                    let mut seen = HashSet::new();
                    let mut addresses = Vec::new();
                    for effect in effects {
                        match effect {
                            ContractTraceElement::Updated { data } => {
                                if seen.insert(data.address) {
                                    addresses.push(data.address);
                                }
                            }
                            ContractTraceElement::Transferred { .. } => (),
                            ContractTraceElement::Interrupted { .. } => (),
                            ContractTraceElement::Resumed { .. } => (),
                        }
                    }
                    addresses
                }
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }

    /// Return the list of addresses affected by the block summary.
    pub fn affected_addresses(&self) -> Vec<AccountAddress> {
        if let BlockItemSummaryDetails::AccountTransaction(at) = &self.details {
            match &at.effects {
                AccountTransactionEffects::None { .. } => vec![at.sender],
                AccountTransactionEffects::ModuleDeployed { .. } => vec![at.sender],
                AccountTransactionEffects::ContractInitialized { .. } => vec![at.sender],
                AccountTransactionEffects::ContractUpdateIssued { effects } => {
                    let mut seen = BTreeSet::new();
                    seen.insert(at.sender);
                    let mut addresses = vec![at.sender];
                    for effect in effects {
                        match effect {
                            ContractTraceElement::Updated { .. } => (),
                            ContractTraceElement::Transferred { to, .. } => {
                                if seen.insert(*to) {
                                    addresses.push(*to);
                                }
                            }
                            ContractTraceElement::Interrupted { .. } => (),
                            ContractTraceElement::Resumed { .. } => (),
                        }
                    }
                    addresses
                }
                AccountTransactionEffects::AccountTransfer { to, .. } => {
                    if *to == at.sender {
                        vec![at.sender]
                    } else {
                        vec![at.sender, *to]
                    }
                }
                AccountTransactionEffects::AccountTransferWithMemo { to, .. } => {
                    if *to == at.sender {
                        vec![at.sender]
                    } else {
                        vec![at.sender, *to]
                    }
                }
                AccountTransactionEffects::BakerAdded { .. } => vec![at.sender],
                AccountTransactionEffects::BakerRemoved { .. } => vec![at.sender],
                AccountTransactionEffects::BakerStakeUpdated { .. } => vec![at.sender],
                AccountTransactionEffects::BakerRestakeEarningsUpdated { .. } => vec![at.sender],
                AccountTransactionEffects::BakerKeysUpdated { .. } => vec![at.sender],
                AccountTransactionEffects::EncryptedAmountTransferred { removed, added } => {
                    vec![removed.account, added.receiver]
                }
                AccountTransactionEffects::EncryptedAmountTransferredWithMemo {
                    removed,
                    added,
                    ..
                } => vec![removed.account, added.receiver],
                AccountTransactionEffects::TransferredToEncrypted { data } => vec![data.account],
                AccountTransactionEffects::TransferredToPublic { removed, .. } => {
                    vec![removed.account]
                }
                AccountTransactionEffects::TransferredWithSchedule { to, .. } => {
                    vec![at.sender, *to]
                }
                AccountTransactionEffects::TransferredWithScheduleAndMemo { to, .. } => {
                    vec![at.sender, *to]
                }
                AccountTransactionEffects::CredentialKeysUpdated { .. } => vec![at.sender],
                AccountTransactionEffects::CredentialsUpdated { .. } => vec![at.sender],
                AccountTransactionEffects::DataRegistered { .. } => vec![at.sender],
                AccountTransactionEffects::BakerConfigured { .. } => vec![at.sender],
                AccountTransactionEffects::DelegationConfigured { .. } => vec![at.sender],
            }
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone)]
/// Details of a block item summary, split by the kind of block item it is for.
pub enum BlockItemSummaryDetails {
    /// The summary is of an account transaction with the given details.
    AccountTransaction(AccountTransactionDetails),
    /// The summary is of an account creation, and the outcome is as specified
    /// by the payload.
    AccountCreation(AccountCreationDetails),
    /// The summary is of a chain update, and the outcome is as specified by the
    /// payload.
    Update(UpdateDetails),
}

#[derive(Debug, Clone)]
/// Details of an account transaction. This always has a sender and is paid for,
/// and it might have some other effects on the state of the chain.
pub struct AccountTransactionDetails {
    /// The amount of CCD the sender paid for including this transaction in
    /// the block.
    pub cost:    Amount,
    /// Sender of the transaction.
    pub sender:  AccountAddress,
    /// Effects of the account transaction, if any.
    pub effects: AccountTransactionEffects,
}

impl AccountTransactionDetails {
    /// Get the transaction type corresponding to the details.
    /// Returns `None` for the
    /// [AccountTransactionEffects::None](AccountTransactionEffects::None)
    /// variant in case the transaction failed with serialization failure
    /// reason.
    pub fn transaction_type(&self) -> Option<TransactionType> { self.effects.transaction_type() }

    /// Return [`Some`] if the transaction has been rejected.
    pub fn is_rejected(&self) -> Option<&RejectReason> { self.effects.is_rejected() }
}

impl AccountTransactionEffects {
    /// Get the transaction type corresponding to the effects.
    /// Returns `None` for the
    /// [AccountTransactionEffects::None](AccountTransactionEffects::None)
    /// variant in case the transaction failed with serialization failure
    /// reason.
    pub fn transaction_type(&self) -> Option<TransactionType> {
        use TransactionType::*;
        match self {
            AccountTransactionEffects::None {
                transaction_type, ..
            } => *transaction_type,
            AccountTransactionEffects::ModuleDeployed { .. } => Some(DeployModule),
            AccountTransactionEffects::ContractInitialized { .. } => Some(InitContract),
            AccountTransactionEffects::ContractUpdateIssued { .. } => Some(Update),
            AccountTransactionEffects::AccountTransfer { .. } => Some(Transfer),
            AccountTransactionEffects::AccountTransferWithMemo { .. } => Some(TransferWithMemo),
            AccountTransactionEffects::BakerAdded { .. } => Some(AddBaker),
            AccountTransactionEffects::BakerRemoved { .. } => Some(RemoveBaker),
            AccountTransactionEffects::BakerStakeUpdated { .. } => Some(UpdateBakerStake),
            AccountTransactionEffects::BakerRestakeEarningsUpdated { .. } => {
                Some(UpdateBakerRestakeEarnings)
            }
            AccountTransactionEffects::BakerKeysUpdated { .. } => Some(UpdateBakerKeys),
            AccountTransactionEffects::EncryptedAmountTransferred { .. } => {
                Some(EncryptedAmountTransfer)
            }
            AccountTransactionEffects::EncryptedAmountTransferredWithMemo { .. } => {
                Some(EncryptedAmountTransferWithMemo)
            }
            AccountTransactionEffects::TransferredToEncrypted { .. } => Some(TransferToEncrypted),
            AccountTransactionEffects::TransferredToPublic { .. } => Some(TransferToPublic),
            AccountTransactionEffects::TransferredWithSchedule { .. } => Some(TransferWithSchedule),
            AccountTransactionEffects::TransferredWithScheduleAndMemo { .. } => {
                Some(TransferWithScheduleAndMemo)
            }
            AccountTransactionEffects::CredentialKeysUpdated { .. } => Some(UpdateCredentialKeys),
            AccountTransactionEffects::CredentialsUpdated { .. } => Some(UpdateCredentials),
            AccountTransactionEffects::DataRegistered { .. } => Some(RegisterData),
            AccountTransactionEffects::BakerConfigured { .. } => Some(ConfigureBaker),
            AccountTransactionEffects::DelegationConfigured { .. } => Some(ConfigureDelegation),
        }
    }
}

#[derive(Debug, Clone)]
/// A successful contract invocation produces a sequence of effects on smart
/// contracts and possibly accounts (if any contract transfers CCD to an
/// account).
pub enum ContractTraceElement {
    /// A contract instance was updated.
    Updated { data: InstanceUpdatedEvent },
    /// A contract transferred am amount to the account,
    Transferred {
        /// Sender contract.
        from:   ContractAddress,
        /// Amount transferred.
        amount: Amount,
        /// Receiver account.
        to:     AccountAddress,
    },
    Interrupted {
        address: ContractAddress,
        events:  Vec<smart_contracts::ContractEvent>,
    },
    Resumed {
        address: ContractAddress,
        success: bool,
    },
}

#[derive(Debug, Clone, Copy)]
/// Data contained in the transaction response in case a baker stake was updated
/// (either increased or decreased.)
pub struct BakerStakeUpdatedData {
    /// Affected baker.
    pub baker_id:  BakerId,
    /// New stake.
    pub new_stake: Amount,
    /// A boolean which indicates whether it increased
    /// (`true`) or decreased (`false`).
    pub increased: bool,
}

#[derive(Debug, Clone)]
/// Effects of an account transactions. All variants apart from
/// [AccountTransactionEffects::None] correspond to a unique transaction that
/// was successful.
pub enum AccountTransactionEffects {
    /// No effects other than payment from this transaction.
    /// The rejection reason indicates why the transaction failed.
    None {
        /// Transaction type of a failed transaction, if known.
        /// In case of serialization failure this will be None.
        transaction_type: Option<TransactionType>,
        /// Reason for rejection of the transaction
        reject_reason:    RejectReason,
    },
    /// A module was deployed. This corresponds to
    /// [`DeployModule`](transactions::Payload::DeployModule) transaction
    /// type.
    ModuleDeployed {
        module_ref: smart_contracts::ModuleRef,
    },
    /// A contract was initialized was deployed. This corresponds to
    /// [`InitContract`](transactions::Payload::InitContract) transaction type.
    ContractInitialized { data: ContractInitializedEvent },
    /// A contract update transaction was issued and produced the given trace.
    /// This is the result of [Update](transactions::Payload::Update)
    /// transaction.
    ContractUpdateIssued { effects: Vec<ContractTraceElement> },
    /// A simple account to account transfer occurred. This is the result of a
    /// successful [`Transfer`](transactions::Payload::Transfer) transaction.
    AccountTransfer {
        /// Amount that was transferred.
        amount: Amount,
        /// Receiver account.
        to:     AccountAddress,
    },
    /// A simple account to account transfer occurred with a memo. This is the
    /// result of a successful
    /// [`TransferWithMemo`](transactions::Payload::TransferWithMemo)
    /// transaction.
    AccountTransferWithMemo {
        /// Amount that was transferred.
        amount: Amount,
        /// Receiver account.
        to:     AccountAddress,
        /// Included memo.
        memo:   Memo,
    },
    /// An account was registered as a baker. This is the result of a successful
    /// [`AddBaker`](transactions::Payload::AddBaker) transaction.
    BakerAdded { data: Box<BakerAddedEvent> },
    /// An account was deregistered as a baker. This is the result of a
    /// successful [RemoveBaker](transactions::Payload::RemoveBaker)
    /// transaction.
    BakerRemoved { baker_id: BakerId },
    /// An account was deregistered as a baker. This is the result of a
    /// successful [`UpdateBakerStake`](transactions::Payload::UpdateBakerStake)
    /// transaction.
    BakerStakeUpdated {
        /// If the stake was updated (that is, it changed and did not stay the
        /// same) then this is [Some], otherwise [None].
        data: Option<BakerStakeUpdatedData>,
    },
    /// An account changed its preference for restaking earnings. This is the
    /// result of a successful
    /// [`UpdateBakerRestakeEarnings`](
    ///    transactions::Payload::UpdateBakerRestakeEarnings) transaction.
    BakerRestakeEarningsUpdated {
        baker_id:         BakerId,
        /// The new value of the flag.
        restake_earnings: bool,
    },
    /// The baker's keys were updated. This is the result of a successful
    /// [`UpdateBakerKeys`](transactions::Payload::UpdateBakerKeys) transaction.
    BakerKeysUpdated { data: Box<BakerKeysEvent> },
    /// An encrypted amount was transferred. This is the result of a successful
    /// [`EncryptedAmountTransfer`](
    ///   transactions::Payload::EncryptedAmountTransfer) transaction.
    EncryptedAmountTransferred {
        // FIXME: It would be better to only have one pointer
        removed: Box<EncryptedAmountRemovedEvent>,
        added:   Box<NewEncryptedAmountEvent>,
    },
    /// An encrypted amount was transferred with an included memo. This is the
    /// result of a successful [`EncryptedAmountTransferWithMemo`](
    ///   transactions::Payload::EncryptedAmountTransferWithMemo) transaction.
    EncryptedAmountTransferredWithMemo {
        // FIXME: It would be better to only have one pointer
        removed: Box<EncryptedAmountRemovedEvent>,
        added:   Box<NewEncryptedAmountEvent>,
        memo:    Memo,
    },
    /// An account transferred part of its public balance to its encrypted
    /// balance. This is the result of a successful
    /// [`TransferToEncrypted`](transactions::Payload::TransferToEncrypted)
    /// transaction.
    TransferredToEncrypted {
        data: Box<EncryptedSelfAmountAddedEvent>,
    },
    /// An account transferred part of its encrypted balance to its public
    /// balance. This is the result of a successful
    /// [`TransferToPublic`](transactions::Payload::TransferToPublic)
    /// transaction.
    TransferredToPublic {
        removed: Box<EncryptedAmountRemovedEvent>,
        amount:  Amount,
    },
    /// A transfer with schedule was performed. This is the result of a
    /// successful
    /// [`TransferWithSchedule`](transactions::Payload::TransferWithSchedule)
    /// transaction.
    TransferredWithSchedule {
        /// Receiver account.
        to:     AccountAddress,
        /// The list of releases. Ordered by increasing timestamp.
        amount: Vec<(Timestamp, Amount)>,
    },
    /// A transfer with schedule was performed with an added memo. This is the
    /// result of a successful [`TransferWithScheduleAndMemo`][link]
    /// transaction.
    ///
    /// [link]: transactions::Payload::TransferWithScheduleAndMemo
    TransferredWithScheduleAndMemo {
        /// Receiver account.
        to:     AccountAddress,
        /// The list of releases. Ordered by increasing timestamp.
        amount: Vec<(Timestamp, Amount)>,
        memo:   Memo,
    },
    /// Keys of a specific credential were updated. This is the result of a
    /// successful
    /// [`UpdateCredentialKeys`](transactions::Payload::UpdateCredentialKeys)
    /// transaction.
    CredentialKeysUpdated {
        /// ID of the credential whose keys were updated.
        cred_id: CredentialRegistrationID,
    },
    /// Account's credentials were updated. This is the result of a
    /// successful
    /// [`UpdateCredentials`](transactions::Payload::UpdateCredentials)
    /// transaction.
    CredentialsUpdated {
        /// The credential ids that were added.
        new_cred_ids:     Vec<CredentialRegistrationID>,
        /// The credentials that were removed.
        removed_cred_ids: Vec<CredentialRegistrationID>,
        /// The (possibly) updated account threshold.
        new_threshold:    AccountThreshold,
    },
    /// Some data was registered on the chain. This is the result of a
    /// successful [`RegisterData`](transactions::Payload::RegisterData)
    /// transaction.
    DataRegistered { data: RegisteredData },
    /// A baker was configured. The details of what happened are contained in
    /// the list of [baker events](BakerEvent).
    BakerConfigured { data: Vec<BakerEvent> },
    /// An account configured delegation. The details of what happened are
    /// contained in the list of [delegation events](DelegationEvent).
    DelegationConfigured { data: Vec<DelegationEvent> },
}

impl AccountTransactionEffects {
    /// Return [`Some`] if the transaction has been rejected.
    pub fn is_rejected(&self) -> Option<&RejectReason> {
        if let Self::None { reject_reason, .. } = self {
            Some(reject_reason)
        } else {
            None
        }
    }
}

/// Events that may happen as a result of the
/// [TransactionType::ConfigureDelegation] transaction.
#[derive(Debug, Clone)]
pub enum DelegationEvent {
    DelegationStakeIncreased {
        /// Delegator's id
        delegator_id: DelegatorId,
        /// New stake
        new_stake:    Amount,
    },
    DelegationStakeDecreased {
        /// Delegator's id
        delegator_id: DelegatorId,
        /// New stake
        new_stake:    Amount,
    },
    DelegationSetRestakeEarnings {
        /// Delegator's id
        delegator_id:     DelegatorId,
        /// Whether earnings will be restaked
        restake_earnings: bool,
    },
    DelegationSetDelegationTarget {
        /// Delegator's id
        delegator_id:      DelegatorId,
        /// New delegation target
        delegation_target: DelegationTarget,
    },
    DelegationAdded {
        /// Delegator's id
        delegator_id: DelegatorId,
    },
    DelegationRemoved {
        /// Delegator's id
        delegator_id: DelegatorId,
    },
}

/// Events that may result from the [TransactionType::ConfigureBaker]
/// transaction.
#[derive(Debug, Clone)]
pub enum BakerEvent {
    BakerAdded {
        data: Box<BakerAddedEvent>,
    },
    BakerRemoved {
        baker_id: BakerId,
    },
    BakerStakeIncreased {
        baker_id:  BakerId,
        new_stake: Amount,
    },
    BakerStakeDecreased {
        baker_id:  BakerId,
        new_stake: Amount,
    },
    BakerRestakeEarningsUpdated {
        baker_id:         BakerId,
        /// The new value of the flag.
        restake_earnings: bool,
    },
    /// The baker's keys were updated.
    BakerKeysUpdated {
        data: Box<BakerKeysEvent>,
    },
    /// Updated open status for a baker pool
    BakerSetOpenStatus {
        /// Baker's id
        baker_id:    BakerId,
        /// The open status.
        open_status: OpenStatus,
    },
    /// Updated metadata url for baker pool
    BakerSetMetadataURL {
        /// Baker's id
        baker_id:     BakerId,
        /// The URL.
        metadata_url: UrlText,
    },
    /// Updated transaction fee commission for baker pool
    BakerSetTransactionFeeCommission {
        /// Baker's id
        baker_id:                   BakerId,
        /// The transaction fee commission.
        transaction_fee_commission: AmountFraction,
    },
    /// Updated baking reward commission for baker pool
    BakerSetBakingRewardCommission {
        /// Baker's id
        baker_id:                 BakerId,
        /// The baking reward commission
        baking_reward_commission: AmountFraction,
    },
    /// Updated finalization reward commission for baker pool
    BakerSetFinalizationRewardCommission {
        /// Baker's id
        baker_id: BakerId,
        /// The finalization reward commission
        finalization_reward_commission: AmountFraction,
    },
}

#[derive(Debug, Clone)]
/// Details of an account creation. These transactions are free, and we only
/// ever get a response for them if the account is created, hence no failure
/// cases.
pub struct AccountCreationDetails {
    /// Whether this is an initial or normal account.
    pub credential_type: CredentialType,
    /// Address of the newly created account.
    pub address:         AccountAddress,
    /// Credential registration ID of the first credential.
    pub reg_id:          CredentialRegistrationID,
}

#[derive(Debug, Clone)]
/// Details of an update instruction. These are free, and we only ever get a
/// response for them if the update is successfully enqueued, hence no failure
/// cases.
pub struct UpdateDetails {
    pub effective_time: TransactionTime,
    pub payload:        UpdatePayload,
}

impl UpdateDetails {
    pub fn update_type(&self) -> UpdateType { self.payload.update_type() }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Event generated when an account receives a new encrypted amount.
pub struct NewEncryptedAmountEvent {
    /// The account onto which the amount was added.
    #[serde(rename = "account")]
    pub receiver:         AccountAddress,
    /// The index the amount was assigned.
    pub new_index:        encrypted_transfers::types::EncryptedAmountIndex,
    /// The encrypted amount that was added.
    pub encrypted_amount: encrypted_transfers::types::EncryptedAmount<EncryptedAmountsCurve>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Event generated when one or more encrypted amounts are consumed from the
/// account.
pub struct EncryptedAmountRemovedEvent {
    /// The affected account.
    pub account:      AccountAddress,
    /// The new self encrypted amount on the affected account.
    pub new_amount:   encrypted_transfers::types::EncryptedAmount<EncryptedAmountsCurve>,
    /// The input encrypted amount that was removed.
    pub input_amount: encrypted_transfers::types::EncryptedAmount<EncryptedAmountsCurve>,
    /// The index indicating which amounts were used.
    pub up_to_index:  encrypted_transfers::types::EncryptedAmountAggIndex,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BakerAddedEvent {
    #[serde(flatten)]
    /// The keys with which the baker registered.
    pub keys_event:       BakerKeysEvent,
    /// The amount the account staked to become a baker. This amount is
    /// locked.
    pub stake:            Amount,
    /// Whether the baker will automatically add earnings to their stake or
    /// not.
    pub restake_earnings: bool,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Result of a successful change of baker keys.
pub struct BakerKeysEvent {
    /// ID of the baker whose keys were changed.
    pub baker_id:        BakerId,
    /// Account address of the baker.
    pub account:         AccountAddress,
    /// The new public key for verifying block signatures.
    pub sign_key:        BakerSignatureVerifyKey,
    /// The new public key for verifying whether the baker won the block
    /// lottery.
    pub election_key:    BakerElectionVerifyKey,
    /// The new public key for verifying finalization records.
    pub aggregation_key: BakerAggregationVerifyKey,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedSelfAmountAddedEvent {
    /// The affected account.
    pub account:    AccountAddress,
    /// The new self encrypted amount of the account.
    pub new_amount: encrypted_transfers::types::EncryptedAmount<EncryptedAmountsCurve>,
    /// The amount that was transferred from public to encrypted balance.
    pub amount:     Amount,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ContractInitializedEvent {
    #[serde(default)]
    pub contract_version: smart_contracts::WasmVersion,
    #[serde(rename = "ref")]
    /// Module with the source code of the contract.
    pub origin_ref:       smart_contracts::ModuleRef,
    /// The newly assigned address of the contract.
    pub address:          ContractAddress,
    /// The amount the instance was initialized with.
    pub amount:           Amount,
    /// The name of the contract.
    pub init_name:        smart_contracts::OwnedContractName,
    /// Any contract events that might have been generated by the contract
    /// initialization.
    pub events:           Vec<smart_contracts::ContractEvent>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Data generated as part of updating a single contract instance.
/// In general a single [Update](transactions::Payload::Update) transaction will
/// generate one or more of these events, together with possibly some transfers.
pub struct InstanceUpdatedEvent {
    #[serde(default)]
    pub contract_version: smart_contracts::WasmVersion,
    /// Address of the affected instance.
    pub address:          ContractAddress,
    /// The origin of the message to the smart contract. This can be either
    /// an account or a smart contract.
    pub instigator:       Address,
    /// The amount the method was invoked with.
    pub amount:           Amount,
    /// The message passed to method.
    pub message:          smart_contracts::Parameter,
    /// The name of the method that was executed.
    pub receive_name:     smart_contracts::OwnedReceiveName,
    /// Any contract events that might have been generated by the contract
    /// execution.
    pub events:           Vec<smart_contracts::ContractEvent>,
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
    MintDistribution(MintDistribution<ChainParameterVersion0>),
    #[serde(rename = "transactionFeeDistribution")]
    TransactionFeeDistribution(TransactionFeeDistribution),
    #[serde(rename = "gASRewards")]
    GASRewards(GASRewards),
    #[serde(rename = "bakerStakeThreshold")]
    BakerStakeThreshold(BakerParameters),
    #[serde(rename = "root")]
    Root(RootUpdate),
    #[serde(rename = "level1")]
    Level1(Level1Update),
    #[serde(rename = "addAnonymityRevoker")]
    AddAnonymityRevoker(Box<id::types::ArInfo<id::constants::ArCurve>>),
    #[serde(rename = "addIdentityProvider")]
    AddIdentityProvider(Box<id::types::IpInfo<id::constants::IpPairing>>),
    #[serde(rename = "cooldownParametersCPV1")]
    CooldownParametersCPV1(CooldownParameters),
    #[serde(rename = "poolParametersCPV1")]
    PoolParametersCPV1(PoolParameters),
    #[serde(rename = "timeParametersCPV1")]
    TimeParametersCPV1(TimeParameters),
    #[serde(rename = "mintDistributionCPV1")]
    MintDistributionCPV1(MintDistribution<ChainParameterVersion1>),
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
    /// Update the microCCD per euro exchange rate
    UpdateMicroGTUPerEuro,
    /// Update the address of the foundation account
    UpdateFoundationAccount,
    /// Update the distribution of newly minted CCD
    UpdateMintDistribution,
    /// Update the distribution of transaction fees
    UpdateTransactionFeeDistribution,
    /// Update the GAS rewards
    UpdateGASRewards,
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
    /// Update the baker pool parameters. In protocol versions <= 3 this
    /// corresponds to the the update of the baker stake threshold. In
    /// protocol version 4 and up this includes other pool parameters.
    UpdatePoolParameters,
    UpdateCooldownParameters,
    UpdateTimeParameters,
}

impl UpdatePayload {
    fn update_type(&self) -> UpdateType {
        use UpdateType::*;
        match self {
            UpdatePayload::Protocol(_) => UpdateProtocol,
            UpdatePayload::ElectionDifficulty(_) => UpdateElectionDifficulty,
            UpdatePayload::EuroPerEnergy(_) => UpdateEuroPerEnergy,
            UpdatePayload::MicroGTUPerEuro(_) => UpdateMicroGTUPerEuro,
            UpdatePayload::FoundationAccount(_) => UpdateFoundationAccount,
            UpdatePayload::MintDistribution(_) => UpdateMintDistribution,
            UpdatePayload::TransactionFeeDistribution(_) => UpdateTransactionFeeDistribution,
            UpdatePayload::GASRewards(_) => UpdateGASRewards,
            UpdatePayload::BakerStakeThreshold(_) => UpdatePoolParameters,
            UpdatePayload::Root(_) => UpdateRootKeys,
            UpdatePayload::Level1(_) => UpdateLevel1Keys,
            UpdatePayload::AddAnonymityRevoker(_) => UpdateAddAnonymityRevoker,
            UpdatePayload::AddIdentityProvider(_) => UpdateAddIdentityProvider,
            UpdatePayload::CooldownParametersCPV1(_) => UpdateCooldownParameters,
            UpdatePayload::PoolParametersCPV1(_) => UpdatePoolParameters,
            UpdatePayload::TimeParametersCPV1(_) => UpdateTimeParameters,
            UpdatePayload::MintDistributionCPV1(_) => UpdateMintDistribution,
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BakerParameters {
    minimum_threshold_for_baking: Amount,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// A generic protocol update. This is essentially an announcement of the
/// update. The details of the update will be communicated in some off-chain
/// way, and bakers will need to update their node software to support the
/// update.
pub struct ProtocolUpdate {
    pub message: String,
    #[serde(rename = "specificationURL")]
    pub specification_url: String,
    pub specification_hash: hashes::Hash,
    #[serde(with = "crate::internal::byte_array_hex")]
    pub specification_auxiliary_data: Vec<u8>,
}

impl Serial for ProtocolUpdate {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let data_len = self.message.as_bytes().len()
            + 8
            + self.specification_url.as_bytes().len()
            + 8
            + 32
            + self.specification_auxiliary_data.len();
        (data_len as u64).serial(out);
        (self.message.as_bytes().len() as u64).serial(out);
        out.write_all(self.message.as_bytes())
            .expect("Serialization to a buffer always succeeds.");
        (self.specification_url.as_bytes().len() as u64).serial(out);
        out.write_all(self.specification_url.as_bytes())
            .expect("Serialization to a buffer always succeeds.");
        self.specification_hash.serial(out);
        out.write_all(&self.specification_auxiliary_data)
            .expect("Serialization to a buffer always succeeds.")
    }
}

impl Deserial for ProtocolUpdate {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let data_len = u64::deserial(source)?;
        let mut limited = source.take(data_len);
        let message_len = u64::deserial(&mut limited)?;
        let message = if message_len <= 4096 {
            // protect against DOS by memory exhaustion
            deserial_string(&mut limited, message_len as usize)?
        } else {
            String::from_utf8(deserial_vector_no_length(
                &mut limited,
                message_len as usize,
            )?)?
        };
        let url_len = u64::deserial(&mut limited)?;
        let specification_url = if message_len <= 4096 {
            deserial_string(&mut limited, url_len as usize)?
        } else {
            String::from_utf8(deserial_vector_no_length(&mut limited, url_len as usize)?)?
        };
        let specification_hash = limited.get()?;
        let remaining = limited.limit();
        let specification_auxiliary_data = if remaining <= 4096 {
            deserial_bytes(&mut limited, remaining as usize)?
        } else {
            deserial_vector_no_length(&mut limited, remaining as usize)?
        };
        Ok(Self {
            message,
            specification_url,
            specification_hash,
            specification_auxiliary_data,
        })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Serial, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(try_from = "transaction_fee_distribution::TransactionFeeDistributionUnchecked")]
/// Update the transaction fee distribution to the specified value.
pub struct TransactionFeeDistribution {
    /// The fraction that goes to the baker of the block.
    pub baker:       AmountFraction,
    /// The fraction that goes to the gas account. The remaining fraction will
    /// go to the foundation.
    pub gas_account: AmountFraction,
}

impl Deserial for TransactionFeeDistribution {
    fn deserial<R: crypto_common::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let baker: AmountFraction = source.get()?;
        let gas_account: AmountFraction = source.get()?;
        anyhow::ensure!(
            (baker + gas_account).is_some(),
            "Reward fractions exceed 100%."
        );
        Ok(Self { baker, gas_account })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
/// The reward fractions related to the gas account and inclusion of special
/// transactions.
pub struct GASRewards {
    /// `BakerPrevTransFrac`: fraction of the previous gas account paid to the
    /// baker.
    pub baker:              AmountFraction,
    /// `FeeAddFinalisationProof`: fraction paid for including a finalization
    /// proof in a block.
    pub finalization_proof: AmountFraction,
    /// `FeeAccountCreation`: fraction paid for including each account creation
    /// transaction in a block.
    pub account_creation:   AmountFraction,
    /// `FeeUpdate`: fraction paid for including an update transaction in a
    /// block.
    pub chain_update:       AmountFraction,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(tag = "typeOfUpdate", content = "updatePayload")]
#[serde(rename_all = "camelCase")]
/// An update with root keys of some other set of governance keys, or the root
/// keys themselves. Each update is a separate transaction.
pub enum RootUpdate {
    RootKeysUpdate(HigherLevelAccessStructure<RootKeysKind>),
    Level1KeysUpdate(HigherLevelAccessStructure<Level1KeysKind>),
    Level2KeysUpdate(Box<Authorizations<ChainParameterVersion0>>),
    Level2KeysUpdateV1(Box<Authorizations<ChainParameterVersion1>>),
}

impl Serial for RootUpdate {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            RootUpdate::RootKeysUpdate(ruk) => {
                0u8.serial(out);
                ruk.serial(out)
            }
            RootUpdate::Level1KeysUpdate(l1k) => {
                1u8.serial(out);
                l1k.serial(out)
            }
            RootUpdate::Level2KeysUpdate(l2k) => {
                2u8.serial(out);
                l2k.serial(out)
            }
            RootUpdate::Level2KeysUpdateV1(l2k) => {
                3u8.serial(out);
                l2k.serial(out)
            }
        }
    }
}

impl Deserial for RootUpdate {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(RootUpdate::RootKeysUpdate(source.get()?)),
            1u8 => Ok(RootUpdate::Level1KeysUpdate(source.get()?)),
            2u8 => Ok(RootUpdate::Level2KeysUpdate(source.get()?)),
            3u8 => Ok(RootUpdate::Level2KeysUpdateV1(source.get()?)),
            tag => anyhow::bail!("Unknown RootUpdate tag {}", tag),
        }
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(tag = "typeOfUpdate", content = "updatePayload")]
#[serde(rename_all = "camelCase")]
/// An update with level 1 keys of either level 1 or level 2 keys. Each of the
/// updates must be a separate transaction.
pub enum Level1Update {
    Level1KeysUpdate(HigherLevelAccessStructure<Level1KeysKind>),
    Level2KeysUpdate(Box<Authorizations<ChainParameterVersion0>>),
    Level2KeysUpdateV1(Box<Authorizations<ChainParameterVersion1>>),
}

impl Serial for Level1Update {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Level1Update::Level1KeysUpdate(l1k) => {
                0u8.serial(out);
                l1k.serial(out)
            }
            Level1Update::Level2KeysUpdate(l2k) => {
                1u8.serial(out);
                l2k.serial(out)
            }
            Level1Update::Level2KeysUpdateV1(l2k) => {
                2u8.serial(out);
                l2k.serial(out)
            }
        }
    }
}

impl Deserial for Level1Update {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Level1Update::Level1KeysUpdate(source.get()?)),
            1u8 => Ok(Level1Update::Level2KeysUpdate(source.get()?)),
            2u8 => Ok(Level1Update::Level2KeysUpdateV1(source.get()?)),
            tag => anyhow::bail!("Unknown Level1Update tag {}", tag),
        }
    }
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

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Serial, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "Kind: Sized")]
/// Either root, level1, or level 2 access structure. They all have the same
/// structure, keys and a threshold. The phantom type parameter is used for
/// added type safety to distinguish different access structures in different
/// contexts.
pub struct HigherLevelAccessStructure<Kind> {
    #[size_length = 2]
    pub keys:      Vec<UpdatePublicKey>,
    pub threshold: UpdateKeysThreshold,
    #[serde(skip)] // use default when deserializing
    pub _phantom: PhantomData<Kind>,
}

impl<Kind> Deserial for HigherLevelAccessStructure<Kind> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let keys_len: u16 = source.get()?;
        let keys = deserial_vector_no_length(source, keys_len as usize)?;
        let threshold: UpdateKeysThreshold = source.get()?;
        anyhow::ensure!(threshold.threshold <= keys_len, "Threshold too large.");
        Ok(Self {
            keys,
            threshold,
            _phantom: Default::default(),
        })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Serial, Clone)]
#[serde(rename_all = "camelCase")]
/// And access structure for performing chain updates. The access structure is
/// only meaningful in the context of a list of update keys to which the indices
/// refer to.
pub struct AccessStructure {
    #[set_size_length = 2]
    pub authorized_keys: BTreeSet<UpdateKeysIndex>,
    pub threshold:       UpdateKeysThreshold,
}

impl Deserial for AccessStructure {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let authorized_keys_len: u16 = source.get()?;
        let authorized_keys = deserial_set_no_length(source, authorized_keys_len as usize)?;
        let threshold: UpdateKeysThreshold = source.get()?;
        anyhow::ensure!(
            threshold.threshold <= authorized_keys_len,
            "Threshold too large."
        );
        Ok(Self {
            authorized_keys,
            threshold,
        })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
/// Access structures for each of the different possible chain updates, togehter
/// with the context giving all the possible keys.
pub struct AuthorizationsV0 {
    #[size_length = 2]
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
    /// Access structure for updating the microccd per euro exchange rate.
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
    /// Access structure for updating the pool parameters. For V0 this is only
    /// the baker stake threshold, for V1 there are more.
    pub pool_parameters: AccessStructure,
    /// Access structure for adding new anonymity revokers.
    pub add_anonymity_revoker: AccessStructure,
    /// Access structure for adding new identity providers.
    pub add_identity_provider: AccessStructure,
}

impl AuthorizationsV0 {
    /// Find key indices given a set of keys and an access structure.
    /// If any of the given `actual_keys` are not authorized in the access
    /// structure [`None`] will be returned.
    /// If there are duplicate keys among `actual_keys` this function also
    /// returns [`None`].
    pub fn construct_update_signer<K>(
        &self,
        update_key_indices: &AccessStructure,
        actual_keys: impl IntoIterator<Item = K>,
    ) -> Option<BTreeMap<UpdateKeysIndex, K>>
    where
        UpdatePublicKey: for<'a> From<&'a K>, {
        construct_update_signer_worker(&self.keys, update_key_indices, actual_keys)
    }
}

// See [AuthorizationsV0::construct_update_signer] for documentation.
fn construct_update_signer_worker<K>(
    keys: &[UpdatePublicKey],
    update_key_indices: &AccessStructure,
    actual_keys: impl IntoIterator<Item = K>,
) -> Option<BTreeMap<UpdateKeysIndex, K>>
where
    UpdatePublicKey: for<'a> From<&'a K>, {
    let mut signer = BTreeMap::new();
    for kp in actual_keys {
        let known_key = &UpdatePublicKey::from(&kp);
        if let Some(i) = keys.iter().position(|public| public == known_key) {
            let idx = UpdateKeysIndex { index: i as u16 };
            if update_key_indices.authorized_keys.contains(&idx) {
                if signer.insert(idx, kp).is_some() {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    Some(signer)
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
/// Access structures for each of the different possible chain updates, togehter
/// with the context giving all the possible keys.
pub struct AuthorizationsV1 {
    #[serde(flatten)]
    pub v0:                  AuthorizationsV0,
    /// Keys for changing cooldown periods related to baking and delegating.
    pub cooldown_parameters: AccessStructure,
    /// Keys for changing the lenghts of the reward period.
    pub time_parameters:     AccessStructure,
}

impl AuthorizationsV1 {
    /// Find key indices given a set of keys and an access structure.
    /// If any of the given `actual_keys` are not authorized in the access
    /// structure [`None`] will be returned.
    /// If there are duplicate keys among `actual_keys` this function also
    /// returns [`None`].
    pub fn construct_update_signer<K>(
        &self,
        update_key_indices: &AccessStructure,
        actual_keys: impl IntoIterator<Item = K>,
    ) -> Option<BTreeMap<UpdateKeysIndex, K>>
    where
        UpdatePublicKey: for<'a> From<&'a K>, {
        construct_update_signer_worker(&self.v0.keys, update_key_indices, actual_keys)
    }
}

pub trait AuthorizationsFamily {
    type Output: std::fmt::Debug;
}

impl AuthorizationsFamily for ChainParameterVersion0 {
    type Output = AuthorizationsV0;
}

impl AuthorizationsFamily for ChainParameterVersion1 {
    type Output = AuthorizationsV1;
}

pub type Authorizations<CPV> = <CPV as AuthorizationsFamily>::Output;

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone, AsRef, Into, AsMut)]
#[serde(transparent)]
/// A data that was registered on the chain.
pub struct RegisteredData {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 2]
    bytes: Vec<u8>,
}

/// Registered data is too large.
#[derive(Debug, Error, Copy, Clone)]
#[error("Data is too large to be registered ({actual_size}).")]
pub struct TooLargeError {
    actual_size: usize,
}

impl TryFrom<Vec<u8>> for RegisteredData {
    type Error = TooLargeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let actual_size = bytes.len();
        if actual_size <= MAX_REGISTERED_DATA_SIZE {
            Ok(RegisteredData { bytes })
        } else {
            Err(TooLargeError { actual_size })
        }
    }
}

impl From<[u8; 32]> for RegisteredData {
    fn from(data: [u8; 32]) -> Self {
        Self {
            bytes: data.to_vec(),
        }
    }
}

impl<M> From<hashes::HashBytes<M>> for RegisteredData {
    fn from(data: hashes::HashBytes<M>) -> Self {
        Self {
            bytes: data.as_ref().to_vec(),
        }
    }
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

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone, AsRef, Into)]
#[serde(transparent)]
/// A data that was registered on the chain.
pub struct Memo {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 2]
    bytes: Vec<u8>,
}

/// An error used to signal that an object was too big to be converted.
#[derive(Display, Error, Debug)]
pub struct TooBig;

impl TryFrom<Vec<u8>> for Memo {
    type Error = TooBig;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() <= MAX_MEMO_SIZE {
            Ok(Self { bytes: value })
        } else {
            Err(TooBig)
        }
    }
}

impl Deserial for Memo {
    fn deserial<R: crypto_common::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        anyhow::ensure!(usize::from(len) <= MAX_MEMO_SIZE, "Memo too big..");
        let bytes = crypto_common::deserial_bytes(source, len.into())?;
        Ok(Memo { bytes })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// The current collection of keys allowed to do updates.
/// Parametrized by the chain parameter version.
pub struct UpdateKeysCollectionSkeleton<Auths> {
    pub root_keys:    HigherLevelAccessStructure<RootKeysKind>,
    #[serde(rename = "level1Keys")]
    pub level_1_keys: HigherLevelAccessStructure<Level1KeysKind>,
    #[serde(rename = "level2Keys")]
    pub level_2_keys: Auths,
}

pub type UpdateKeysCollection<CPV> = UpdateKeysCollectionSkeleton<Authorizations<CPV>>;

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Values of chain parameters that can be updated via chain updates.
pub struct ChainParametersV0 {
    /// Election difficulty for consensus lottery.
    pub election_difficulty:          ElectionDifficulty,
    /// Euro per energy exchange rate.
    pub euro_per_energy:              ExchangeRate,
    #[serde(rename = "microGTUPerEuro")]
    /// Micro ccd per euro exchange rate.
    pub micro_gtu_per_euro:           ExchangeRate,
    /// Extra number of epochs before reduction in stake, or baker
    /// deregistration is completed.
    pub baker_cooldown_epochs:        Epoch,
    /// The limit for the number of account creations in a block.
    pub account_creation_limit:       CredentialsPerBlockLimit,
    /// Current reward parameters.
    pub reward_parameters:            RewardParameters<ChainParameterVersion0>,
    /// Index of the foundation account.
    pub foundation_account_index:     AccountIndex,
    /// Minimum threshold for becoming a baker.
    pub minimum_threshold_for_baking: Amount,
}

#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize, Copy, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CooldownParameters {
    /// Number of seconds that pool owners must cooldown
    /// when reducing their equity capital or closing the pool.
    pub pool_owner_cooldown: DurationSeconds,
    /// Number of seconds that a delegator must cooldown
    /// when reducing their delegated stake.
    pub delegator_cooldown:  DurationSeconds,
}

/// Length of a reward period in epochs.
/// Must always be a strictly positive integer.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Debug,
    FromStr,
    Display,
    From,
    Into,
    SerdeSerialize,
    SerdeDeserialize,
    Serialize,
)]
#[serde(transparent)]
pub struct RewardPeriodLength {
    reward_period_epochs: Epoch,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Serialize, Copy, Clone)]
#[serde(rename_all = "camelCase")]
/// The time parameters are introduced as of protocol version 4, and consist of
/// the reward period length and the mint rate per payday. These are coupled as
/// a change to either affects the overall rate of minting.
pub struct TimeParameters {
    pub reward_period_length: RewardPeriodLength,
    pub mint_per_payday:      MintRate,
}

#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Parameters related to staking pools.
pub struct PoolParameters {
    /// Fraction of finalization rewards charged by the passive delegation.
    pub passive_finalization_commission: AmountFraction,
    /// Fraction of baking rewards charged by the passive delegation.
    pub passive_baking_commission:       AmountFraction,
    /// Fraction of transaction rewards charged by the L-pool.
    pub passive_transaction_commission:  AmountFraction,
    /// Bounds on the commission rates that may be charged by bakers.
    #[serde(flatten)]
    pub commission_bounds:               CommissionRanges,
    /// Minimum equity capital required for a new baker.
    pub minimum_equity_capital:          Amount,
    /// Maximum fraction of the total staked capital of that a new baker can
    /// have.
    pub capital_bound:                   CapitalBound,
    /// The maximum leverage that a baker can have as a ratio of total stake
    /// to equity capital.
    pub leverage_bound:                  LeverageFactor,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Values of chain parameters that can be updated via chain updates.
pub struct ChainParametersV1 {
    /// Election difficulty for consensus lottery.
    pub election_difficulty:      ElectionDifficulty,
    /// Euro per energy exchange rate.
    pub euro_per_energy:          ExchangeRate,
    #[serde(rename = "microGTUPerEuro")]
    /// Micro ccd per euro exchange rate.
    pub micro_gtu_per_euro:       ExchangeRate,
    #[serde(flatten)]
    pub cooldown_parameters:      CooldownParameters,
    #[serde(flatten)]
    pub time_parameters:          TimeParameters,
    /// The limit for the number of account creations in a block.
    pub account_creation_limit:   CredentialsPerBlockLimit,
    /// Current reward parameters.
    pub reward_parameters:        RewardParameters<ChainParameterVersion1>,
    /// Index of the foundation account.
    pub foundation_account_index: AccountIndex,
    #[serde(flatten)]
    /// Parameters for baker pools.
    pub pool_parameters:          PoolParameters,
}

pub trait ChainParametersFamily {
    type Output: std::fmt::Debug;
}

impl ChainParametersFamily for ChainParameterVersion0 {
    type Output = ChainParametersV0;
}

impl ChainParametersFamily for ChainParameterVersion1 {
    type Output = ChainParametersV1;
}

pub type ChainParameters<CPV> = <CPV as ChainParametersFamily>::Output;

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Values of reward parameters.
pub struct RewardParametersSkeleton<MD> {
    pub mint_distribution:            MD,
    pub transaction_fee_distribution: TransactionFeeDistribution,
    #[serde(rename = "gASRewards")]
    pub gas_rewards:                  GASRewards,
}

pub type RewardParameters<CPV> = RewardParametersSkeleton<MintDistribution<CPV>>;

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
pub struct PendingUpdatesV0 {
    pub root_keys:                    UpdateQueue<HigherLevelAccessStructure<RootKeysKind>>,
    pub level_1_keys:                 UpdateQueue<HigherLevelAccessStructure<Level1KeysKind>>,
    pub level_2_keys:                 UpdateQueue<Authorizations<ChainParameterVersion0>>,
    pub protocol:                     UpdateQueue<ProtocolUpdate>,
    pub election_difficulty:          UpdateQueue<ElectionDifficulty>,
    pub euro_per_energy:              UpdateQueue<ExchangeRate>,
    #[serde(rename = "microGTUPerEuro")]
    pub micro_gtu_per_euro:           UpdateQueue<ExchangeRate>,
    pub foundation_account:           UpdateQueue<AccountIndex>,
    pub mint_distribution:            UpdateQueue<MintDistribution<ChainParameterVersion0>>,
    pub transaction_fee_distribution: UpdateQueue<TransactionFeeDistribution>,
    pub gas_rewards:                  UpdateQueue<GASRewards>,
    pub baker_stake_threshold:        UpdateQueue<BakerParameters>,
    pub add_anonymity_revoker:        UpdateQueue<id::types::ArInfo<id::constants::ArCurve>>,
    pub add_identity_provider:        UpdateQueue<id::types::IpInfo<id::constants::IpPairing>>,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PendingUpdatesV1 {
    pub root_keys:                    UpdateQueue<HigherLevelAccessStructure<RootKeysKind>>,
    pub level_1_keys:                 UpdateQueue<HigherLevelAccessStructure<Level1KeysKind>>,
    pub level_2_keys:                 UpdateQueue<Authorizations<ChainParameterVersion1>>,
    pub protocol:                     UpdateQueue<ProtocolUpdate>,
    pub election_difficulty:          UpdateQueue<ElectionDifficulty>,
    pub euro_per_energy:              UpdateQueue<ExchangeRate>,
    #[serde(rename = "microGTUPerEuro")]
    pub micro_gtu_per_euro:           UpdateQueue<ExchangeRate>,
    pub foundation_account:           UpdateQueue<AccountIndex>,
    pub mint_distribution:            UpdateQueue<MintDistribution<ChainParameterVersion1>>,
    pub transaction_fee_distribution: UpdateQueue<TransactionFeeDistribution>,
    pub gas_rewards:                  UpdateQueue<GASRewards>,
    pub pool_parameters:              UpdateQueue<PoolParameters>,
    pub add_anonymity_revoker:        UpdateQueue<id::types::ArInfo<id::constants::ArCurve>>,
    pub add_identity_provider:        UpdateQueue<id::types::IpInfo<id::constants::IpPairing>>,
    pub cooldown_parameters:          UpdateQueue<CooldownParameters>,
    pub time_parameters:              UpdateQueue<TimeParameters>,
}

pub trait PendingUpdatesFamily {
    type Output: std::fmt::Debug;
}

impl PendingUpdatesFamily for ChainParameterVersion0 {
    type Output = PendingUpdatesV0;
}

impl PendingUpdatesFamily for ChainParameterVersion1 {
    type Output = PendingUpdatesV1;
}

pub type PendingUpdates<CPV> = <CPV as PendingUpdatesFamily>::Output;

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// State of updates. This includes current values of parameters as well as any
/// scheduled updates.
pub struct UpdatesSkeleton<UKC, CP, PU> {
    /// Keys allowed to perform updates.
    pub keys:             UKC,
    #[serde(default)]
    /// Possibly pending protocol update.
    pub protocol_update:  Option<ProtocolUpdate>,
    /// Values of chain parameters.
    pub chain_parameters: CP,
    /// Any scheduled updates.
    pub update_queues:    PU,
}

/// State of updates. This includes current values of parameters as well as any
/// scheduled updates.
pub type Updates<CPV> =
    UpdatesSkeleton<UpdateKeysCollection<CPV>, ChainParameters<CPV>, PendingUpdates<CPV>>;

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
        contents: (
            smart_contracts::ModuleRef,
            smart_contracts::OwnedContractName,
        ),
    },
    /// Reference to a non-existing contract receive method.
    InvalidReceiveMethod {
        contents: (
            smart_contracts::ModuleRef,
            smart_contracts::OwnedReceiveName,
        ),
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
        receive_name:     smart_contracts::OwnedReceiveName,
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
    /// A configure baker transaction is missing one or more arguments in order
    /// to add a baker.
    MissingBakerAddParameters,
    /// Finalization reward commission is not in the valid range for a baker
    FinalizationRewardCommissionNotInRange,
    /// Baking reward commission is not in the valid range for a baker
    BakingRewardCommissionNotInRange,
    /// Transaction fee commission is not in the valid range for a baker
    TransactionFeeCommissionNotInRange,
    /// Tried to add baker for an account that already has a delegator.
    AlreadyADelegator,
    /// The amount on the account was insufficient to cover the proposed stake.
    InsufficientBalanceForDelegationStake,
    /// A configure delegation transaction is missing one or more arguments in
    /// order to add a delegator.
    MissingDelegationAddParameters,
    /// Delegation stake when adding a delegator was 0.
    InsufficientDelegationStake,
    /// Account is not a delegation account.
    DelegatorInCooldown,
    /// Account is not a delegation account.
    NotADelegator {
        #[serde(rename = "contents")]
        address: AccountAddress,
    },
    /// Delegation target is not a baker
    DelegationTargetNotABaker {
        #[serde(rename = "contents")]
        target: BakerId,
    },
    /// The amount would result in pool capital higher than the maximum
    /// threshold.
    StakeOverMaximumThresholdForPool,
    /// The amount would result in pool with a too high fraction of delegated
    /// capital.
    PoolWouldBecomeOverDelegated,
    /// The pool is not open to delegators.
    PoolClosed,
}

mod transaction_fee_distribution {
    use super::*;
    #[derive(SerdeDeserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TransactionFeeDistributionUnchecked {
        baker:       AmountFraction,
        gas_account: AmountFraction,
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
