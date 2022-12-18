use anyhow::Context;
pub use concordium_base::hashes;
// re-export to maintain backwards compatibility.
pub use concordium_base::id::types::CredentialType;
pub mod network;
pub mod queries;
pub mod smart_contracts;
mod summary_helper;
pub mod transactions;

use crate::constants::*;
pub use crate::generated_types::PeerStatsResponse;
pub use concordium_base::base::*;
use concordium_base::{
    common::{
        self,
        derive::Serialize,
        types::{Amount, CredentialIndex, Timestamp, TransactionTime},
        Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
        Versioned,
    },
    encrypted_transfers,
    encrypted_transfers::types::{
        AggregatedDecryptedAmount, EncryptedAmountTransferData, SecToPubAmountTransferData,
    },
    id::{
        constants::{ArCurve, AttributeKind},
        elgamal,
        types::{AccountAddress, AccountCredentialWithoutProofs, AccountKeys},
    },
    transactions::{ExactSizeTransactionSigner, TransactionSigner},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    convert::TryFrom,
};

/// Cryptographic context for the chain. These parameters are used to support
/// zero-knowledge proofs.
pub type CryptographicParameters = crate::id::types::GlobalContext<crate::id::constants::ArCurve>;

#[derive(SerdeSerialize, PartialEq, Eq, SerdeDeserialize, Debug)]
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
    pub self_amount:       crate::encrypted_transfers::types::EncryptedAmount<ArCurve>,
    /// Starting index for incoming encrypted amounts. If an aggregated amount
    /// is present then this index is associated with such an amount and the
    /// list of incoming encrypted amounts starts at the index `start_index
    /// + 1`.
    pub start_index:       u64,
    #[serde(default)]
    /// If ['Some'], the amount that has resulted from aggregating other amounts
    /// and the number of aggregated amounts (must be at least 2 if
    /// present).
    pub aggregated_amount: Option<(
        crate::encrypted_transfers::types::EncryptedAmount<ArCurve>,
        u32,
    )>,
    /// Amounts starting at `start_index` (or at `start_index + 1` if there is
    /// an aggregated amount present). They are assumed to be numbered
    /// sequentially. The length of this list is bounded by the maximum number
    /// of incoming amounts on the accounts, which is currently 32. After
    /// that aggregation kicks in.
    pub incoming_amounts:  Vec<crate::encrypted_transfers::types::EncryptedAmount<ArCurve>>,
}

/// Context that speeds up decryption of encrypted amounts.
#[derive(Debug)]
pub struct EncryptedAmountDecryptionContext<'a> {
    params: &'a concordium_base::id::types::GlobalContext<ArCurve>,
    table:  elgamal::BabyStepGiantStep<EncryptedAmountsCurve>,
}

impl<'a> EncryptedAmountDecryptionContext<'a> {
    /// Construct the decryption context from cryptographic parameters.
    /// It is crucial that the cryptographic parameters are for the right chain.
    /// Otherwise decryption with the constructed context will not
    /// terminate.
    pub fn new(
        params: &'a concordium_base::id::types::GlobalContext<EncryptedAmountsCurve>,
    ) -> Self {
        Self {
            params,
            table: elgamal::BabyStepGiantStep::new(
                params.encryption_in_exponent_generator(),
                1 << 16,
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MakeEncryptedTransferError {
    #[error(
        "Attempt to transfer too many CCD. Encrypted balance is {existing} but {requested} was \
         requested."
    )]
    InsufficientAmount {
        /// An existing encrypted amount.
        existing:  Amount,
        /// An amount that was attempted to be transferred.
        requested: Amount,
    },
    #[error("Cannot produce proof.")]
    FailedToProve,
}

impl AccountEncryptedAmount {
    /// Decrypt all the encrypted amounts and combine them in preparation for
    /// sending an encrypted transfer.
    pub fn decrypt_and_combine(
        &self,
        ctx: &EncryptedAmountDecryptionContext,
        sk: &elgamal::SecretKey<EncryptedAmountsCurve>,
    ) -> AggregatedDecryptedAmount<EncryptedAmountsCurve> {
        let table = &ctx.table;
        let mut combined = self.self_amount.clone();
        let mut agg_amount = encrypted_transfers::decrypt_amount(table, sk, &self.self_amount);
        let mut index = self.start_index;
        if let Some((agg, num_agg)) = self.aggregated_amount.as_ref() {
            agg_amount += encrypted_transfers::decrypt_amount(table, sk, agg);
            combined = encrypted_transfers::aggregate(&combined, agg);
            index += u64::from(*num_agg);
        }
        for amount in &self.incoming_amounts {
            agg_amount += encrypted_transfers::decrypt_amount(table, sk, amount);
            combined = encrypted_transfers::aggregate(&combined, amount);
            index += 1;
        }
        AggregatedDecryptedAmount {
            agg_encrypted_amount: combined,
            agg_amount,
            agg_index: index.into(),
        }
    }

    /// Construct the payload of a transfer from encrypted to public balance of
    /// the same account.
    pub fn make_transfer_to_public_data<R: rand::CryptoRng + rand::Rng>(
        &self,
        ctx: &EncryptedAmountDecryptionContext,
        sk: &elgamal::SecretKey<ArCurve>,
        amount: Amount,
        rng: &mut R,
    ) -> Result<SecToPubAmountTransferData<EncryptedAmountsCurve>, MakeEncryptedTransferError> {
        let agg_amount = self.decrypt_and_combine(ctx, sk);
        if amount <= agg_amount.agg_amount {
            let data = encrypted_transfers::make_sec_to_pub_transfer_data(
                ctx.params,
                sk,
                &agg_amount,
                amount,
                rng,
            )
            .ok_or(MakeEncryptedTransferError::FailedToProve)?;
            Ok(data)
        } else {
            Err(MakeEncryptedTransferError::InsufficientAmount {
                existing:  agg_amount.agg_amount,
                requested: amount,
            })
        }
    }

    /// Construct the payload of an encrypted transfer to another address.
    /// The arguments are ...
    pub fn make_encrypted_transfer_data<R: rand::CryptoRng + rand::Rng>(
        &self,
        ctx: &EncryptedAmountDecryptionContext,
        sk: &elgamal::SecretKey<ArCurve>,
        amount: Amount,
        receiver_pk: &elgamal::PublicKey<EncryptedAmountsCurve>,
        rng: &mut R,
    ) -> Result<EncryptedAmountTransferData<EncryptedAmountsCurve>, MakeEncryptedTransferError>
    {
        let agg_amount = self.decrypt_and_combine(ctx, sk);
        if amount <= agg_amount.agg_amount {
            let data = encrypted_transfers::make_transfer_data(
                ctx.params,
                receiver_pk,
                sk,
                &agg_amount,
                amount,
                rng,
            )
            .ok_or(MakeEncryptedTransferError::FailedToProve)?;
            Ok(data)
        } else {
            Err(MakeEncryptedTransferError::InsufficientAmount {
                existing:  agg_amount.agg_amount,
                requested: amount,
            })
        }
    }
}
#[derive(SerdeSerialize, SerdeDeserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
/// State of the account's release schedule. This is the balance of the account
/// that is owned by the account, but cannot be used until the release point.
pub struct AccountReleaseSchedule {
    /// Total amount that is locked up in releases.
    pub total:    Amount,
    /// List of timestamped releases. In increasing order of timestamps.
    pub schedule: Vec<Release>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Eq, PartialEq)]
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, PartialEq)]
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum AccountStakingInfo {
    #[serde(rename_all = "camelCase")]
    /// The account is a baker.
    Baker {
        staked_amount:    Amount,
        restake_earnings: bool,
        #[serde(flatten)]
        baker_info:       Box<BakerInfo>,
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, PartialEq)]
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, PartialEq)]
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, PartialEq)]
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

#[derive(SerdeSerialize, SerdeDeserialize, PartialEq, Debug, Clone, Copy)]
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

#[derive(Debug, Clone, Copy, PartialEq)]
/// Information about a registered passive or pool delegator.
pub struct DelegatorInfo {
    /// The delegator account address.
    pub account:        AccountAddress,
    /// The amount of stake currently staked to the pool.
    pub stake:          Amount,
    /// Pending change to the current stake of the delegator.
    pub pending_change: Option<StakePendingChange>,
}

#[derive(Debug, Clone, Copy)]
/// Information about a passive or pool delegator fixed in a reward period.
pub struct DelegatorRewardPeriodInfo {
    /// The delegator account address.
    pub account: AccountAddress,
    /// The amount of stake currently staked to the pool.
    pub stake:   Amount,
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy, PartialEq)]
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, PartialEq)]
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
/// The state of the baker currently registered on the account.
/// Current here means "present". This is the information that is being updated
/// by transactions (and rewards). This is in contrast to "epoch baker" which is
/// the state of the baker that is currently eligible for baking.
pub struct BakerPoolStatus {
    /// The 'BakerId' of the pool owner.
    pub baker_id:                   BakerId,
    /// The account address of the pool owner.
    pub baker_address:              AccountAddress,
    /// The equity capital provided by the pool owner.
    pub baker_equity_capital:       Amount,
    /// The capital delegated to the pool by other accounts.
    pub delegated_capital:          Amount,
    /// The maximum amount that may be delegated to the pool, accounting for
    /// leverage and stake limits.
    pub delegated_capital_cap:      Amount,
    /// The pool info associated with the pool: open status, metadata URL
    /// and commission rates.
    pub pool_info:                  BakerPoolInfo,
    /// Any pending change to the baker's stake.
    pub baker_stake_pending_change: PoolPendingChange,
    /// Status of the pool in the current reward period. This will be [`None`]
    /// if the pool is not a
    pub current_payday_status:      Option<CurrentPaydayBakerPoolStatus>,
    /// Total capital staked across all pools.
    pub all_pool_total_capital:     Amount,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// State of the passive delegation pool at present. Changes to delegation,
/// e.g., an account deciding to delegate are reflected in this structure at
/// first.
pub struct PassiveDelegationStatus {
    /// The total capital delegated passively.
    pub delegated_capital: Amount,
    /// The passive delegation commission rates.
    pub commission_rates: CommissionRates,
    /// The transaction fees accruing to the passive delegators in the
    /// current reward period.
    pub current_payday_transaction_fees_earned: Amount,
    /// The effective delegated capital to the passive delegators for the
    /// current reward period.
    pub current_payday_delegated_capital: Amount,
    /// Total capital staked across all pools, including passive delegation.
    pub all_pool_total_capital: Amount,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "poolType")]
pub enum PoolStatus {
    #[serde(rename_all = "camelCase")]
    BakerPool {
        #[serde(flatten)]
        status: BakerPoolStatus,
    },
    #[serde(rename_all = "camelCase")]
    PassiveDelegation {
        #[serde(flatten)]
        status: PassiveDelegationStatus,
    },
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
    Finalized(BTreeMap<hashes::BlockHash, BlockItemSummary>), /* TODO: Change to tuple instead
                                                               * of map when deprecating use of
                                                               * gRPC v1. */
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
        data:             super::BlockSummaryData<serde_json::Value>,
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
                P4 | P5 => {
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
    /// Return whether the transaction was successful, i.e., the intended effect
    /// happened.
    pub fn is_success(&self) -> bool {
        match &self.details {
            BlockItemSummaryDetails::AccountTransaction(ad) => ad.is_rejected().is_none(),
            BlockItemSummaryDetails::AccountCreation(_) => true,
            BlockItemSummaryDetails::Update(_) => true,
        }
    }

    /// Return whether the transaction has failed to achieve the intended
    /// effects.
    pub fn is_reject(&self) -> bool {
        match &self.details {
            BlockItemSummaryDetails::AccountTransaction(ad) => ad.is_rejected().is_some(),
            BlockItemSummaryDetails::AccountCreation(_) => false,
            BlockItemSummaryDetails::Update(_) => false,
        }
    }

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
                            ContractTraceElement::Upgraded { .. } => (),
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

    /// If the block item is a smart contract init transaction then
    /// return the initialization data.
    pub fn contract_init(&self) -> Option<&ContractInitializedEvent> {
        if let BlockItemSummaryDetails::AccountTransaction(at) = &self.details {
            match &at.effects {
                AccountTransactionEffects::ContractInitialized { data } => Some(data),
                AccountTransactionEffects::ContractUpdateIssued { .. } => None,
                _ => None,
            }
        } else {
            None
        }
    }

    /// If the block item is a smart contract update transaction then return
    /// an iterator over pairs of a contract address that was affected, and the
    /// logs that were produced.
    pub fn contract_update_logs(
        &self,
    ) -> Option<impl Iterator<Item = (ContractAddress, &[smart_contracts::ContractEvent])>> {
        if let BlockItemSummaryDetails::AccountTransaction(at) = &self.details {
            match &at.effects {
                AccountTransactionEffects::ContractInitialized { .. } => None,
                AccountTransactionEffects::ContractUpdateIssued { effects } => {
                    let iter = effects.iter().flat_map(|effect| match effect {
                        ContractTraceElement::Updated { data } => {
                            Some((data.address, &data.events[..]))
                        }
                        ContractTraceElement::Transferred { .. } => None,
                        ContractTraceElement::Interrupted { address, events } => {
                            Some((*address, &events[..]))
                        }
                        ContractTraceElement::Resumed { .. } => None,
                        ContractTraceElement::Upgraded { .. } => None,
                    });
                    Some(iter)
                }
                _ => None,
            }
        } else {
            None
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
                            ContractTraceElement::Upgraded { .. } => (),
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
    /// A contract transferred an amount to the account.
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
    Upgraded {
        /// Address of the instance that was upgraded.
        address: ContractAddress,
        /// The existing module reference that is in effect before the upgrade.
        from:    smart_contracts::ModuleRef,
        /// The new module reference that is in effect after the upgrade.
        to:      smart_contracts::ModuleRef,
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
        // TODO: Consider combining this with the non-memo version when we move to gRPC v2 and have
        // Option<Memo>.
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
        // TODO: Consider combining this with the non-memo version when we move to gRPC v2 and have
        // Option<Memo>. FIXME: It would be better to only have one pointer
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
        // TODO: Consider combining this with the non-memo version when we move to gRPC v2 and have
        // Option<Memo>.
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
    pub new_index:        crate::encrypted_transfers::types::EncryptedAmountIndex,
    /// The encrypted amount that was added.
    pub encrypted_amount: crate::encrypted_transfers::types::EncryptedAmount<EncryptedAmountsCurve>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Event generated when one or more encrypted amounts are consumed from the
/// account.
pub struct EncryptedAmountRemovedEvent {
    /// The affected account.
    pub account:      AccountAddress,
    /// The new self encrypted amount on the affected account.
    pub new_amount:   crate::encrypted_transfers::types::EncryptedAmount<EncryptedAmountsCurve>,
    /// The input encrypted amount that was removed.
    pub input_amount: crate::encrypted_transfers::types::EncryptedAmount<EncryptedAmountsCurve>,
    /// The index indicating which amounts were used.
    pub up_to_index:  crate::encrypted_transfers::types::EncryptedAmountAggIndex,
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
    pub new_amount: crate::encrypted_transfers::types::EncryptedAmount<EncryptedAmountsCurve>,
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

// re-export for backwards compatibility
pub use concordium_base::{
    transactions::{Memo, RegisteredData, TransactionType},
    updates::*,
};

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

impl<Auths: Serial> Serial for UpdateKeysCollectionSkeleton<Auths> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        self.root_keys.serial(out);
        self.level_1_keys.serial(out);
        self.level_2_keys.serial(out);
    }
}

impl<Auths: Deserial> Deserial for UpdateKeysCollectionSkeleton<Auths> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let root_keys = source.get()?;
        let level_1_keys = source.get()?;
        let level_2_keys = source.get()?;
        Ok(Self {
            root_keys,
            level_1_keys,
            level_2_keys,
        })
    }
}

pub type UpdateKeysCollection<CPV> = UpdateKeysCollectionSkeleton<Authorizations<CPV>>;

#[derive(Serialize, Debug, SerdeSerialize, SerdeDeserialize)]
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

#[derive(Serialize, Debug, SerdeSerialize, SerdeDeserialize)]
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

impl<MD: common::Serial> common::Serial for RewardParametersSkeleton<MD> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        self.mint_distribution.serial(out);
        self.transaction_fee_distribution.serial(out);
        self.gas_rewards.serial(out)
    }
}

impl<MD: common::Deserial> common::Deserial for RewardParametersSkeleton<MD> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mint_distribution = source.get()?;
        let transaction_fee_distribution = source.get()?;
        let gas_rewards = source.get()?;
        Ok(Self {
            mint_distribution,
            transaction_fee_distribution,
            gas_rewards,
        })
    }
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
    pub add_anonymity_revoker: UpdateQueue<crate::id::types::ArInfo<crate::id::constants::ArCurve>>,
    pub add_identity_provider:
        UpdateQueue<crate::id::types::IpInfo<crate::id::constants::IpPairing>>,
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
    pub add_anonymity_revoker: UpdateQueue<crate::id::types::ArInfo<crate::id::constants::ArCurve>>,
    pub add_identity_provider:
        UpdateQueue<crate::id::types::IpInfo<crate::id::constants::IpPairing>>,
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

/// The network information of a node.
#[derive(Debug)]
pub struct NetworkInfo {
    /// An identifier which it uses to identify itself to other peers and it
    /// is used for logging purposes internally. NB. The 'node_id' is spoofable
    /// and as such should not serve as a trust instrument.
    pub node_id:             String,
    /// The total amount of packets sent by the node.
    pub peer_total_sent:     u64,
    /// The total amount of packets received by the node.
    pub peer_total_received: u64,
    /// The average bytes per second received by the node.
    pub avg_bps_in:          u64,
    /// The average bytes per second transmitted by the node.
    pub avg_bps_out:         u64,
}

// Details of the consensus protocol running on the node.
#[derive(Debug)]
pub enum NodeConsensusStatus {
    /// The consensus protocol is not running on the node.
    /// This only occurs when the node does not support the protocol on the
    /// chain or the node is a 'Bootstrapper'.
    ConsensusNotRunning,
    /// The node is a passive member of the consensus. This means:
    /// * The node is processing blocks.
    /// * The node is relaying transactions and blocks onto the network.
    /// * The node is responding to catch up messages from its peers.
    /// * In particular this means that the node is __not__ baking blocks.
    ConsensusPassive,
    /// The node has been configured with baker keys however it is not currently
    /// baking and possilby never will.
    NotInCommittee(crate::types::BakerId),
    /// The baker keys are registered however the baker is not in the committee
    /// for the current 'Epoch'.
    AddedButNotActiveInCommittee(crate::types::BakerId),
    /// The node has been configured with baker keys that does not match the
    /// account.
    AddedButWrongKeys(crate::types::BakerId),
    /// The node is member of the baking committee.
    Baker(crate::types::BakerId),
    /// The node is member of the baking and finalization committee.
    Finalizer(crate::types::BakerId),
}

/// Consensus related information for a node.
#[derive(Debug)]
pub enum NodeDetails {
    /// The node is a bootstrapper and does not
    /// run the consensus protocol.
    Bootstrapper,
    /// The node is a regular node and is eligible for
    /// running the consensus protocol.
    Node(NodeConsensusStatus),
}

#[derive(Debug)]
/// The status of the requested node.
pub struct NodeInfo {
    /// The version of the node.
    pub version:      semver::Version,
    /// The local (UTC) time of the node.
    pub local_time:   chrono::DateTime<chrono::Utc>,
    /// How long the node has been alive.
    pub uptime:       chrono::Duration,
    /// Information related to the network for the node.
    pub network_info: NetworkInfo,
    /// Information related to consensus for the node.
    pub details:      NodeDetails,
}

#[derive(Debug, SerdeDeserialize)]
#[serde(try_from = "wallet_account_json::VersionedWalletAccount")]
/// An account imported from one of the supported export formats.
/// In particular the `serde` instance supports the browser wallet key export
/// format, but there are other constructors available.
///
/// This structure implements [`TransactionSigner`] and
/// [`ExactSizeTransactionSigner`] so it may be used for sending transactions.
///
/// This structure does not have the encryption key for sending encrypted
/// transfers, it only contains keys for signing transactions.
pub struct WalletAccount {
    pub address: AccountAddress,
    pub keys:    AccountKeys,
}

impl TransactionSigner for WalletAccount {
    fn sign_transaction_hash(
        &self,
        hash_to_sign: &hashes::TransactionSignHash,
    ) -> common::types::TransactionSignature {
        self.keys.sign_transaction_hash(hash_to_sign)
    }
}

impl ExactSizeTransactionSigner for WalletAccount {
    fn num_keys(&self) -> u32 { self.keys.num_keys() }
}

impl WalletAccount {
    /// Attempt to construct a [`WalletAccount`] from the genesis account in
    /// JSON. This format of an account is generated by the genesis tool.
    pub fn from_genesis_account(gen_acc_data: &str) -> Result<Self, serde_json::Error> {
        let ad = serde_json::from_str(gen_acc_data)?;
        Self::from_genesis_account_value(ad)
    }

    /// Attempt to construct a [`WalletAccount`] from the genesis account in
    /// JSON. This format of an account is generated by the genesis tool.
    pub fn from_genesis_account_value(
        gen_acc_data: serde_json::Value,
    ) -> Result<Self, serde_json::Error> {
        #[derive(SerdeDeserialize)]
        #[serde(rename_all = "camelCase")]
        struct AccountData {
            account_keys: AccountKeys,
            address:      AccountAddress,
        }
        let ad = serde_json::from_value::<AccountData>(gen_acc_data)?;
        Ok(Self {
            address: ad.address,
            keys:    ad.account_keys,
        })
    }

    /// Attempt to read a wallet account from a number of formats. The currently
    /// supported formats are genesis accounts and browser extension wallet
    /// format.
    pub fn from_json_value(data: serde_json::Value) -> Result<Self, serde_json::Error> {
        if let Some(obj) = data.as_object() {
            // The browser extension export has a type field. If this is set attempt to
            // parse it as that format.
            if obj.contains_key("type") {
                return serde_json::from_value::<Self>(data);
            }
        }
        Self::from_genesis_account_value(data)
    }

    /// Helper for reading keys from files or other readers directly. See
    /// [`from_json`](Self::from_json) for details.
    pub fn from_json_reader(reader: impl std::io::Read) -> Result<Self, serde_json::Error> {
        let v = serde_json::from_reader(reader)?;
        Self::from_json_value(v)
    }

    /// Helper for reading keys from strings. See
    /// [`from_json`](Self::from_json) for details.
    pub fn from_json_str(reader: &str) -> Result<Self, serde_json::Error> {
        let v = serde_json::from_str(reader)?;
        Self::from_json_value(v)
    }

    /// Helper for reading keys from files. See
    /// [`from_json`](Self::from_json) for details.
    pub fn from_json_file(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        Ok(Self::from_json_reader(
            std::fs::File::open(path).context("Unable to open key file.")?,
        )?)
    }
}

mod wallet_account_json {
    use concordium_base::common::{Version, VERSION_0};

    use super::*;

    #[derive(Debug, SerdeDeserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WalletAccount {
        account_keys: AccountKeys,
        pub address:  AccountAddress,
    }

    #[derive(Debug, SerdeDeserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VersionedWalletAccount {
        r#type: String,
        v:      Version,
        value:  WalletAccount,
    }

    impl TryFrom<VersionedWalletAccount> for super::WalletAccount {
        type Error = anyhow::Error;

        fn try_from(value: VersionedWalletAccount) -> Result<Self, Self::Error> {
            if value.v == VERSION_0 && value.r#type == "concordium-browser-wallet-account" {
                Ok(Self {
                    address: value.value.address,
                    keys:    value.value.account_keys,
                })
            } else {
                anyhow::bail!("Unexpected wallet export version.")
            }
        }
    }
}
