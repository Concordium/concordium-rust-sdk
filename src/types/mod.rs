//! Type definitions used throughout the rest of the SDK.
use anyhow::Context;
pub use concordium_base::hashes;
// re-export to maintain backwards compatibility.
pub use concordium_base::id::types::CredentialType;
pub mod block_certificates;
pub mod network;
pub mod queries;
pub mod smart_contracts;
mod summary_helper;
pub mod transactions;

use crate::constants::*;
pub use concordium_base::{
    base::*,
    smart_contracts::{ContractTraceElement, InstanceUpdatedEvent},
};
use concordium_base::{
    common::{
        self,
        types::{Amount, CredentialIndex, Timestamp, TransactionTime},
        Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
        Versioned,
    },
    contracts_common::{Duration, EntrypointName, Parameter},
    encrypted_transfers,
    encrypted_transfers::types::{
        AggregatedDecryptedAmount, EncryptedAmountTransferData, SecToPubAmountTransferData,
    },
    id::{
        constants::{ArCurve, AttributeKind},
        elgamal,
        types::{
            AccountAddress, AccountCredentialWithoutProofs, AccountKeys, CredentialPublicKeys,
        },
    },
    smart_contracts::{
        ContractEvent, ModuleReference, OwnedParameter, OwnedReceiveName, WasmVersion,
    },
    transactions::{AccountAccessStructure, ExactSizeTransactionSigner, TransactionSigner},
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
    /// - remaining amounts that result when transferring to public balance
    /// - remaining amounts when transferring to another account
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
        #[allow(deprecated)]
        if let Some((agg, num_agg)) = self.aggregated_amount.as_ref() {
            agg_amount += encrypted_transfers::decrypt_amount(table, sk, agg);
            combined = encrypted_transfers::aggregate(&combined, agg);
            index += u64::from(*num_agg);
        }
        #[allow(deprecated)]
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
            #[allow(deprecated)]
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
        /// A flag indicating whether the baker is currently suspended or not.
        /// The flag will always be `false` for protocol versions before version
        /// 8. A suspended validator will not be included in the validator
        /// committee the next time it is calculated.
        is_suspended:     bool,
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

/// The status of a cooldown. When stake is removed from a baker or delegator
/// (from protocol version 7) it first enters the pre-pre-cooldown state.
/// The next time the stake snaphot is taken (at the epoch transition before
/// a payday) it enters the pre-cooldown state. At the subsequent payday, it
/// enters the cooldown state. At the payday after the end of the cooldown
/// period, the stake is finally released.
#[derive(SerdeSerialize, SerdeDeserialize, Debug, PartialEq)]
pub enum CooldownStatus {
    /// The amount is in cooldown and will expire at the specified time,
    /// becoming available at the subsequent pay day.
    Cooldown,

    /// The amount will enter cooldown at the next pay day. The specified
    /// end time is projected to be the end of the cooldown period,
    /// but the actual end time will be determined at the payday,
    /// and may be different if the global cooldown period changes.
    PreCooldown,

    /// The amount will enter pre-cooldown at the next snapshot epoch (i.e.
    /// the epoch transition before a pay day transition). As with
    /// pre-cooldown, the specified end time is projected, but the
    /// actual end time will be determined later.
    PrePreCooldown,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Cooldown {
    /// The time in milliseconds since the Unix epoch when the cooldown period
    /// ends.
    pub end_time: Timestamp,

    /// The amount that is in cooldown and set to be released at the end of the
    /// cooldown period.
    pub amount: Amount,

    /// The status of the cooldown.
    pub status: CooldownStatus,
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

    /// The stake on the account that is in cooldown.
    /// There can be multiple amounts in cooldown that expire at different
    /// times.
    /// Empty for nodes using protocol version 6 or lower.
    pub cooldowns: Vec<Cooldown>,

    /// The available (unencrypted) balance of the account (i.e. that can be
    /// transferred or used to pay for transactions). This is the balance
    /// minus the locked amount. The locked amount is the maximum of the
    /// amount in the release schedule and the total amount that is actively
    /// staked or in cooldown (inactive stake).
    pub available_balance: Amount,
}

impl From<&AccountInfo> for AccountAccessStructure {
    fn from(value: &AccountInfo) -> Self {
        Self {
            keys:      value
                .account_credentials
                .iter()
                .map(|(idx, v)| {
                    let key = match v.value {
                        crate::id::types::AccountCredentialWithoutProofs::Initial { ref icdv } => {
                            icdv.cred_account.clone()
                        }
                        crate::id::types::AccountCredentialWithoutProofs::Normal {
                            ref cdv,
                            ..
                        } => cdv.cred_key_info.clone(),
                    };
                    (*idx, key)
                })
                .collect(),
            threshold: value.account_threshold,
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
/// The state of consensus parameters, and allowed participants (i.e., bakers).
pub struct BirkParameters {
    /// Current election difficulty. This is only present for protocol versions
    /// 1-5.
    pub election_difficulty: Option<ElectionDifficulty>,
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

#[derive(SerdeSerialize, SerdeDeserialize, PartialEq, Eq, Debug, Clone, Copy)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
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
    /// The commission rates that apply for the current reward period for the
    /// baker pool.
    pub commission_rates:        CommissionRates,
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
    pub baker_id:                 BakerId,
    /// The account address of the pool owner.
    pub baker_address:            AccountAddress,
    /// The active status of the pool. This reflects any changes to the pool
    /// since the last snapshot.
    pub active_baker_pool_status: Option<ActiveBakerPoolStatus>,
    /// Status of the pool in the current reward period. This will be [`None`]
    /// if the pool is not a baker in the payday (e.g., because they just
    /// registered and a new payday has not started yet).
    pub current_payday_status:    Option<CurrentPaydayBakerPoolStatus>,
    /// Total capital staked across all pools.
    pub all_pool_total_capital:   Amount,
}

// Information about a baker pool's active stake and status. This does not
// reflect the stake used for the current reward period, but rather the stake
// that is currently active.
#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActiveBakerPoolStatus {
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
        /// Remaining balance of the baking account. This will be transferred to
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
    /// A validator was suspended due to too many missed rounds.
    #[serde(rename_all = "camelCase")]
    ValidatorSuspended {
        /// The validator that was suspended.
        baker_id: BakerId,
        /// The account address of the validator.
        account:  AccountAddress,
    },
    /// A validator was primed to be suspended at the next snapshot epoch due to
    /// too many missed rounds.
    #[serde(rename_all = "camelCase")]
    ValidatorPrimedForSuspension {
        /// The validator that was primed for suspension.
        baker_id: BakerId,
        /// The account address of the validator.
        account:  AccountAddress,
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
            SpecialTransactionOutcome::ValidatorSuspended { account, .. } => {
                vec![*account]
            }
            SpecialTransactionOutcome::ValidatorPrimedForSuspension { account, .. } => {
                vec![*account]
            }
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

#[derive(Debug)]
/// Summary of transactions, protocol generated transfers, and chain parameters
/// in a given block.
pub enum BlockSummary {
    V0 {
        /// Protocol version at which this block was baked. This is no more than
        /// [`ProtocolVersion::P3`]
        protocol_version: ProtocolVersion,
        data:             BlockSummaryData<Updates<ChainParameterVersion0>>,
    },
    V1 {
        /// Protocol version at which this block was baked. This is at least
        /// [`ProtocolVersion::P4`]
        protocol_version: ProtocolVersion,
        data:             BlockSummaryData<Updates<ChainParameterVersion1>>,
    },
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
    pub fn is_reject(&self) -> bool { self.is_rejected_account_transaction().is_some() }

    /// Return `Some` if the result corresponds to a rejected account
    /// transaction. This returns `Some` if and only if
    /// [`is_reject`](Self::is_reject) returns `true`.
    pub fn is_rejected_account_transaction(&self) -> Option<&RejectReason> {
        match &self.details {
            BlockItemSummaryDetails::AccountTransaction(ad) => ad.is_rejected(),
            BlockItemSummaryDetails::AccountCreation(_) => None,
            BlockItemSummaryDetails::Update(_) => None,
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

    /// If the block item is a smart contract update transaction then return the
    /// execution tree.
    pub fn contract_update(self) -> Option<ExecutionTree> {
        if let BlockItemSummaryDetails::AccountTransaction(at) = self.details {
            match at.effects {
                AccountTransactionEffects::ContractInitialized { .. } => None,
                AccountTransactionEffects::ContractUpdateIssued { effects } => {
                    execution_tree(effects)
                }
                _ => None,
            }
        } else {
            None
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
    ) -> Option<impl Iterator<Item = (ContractAddress, &[smart_contracts::ContractEvent])> + '_>
    {
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

#[derive(Debug, PartialEq)]
/// A result of updating a smart contract instance.
pub enum ExecutionTree {
    /// The top-level call was a V0 contract instance update.
    V0(ExecutionTreeV0),
    /// The top-level call was a V1 contract instance update.
    V1(ExecutionTreeV1),
}

impl ExecutionTree {
    /// Return the name of the top-level entrypoint that was invoked.
    pub fn entrypoint(&self) -> EntrypointName {
        match self {
            ExecutionTree::V0(v0) => v0
                .top_level
                .receive_name
                .as_receive_name()
                .entrypoint_name(),
            ExecutionTree::V1(v1) => v1.receive_name.as_receive_name().entrypoint_name(),
        }
    }

    /// Return the name of the top-level contract that was invoked.
    pub fn address(&self) -> ContractAddress {
        match self {
            ExecutionTree::V0(v0) => v0.top_level.address,
            ExecutionTree::V1(v1) => v1.address,
        }
    }

    /// Return parameter to the top-level contract call.
    pub fn parameter(&self) -> Parameter {
        match self {
            ExecutionTree::V0(v0) => v0.top_level.message.as_parameter(),
            ExecutionTree::V1(v1) => v1.message.as_parameter(),
        }
    }

    /// Return a set of contract addresses that appear in this execution
    /// tree, together with a set of [receive names](OwnedReceiveName) that
    /// were called for that contract address.
    pub fn affected_addresses(&self) -> BTreeMap<ContractAddress, BTreeSet<OwnedReceiveName>> {
        let mut addresses = BTreeMap::<ContractAddress, BTreeSet<_>>::new();
        let mut todo = vec![self];
        while let Some(head) = todo.pop() {
            match head {
                ExecutionTree::V0(v0) => {
                    addresses
                        .entry(v0.top_level.address)
                        .or_default()
                        .insert(v0.top_level.receive_name.clone());
                    for rest in &v0.rest {
                        if let TraceV0::Call(call) = rest {
                            todo.push(call);
                        }
                    }
                }
                ExecutionTree::V1(v1) => {
                    addresses
                        .entry(v1.address)
                        .or_default()
                        .insert(v1.receive_name.clone());
                    for event in &v1.events {
                        if let TraceV1::Call { call } = event {
                            todo.push(call);
                        }
                    }
                }
            }
        }
        addresses
    }

    /// Get an iterator over the events logged by the contracts that were called
    /// as part of the execution tree. The iterator returns triples of the
    /// `(address, entrypoint, logs)` where the meaning is that the contract
    /// at the given address, while executing the entrypoint `entrypoint`
    /// produced the `logs`. Note that the `logs` might be an empty slice.
    pub fn events(
        &self,
    ) -> impl Iterator<
        Item = (
            ContractAddress,
            EntrypointName<'_>,
            &[smart_contracts::ContractEvent],
        ),
    > + '_ {
        // An auxiliary type used to store the list of next items produced by
        // the [`EventsIterator`]
        enum LogsIteratorNext<'a> {
            Tree(&'a ExecutionTree),
            Events(
                (
                    ContractAddress,
                    EntrypointName<'a>,
                    &'a [smart_contracts::ContractEvent],
                ),
            ),
        }

        struct LogsIterator<'a> {
            // A stack of next items to process.
            next: Vec<LogsIteratorNext<'a>>,
        }

        impl<'a> Iterator for LogsIterator<'a> {
            type Item = (
                ContractAddress,
                EntrypointName<'a>,
                &'a [smart_contracts::ContractEvent],
            );

            fn next(&mut self) -> Option<Self::Item> {
                while let Some(next) = self.next.pop() {
                    match next {
                        LogsIteratorNext::Events(r) => return Some(r),
                        LogsIteratorNext::Tree(next) => match next {
                            ExecutionTree::V0(v0) => {
                                let rv = (
                                    v0.top_level.address,
                                    v0.top_level
                                        .receive_name
                                        .as_receive_name()
                                        .entrypoint_name(),
                                    &v0.top_level.events[..],
                                );
                                for rest in v0.rest.iter().rev() {
                                    if let TraceV0::Call(call) = rest {
                                        self.next.push(LogsIteratorNext::Tree(call));
                                    }
                                }
                                return Some(rv);
                            }
                            ExecutionTree::V1(v1) => {
                                for event in v1.events.iter().rev() {
                                    match event {
                                        TraceV1::Events { events } => {
                                            self.next.push(LogsIteratorNext::Events((
                                                v1.address,
                                                v1.receive_name.as_receive_name().entrypoint_name(),
                                                events,
                                            )))
                                        }
                                        TraceV1::Call { call } => {
                                            self.next.push(LogsIteratorNext::Tree(call));
                                        }
                                        TraceV1::Transfer { .. } => (),
                                        TraceV1::Upgrade { .. } => (),
                                    }
                                }
                            }
                        },
                    }
                }
                None
            }
        }

        LogsIterator {
            next: vec![LogsIteratorNext::Tree(self)],
        }
    }
}

/// Convert the trace elements into an [`ExecutionTree`].
/// This will fail if the list was not generated correctly, but if the list of
/// trace elements is coming from the node it will always be in the correct
/// format.
pub fn execution_tree(elements: Vec<ContractTraceElement>) -> Option<ExecutionTree> {
    #[derive(Debug)]
    struct PartialTree {
        address: ContractAddress,
        /// Whether the matching resume was seen for the interrupt.
        resumed: bool,
        events:  Vec<TraceV1>,
    }

    #[derive(Debug)]
    enum Worker {
        V0(ExecutionTreeV0),
        Partial(PartialTree),
    }

    // The current stack of calls. Stack is pushed on new interrupts (interrupts
    // that introduce new nested calls) and on calls to V0 contracts.
    let mut stack: Vec<Worker> = Vec::new();
    let mut elements = elements.into_iter();
    while let Some(element) = elements.next() {
        match element {
            ContractTraceElement::Updated {
                data:
                    InstanceUpdatedEvent {
                        contract_version,
                        address,
                        instigator,
                        amount,
                        message,
                        receive_name,
                        events,
                    },
            } => {
                if let Some(end) = stack.pop() {
                    let tree = match contract_version {
                        WasmVersion::V0 => ExecutionTree::V0(ExecutionTreeV0 {
                            top_level: UpdateV0 {
                                address,
                                instigator,
                                amount,
                                message,
                                receive_name,
                                events,
                            },
                            rest:      Vec::new(),
                        }),
                        WasmVersion::V1 => ExecutionTree::V1(ExecutionTreeV1 {
                            address,
                            instigator,
                            amount,
                            message,
                            receive_name,
                            events: vec![TraceV1::Events { events }],
                        }),
                    };
                    match end {
                        Worker::V0(mut v0) => {
                            v0.rest.push(TraceV0::Call(tree));
                            stack.push(Worker::V0(v0));
                        }
                        Worker::Partial(mut partial) => {
                            if partial.resumed {
                                // terminate it.
                                let ExecutionTree::V1(mut tree) = tree else {
                                    return None;
                                };
                                std::mem::swap(&mut tree.events, &mut partial.events);
                                tree.events.append(&mut partial.events);
                                if let Some(last) = stack.last_mut() {
                                    match last {
                                        Worker::V0(v0) => {
                                            v0.rest.push(TraceV0::Call(ExecutionTree::V1(tree)));
                                        }
                                        Worker::Partial(v0) => {
                                            v0.events.push(TraceV1::Call {
                                                call: ExecutionTree::V1(tree),
                                            });
                                        }
                                    }
                                } else {
                                    // and return it.
                                    if elements.next().is_none() {
                                        return Some(ExecutionTree::V1(tree));
                                    } else {
                                        return None;
                                    }
                                }
                            } else {
                                partial.events.push(TraceV1::Call { call: tree });
                                stack.push(Worker::Partial(partial));
                            }
                        }
                    }
                } else {
                    // no stack yet
                    match contract_version {
                        WasmVersion::V0 => stack.push(Worker::V0(ExecutionTreeV0 {
                            top_level: UpdateV0 {
                                address,
                                instigator,
                                amount,
                                message,
                                receive_name,
                                events,
                            },
                            rest:      Vec::new(),
                        })),
                        WasmVersion::V1 => {
                            let tree = ExecutionTreeV1 {
                                address,
                                instigator,
                                amount,
                                message,
                                receive_name,
                                events: vec![TraceV1::Events { events }],
                            };
                            // and return it.
                            if elements.next().is_none() {
                                return Some(ExecutionTree::V1(tree));
                            } else {
                                return None;
                            }
                        }
                    }
                }
            }
            ContractTraceElement::Transferred { from, amount, to } => {
                let last = stack.last_mut()?;
                match last {
                    Worker::V0(v0) => v0.rest.push(TraceV0::Transfer { from, amount, to }),
                    Worker::Partial(partial) => {
                        partial.events.push(TraceV1::Transfer { from, amount, to });
                    }
                }
            }
            ContractTraceElement::Interrupted { address, events } => match stack.last_mut() {
                Some(Worker::Partial(partial)) if partial.resumed => {
                    partial.resumed = false;
                    partial.events.push(TraceV1::Events { events })
                }
                _ => {
                    stack.push(Worker::Partial(PartialTree {
                        address,
                        resumed: false,
                        events: vec![TraceV1::Events { events }],
                    }));
                }
            },
            ContractTraceElement::Resumed {
                address,
                success: _,
            } => {
                match stack.pop()? {
                    Worker::V0(v0) => {
                        let Worker::Partial(partial) = stack.last_mut()? else {
                            return None;
                        };
                        partial.events.push(TraceV1::Call {
                            call: ExecutionTree::V0(v0),
                        });
                        partial.resumed = true;
                    }
                    Worker::Partial(mut partial) => {
                        if address != partial.address {
                            return None;
                        }
                        partial.resumed = true;
                        stack.push(Worker::Partial(partial));
                    }
                };
            }
            ContractTraceElement::Upgraded { address, from, to } => {
                let Worker::Partial(partial) = stack.last_mut()? else {
                    return None;
                };
                if address != partial.address {
                    return None;
                }
                // Put an upgrade event to the list, and continue.
                partial.events.push(TraceV1::Upgrade { from, to });
            }
        }
    }
    let Worker::V0(v0) = stack.pop()? else {
        return None;
    };
    if stack.is_empty() {
        Some(ExecutionTree::V0(v0))
    } else {
        None
    }
}

#[derive(Debug, PartialEq)]
pub struct UpdateV0 {
    /// Address of the affected instance.
    pub address:      ContractAddress,
    /// The origin of the message to the smart contract. This can be either
    /// an account or a smart contract.
    pub instigator:   Address,
    /// The amount the method was invoked with.
    pub amount:       Amount,
    /// The message passed to method.
    pub message:      OwnedParameter,
    /// The name of the method that was executed.
    pub receive_name: OwnedReceiveName,
    /// Events emitted by the contract call.
    pub events:       Vec<ContractEvent>,
}

#[derive(Debug, PartialEq)]
/// An update of a V0 contract with all of its subsequent trace elements in the
/// order they were executed. Note that some of those events might have been
/// generated by subsequent calls, not directly by the top-level call.
pub struct ExecutionTreeV0 {
    pub top_level: UpdateV0,
    pub rest:      Vec<TraceV0>,
}

#[derive(Debug, PartialEq)]
/// An action generated by a V0 contract.
pub enum TraceV0 {
    /// A contract call, either V0 or V1 contract with all its nested calls.
    Call(ExecutionTree),
    /// A transfer of CCD from the V0 contract to an account.
    Transfer {
        /// Sender contract.
        from:   ContractAddress,
        /// Amount transferred.
        amount: Amount,
        /// Receiver account.
        to:     AccountAddress,
    },
}

#[derive(Debug, PartialEq)]
/// An update of a V1 contract with all of its nested calls.
pub struct ExecutionTreeV1 {
    /// Address of the affected instance.
    pub address:      ContractAddress,
    /// The origin of the message to the smart contract. This can be either
    /// an account or a smart contract.
    pub instigator:   Address,
    /// The amount the method was invoked with.
    pub amount:       Amount,
    /// The message passed to method.
    pub message:      OwnedParameter,
    /// The name of the method that was executed.
    pub receive_name: OwnedReceiveName,
    /// A sequence of calls, transfers, etc. performed by the contract, in the
    /// order that they took effect.
    pub events:       Vec<TraceV1>,
}

#[derive(Debug, PartialEq)]
/// An operation performed directly by a V1 contract.
pub enum TraceV1 {
    /// New events emitted.
    Events { events: Vec<ContractEvent> },
    /// A successful call to another contract, either V0 or V1.
    Call { call: ExecutionTree },
    /// A transfer of CCD from the contract to the account.
    Transfer {
        /// Sender contract.
        from:   ContractAddress,
        /// Amount transferred.
        amount: Amount,
        /// Receiver account.
        to:     AccountAddress,
    },
    /// An upgrade of the contract instance.
    Upgrade {
        /// The existing module reference that is in effect before the upgrade.
        from: ModuleReference,
        /// The new module reference that is in effect after the upgrade.
        to:   ModuleReference,
    },
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
    /// [AccountTransactionEffects::None]
    /// variant in case the transaction failed with serialization failure
    /// reason.
    pub fn transaction_type(&self) -> Option<TransactionType> { self.effects.transaction_type() }

    /// Return [`Some`] if the transaction has been rejected.
    pub fn is_rejected(&self) -> Option<&RejectReason> { self.effects.is_rejected() }
}

impl AccountTransactionEffects {
    /// Get the transaction type corresponding to the effects.
    /// Returns `None` for the
    /// [AccountTransactionEffects::None]
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
            #[allow(deprecated)]
            AccountTransactionEffects::BakerAdded { .. } => Some(AddBaker),
            #[allow(deprecated)]
            AccountTransactionEffects::BakerRemoved { .. } => Some(RemoveBaker),
            #[allow(deprecated)]
            AccountTransactionEffects::BakerStakeUpdated { .. } => Some(UpdateBakerStake),
            #[allow(deprecated)]
            AccountTransactionEffects::BakerRestakeEarningsUpdated { .. } => {
                Some(UpdateBakerRestakeEarnings)
            }
            #[allow(deprecated)]
            AccountTransactionEffects::BakerKeysUpdated { .. } => Some(UpdateBakerKeys),
            #[allow(deprecated)]
            AccountTransactionEffects::EncryptedAmountTransferred { .. } => {
                Some(EncryptedAmountTransfer)
            }
            #[allow(deprecated)]
            AccountTransactionEffects::EncryptedAmountTransferredWithMemo { .. } => {
                Some(EncryptedAmountTransferWithMemo)
            }
            #[allow(deprecated)]
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
        module_ref: smart_contracts::ModuleReference,
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
    BakerRemoved {
        /// The id of the baker that was removed. If the account is a baker in
        /// the current payday, it will remain so until the next payday,
        /// although the baker record will be removed from the account
        /// immediately.
        baker_id: BakerId,
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
    /// Removed an existing delegator
    DelegationRemoved {
        /// The id of the delegator that was removed. If the account is a
        /// delegator in the current payday, it will remain so until the
        /// next payday, although the delegation record will be removed
        /// from the account immediately.
        delegator_id: DelegatorId,
    },
    /// The baker was suspended.
    BakerSuspended {
        // Baker's id
        baker_id: BakerId,
    },
    /// The baker was suspended.
    BakerResumed {
        // Baker's id
        baker_id: BakerId,
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
    pub origin_ref:       smart_contracts::ModuleReference,
    /// The newly assigned address of the contract.
    pub address:          ContractAddress,
    /// The amount the instance was initialized with.
    pub amount:           Amount,
    /// The name of the contract.
    pub init_name:        smart_contracts::OwnedContractName,
    /// Any contract events that might have been generated by the contract
    /// initialization.
    pub events:           Vec<smart_contracts::ContractEvent>,
    /// The parameter passed to the initializer. This should not be `None` when
    /// querying node version >= 8.
    pub parameter:        Option<smart_contracts::OwnedParameter>,
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

#[derive(common::Serialize, Debug, SerdeSerialize, SerdeDeserialize)]
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

#[derive(common::Serialize, Debug, SerdeSerialize, SerdeDeserialize)]
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

#[derive(common::Serialize, Debug)]
/// Values of chain parameters that can be updated via chain updates.
pub struct ChainParametersV2 {
    /// Consensus protocol version 2 timeout parameters.
    pub timeout_parameters:                TimeoutParameters,
    /// Minimum time interval between blocks.
    pub min_block_time:                    Duration,
    /// Maximum energy allowed per block.
    pub block_energy_limit:                Energy,
    /// Euro per energy exchange rate.
    pub euro_per_energy:                   ExchangeRate,
    /// Micro ccd per euro exchange rate.
    pub micro_ccd_per_euro:                ExchangeRate,
    pub cooldown_parameters:               CooldownParameters,
    pub time_parameters:                   TimeParameters,
    /// The limit for the number of account creations in a block.
    pub account_creation_limit:            CredentialsPerBlockLimit,
    /// Current reward parameters.
    pub reward_parameters:                 RewardParameters<ChainParameterVersion2>,
    /// Index of the foundation account.
    pub foundation_account_index:          AccountIndex,
    /// Parameters for baker pools.
    pub pool_parameters:                   PoolParameters,
    /// The finalization committee parameters.
    pub finalization_committee_parameters: FinalizationCommitteeParameters,
}

#[derive(common::Serialize, Debug)]
/// Values of chain parameters that can be updated via chain updates.
pub struct ChainParametersV3 {
    /// Consensus protocol version 2 timeout parameters.
    pub timeout_parameters:                TimeoutParameters,
    /// Minimum time interval between blocks.
    pub min_block_time:                    Duration,
    /// Maximum energy allowed per block.
    pub block_energy_limit:                Energy,
    /// Euro per energy exchange rate.
    pub euro_per_energy:                   ExchangeRate,
    /// Micro ccd per euro exchange rate.
    pub micro_ccd_per_euro:                ExchangeRate,
    pub cooldown_parameters:               CooldownParameters,
    pub time_parameters:                   TimeParameters,
    /// The limit for the number of account creations in a block.
    pub account_creation_limit:            CredentialsPerBlockLimit,
    /// Current reward parameters.
    pub reward_parameters:                 RewardParameters<ChainParameterVersion2>,
    /// Index of the foundation account.
    pub foundation_account_index:          AccountIndex,
    /// Parameters for baker pools.
    pub pool_parameters:                   PoolParameters,
    /// The finalization committee parameters.
    pub finalization_committee_parameters: FinalizationCommitteeParameters,
    /// Parameter for determining when a validator is considered inactive.
    pub validator_score_parameters:        ValidatorScoreParameters,
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

impl ChainParametersFamily for ChainParameterVersion2 {
    type Output = ChainParametersV2;
}

impl ChainParametersFamily for ChainParameterVersion3 {
    type Output = ChainParametersV3;
}

pub type ChainParameters<CPV> = <CPV as ChainParametersFamily>::Output;

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Values of reward parameters.
///
/// The concrete types for some of the fields depends on the version of chain
/// parameters, thus the generics. See [`RewardParameters`] for the connections
/// to the concrete types.
pub struct RewardParametersSkeleton<MintDistribution, GasRewards> {
    pub mint_distribution:            MintDistribution,
    pub transaction_fee_distribution: TransactionFeeDistribution,
    #[serde(rename = "gASRewards")]
    pub gas_rewards:                  GasRewards,
}

impl<MD: common::Serial, GR: common::Serial> common::Serial for RewardParametersSkeleton<MD, GR> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        self.mint_distribution.serial(out);
        self.transaction_fee_distribution.serial(out);
        self.gas_rewards.serial(out)
    }
}

impl<MD: common::Deserial, GR: common::Deserial> common::Deserial
    for RewardParametersSkeleton<MD, GR>
{
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

/// Values of reward parameters.
///
/// The concrete types for some of the fields depends on the version of chain
/// parameters. See implementations of [`MintDistribution`] and
/// [`GASRewardsFor`] for concrete types.
pub type RewardParameters<CPV> =
    RewardParametersSkeleton<MintDistribution<CPV>, GASRewardsFor<CPV>>;

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
        contents: smart_contracts::ModuleReference,
    },
    /// Account does not exist.
    InvalidAccountReference { contents: AccountAddress },
    /// Reference to a non-existing contract init method.
    InvalidInitMethod {
        contents: (
            smart_contracts::ModuleReference,
            smart_contracts::OwnedContractName,
        ),
    },
    /// Reference to a non-existing contract receive method.
    InvalidReceiveMethod {
        contents: (
            smart_contracts::ModuleReference,
            smart_contracts::OwnedReceiveName,
        ),
    },
    /// Reference to a non-existing module.
    InvalidModuleReference {
        contents: smart_contracts::ModuleReference,
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
        parameter:        smart_contracts::OwnedParameter,
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
    /// Attempt to remove the first credential
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
#[derive(Debug, Clone, Copy)]
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

impl NodeConsensusStatus {
    /// Retrieve the baker ID the node is configured with, if that is the case.
    pub fn baker(self) -> Option<BakerId> {
        match self {
            NodeConsensusStatus::ConsensusNotRunning => None,
            NodeConsensusStatus::ConsensusPassive => None,
            NodeConsensusStatus::NotInCommittee(bi) => Some(bi),
            NodeConsensusStatus::AddedButNotActiveInCommittee(bi) => Some(bi),
            NodeConsensusStatus::AddedButWrongKeys(bi) => Some(bi),
            NodeConsensusStatus::Baker(bi) => Some(bi),
            NodeConsensusStatus::Finalizer(bi) => Some(bi),
        }
    }
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

/// A baker that has won a round in consensus version 1.
#[derive(Debug)]
pub struct WinningBaker {
    /// The round that was won.
    pub round:   Round,
    /// The id of the baker that won the round.
    pub winner:  BakerId,
    /// Whether the block that was made (if any) is
    /// part of the finalized chain.
    pub present: bool,
}

/// An account that is pending either a scheduled release or a cooldown.
#[derive(Debug)]
pub struct AccountPending {
    /// The account that is pending.
    pub account_index:   AccountIndex,
    /// The timestamp at which the first pending event is set to occur.
    pub first_timestamp: Timestamp,
}

/// Information of a baker for a certain reward period.
#[derive(Debug)]
pub struct BakerRewardPeriodInfo {
    /// Baker id and public keys.
    pub baker:             BakerInfo,
    /// The stake of the baker that the
    /// consensus protocol uses to determine lottery weight.
    /// This is the stake after applying leverage bound and caps.
    /// If the baker is also a finalizer then the effective stake is
    /// also used to calculate the weight that the baker votes with as part of
    /// the finalization committee.
    pub effective_stake:   Amount,
    /// The effective commission rates for the baker that applies
    /// in the reward period.
    pub commission_rates:  CommissionRates,
    /// The amount that the baker staked itself in the
    /// reward period.
    pub equity_capital:    Amount,
    /// The amount that was delegated to the baker in the
    /// reward period.
    pub delegated_capital: Amount,
    /// Whether the baker is part of the finalization committee
    /// in the reward period.
    pub is_finalizer:      bool,
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
    /// Construct an [`AccountAccessStructure`] from the wallet.
    /// This can used for validating signatures.
    pub fn access_structure(&self) -> AccountAccessStructure {
        let mut keys = BTreeMap::new();
        for (&ci, k) in self.keys.keys.iter() {
            let public = CredentialPublicKeys {
                keys:      k.keys.iter().map(|(ki, kp)| (*ki, kp.into())).collect(),
                threshold: k.threshold,
            };
            keys.insert(ci, public);
        }
        AccountAccessStructure {
            threshold: self.keys.threshold,
            keys,
        }
    }

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
    /// [`from_json_value`](Self::from_json_value) for details.
    pub fn from_json_reader(reader: impl std::io::Read) -> Result<Self, serde_json::Error> {
        let v = serde_json::from_reader(reader)?;
        Self::from_json_value(v)
    }

    /// Helper for reading keys from strings. See
    /// [`from_json_value`](Self::from_json_value) for details.
    pub fn from_json_str(reader: &str) -> Result<Self, serde_json::Error> {
        let v = serde_json::from_str(reader)?;
        Self::from_json_value(v)
    }

    /// Helper for reading keys from files. See
    /// [`from_json_value`](Self::from_json_value) for details.
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
