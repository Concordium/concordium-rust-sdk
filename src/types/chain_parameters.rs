use crate::types;

use concordium_base::{
    base::{
        AmountFraction, CapitalBound, CommissionRanges, CredentialsPerBlockLimit, DurationSeconds,
        ElectionDifficulty, Energy, Epoch, ExchangeRate, InclusiveRange, LeverageFactor, MintRate,
        PartsPerHundredThousands, UpdatePublicKey,
    },
    common::types::Ratio,
    contracts_common::{AccountAddress, Amount, Duration},
    updates::{
        AccessStructure, HigherLevelAccessStructure, Level1KeysKind, RewardPeriodLength,
        RootKeysKind,
    },
};
// pub use endpoints::{QueryError, QueryResult, RPCError, RPCResult};
pub use http::uri::Scheme;
use num::{BigUint, ToPrimitive};
pub use tonic::{
    transport::{Endpoint, Error},
    Code, Status,
};

/// The mint distribution determines how newly-minted CCDs are distributed.
/// The fractions must sum to at most 1, and the remaining fraction is
/// allocated to the foundation account.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct MintDistribution {
    /// Fraction of newly minted CCD allocated to baker rewards.
    pub baking_reward: Option<AmountFraction>,
    /// Fraction of newly minted CCD allocated to finalization rewards.
    pub finalization_reward: Option<AmountFraction>,
}

#[derive(thiserror::Error, Debug)]
pub enum MintDistributionConversionError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
}

impl TryFrom<MintDistribution> for types::MintDistributionV1 {
    type Error = MintDistributionConversionError;
    fn try_from(value: MintDistribution) -> Result<Self, Self::Error> {
        let baking_reward =
            value
                .baking_reward
                .ok_or(MintDistributionConversionError::MissingField(
                    "baking_reward",
                ))?;
        let finalization_reward =
            value
                .finalization_reward
                .ok_or(MintDistributionConversionError::MissingField(
                    "finalization_reward",
                ))?;
        Ok(Self {
            baking_reward,
            finalization_reward,
        })
    }
}

/// The distribution of block transaction fees.
/// These are distributed among the block baker (pool), the GAS account,
/// and the foundation account. `baker + gas_account <= 1` must hold,
/// with the remainder going to the foundation account.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TransactionFeeDistribution {
    /// Fraction of transaction fees allocated to the block baker.
    pub baker: Option<AmountFraction>,
    /// Fraction of transaction fees allocated to the GAS account.
    pub gas_account: Option<AmountFraction>,
}

/// An error resulting from conversion from [`TransactionFeeDistribution`].
#[derive(thiserror::Error, Debug)]
pub enum TransactionFeeDistributionConversionError {
    #[error("missing required field `{0}`")]
    MissingFields(&'static str),
}

impl TryFrom<TransactionFeeDistribution> for types::TransactionFeeDistribution {
    type Error = TransactionFeeDistributionConversionError;
    fn try_from(value: TransactionFeeDistribution) -> Result<Self, Self::Error> {
        let baker = value
            .baker
            .ok_or(TransactionFeeDistributionConversionError::MissingFields(
                "baker",
            ))?;
        let gas_account =
            value
                .gas_account
                .ok_or(TransactionFeeDistributionConversionError::MissingFields(
                    "gas_account",
                ))?;
        Ok(Self { baker, gas_account })
    }
}

/// The GAS rewards define rewards paid to the block baker (pool) from the GAS
/// account for including certain transactions/proofs in a block.
/// For each item, the fraction of the GAS account is credited to the baker's
/// pool.
///
/// Note that these fractions behave multiplicatively (not additively)
/// meaning that if a block includes two account creation transactions,
/// each with a fraction of 1/10, then the baker receives 1/10 of the GAS
/// account for the first transaction, and then 1/10 of the remaining 9/10
/// for the second transaction, resulting in a total of 19/100 of the GAS
/// account being credited to the baker.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct GasRewards {
    /// `BakerPrevTransFrac`: fraction of the previous gas account paid to the
    /// baker.
    pub baker: Option<AmountFraction>,
    /// `FeeAddFinalisationProof`: fraction paid for including a finalization
    /// proof in a block.
    /// Supported in protocol versions 1 to 5.
    pub finalization_proof: Option<AmountFraction>,
    /// `FeeAccountCreation`: fraction paid for including each account creation
    /// transaction in a block.
    pub account_creation: Option<AmountFraction>,
    /// `FeeUpdate`: fraction paid for including an update transaction in a
    /// block.
    pub chain_update: Option<AmountFraction>,
}

/// An error resulting from a conversion from [`GasRewards`].
#[derive(thiserror::Error, Debug)]
pub enum GasRewardsConversionError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
}

impl TryFrom<GasRewards> for types::GASRewards {
    type Error = GasRewardsConversionError;
    fn try_from(value: GasRewards) -> Result<Self, Self::Error> {
        let baker = value
            .baker
            .ok_or(GasRewardsConversionError::MissingField("baker"))?;
        let finalization_proof =
            value
                .finalization_proof
                .ok_or(GasRewardsConversionError::MissingField(
                    "finalization_proof",
                ))?;
        let account_creation = value
            .account_creation
            .ok_or(GasRewardsConversionError::MissingField("account_creation"))?;
        let chain_update = value
            .chain_update
            .ok_or(GasRewardsConversionError::MissingField("chain_update"))?;
        Ok(Self {
            baker,
            finalization_proof,
            account_creation,
            chain_update,
        })
    }
}

impl TryFrom<GasRewards> for types::GASRewardsV1 {
    type Error = GasRewardsConversionError;
    fn try_from(value: GasRewards) -> Result<Self, Self::Error> {
        let baker = value
            .baker
            .ok_or(GasRewardsConversionError::MissingField("baker"))?;
        let account_creation = value
            .account_creation
            .ok_or(GasRewardsConversionError::MissingField("account_creation"))?;
        let chain_update = value
            .chain_update
            .ok_or(GasRewardsConversionError::MissingField("chain_update"))?;
        Ok(Self {
            baker,
            account_creation,
            chain_update,
        })
    }
}

/// Parameters related to staking and pools. This generalizes the
/// "minimum threshold for baking" and the "pool parameters".
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct StakingParameters {
    /// Fraction of finalization rewards charged by the passive delegation.
    /// Supported from protocol version 4.
    pub passive_finalization_commission: Option<AmountFraction>,
    /// Fraction of baking rewards charged by the passive delegation.
    /// Supported from protocol version 4.
    pub passive_baking_commission: Option<AmountFraction>,
    /// Fraction of transaction rewards charged by the L-pool.
    /// Supported from protocol version 4.
    pub passive_transaction_commission: Option<AmountFraction>,
    /// The range of allowed finalization commission rates.
    /// Supported from protocol version 4.
    pub finalization_commission_range: Option<InclusiveRange<AmountFraction>>,
    /// The range of allowed baker commission rates.
    /// Supported from protocol version 4.
    pub baking_commission_range: Option<InclusiveRange<AmountFraction>>,
    /// The range of allowed transaction commission rates.
    /// Supported from protocol version 4.
    pub transaction_commission_range: Option<InclusiveRange<AmountFraction>>,
    /// Minimum equity capital required for a new validator.
    pub minimum_equity_capital: Option<Amount>,
    /// Cap on the effective stake of a validator as a fraction of the total
    /// staked capital across all pools.
    /// Supported from protocol version 4.
    pub capital_bound: Option<CapitalBound>,
    /// The maximum leverage that a validator can have as a ratio of total pool
    /// stake to equity capital.
    /// Supported from protocol version 4.
    pub leverage_bound: Option<LeverageFactor>,
}

/// An error resulting from conversion from [`StakingParameters`].
#[derive(thiserror::Error, Debug)]
pub enum StakingParametersConversionError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
}

impl TryFrom<StakingParameters> for types::PoolParameters {
    type Error = StakingParametersConversionError;
    fn try_from(value: StakingParameters) -> Result<Self, Self::Error> {
        let passive_finalization_commission = value.passive_finalization_commission.ok_or(
            StakingParametersConversionError::MissingField("passive_finalization_commission"),
        )?;
        let passive_baking_commission = value.passive_baking_commission.ok_or(
            StakingParametersConversionError::MissingField("passive_baking_commission"),
        )?;
        let passive_transaction_commission = value.passive_transaction_commission.ok_or(
            StakingParametersConversionError::MissingField("passive_transaction_commission"),
        )?;
        let finalization_commission_range = value.finalization_commission_range.ok_or(
            StakingParametersConversionError::MissingField("finalization_commission_range"),
        )?;
        let baking_commission_range =
            value
                .baking_commission_range
                .ok_or(StakingParametersConversionError::MissingField(
                    "baking_commission_range",
                ))?;
        let transaction_commission_range = value.transaction_commission_range.ok_or(
            StakingParametersConversionError::MissingField("transaction_commission_range"),
        )?;
        let minimum_equity_capital =
            value
                .minimum_equity_capital
                .ok_or(StakingParametersConversionError::MissingField(
                    "minimum_equity_capital",
                ))?;
        let capital_bound =
            value
                .capital_bound
                .ok_or(StakingParametersConversionError::MissingField(
                    "capital_bound",
                ))?;
        let leverage_bound =
            value
                .leverage_bound
                .ok_or(StakingParametersConversionError::MissingField(
                    "leverage_bound",
                ))?;
        let commission_bounds = CommissionRanges {
            finalization: finalization_commission_range,
            baking: baking_commission_range,
            transaction: transaction_commission_range,
        };
        Ok(Self {
            passive_finalization_commission,
            passive_baking_commission,
            passive_transaction_commission,
            commission_bounds,
            minimum_equity_capital,
            capital_bound,
            leverage_bound,
        })
    }
}

/// The keys and authorizations for level 2 chain updates.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Level2Keys {
    pub keys: Vec<UpdatePublicKey>,
    /// Access structure for emergency updates.
    pub emergency: Option<AccessStructure>,
    /// Access structure for protocol updates.
    pub protocol: Option<AccessStructure>,
    /// Access structure for updating the consensus parameters.
    pub consensus: Option<AccessStructure>,
    /// Access structure for updating the euro to energy exchange rate.
    pub euro_per_energy: Option<AccessStructure>,
    /// Access structure for updating the micro CCD per euro exchange rate.
    pub micro_ccd_per_euro: Option<AccessStructure>,
    /// Access structure for updating the foundation account address.
    pub foundation_account: Option<AccessStructure>,
    /// Access structure for updating the mint distribution parameters.
    pub mint_distribution: Option<AccessStructure>,
    /// Access structure for updating the transaction fee distribution.
    pub transaction_fee_distribution: Option<AccessStructure>,
    /// Access structure for updating the gas reward distribution parameters.
    pub param_gas_rewards: Option<AccessStructure>,
    /// Access structure for updating the pool parameters. For protocol version
    /// 1 to 3, this is only the validator minimum stake threshold. Protocol
    /// version 4 introduced staking pools and the associated parameters.
    pub pool_parameters: Option<AccessStructure>,
    /// Access structure for adding new anonymity revokers.
    pub add_anonymity_revoker: Option<AccessStructure>,
    /// Access structure for adding new identity providers.
    pub add_identity_provider: Option<AccessStructure>,
    /// Access structure for changing cooldown periods related to
    /// validator and delegator staking.
    /// Supported from protocol version 4.
    pub cooldown_parameters: Option<AccessStructure>,
    /// Access structure for changing the length of the reward period.
    /// Supported from protocol version 4.
    pub time_parameters: Option<AccessStructure>,
    /// Access structure for creating a protocol level token.
    /// Supported from protocol version 9.
    pub create_plt: Option<AccessStructure>,
}

impl Level2Keys {
    pub fn construct_update_signer(
        &self,
        update_key_indices: &AccessStructure,
        actual_keys: impl IntoIterator<Item = concordium_base::base::UpdateKeyPair>,
    ) -> Option<impl concordium_base::updates::UpdateSigner> {
        concordium_base::updates::find_authorized_keys(&self.keys, update_key_indices, actual_keys)
    }
}

/// An error resulting from a conversion from [`Level2Keys`].
#[derive(thiserror::Error, Debug)]
pub enum Level2KeysConversionError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
}

impl TryFrom<Level2Keys> for types::AuthorizationsV0 {
    type Error = Level2KeysConversionError;

    fn try_from(value: Level2Keys) -> Result<Self, Self::Error> {
        let keys = if value.keys.is_empty() {
            return Err(Level2KeysConversionError::MissingField("keys"));
        } else {
            value.keys
        };
        let emergency = value
            .emergency
            .ok_or(Level2KeysConversionError::MissingField("emergency"))?;
        let protocol = value
            .protocol
            .ok_or(Level2KeysConversionError::MissingField("protocol"))?;
        let election_difficulty = value
            .consensus
            .ok_or(Level2KeysConversionError::MissingField("consensus"))?;
        let euro_per_energy = value
            .euro_per_energy
            .ok_or(Level2KeysConversionError::MissingField("euro_per_energy"))?;
        let micro_ccd_per_euro =
            value
                .micro_ccd_per_euro
                .ok_or(Level2KeysConversionError::MissingField(
                    "micro_ccd_per_euro",
                ))?;
        let foundation_account =
            value
                .foundation_account
                .ok_or(Level2KeysConversionError::MissingField(
                    "foundation_account",
                ))?;
        let mint_distribution = value
            .mint_distribution
            .ok_or(Level2KeysConversionError::MissingField("mint_distribution"))?;
        let transaction_fee_distribution =
            value
                .transaction_fee_distribution
                .ok_or(Level2KeysConversionError::MissingField(
                    "transaction_fee_distribution",
                ))?;
        let param_gas_rewards = value
            .param_gas_rewards
            .ok_or(Level2KeysConversionError::MissingField("param_gas_rewards"))?;
        let pool_parameters = value
            .pool_parameters
            .ok_or(Level2KeysConversionError::MissingField("pool_parameters"))?;
        let add_anonymity_revoker =
            value
                .add_anonymity_revoker
                .ok_or(Level2KeysConversionError::MissingField(
                    "add_anonymity_revoker",
                ))?;
        let add_identity_provider =
            value
                .add_identity_provider
                .ok_or(Level2KeysConversionError::MissingField(
                    "add_identity_provider",
                ))?;
        Ok(Self {
            keys,
            emergency,
            protocol,
            election_difficulty,
            euro_per_energy,
            micro_gtu_per_euro: micro_ccd_per_euro,
            foundation_account,
            mint_distribution,
            transaction_fee_distribution,
            param_gas_rewards,
            pool_parameters,
            add_anonymity_revoker,
            add_identity_provider,
        })
    }
}

impl TryFrom<Level2Keys> for types::AuthorizationsV1 {
    type Error = Level2KeysConversionError;

    fn try_from(mut value: Level2Keys) -> Result<Self, Self::Error> {
        let cooldown_parameters =
            value
                .cooldown_parameters
                .take()
                .ok_or(Level2KeysConversionError::MissingField(
                    "cooldown_parameters",
                ))?;
        let time_parameters = value
            .time_parameters
            .take()
            .ok_or(Level2KeysConversionError::MissingField("time_parameters"))?;
        let create_plt = value.create_plt.take();
        let v0: types::AuthorizationsV0 = value.try_into()?;
        Ok(Self {
            v0,
            cooldown_parameters,
            time_parameters,
            create_plt,
        })
    }
}

/// The public keys used for performing chain updates.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct UpdateKeys {
    /// Root keys. Authorized to update the root keys, level 1 keys, and level 2
    /// keys.
    pub root_keys: Option<HigherLevelAccessStructure<RootKeysKind>>,
    /// Level 1 keys. Authorized to update level 1 keys and level 2 keys.
    pub level_1_keys: Option<HigherLevelAccessStructure<Level1KeysKind>>,
    /// Level 2 keys. Authorized to perform chain updates (such as updating
    /// parameters, or initiating a protocol update).
    pub level_2_keys: Option<Level2Keys>,
}

/// Timeout parameters for the new consensus protocol introduced in protocol
/// version 6.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TimeoutParameters {
    /// The base timeout duration for blocks.
    pub base: Option<Duration>,
    /// Factor for increasing the timeout duration on a failed round.
    /// Must be greater than 1.
    pub increase: Option<Ratio>,
    /// Factor for decreasing the timeout duration on a successful finalization.
    /// Must be between 0 and 1.
    pub decrease: Option<Ratio>,
}

/// An error resulting from conversion from [`TimeoutParameters`].
#[derive(thiserror::Error, Debug)]
pub enum TimeoutParametersConversionError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
}

impl TryFrom<TimeoutParameters> for types::TimeoutParameters {
    type Error = TimeoutParametersConversionError;
    fn try_from(value: TimeoutParameters) -> Result<Self, Self::Error> {
        let base = value
            .base
            .ok_or(TimeoutParametersConversionError::MissingField("base"))?;
        let increase = value
            .increase
            .ok_or(TimeoutParametersConversionError::MissingField("increase"))?;
        let decrease = value
            .decrease
            .ok_or(TimeoutParametersConversionError::MissingField("decrease"))?;
        Ok(Self {
            base,
            increase,
            decrease,
        })
    }
}

/// The parameters that affect cooldown, i.e., the period of time between
/// stake being reduced and the stake becoming available to spend.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CooldownParameters {
    /// Extra number of epochs before reduction in stake, or baker
    /// deregistration is completed.
    /// Supported in protocol versions 1 to 3.
    pub baker_cooldown_epochs: Option<Epoch>,
    /// Cooldown duration for validators (pool owners).
    /// Supported from protocol version 4.
    /// From protocol version 7, the cooldown duration is the minimum of
    /// `pool_owner_cooldown` and `delegator_cooldown`.
    pub pool_owner_cooldown: Option<DurationSeconds>,
    /// Cooldown duration for delegators.
    /// Supported from protocol version 4.
    /// From protocol version 7, the cooldown duration is the minimum of
    /// `pool_owner_cooldown` and `delegator_cooldown`.
    pub delegator_cooldown: Option<DurationSeconds>,
}

/// An error resulting from conversion from [`CooldownParameters`].
#[derive(thiserror::Error, Debug)]
pub enum CooldownParametersConversionError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
}

impl TryFrom<CooldownParameters> for types::CooldownParameters {
    type Error = CooldownParametersConversionError;
    fn try_from(value: CooldownParameters) -> Result<Self, Self::Error> {
        let pool_owner_cooldown =
            value
                .pool_owner_cooldown
                .ok_or(CooldownParametersConversionError::MissingField(
                    "pool_owner_cooldown",
                ))?;
        let delegator_cooldown =
            value
                .delegator_cooldown
                .ok_or(CooldownParametersConversionError::MissingField(
                    "delegator_cooldown",
                ))?;
        Ok(Self {
            pool_owner_cooldown,
            delegator_cooldown,
        })
    }
}

/// Finalization committee parameters. These parameters control which validators
/// are in the finalization committee.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct FinalizationCommitteeParameters {
    /// Minimum number of bakers to include in the finalization committee before
    /// the 'finalizer_relative_stake_threshold' takes effect.
    pub min_finalizers: Option<u32>,
    /// Maximum number of bakers to include in the finalization committee.
    pub max_finalizers: Option<u32>,
    /// Determining the staking threshold required for being eligible the
    /// finalization committee. The required amount is given by `total stake
    /// in pools * finalizer_relative_stake_threshold` provided as parts per
    /// hundred thousands. Accepted values are between a value of 0 and 1.
    pub finalizers_relative_stake_threshold: Option<PartsPerHundredThousands>,
}

/// An error resulting from conversion from [`FinalizationCommitteeParameters`].
#[derive(thiserror::Error, Debug)]
pub enum FinalizationCommitteeParametersConversionError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
}

impl TryFrom<FinalizationCommitteeParameters> for types::FinalizationCommitteeParameters {
    type Error = FinalizationCommitteeParametersConversionError;
    fn try_from(value: FinalizationCommitteeParameters) -> Result<Self, Self::Error> {
        let min_finalizers = value.min_finalizers.ok_or(
            FinalizationCommitteeParametersConversionError::MissingField("min_finalizers"),
        )?;
        let max_finalizers = value.max_finalizers.ok_or(
            FinalizationCommitteeParametersConversionError::MissingField("max_finalizers"),
        )?;
        let finalizers_relative_stake_threshold = value.finalizers_relative_stake_threshold.ok_or(
            FinalizationCommitteeParametersConversionError::MissingField(
                "finalizers_relative_stake_threshold",
            ),
        )?;
        Ok(Self {
            min_finalizers,
            max_finalizers,
            finalizers_relative_stake_threshold,
        })
    }
}

/// The parameters that govern the behavior of the blockchain.
/// Which parameters are available depends on the protocol version, and so
/// all parameters are treated as optional in this structure in order
/// to support existing and future changes.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ChainParameters {
    /// Timeout parameters for the consensus protocol introduced in protocol
    /// version 6.
    pub timeout_parameters: TimeoutParameters,
    /// Election difficulty for consensus lottery.
    /// Supported in protocol versions 1 to 5.
    pub election_difficulty: Option<ElectionDifficulty>,
    /// The minimum time interval between blocks.
    /// Introduced in protocol version 6.
    pub min_block_time: Option<Duration>,
    /// Maximum energy allowed per block.
    /// Introduced in protocol version 6.
    pub block_energy_limit: Option<Energy>,
    /// Euro per energy exchange rate.
    pub euro_per_energy: Option<ExchangeRate>,
    /// Micro ccd per euro exchange rate.
    pub micro_ccd_per_euro: Option<ExchangeRate>,
    /// Parameters related to cooldowns when staking.
    pub cooldown_parameters: CooldownParameters,
    /// The length of a reward period (pay day) as a number of epochs.
    /// Supported from protocol version 4.
    pub reward_period_length: Option<RewardPeriodLength>,
    /// The proportion of current total CCDs that are minted at each payday.
    /// Supported from protocol version 4.
    pub mint_per_payday: Option<MintRate>,
    /// The increase in CCD amount per slot.
    /// Supported in protocol versions 1-3.
    pub mint_per_slot: Option<MintRate>,
    /// The limit for the number of account creations in a block.
    pub account_creation_limit: Option<CredentialsPerBlockLimit>,
    /// Distribution of newly-minted CCDs.
    pub mint_distribution: MintDistribution,
    /// Parameters related to the distribution of transaction fees.
    pub transaction_fee_distribution: TransactionFeeDistribution,
    /// Parameters related to the distribution of the GAS account.
    pub gas_rewards: GasRewards,
    /// Address of the foundation account.
    pub foundation_account: Option<AccountAddress>,
    /// Parameters related to staking and pools.
    /// For protocol versions 1-3 this only contains the minimum threshold
    /// for baking. From protocol version 4, this includes the pool parameters.
    pub staking_parameters: StakingParameters,
    /// The finalization committee parameters.
    /// Supported from protocol version 6.
    pub finalization_committee_parameters: FinalizationCommitteeParameters,
    /// Maximum number of consecutive rounds a validator is allowed to miss
    /// without being suspended as a validator.
    /// Supported from protocol version 8.
    pub validator_max_missed_rounds: Option<u64>,
    /// Keys allowed to do chain updates.
    pub keys: UpdateKeys,
}

/// The exchange rate between `microCCD` and `NRG`.
#[derive(Debug, Clone)]
pub struct EnergyRate {
    pub micro_ccd_per_energy: num::rational::Ratio<u128>,
}

impl EnergyRate {
    /// Get the cost as a CCD `Amount` for the given `Energy` amount at this
    /// exchange rate.
    pub fn ccd_cost(&self, nrg: Energy) -> Amount {
        let numer = BigUint::from(*self.micro_ccd_per_energy.numer()) * nrg.energy;
        let denomer = BigUint::from(*self.micro_ccd_per_energy.denom());
        let cost = num::rational::Ratio::new(numer, denomer);
        let i = cost.ceil().to_integer();
        // The next line should be a no-op when the values are coming from the chain
        let micro = i % u64::MAX;
        Amount::from_micro_ccd(micro.to_u64().expect("Value is known to be under u64::MAX"))
    }
}

/// An error resulting from conversion from [`EnergyRate`].
#[derive(thiserror::Error, Debug)]
pub enum EnergyRateConversionError {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
}

impl ChainParameters {
    /// Compute the exchange rate between `microCCD` and `NRG`.
    pub fn energy_rate(&self) -> Result<EnergyRate, EnergyRateConversionError> {
        let x = self
            .micro_ccd_per_euro
            .as_ref()
            .ok_or(EnergyRateConversionError::MissingField(
                "micro_ccd_per_euro",
            ))?;
        let y = self
            .euro_per_energy
            .as_ref()
            .ok_or(EnergyRateConversionError::MissingField("euro_per_energy"))?;
        let num = u128::from(x.numerator()) * u128::from(y.numerator());
        let denom = u128::from(x.denominator()) * u128::from(y.denominator());
        Ok(EnergyRate {
            micro_ccd_per_energy: num::rational::Ratio::new(num, denom),
        })
    }
}
