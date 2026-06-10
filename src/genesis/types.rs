//! Genesis data types and serialisation.
//!
//! These types represent the in-memory typed genesis block structure used
//! across all protocol versions. They are produced by the genesis
//! builders and consumed by [`serialize_genesis`](super::serialize_genesis) and
//! [`GenesisData::hash`].
use crate::types::{
    hashes::{BlockHash, LeadershipElectionNonce},
    AccountIndex, AccountThreshold, AuthorizationsV0, AuthorizationsV1, BakerAggregationVerifyKey,
    BakerElectionVerifyKey, BakerId, BakerSignatureVerifyKey, BlockHeight, CooldownParameters,
    CredentialsPerBlockLimit, ElectionDifficulty, Energy, Epoch, ExchangeRate,
    FinalizationCommitteeParameters, GASRewards, GASRewardsV1, HigherLevelAccessStructure,
    Level1KeysKind, MintDistributionV0, MintDistributionV1, PoolParameters, ProtocolVersion,
    RootKeysKind, Slot, SlotDuration, TimeParameters, TimeoutParameters,
    TransactionFeeDistribution, ValidatorScoreParameters,
};
use concordium_base::{
    common::{
        types::{Amount, CredentialIndex, Ratio, Timestamp},
        Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
        Serialize, Versioned,
    },
    contracts_common::Duration,
    id::{
        self,
        constants::{ArCurve, IpPairing},
        types::{
            AccCredentialInfo, AccountAddress, AccountCredentialWithoutProofs, AccountKeys,
            ArIdentity, ArInfo, GlobalContext, IpIdentity, IpInfo,
        },
    },
};
use serde::de;
use sha2::Digest;
use std::collections::BTreeMap;

// ── Reward parameter skeletons ────────────────────────────────────────────────

/// Generic container for the three reward-parameter groups present in every
/// chain parameters version.
///
/// The concrete type aliases [`RewardParametersCPV0`], [`RewardParametersCPV1`],
/// and [`RewardParametersCPV2`] pin the type parameters to the appropriate SDK
/// types for each chain parameters version.
#[derive(Debug, Clone)]
pub struct RewardParametersSkeleton<MintDistribution, GasRewards> {
    /// Mint-rate and baker/finalizer reward split for newly minted CCD.
    pub mint_distribution: MintDistribution,
    /// How transaction fees are divided between the baker and the gas account.
    pub transaction_fee_distribution: TransactionFeeDistribution,
    /// Fractions of the gas account paid out for various special transactions.
    pub gas_rewards: GasRewards,
}

impl<MD: Serial, GR: Serial> Serial for RewardParametersSkeleton<MD, GR> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        self.mint_distribution.serial(out);
        self.transaction_fee_distribution.serial(out);
        self.gas_rewards.serial(out)
    }
}

impl<MD: Deserial, GR: Deserial> Deserial for RewardParametersSkeleton<MD, GR> {
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

/// Reward parameters for CPV0 genesis blocks (P1–P3).
pub type RewardParametersCPV0 = RewardParametersSkeleton<MintDistributionV0, GASRewards>;

/// Reward parameters for CPV1 genesis blocks (P4–P5).
pub type RewardParametersCPV1 = RewardParametersSkeleton<MintDistributionV1, GASRewards>;

/// Reward parameters for CPV2 genesis blocks (P6+).
pub type RewardParametersCPV2 = RewardParametersSkeleton<MintDistributionV1, GASRewardsV1>;

// ── Chain parameter types ─────────────────────────────────────────────────────

/// Fully-resolved chain parameters serialised into a CPV0 genesis block (P1–P3).
///
/// This is the final form produced by [`GenesisChainParametersV0::resolve`];
/// it is embedded directly in the serialised genesis state and is not meant to
/// be constructed by callers directly.
#[derive(Serialize, Debug)]
pub struct ChainParametersV0 {
    /// Probability that a given baker wins the slot lottery.
    pub election_difficulty: ElectionDifficulty,
    /// Exchange rate between euros and NRG (energy).
    pub euro_per_energy: ExchangeRate,
    /// Exchange rate between micro-GTU (µCCD) and euros.
    pub micro_gtu_per_euro: ExchangeRate,
    /// Number of epochs a baker must wait after removing stake before it is
    /// released.
    pub baker_cooldown_epochs: Epoch,
    /// Maximum number of credential deployments per block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Reward fractions for minting, fees, and gas.
    pub reward_parameters: RewardParametersCPV0,
    /// Index of the foundation account in the genesis account list.
    pub foundation_account_index: AccountIndex,
    /// Minimum stake required to become a baker.
    pub minimum_threshold_for_baking: Amount,
}

/// Fully-resolved chain parameters serialised into a CPV1 genesis block (P4–P5).
///
/// This is the final form produced by [`GenesisChainParametersV1::resolve`];
/// it is embedded directly in the serialised genesis state and is not meant to
/// be constructed by callers directly.
#[derive(Serialize, Debug)]
pub struct ChainParametersV1 {
    /// Probability that a given baker wins the slot lottery.
    pub election_difficulty: ElectionDifficulty,
    /// Exchange rate between euros and NRG (energy).
    pub euro_per_energy: ExchangeRate,
    /// Exchange rate between micro-GTU (µCCD) and euros.
    pub micro_gtu_per_euro: ExchangeRate,
    /// Cooldown durations for validators and delegators.
    pub cooldown_parameters: CooldownParameters,
    /// Mint timing and pay-day configuration.
    pub time_parameters: TimeParameters,
    /// Maximum number of credential deployments per block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Reward fractions for minting, fees, and gas.
    pub reward_parameters: RewardParametersCPV1,
    /// Index of the foundation account in the genesis account list.
    pub foundation_account_index: AccountIndex,
    /// Staking pool configuration.
    pub pool_parameters: PoolParameters,
}

/// Fully-resolved chain parameters serialised into a CPV2 genesis block (P6–P7).
///
/// This is the final form produced by [`GenesisChainParametersV2::resolve`];
/// it is embedded directly in the serialised genesis state and is not meant to
/// be constructed by callers directly.
#[derive(Serialize, Debug)]
pub struct ChainParametersV2 {
    /// Block timeout configuration for the ConcordiumBFT consensus.
    pub timeout_parameters: TimeoutParameters,
    /// Minimum time between the arrival of two consecutive blocks.
    pub min_block_time: Duration,
    /// Maximum total NRG allowed in a block.
    pub block_energy_limit: Energy,
    /// Exchange rate between euros and NRG (energy).
    pub euro_per_energy: ExchangeRate,
    /// Exchange rate between micro-CCD (µCCD) and euros.
    pub micro_ccd_per_euro: ExchangeRate,
    /// Cooldown durations for validators and delegators.
    pub cooldown_parameters: CooldownParameters,
    /// Mint timing and pay-day configuration.
    pub time_parameters: TimeParameters,
    /// Maximum number of credential deployments per block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Reward fractions for minting, fees, and gas.
    pub reward_parameters: RewardParametersCPV2,
    /// Index of the foundation account in the genesis account list.
    pub foundation_account_index: AccountIndex,
    /// Staking pool configuration.
    pub pool_parameters: PoolParameters,
    /// Finalization committee membership thresholds.
    pub finalization_committee_parameters: FinalizationCommitteeParameters,
}

/// Fully-resolved chain parameters serialised into a CPV3 genesis block (P8+).
///
/// This is the final form produced by [`GenesisChainParametersV3::resolve`];
/// it is embedded directly in the serialised genesis state and is not meant to
/// be constructed by callers directly.
#[derive(Serialize, Debug)]
pub struct ChainParametersV3 {
    /// Block timeout configuration for the ConcordiumBFT consensus.
    pub timeout_parameters: TimeoutParameters,
    /// Minimum time between the arrival of two consecutive blocks.
    pub min_block_time: Duration,
    /// Maximum total NRG allowed in a block.
    pub block_energy_limit: Energy,
    /// Exchange rate between euros and NRG (energy).
    pub euro_per_energy: ExchangeRate,
    /// Exchange rate between micro-CCD (µCCD) and euros.
    pub micro_ccd_per_euro: ExchangeRate,
    /// Cooldown durations for validators and delegators.
    pub cooldown_parameters: CooldownParameters,
    /// Mint timing and pay-day configuration.
    pub time_parameters: TimeParameters,
    /// Maximum number of credential deployments per block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Reward fractions for minting, fees, and gas.
    pub reward_parameters: RewardParametersCPV2,
    /// Index of the foundation account in the genesis account list.
    pub foundation_account_index: AccountIndex,
    /// Staking pool configuration.
    pub pool_parameters: PoolParameters,
    /// Finalization committee membership thresholds.
    pub finalization_committee_parameters: FinalizationCommitteeParameters,
    /// Scoring parameters used to rank and exclude underperforming validators.
    pub validator_score_parameters: ValidatorScoreParameters,
}

// ── Governance key collection ─────────────────────────────────────────────────

/// Governance (update) key collection for a genesis block.
///
/// Groups root keys, level-1 keys, and level-2 keys into a single structure.
/// The `Auths` type parameter is [`AuthorizationsV0`] for CPV0 or
/// [`AuthorizationsV1`] for CPV1 and later.
///
/// This type is both binary-serialised (for the genesis block) and JSON
/// serialised/deserialised.
#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UpdateKeysCollectionSkeleton<Auths> {
    /// Root-level keys that can authorise level-1 key updates.
    pub root_keys: HigherLevelAccessStructure<RootKeysKind>,
    /// Level-1 keys that can authorise level-2 key updates.
    #[serde(rename = "level1Keys")]
    pub level_1_keys: HigherLevelAccessStructure<Level1KeysKind>,
    /// Level-2 keys that authorise individual on-chain update types.
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

/// Governance key collection for CPV0 genesis blocks (P1–P3).
///
/// Uses [`AuthorizationsV0`], which does not have a `create_plt` authorisation.
pub type UpdateKeysCollectionCPV0 = UpdateKeysCollectionSkeleton<AuthorizationsV0>;

/// Governance key collection for CPV1 and later genesis blocks (P4+).
///
/// Uses [`AuthorizationsV1`]. For P4–P7 the `create_plt` field must be absent;
/// for P9+ it must be present.
pub type UpdateKeysCollectionCPV1 = UpdateKeysCollectionSkeleton<AuthorizationsV1>;

// ── Account types ─────────────────────────────────────────────────────────────

/// Map from credential index to the credential (without proofs) for a genesis
/// account.
pub type GenesisCredentials = BTreeMap<
    CredentialIndex,
    AccountCredentialWithoutProofs<id::constants::ArCurve, id::constants::AttributeKind>,
>;

/// Full genesis account, including private key material.
///
/// Produced by the builder when accounts are generated or supplied as
/// `ExistingFull`. Often written to disk as JSON for testing, so other tooling
/// can recover the keys; not included in the genesis block itself.
#[derive(SerdeDeserialize, SerdeSerialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GenesisAccount {
    /// Account signing keys.
    pub account_keys: AccountKeys,
    /// Account credential info used to derive the on-chain credential.
    pub aci: AccCredentialInfo<id::constants::ArCurve>,
    /// On-chain account address.
    pub address: AccountAddress,
    /// Versioned map of credentials deployed at genesis.
    pub credentials: Versioned<GenesisCredentials>,
    /// ElGamal public key for encrypted transfers.
    pub encryption_public_key: id::elgamal::PublicKey<id::constants::ArCurve>,
    /// ElGamal secret key for encrypted transfers.
    pub encryption_secret_key: id::elgamal::SecretKey<id::constants::ArCurve>,
}

/// Public baker fields embedded in a [`GenesisAccountPublic`] when the account
/// is a baker at genesis.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GenesisBakerPublic {
    /// Amount staked by this baker.
    pub stake: Amount,
    /// Whether staking rewards are automatically restaked.
    pub restake_earnings: bool,
    /// Baker identifier assigned at genesis.
    pub baker_id: BakerId,
    /// Election (VRF) verification key.
    pub election_verify_key: BakerElectionVerifyKey,
    /// Block signature verification key.
    pub signature_verify_key: BakerSignatureVerifyKey,
    /// Aggregate-signature (BLS) verification key used in finalization.
    pub aggregation_verify_key: BakerAggregationVerifyKey,
}

/// Public account information written into the genesis block.
///
/// This is the form included in [`GenesisStateCPV0`] through
/// [`GenesisStateCPV3`] and serialised into `genesis.dat`. The full private-key
/// version is [`GenesisAccount`].
#[derive(Serialize, SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GenesisAccountPublic {
    /// On-chain account address.
    pub address: AccountAddress,
    /// Minimum number of credential keys required to sign transactions.
    pub account_threshold: AccountThreshold,
    /// Credentials deployed for this account at genesis.
    #[map_size_length = 8]
    #[serde(deserialize_with = "deserialize_versioned_public_account")]
    pub credentials: GenesisCredentials,
    /// Initial CCD balance.
    pub balance: Amount,
    /// Baker configuration, present if this account is a baker at genesis.
    pub baker: Option<GenesisBakerPublic>,
}

fn deserialize_versioned_public_account<'de, D: de::Deserializer<'de>>(
    des: D,
) -> Result<GenesisCredentials, D::Error> {
    let versioned: Versioned<GenesisCredentials> =
        Versioned::<GenesisCredentials>::deserialize(des)?;
    Ok(versioned.value)
}

// ── Finalization parameters ───────────────────────────────────────────────────

/// Finalization committee and timing parameters for CPV0 genesis blocks (P1–P3).
///
/// These govern the slot-based finalization protocol used before the
/// ConcordiumBFT transition.
#[derive(SerdeDeserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FinalizationParameters {
    minimum_skip: BlockHeight,
    committee_max_size: u32,
    waiting_time: u64,
    skip_shrink_factor: Ratio,
    skip_grow_factor: Ratio,
    delay_shrink_factor: Ratio,
    delay_grow_factor: Ratio,
    allow_zero_delay: bool,
}

// ── Genesis chain parameter config types ─────────────────────────────────────

/// Pending chain parameters for CPV0 genesis blocks (P1–P3).
///
/// All chain parameters except `foundation_account_index`, which the builder
/// resolves automatically from the account inputs at build time.
/// Call [`GenesisChainParametersV0::resolve`] to obtain the final
/// [`ChainParametersV0`].
#[derive(Debug, Clone)]
pub struct GenesisChainParametersV0 {
    /// Probability that a given baker wins the slot lottery.
    pub election_difficulty: ElectionDifficulty,
    /// Exchange rate between euros and NRG (energy).
    pub euro_per_energy: ExchangeRate,
    /// Exchange rate between micro-CCD (µCCD) and euros.
    pub micro_ccd_per_euro: ExchangeRate,
    /// Maximum number of credential deployments per block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Number of epochs a baker must wait after reducing stake before it is
    /// released.
    pub baker_cooldown_epochs: Epoch,
    /// Reward fractions for minting, fees, and gas.
    pub reward_parameters: RewardParametersCPV0,
    /// Minimum stake required to register as a baker.
    pub minimum_threshold_for_baking: Amount,
}

impl GenesisChainParametersV0 {
    /// Resolve pending chain parameters to final [`ChainParametersV0`] by
    /// injecting the `foundation_account_index` determined from the account
    /// inputs during build.
    pub fn resolve(self, foundation_account_index: AccountIndex) -> ChainParametersV0 {
        ChainParametersV0 {
            election_difficulty: self.election_difficulty,
            euro_per_energy: self.euro_per_energy,
            micro_gtu_per_euro: self.micro_ccd_per_euro,
            baker_cooldown_epochs: self.baker_cooldown_epochs,
            account_creation_limit: self.account_creation_limit,
            reward_parameters: self.reward_parameters,
            foundation_account_index,
            minimum_threshold_for_baking: self.minimum_threshold_for_baking,
        }
    }
}

/// Pending chain parameters for CPV1 genesis blocks (P4–P5).
///
/// All chain parameters except `foundation_account_index`, which the builder
/// resolves automatically from the account inputs at build time.
/// Call [`GenesisChainParametersV1::resolve`] to obtain the final
/// [`ChainParametersV1`].
#[derive(Debug, Clone)]
pub struct GenesisChainParametersV1 {
    /// Probability that a given baker wins the slot lottery.
    pub election_difficulty: ElectionDifficulty,
    /// Exchange rate between euros and NRG (energy).
    pub euro_per_energy: ExchangeRate,
    /// Exchange rate between micro-CCD (µCCD) and euros.
    pub micro_ccd_per_euro: ExchangeRate,
    /// Maximum number of credential deployments per block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Reward fractions for minting, fees, and gas.
    pub reward_parameters: RewardParametersCPV1,
    /// Mint timing and pay-day configuration.
    pub time_parameters: TimeParameters,
    /// Staking pool configuration.
    pub pool_parameters: PoolParameters,
    /// Cooldown durations for validators and delegators.
    pub cooldown_parameters: CooldownParameters,
}

impl GenesisChainParametersV1 {
    /// Resolve pending chain parameters to final [`ChainParametersV1`] by
    /// injecting the `foundation_account_index` determined from the account
    /// inputs during build.
    pub fn resolve(self, foundation_account_index: AccountIndex) -> ChainParametersV1 {
        ChainParametersV1 {
            election_difficulty: self.election_difficulty,
            euro_per_energy: self.euro_per_energy,
            micro_gtu_per_euro: self.micro_ccd_per_euro,
            time_parameters: self.time_parameters,
            pool_parameters: self.pool_parameters,
            cooldown_parameters: self.cooldown_parameters,
            account_creation_limit: self.account_creation_limit,
            reward_parameters: self.reward_parameters,
            foundation_account_index,
        }
    }
}

/// Pending chain parameters for CPV2 genesis blocks (P6–P7).
///
/// All chain parameters except `foundation_account_index`, which the builder
/// resolves automatically from the account inputs at build time.
/// Call [`GenesisChainParametersV2::resolve`] to obtain the final
/// [`ChainParametersV2`].
#[derive(Debug, Clone)]
pub struct GenesisChainParametersV2 {
    /// Block timeout configuration for the ConcordiumBFT consensus.
    pub timeout_parameters: TimeoutParameters,
    /// Minimum time between the arrival of two consecutive blocks.
    pub min_block_time: Duration,
    /// Maximum total NRG allowed in a block.
    pub block_energy_limit: Energy,
    /// Exchange rate between euros and NRG (energy).
    pub euro_per_energy: ExchangeRate,
    /// Exchange rate between micro-CCD (µCCD) and euros.
    pub micro_ccd_per_euro: ExchangeRate,
    /// Maximum number of credential deployments per block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Reward fractions for minting, fees, and gas.
    pub reward_parameters: RewardParametersCPV2,
    /// Mint timing and pay-day configuration.
    pub time_parameters: TimeParameters,
    /// Staking pool configuration.
    pub pool_parameters: PoolParameters,
    /// Cooldown durations for validators and delegators.
    pub cooldown_parameters: CooldownParameters,
    /// Finalization committee membership thresholds.
    pub finalization_committee_parameters: FinalizationCommitteeParameters,
}

impl GenesisChainParametersV2 {
    /// Resolve pending chain parameters to final [`ChainParametersV2`] by
    /// injecting the `foundation_account_index` determined from the account
    /// inputs during build.
    pub fn resolve(self, foundation_account_index: AccountIndex) -> ChainParametersV2 {
        ChainParametersV2 {
            timeout_parameters: self.timeout_parameters,
            min_block_time: self.min_block_time,
            block_energy_limit: self.block_energy_limit,
            euro_per_energy: self.euro_per_energy,
            micro_ccd_per_euro: self.micro_ccd_per_euro,
            time_parameters: self.time_parameters,
            pool_parameters: self.pool_parameters,
            cooldown_parameters: self.cooldown_parameters,
            account_creation_limit: self.account_creation_limit,
            reward_parameters: self.reward_parameters,
            foundation_account_index,
            finalization_committee_parameters: self.finalization_committee_parameters,
        }
    }
}

/// Pending chain parameters for CPV3 genesis blocks (P8+).
///
/// All chain parameters except `foundation_account_index`, which the builder
/// resolves automatically from the account inputs at build time.
/// Call [`GenesisChainParametersV3::resolve`] to obtain the final
/// [`ChainParametersV3`].
#[derive(Debug, Clone)]
pub struct GenesisChainParametersV3 {
    /// Block timeout configuration for the ConcordiumBFT consensus.
    pub timeout_parameters: TimeoutParameters,
    /// Minimum time between the arrival of two consecutive blocks.
    pub min_block_time: Duration,
    /// Maximum total NRG allowed in a block.
    pub block_energy_limit: Energy,
    /// Exchange rate between euros and NRG (energy).
    pub euro_per_energy: ExchangeRate,
    /// Exchange rate between micro-CCD (µCCD) and euros.
    pub micro_ccd_per_euro: ExchangeRate,
    /// Maximum number of credential deployments per block.
    pub account_creation_limit: CredentialsPerBlockLimit,
    /// Reward fractions for minting, fees, and gas.
    pub reward_parameters: RewardParametersCPV2,
    /// Mint timing and pay-day configuration.
    pub time_parameters: TimeParameters,
    /// Staking pool configuration.
    pub pool_parameters: PoolParameters,
    /// Cooldown durations for validators and delegators.
    pub cooldown_parameters: CooldownParameters,
    /// Finalization committee membership thresholds.
    pub finalization_committee_parameters: FinalizationCommitteeParameters,
    /// Scoring parameters used to rank and exclude underperforming validators.
    pub validator_score_parameters: ValidatorScoreParameters,
}

impl GenesisChainParametersV3 {
    /// Resolve pending chain parameters to final [`ChainParametersV3`] by
    /// injecting the `foundation_account_index` determined from the account
    /// inputs during build.
    pub fn resolve(self, foundation_account_index: AccountIndex) -> ChainParametersV3 {
        ChainParametersV3 {
            timeout_parameters: self.timeout_parameters,
            min_block_time: self.min_block_time,
            block_energy_limit: self.block_energy_limit,
            euro_per_energy: self.euro_per_energy,
            micro_ccd_per_euro: self.micro_ccd_per_euro,
            account_creation_limit: self.account_creation_limit,
            reward_parameters: self.reward_parameters,
            time_parameters: self.time_parameters,
            pool_parameters: self.pool_parameters,
            cooldown_parameters: self.cooldown_parameters,
            finalization_committee_parameters: self.finalization_committee_parameters,
            validator_score_parameters: self.validator_score_parameters,
            foundation_account_index,
        }
    }
}

// ── Core genesis parameters ───────────────────────────────────────────────────

/// Core timing and consensus parameters for CPV0 genesis blocks (P1–P3).
///
/// These are the slot-based timing parameters used by the original Concordium
/// consensus. Passed as the `core` field of [`ProtocolParamsCPV0`] and
/// [`ProtocolParamsCPV1`].
#[derive(Debug, Clone, Serialize)]
pub struct CoreGenesisParametersV0 {
    /// Absolute time of the genesis block (milliseconds since Unix epoch).
    pub time: Timestamp,
    /// Duration of one slot in milliseconds.
    pub slot_duration: SlotDuration,
    /// Number of slots in one epoch.
    pub epoch_length: u64,
    /// Maximum energy allowed in a single block.
    pub max_block_energy: Energy,
    /// Parameters governing the finalization committee and its timing.
    pub finalization_parameters: FinalizationParameters,
}

/// Core timing and consensus parameters for CPV1–CPV3 genesis blocks (P6+).
///
/// These are the epoch-based timing parameters used by the ConcordiumBFT
/// consensus. Passed as the `core` field of [`ProtocolParamsCPV2`] and
/// [`ProtocolParamsCPV3`].
#[derive(Debug, Clone, Serialize)]
pub struct CoreGenesisParametersV1 {
    /// Absolute time of the genesis block (milliseconds since Unix epoch).
    pub genesis_time: Timestamp,
    /// Duration of one epoch.
    pub epoch_duration: Duration,
    /// Minimum fraction of finalizers' stake required to finalize a block.
    pub signature_threshold: Ratio,
}

// ── Genesis state types ───────────────────────────────────────────────────────

fn serialize_with_length_header(data: &impl Serial, buf: &mut Vec<u8>, out: &mut impl Buffer) {
    data.serial(buf);
    (buf.len() as u32).serial(out);
    out.write_all(buf).expect("Writing to buffers succeeds.");
    buf.clear();
}

/// Complete genesis state for a CPV0 block (P1–P3).
///
/// Holds all on-chain state at genesis serialised by the [`Serial`] impl.
/// Produced by [`GenesisBuilderCPV0::build`](super::GenesisBuilderCPV0::build).
#[derive(Debug)]
pub struct GenesisStateCPV0 {
    /// Global cryptographic parameters (generators, commitment keys).
    pub cryptographic_parameters: GlobalContext<ArCurve>,
    /// Identity providers registered at genesis.
    pub identity_providers: BTreeMap<IpIdentity, IpInfo<IpPairing>>,
    /// Anonymity revokers registered at genesis.
    pub anonymity_revokers: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
    /// Governance (update) keys at genesis.
    pub update_keys: UpdateKeysCollectionCPV0,
    /// Fully-resolved chain parameters.
    pub chain_parameters: ChainParametersV0,
    /// Nonce used for the leader-election VRF in the first epoch.
    pub leadership_election_nonce: LeadershipElectionNonce,
    /// Public account data for all accounts at genesis.
    pub accounts: Vec<GenesisAccountPublic>,
}

impl Serial for GenesisStateCPV0 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let mut tmp = Vec::new();
        serialize_with_length_header(&self.cryptographic_parameters, &mut tmp, out);
        (self.identity_providers.len() as u32).serial(out);
        for (k, v) in self.identity_providers.iter() {
            k.serial(out);
            serialize_with_length_header(v, &mut tmp, out);
        }
        (self.anonymity_revokers.len() as u32).serial(out);
        for (k, v) in self.anonymity_revokers.iter() {
            k.serial(out);
            serialize_with_length_header(v, &mut tmp, out);
        }
        self.update_keys.serial(out);
        self.chain_parameters.serial(out);
        self.leadership_election_nonce.serial(out);
        self.accounts.serial(out)
    }
}

/// Complete genesis state for a CPV1 block (P4–P5).
///
/// Holds all on-chain state at genesis serialised by the [`Serial`] impl.
/// Produced by [`GenesisBuilderCPV1::build`](super::GenesisBuilderCPV1::build).
#[derive(Debug)]
pub struct GenesisStateCPV1 {
    /// Global cryptographic parameters (generators, commitment keys).
    pub cryptographic_parameters: GlobalContext<ArCurve>,
    /// Identity providers registered at genesis.
    pub identity_providers: BTreeMap<IpIdentity, IpInfo<IpPairing>>,
    /// Anonymity revokers registered at genesis.
    pub anonymity_revokers: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
    /// Governance (update) keys at genesis.
    pub update_keys: UpdateKeysCollectionCPV1,
    /// Fully-resolved chain parameters.
    pub chain_parameters: ChainParametersV1,
    /// Nonce used for the leader-election VRF in the first epoch.
    pub leadership_election_nonce: LeadershipElectionNonce,
    /// Public account data for all accounts at genesis.
    pub accounts: Vec<GenesisAccountPublic>,
}

impl Serial for GenesisStateCPV1 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let mut tmp = Vec::new();
        serialize_with_length_header(&self.cryptographic_parameters, &mut tmp, out);
        (self.identity_providers.len() as u32).serial(out);
        for (k, v) in self.identity_providers.iter() {
            k.serial(out);
            serialize_with_length_header(v, &mut tmp, out);
        }
        (self.anonymity_revokers.len() as u32).serial(out);
        for (k, v) in self.anonymity_revokers.iter() {
            k.serial(out);
            serialize_with_length_header(v, &mut tmp, out);
        }
        self.update_keys.serial(out);
        self.chain_parameters.serial(out);
        self.leadership_election_nonce.serial(out);
        self.accounts.serial(out)
    }
}

/// Complete genesis state for a CPV2 block (P6–P7).
///
/// Holds all on-chain state at genesis serialised by the [`Serial`] impl.
/// Produced by [`GenesisBuilderCPV2::build`](super::GenesisBuilderCPV2::build).
#[derive(Debug)]
pub struct GenesisStateCPV2 {
    /// Global cryptographic parameters (generators, commitment keys).
    pub cryptographic_parameters: GlobalContext<ArCurve>,
    /// Identity providers registered at genesis.
    pub identity_providers: BTreeMap<IpIdentity, IpInfo<IpPairing>>,
    /// Anonymity revokers registered at genesis.
    pub anonymity_revokers: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
    /// Governance (update) keys at genesis.
    pub update_keys: UpdateKeysCollectionCPV1,
    /// Fully-resolved chain parameters.
    pub chain_parameters: ChainParametersV2,
    /// Nonce used for the leader-election VRF in the first epoch.
    pub leadership_election_nonce: LeadershipElectionNonce,
    /// Public account data for all accounts at genesis.
    pub accounts: Vec<GenesisAccountPublic>,
}

impl Serial for GenesisStateCPV2 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let mut tmp = Vec::new();
        serialize_with_length_header(&self.cryptographic_parameters, &mut tmp, out);
        (self.identity_providers.len() as u32).serial(out);
        for (k, v) in self.identity_providers.iter() {
            k.serial(out);
            serialize_with_length_header(v, &mut tmp, out);
        }
        (self.anonymity_revokers.len() as u32).serial(out);
        for (k, v) in self.anonymity_revokers.iter() {
            k.serial(out);
            serialize_with_length_header(v, &mut tmp, out);
        }
        self.update_keys.serial(out);
        self.chain_parameters.serial(out);
        self.leadership_election_nonce.serial(out);
        self.accounts.serial(out)
    }
}

/// Complete genesis state for a CPV3 block (P8+).
///
/// Holds all on-chain state at genesis serialised by the [`Serial`] impl.
/// Produced by [`GenesisBuilderCPV3::build`](super::GenesisBuilderCPV3::build).
#[derive(Debug)]
pub struct GenesisStateCPV3 {
    /// Global cryptographic parameters (generators, commitment keys).
    pub cryptographic_parameters: GlobalContext<ArCurve>,
    /// Identity providers registered at genesis.
    pub identity_providers: BTreeMap<IpIdentity, IpInfo<IpPairing>>,
    /// Anonymity revokers registered at genesis.
    pub anonymity_revokers: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
    /// Governance (update) keys at genesis.
    pub update_keys: UpdateKeysCollectionCPV1,
    /// Fully-resolved chain parameters.
    pub chain_parameters: ChainParametersV3,
    /// Nonce used for the leader-election VRF in the first epoch.
    pub leadership_election_nonce: LeadershipElectionNonce,
    /// Public account data for all accounts at genesis.
    pub accounts: Vec<GenesisAccountPublic>,
}

impl Serial for GenesisStateCPV3 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let mut tmp = Vec::new();
        serialize_with_length_header(&self.cryptographic_parameters, &mut tmp, out);
        (self.identity_providers.len() as u32).serial(out);
        for (k, v) in self.identity_providers.iter() {
            k.serial(out);
            serialize_with_length_header(v, &mut tmp, out);
        }
        (self.anonymity_revokers.len() as u32).serial(out);
        for (k, v) in self.anonymity_revokers.iter() {
            k.serial(out);
            serialize_with_length_header(v, &mut tmp, out);
        }
        self.update_keys.serial(out);
        self.chain_parameters.serial(out);
        self.leadership_election_nonce.serial(out);
        self.accounts.serial(out)
    }
}

// ── GenesisData enum ──────────────────────────────────────────────────────────

/// A fully-assembled genesis block value for any supported protocol version.
///
/// Each variant pairs core timing parameters with the corresponding genesis
/// state. Serialise with [`super::serialize_genesis`] to produce `genesis.dat`,
/// or call [`GenesisData::hash`] to obtain the genesis block hash.
pub enum GenesisData {
    /// Genesis block for protocol version P1.
    P1 {
        /// Slot-based timing and finalization parameters.
        core: CoreGenesisParametersV0,
        /// Full CPV0 on-chain state.
        initial_state: GenesisStateCPV0,
    },
    /// Genesis block for protocol version P2.
    P2 {
        /// Slot-based timing and finalization parameters.
        core: CoreGenesisParametersV0,
        /// Full CPV0 on-chain state.
        initial_state: GenesisStateCPV0,
    },
    /// Genesis block for protocol version P3.
    P3 {
        /// Slot-based timing and finalization parameters.
        core: CoreGenesisParametersV0,
        /// Full CPV0 on-chain state.
        initial_state: GenesisStateCPV0,
    },
    /// Genesis block for protocol version P4.
    P4 {
        /// Slot-based timing and finalization parameters.
        core: CoreGenesisParametersV0,
        /// Full CPV1 on-chain state.
        initial_state: GenesisStateCPV1,
    },
    /// Genesis block for protocol version P5.
    P5 {
        /// Slot-based timing and finalization parameters.
        core: CoreGenesisParametersV0,
        /// Full CPV1 on-chain state.
        initial_state: GenesisStateCPV1,
    },
    /// Genesis block for protocol version P6.
    P6 {
        /// Epoch-based timing and quorum parameters.
        core: CoreGenesisParametersV1,
        /// Full CPV2 on-chain state.
        initial_state: GenesisStateCPV2,
    },
    /// Genesis block for protocol version P7.
    P7 {
        /// Epoch-based timing and quorum parameters.
        core: CoreGenesisParametersV1,
        /// Full CPV2 on-chain state.
        initial_state: GenesisStateCPV2,
    },
    /// Genesis block for protocol version P8.
    P8 {
        /// Epoch-based timing and quorum parameters.
        core: CoreGenesisParametersV1,
        /// Full CPV3 on-chain state.
        initial_state: GenesisStateCPV3,
    },
    /// Genesis block for protocol version P9.
    P9 {
        /// Epoch-based timing and quorum parameters.
        core: CoreGenesisParametersV1,
        /// Full CPV3 on-chain state.
        initial_state: GenesisStateCPV3,
    },
    /// Genesis block for protocol version P10.
    P10 {
        /// Epoch-based timing and quorum parameters.
        core: CoreGenesisParametersV1,
        /// Full CPV3 on-chain state.
        initial_state: GenesisStateCPV3,
    },
    /// Genesis block for protocol version P11.
    P11 {
        /// Epoch-based timing and quorum parameters.
        core: CoreGenesisParametersV1,
        /// Full CPV3 on-chain state.
        initial_state: GenesisStateCPV3,
    },
}

impl GenesisData {
    /// Compute the genesis block hash.
    ///
    /// The hash is the SHA-256 of the concatenation of a zero slot number, the
    /// protocol version byte, a zero variant byte, the serialised core
    /// parameters, and the serialised initial state — matching the format
    /// expected by `concordium-node`.
    pub fn hash(&self) -> BlockHash {
        let mut hasher = sha2::Sha256::new();
        Slot::from(0u64).serial(&mut hasher);
        match self {
            GenesisData::P1 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P1.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P2 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P2.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P3 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P3.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P4 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P4.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P5 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P5.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P6 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P6.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P7 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P7.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P8 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P8.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P9 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P9.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P10 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P10.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
            GenesisData::P11 {
                core,
                initial_state,
            } => {
                ProtocolVersion::P11.serial(&mut hasher);
                0u8.serial(&mut hasher);
                core.serial(&mut hasher);
                initial_state.serial(&mut hasher);
            }
        }
        let bytes: [u8; 32] = hasher.finalize().into();
        bytes.into()
    }
}

impl Serial for GenesisData {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            GenesisData::P1 {
                core,
                initial_state,
            } => {
                3u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P2 {
                core,
                initial_state,
            } => {
                4u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P3 {
                core,
                initial_state,
            } => {
                5u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P4 {
                core,
                initial_state,
            } => {
                6u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P5 {
                core,
                initial_state,
            } => {
                7u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P6 {
                core,
                initial_state,
            } => {
                8u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P7 {
                core,
                initial_state,
            } => {
                9u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P8 {
                core,
                initial_state,
            } => {
                10u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P9 {
                core,
                initial_state,
            } => {
                11u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P10 {
                core,
                initial_state,
            } => {
                12u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
            GenesisData::P11 {
                core,
                initial_state,
            } => {
                13u8.serial(out);
                0u8.serial(out);
                core.serial(out);
                initial_state.serial(out)
            }
        }
    }
}

// ── Protocol parameter structs ────────────────────────────────────────────────

/// Fully-typed protocol parameters for CPV0 genesis blocks (P1–P3).
///
/// Pass to [`GenesisBuilderCPV0::with_protocol`](super::GenesisBuilderCPV0::with_protocol).
#[derive(Debug, Clone)]
pub struct ProtocolParamsCPV0 {
    /// Core slot-based timing and finalization parameters.
    pub core: CoreGenesisParametersV0,
    /// Pending chain parameters (foundation account index resolved at build time).
    pub chain: GenesisChainParametersV0,
    /// Nonce used for leader election in the first epoch.
    pub leadership_election_nonce: LeadershipElectionNonce,
}

/// Fully-typed protocol parameters for CPV1 genesis blocks (P4–P5).
///
/// Pass to [`GenesisBuilderCPV1::with_protocol`](super::GenesisBuilderCPV1::with_protocol).
#[derive(Debug, Clone)]
pub struct ProtocolParamsCPV1 {
    /// Core slot-based timing and finalization parameters.
    pub core: CoreGenesisParametersV0,
    /// Pending chain parameters (foundation account index resolved at build time).
    pub chain: GenesisChainParametersV1,
    /// Nonce used for leader election in the first epoch.
    pub leadership_election_nonce: LeadershipElectionNonce,
}

/// Fully-typed protocol parameters for CPV2 genesis blocks (P6–P7).
///
/// Pass to [`GenesisBuilderCPV2::with_protocol`](super::GenesisBuilderCPV2::with_protocol).
#[derive(Debug, Clone)]
pub struct ProtocolParamsCPV2 {
    /// Core epoch-based timing and quorum parameters.
    pub core: CoreGenesisParametersV1,
    /// Pending chain parameters (foundation account index resolved at build time).
    pub chain: GenesisChainParametersV2,
    /// Nonce used for leader election in the first epoch.
    pub leadership_election_nonce: LeadershipElectionNonce,
}

/// Fully-typed protocol parameters for CPV3 genesis blocks (P8+).
///
/// Pass to [`GenesisBuilderCPV3::with_protocol`](super::GenesisBuilderCPV3::with_protocol).
#[derive(Debug, Clone)]
pub struct ProtocolParamsCPV3 {
    /// Core epoch-based timing and quorum parameters.
    pub core: CoreGenesisParametersV1,
    /// Pending chain parameters (foundation account index resolved at build time).
    pub chain: GenesisChainParametersV3,
    /// Nonce used for leader election in the first epoch.
    pub leadership_election_nonce: LeadershipElectionNonce,
}
