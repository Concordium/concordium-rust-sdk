//! Genesis builder types for all chain parameter versions (CPV0-CPV3).
use super::output::{GeneratedKeyPair, GenesisOutputCPV3};
use super::types::{
    GenesisAccountPublic, GenesisBakerPublic, GenesisData, GenesisStateCPV3,
    UpdateKeysCollectionCPV1, UpdateKeysCollectionSkeleton,
};
use crate::types::{
    AccessStructure, AccountIndex, AuthorizationsV0, AuthorizationsV1, BakerCredentials, BakerId,
    BakerKeyPairs, HigherLevelAccessStructure, ProtocolVersion, UpdateKeyPair, UpdateKeysIndex,
    UpdateKeysThreshold, UpdatePublicKey,
};
use anyhow::{anyhow, bail, ensure};
use concordium_base::{
    common::{
        types::{Amount, CredentialIndex, KeyIndex, KeyPair},
        Versioned, VERSION_0,
    },
    id::{
        self,
        account_holder::compute_sharing_data,
        constants::{ArCurve, IpPairing},
        curve_arithmetic::{Curve, Value},
        types::{
            account_address_from_registration_id, mk_dummy_description, AccCredentialInfo,
            AccountCredentialWithoutProofs, AccountKeys, ArData, ArIdentity, ArInfo, ChainArData,
            CredentialData, CredentialDeploymentCommitments, CredentialDeploymentValues,
            CredentialHolderInfo, GlobalContext, IpData, IpIdentity, IpInfo, Policy,
            PublicCredentialData, SignatureThreshold, YearMonth,
        },
    },
};
use std::{collections::BTreeMap, collections::BTreeSet, sync::atomic::AtomicU64};

// ── Input types ───────────────────────────────────────────────────────────────

/// How to supply cryptographic parameters to the builder.
pub enum CryptoParamsInput {
    /// Use pre-existing, already-loaded cryptographic parameters.
    Existing(Box<GlobalContext<ArCurve>>),
    /// Generate fresh cryptographic parameters from the given genesis string.
    Generate { genesis_string: String },
}

/// A single identity-provider input item.
pub enum IpInputItem {
    /// An existing identity provider with full private key data (generate mode).
    ExistingFull(Box<IpData<IpPairing>>),
    /// An existing identity provider with public info only (assemble mode).
    ExistingPublic(Box<IpInfo<IpPairing>>),
    /// Generate `count` fresh identity providers starting at `start_id`.
    Fresh { start_id: IpIdentity, count: u32 },
}

/// A single anonymity-revoker input item.
pub enum ArInputItem {
    /// An existing anonymity revoker with full private key data (generate mode).
    ExistingFull(Box<ArData<ArCurve>>),
    /// An existing anonymity revoker with public info only (assemble mode).
    ExistingPublic(Box<ArInfo<ArCurve>>),
    /// Generate `count` fresh anonymity revokers starting at `start_id`.
    Fresh { start_id: ArIdentity, count: u32 },
}

/// Full account data for an existing account supplied with private keys (generate mode).
/// Used as the payload of [`AccountInputItem::ExistingFull`].
pub struct ExistingFullAccount {
    /// The account, including private key material.
    pub account: super::types::GenesisAccount,
    /// Initial CCD balance.
    pub balance: Amount,
    /// Staking amount, or `None` if not a baker.
    pub stake: Option<Amount>,
    /// Whether staking rewards are automatically restaked.
    pub restake_earnings: bool,
    /// Pre-existing baker credentials, or `None` to generate fresh ones when `stake` is set.
    pub baker_credentials: Option<BakerCredentials>,
    /// Whether this is the foundation account.
    pub foundation: bool,
}

/// A single account input item.
pub enum AccountInputItem {
    /// An existing account with full private key data (generate mode).
    ExistingFull(Box<ExistingFullAccount>),
    /// An existing account with public data only (assemble mode).
    ExistingPublic {
        account: GenesisAccountPublic,
        foundation: bool,
    },
    /// Generate `count` fresh accounts according to `config`.
    Fresh(FreshAccountConfig),
}

/// Configuration for a batch of freshly generated accounts.
pub struct FreshAccountConfig {
    /// The size of the batch.
    pub count: u32,
    /// The stake of these accounts, None meaning they are not validating.
    pub stake: Option<Amount>,
    /// The initial balance.
    pub balance: Amount,
    /// Number of credential keys per account.
    pub num_keys: u8,
    /// Signature threshold.
    pub threshold: SignatureThreshold,
    /// Identifier of the identity provider.
    pub identity_provider: IpIdentity,
    /// Whether validator stake have restake earnings enabled.
    pub restake_earnings: bool,
    /// Whether this is the foundation account (ensure `count` is 1).
    pub foundation: bool,
}

// ── Governance key input types ────────────────────────────────────────────────

/// Specifier for a single governance key within a level.
pub enum GovernanceKeySpec {
    /// Use a pre-loaded public key (no private key available).
    Existing(UpdatePublicKey),
    /// Generate `count` fresh key pairs.
    Fresh { count: u32 },
}

/// Configuration for one key level (root or level-1).
pub struct GovernanceKeyLevelConfig {
    /// Minimum number of keys required to authorise an update at this level.
    pub threshold: UpdateKeysThreshold,
    /// Key specifiers: each entry is either an existing public key or a
    /// request to generate `count` fresh key pairs.
    pub keys: Vec<GovernanceKeySpec>,
}

/// Access-structure configuration for a single level-2 update type.
pub struct Level2AccessConfig {
    /// Indices into the level-2 key array of keys authorised for this update type.
    pub authorized_keys: Vec<UpdateKeysIndex>,
    /// Minimum number of those keys required to authorise an update.
    pub threshold: UpdateKeysThreshold,
}

impl Level2AccessConfig {
    fn access_structure(&self, ctx: &[UpdatePublicKey]) -> anyhow::Result<AccessStructure> {
        let num_given_keys = self.authorized_keys.len();
        let authorized_keys: BTreeSet<_> = self.authorized_keys.iter().copied().collect();
        ensure!(
            authorized_keys.len() == num_given_keys,
            "Duplicate key index provided."
        );
        for key_idx in authorized_keys.iter() {
            ensure!(
                usize::from(key_idx.index) < ctx.len(),
                "Key index {} does not specify a known update key.",
                key_idx.index
            );
        }
        ensure!(
            usize::from(u16::from(self.threshold)) <= num_given_keys,
            "Governance key threshold ({}) exceeds the number of authorized keys ({}).",
            self.threshold,
            num_given_keys
        );
        Ok(AccessStructure {
            authorized_keys,
            threshold: self.threshold,
        })
    }
}

/// Full level-2 governance key configuration for CPV1 and later (P4+).
///
/// Each field corresponds to one on-chain update type. `create_plt` must be
/// `None` for P4–P8 and `Some` for P9+.
pub struct Level2GovernanceKeysConfig {
    /// Level-2 public keys; each [`GovernanceKeySpec`] entry adds existing or
    /// fresh keys to the shared pool referenced by the access structures below.
    pub keys: Vec<GovernanceKeySpec>,
    /// Keys authorised to trigger emergency updates.
    pub emergency: Level2AccessConfig,
    /// Keys authorised to trigger protocol updates.
    pub protocol: Level2AccessConfig,
    /// Keys authorised to update the election difficulty.
    pub election_difficulty: Level2AccessConfig,
    /// Keys authorised to update the euro-per-energy rate.
    pub euro_per_energy: Level2AccessConfig,
    /// Keys authorised to update the micro-CCD-per-euro rate.
    pub micro_ccd_per_euro: Level2AccessConfig,
    /// Keys authorised to update the foundation account.
    pub foundation_account: Level2AccessConfig,
    /// Keys authorised to update the mint distribution.
    pub mint_distribution: Level2AccessConfig,
    /// Keys authorised to update the transaction fee distribution.
    pub transaction_fee_distribution: Level2AccessConfig,
    /// Keys authorised to update GAS rewards.
    pub gas_rewards: Level2AccessConfig,
    /// Keys authorised to update pool parameters.
    pub pool_parameters: Level2AccessConfig,
    /// Keys authorised to add a new anonymity revoker.
    pub add_anonymity_revoker: Level2AccessConfig,
    /// Keys authorised to add a new identity provider.
    pub add_identity_provider: Level2AccessConfig,
    /// Keys authorised to update cooldown parameters.
    pub cooldown_parameters: Level2AccessConfig,
    /// Keys authorised to update time parameters.
    pub time_parameters: Level2AccessConfig,
    /// Keys authorised to create a new PLT. Must be `None` for P4–P8 and
    /// `Some` for P9+.
    pub create_plt: Option<Level2AccessConfig>,
}

/// Full governance key generation configuration for CPV1 and later.
///
/// Passed to [`GovernanceKeysInput::Generate`] or
/// [`GovernanceKeysInputCPV0::Generate`].
pub struct GovernanceKeysGenerateConfig {
    /// Root key level configuration.
    pub root: GovernanceKeyLevelConfig,
    /// Level-1 key level configuration.
    pub level1: GovernanceKeyLevelConfig,
    /// Level-2 key and access-structure configuration.
    pub level2: Level2GovernanceKeysConfig,
}

/// How to supply governance keys to a CPV3 builder.
pub enum GovernanceKeysInput {
    /// Use a pre-existing, already-built governance key collection.
    Existing(UpdateKeysCollectionCPV1),
    /// Generate governance keys from the given configuration.
    Generate(Box<GovernanceKeysGenerateConfig>),
}

// ── impl_common_builder_methods! macro ────────────────────────────────────────
//
// Stamps the 11 common input-population methods as inherent `pub` methods on
// each CPV builder.  Methods live on the concrete type — no trait import needed.

macro_rules! impl_common_builder_methods {
    () => {
        // ── Crypto params ─────────────────────────────────────────────────

        /// Supply pre-existing cryptographic parameters.
        pub fn with_crypto_params(mut self, params: GlobalContext<ArCurve>) -> Self {
            self.inner.crypto_params = Some(CryptoParamsInput::Existing(Box::new(params)));
            self
        }

        /// Derive fresh cryptographic parameters from `genesis_string`.
        pub fn generate_crypto_params(mut self, genesis_string: String) -> Self {
            self.inner.crypto_params = Some(CryptoParamsInput::Generate { genesis_string });
            self
        }

        // ── Identity providers ────────────────────────────────────────────

        /// Add an existing identity provider with full private-key data (generate mode).
        pub fn add_identity_provider(mut self, ip: IpData<IpPairing>) -> Self {
            self.inner
                .ip_inputs
                .push(IpInputItem::ExistingFull(Box::new(ip)));
            self
        }

        /// Add an existing identity provider with public info only (assemble mode).
        pub fn add_identity_provider_public(mut self, ip: IpInfo<IpPairing>) -> Self {
            self.inner
                .ip_inputs
                .push(IpInputItem::ExistingPublic(Box::new(ip)));
            self
        }

        /// Generate `count` fresh identity providers starting at `start_id`.
        pub fn generate_identity_providers(mut self, start_id: IpIdentity, count: u32) -> Self {
            self.inner
                .ip_inputs
                .push(IpInputItem::Fresh { start_id, count });
            self
        }

        // ── Anonymity revokers ────────────────────────────────────────────

        /// Add an existing anonymity revoker with full private-key data (generate mode).
        pub fn add_anonymity_revoker(mut self, ar: ArData<ArCurve>) -> Self {
            self.inner
                .ar_inputs
                .push(ArInputItem::ExistingFull(Box::new(ar)));
            self
        }

        /// Add an existing anonymity revoker with public info only (assemble mode).
        pub fn add_anonymity_revoker_public(mut self, ar: ArInfo<ArCurve>) -> Self {
            self.inner
                .ar_inputs
                .push(ArInputItem::ExistingPublic(Box::new(ar)));
            self
        }

        /// Generate `count` fresh anonymity revokers starting at `start_id`.
        pub fn generate_anonymity_revokers(mut self, start_id: ArIdentity, count: u32) -> Self {
            self.inner
                .ar_inputs
                .push(ArInputItem::Fresh { start_id, count });
            self
        }

        // ── Accounts ─────────────────────────────────────────────────────

        /// Add an existing account with full private-key data (generate mode).
        pub fn add_existing_account(
            mut self,
            account: super::types::GenesisAccount,
            balance: Amount,
            stake: Option<Amount>,
            restake_earnings: bool,
            baker_credentials: Option<BakerCredentials>,
            foundation: bool,
        ) -> Self {
            self.inner
                .account_inputs
                .push(AccountInputItem::ExistingFull(Box::new(
                    ExistingFullAccount {
                        account,
                        balance,
                        stake,
                        restake_earnings,
                        baker_credentials,
                        foundation,
                    },
                )));
            self
        }

        /// Add an existing account with public data only (assemble mode).
        pub fn add_existing_public_account(
            mut self,
            account: GenesisAccountPublic,
            foundation: bool,
        ) -> Self {
            self.inner
                .account_inputs
                .push(AccountInputItem::ExistingPublic {
                    account,
                    foundation,
                });
            self
        }

        /// Generate a batch of fresh accounts according to `config`.
        pub fn generate_accounts(mut self, config: FreshAccountConfig) -> Self {
            self.inner
                .account_inputs
                .push(AccountInputItem::Fresh(config));
            self
        }
    };
}

// ── GenesisBuilderCommon trait ───────────────────────────────────────────────────

/// Input-population methods shared by all four CPV genesis builders.
///
/// Allows generic code to feed cryptographic parameters, identity providers,
/// anonymity revokers, and accounts to any builder without knowing the concrete
/// CPV type. Protocol parameters and governance keys are CPV-specific and are set
/// directly on the concrete builder types.
pub trait GenesisBuilderCommon: Sized {
    /// Supply pre-existing cryptographic parameters.
    fn with_crypto_params(self, params: GlobalContext<ArCurve>) -> Self;
    /// Derive fresh cryptographic parameters from `genesis_string`.
    fn generate_crypto_params(self, genesis_string: String) -> Self;
    /// Add one existing identity provider (public info only).
    fn add_identity_provider_public(self, ip: IpInfo<IpPairing>) -> Self;
    /// Generate `count` fresh identity providers starting at `start_id`.
    fn generate_identity_providers(self, start_id: IpIdentity, count: u32) -> Self;
    /// Add one existing anonymity revoker (public info only).
    fn add_anonymity_revoker_public(self, ar: ArInfo<ArCurve>) -> Self;
    /// Generate `count` fresh anonymity revokers starting at `start_id`.
    fn generate_anonymity_revokers(self, start_id: ArIdentity, count: u32) -> Self;
    /// Add an existing account with full private-key data (generate mode).
    fn add_existing_account(
        self,
        account: super::types::GenesisAccount,
        balance: concordium_base::common::types::Amount,
        stake: Option<concordium_base::common::types::Amount>,
        restake_earnings: bool,
        baker_credentials: Option<crate::types::BakerCredentials>,
        foundation: bool,
    ) -> Self;
    /// Add an existing account with public data only (assemble mode).
    fn add_existing_public_account(
        self,
        account: super::types::GenesisAccountPublic,
        foundation: bool,
    ) -> Self;
    /// Generate a batch of fresh accounts.
    fn generate_accounts(self, config: FreshAccountConfig) -> Self;
}

macro_rules! impl_genesis_builder_common {
    ($Builder:ty) => {
        impl GenesisBuilderCommon for $Builder {
            fn with_crypto_params(self, params: GlobalContext<ArCurve>) -> Self {
                self.with_crypto_params(params)
            }
            fn generate_crypto_params(self, genesis_string: String) -> Self {
                self.generate_crypto_params(genesis_string)
            }
            fn add_identity_provider_public(self, ip: IpInfo<IpPairing>) -> Self {
                self.add_identity_provider_public(ip)
            }
            fn generate_identity_providers(self, start_id: IpIdentity, count: u32) -> Self {
                self.generate_identity_providers(start_id, count)
            }
            fn add_anonymity_revoker_public(self, ar: ArInfo<ArCurve>) -> Self {
                self.add_anonymity_revoker_public(ar)
            }
            fn generate_anonymity_revokers(self, start_id: ArIdentity, count: u32) -> Self {
                self.generate_anonymity_revokers(start_id, count)
            }
            fn add_existing_account(
                self,
                account: super::types::GenesisAccount,
                balance: concordium_base::common::types::Amount,
                stake: Option<concordium_base::common::types::Amount>,
                restake_earnings: bool,
                baker_credentials: Option<crate::types::BakerCredentials>,
                foundation: bool,
            ) -> Self {
                self.add_existing_account(
                    account,
                    balance,
                    stake,
                    restake_earnings,
                    baker_credentials,
                    foundation,
                )
            }
            fn add_existing_public_account(
                self,
                account: super::types::GenesisAccountPublic,
                foundation: bool,
            ) -> Self {
                self.add_existing_public_account(account, foundation)
            }
            fn generate_accounts(self, config: FreshAccountConfig) -> Self {
                self.generate_accounts(config)
            }
        }
    };
}

impl_genesis_builder_common!(GenesisBuilderCPV3);
impl_genesis_builder_common!(GenesisBuilderCPV2);
impl_genesis_builder_common!(GenesisBuilderCPV1);
impl_genesis_builder_common!(GenesisBuilderCPV0);

// ── CommonGenesisBuilder (internal) ──────────────────────────────────────────

/// Internal builder state shared by all CPV builders.
/// Not exported — accessed only through the CPV-specific builders.
struct CommonGenesisBuilder {
    crypto_params: Option<CryptoParamsInput>,
    ip_inputs: Vec<IpInputItem>,
    ar_inputs: Vec<ArInputItem>,
    account_inputs: Vec<AccountInputItem>,
}

impl CommonGenesisBuilder {
    fn new() -> Self {
        Self {
            crypto_params: None,
            ip_inputs: Vec::new(),
            ar_inputs: Vec::new(),
            account_inputs: Vec::new(),
        }
    }
}

// ── GenesisBuilderCPV3 ────────────────────────────────────────────────────────

/// Builder for genesis blocks targeting Chain Parameters Version 3 (P8–P11).
///
/// Obtain an instance via one of the factory functions:
/// [`genesis_builder_p8`], [`genesis_builder_p9`], [`genesis_builder_p10`],
/// [`genesis_builder_p11`].
pub struct GenesisBuilderCPV3 {
    inner: CommonGenesisBuilder,
    /// Protocol version baked in at construction via a factory function.
    protocol_version: ProtocolVersion,
    /// Typed protocol parameters supplied via [`GenesisBuilderCPV3::with_protocol`].
    protocol_params: Option<super::types::ProtocolParamsCPV3>,
    governance_keys_input: Option<GovernanceKeysInput>,
}

impl GenesisBuilderCPV3 {
    /// Private constructor. Use `genesis_builder_p8()` through
    /// `genesis_builder_p11()` instead.
    fn new(pv: ProtocolVersion) -> Self {
        Self {
            inner: CommonGenesisBuilder::new(),
            protocol_version: pv,
            protocol_params: None,
            governance_keys_input: None,
        }
    }

    impl_common_builder_methods!();

    // ── Governance keys ───────────────────────────────────────────────────────

    /// Use a pre-existing governance key collection.
    pub fn with_governance_keys(mut self, keys: UpdateKeysCollectionCPV1) -> Self {
        self.governance_keys_input = Some(GovernanceKeysInput::Existing(keys));
        self
    }

    /// Generate governance keys from the given configuration.
    pub fn generate_governance_keys(mut self, config: GovernanceKeysGenerateConfig) -> Self {
        self.governance_keys_input = Some(GovernanceKeysInput::Generate(Box::new(config)));
        self
    }

    /// Set governance keys input directly (either existing or generate).
    pub fn with_governance_keys_input(mut self, input: GovernanceKeysInput) -> Self {
        self.governance_keys_input = Some(input);
        self
    }

    // ── Protocol ──────────────────────────────────────────────────────────────

    /// Set the typed protocol parameters.
    ///
    /// The protocol version is already fixed by the factory function used to
    /// construct this builder; this method supplies the chain and core parameters.
    pub fn with_protocol(mut self, params: super::types::ProtocolParamsCPV3) -> Self {
        self.protocol_params = Some(params);
        self
    }

    // ── Build ─────────────────────────────────────────────────────────────────

    /// Build the genesis block.
    ///
    /// Build the CPV3 genesis block.
    ///
    /// The protocol version was fixed at construction via a factory function.
    /// Returns an error if validation fails.
    pub fn build(self) -> anyhow::Result<GenesisOutputCPV3> {
        let mut csprng = rand::thread_rng();
        let pv = self.protocol_version;

        // 1. Protocol parameters
        let params = self.protocol_params.ok_or_else(|| {
            anyhow!("Protocol parameters not set. Call .with_protocol() before .build().")
        })?;

        // 2. Cryptographic parameters
        let crypto_params = build_crypto_params(self.inner.crypto_params)?;

        // 3. Identity providers
        let IpBuildOutput {
            data_list: ip_data_list,
            info_map: ip_info_map,
        } = build_identity_providers(self.inner.ip_inputs, &mut csprng)?;

        // 4. Anonymity revokers
        let ArBuildOutput {
            data_list: ar_data_list,
            info_map: ar_info_map,
        } = build_anonymity_revokers(self.inner.ar_inputs, &crypto_params, &mut csprng)?;

        // 5. Accounts — also resolves the foundation account index.
        let AccountBuildOutput {
            account_data,
            accounts_public,
            baker_credentials: baker_creds,
            foundation_index: foundation_idx,
        } = build_accounts(self.inner.account_inputs, &crypto_params, &ar_info_map)?;

        tracing::info!(
            "There are {} accounts in genesis, {} of which are bakers.",
            accounts_public.len(),
            baker_creds.len()
        );

        let governance_keys_input = self.governance_keys_input.ok_or_else(|| {
            anyhow!(
                "Governance keys not set. Call .with_governance_keys() or \n                 .generate_governance_keys() before .build()."
            )
        })?;

        let GovernanceKeysOutput {
            keys: governance_keys,
            generated_root_key_pairs: gen_root,
            generated_level1_key_pairs: gen_level1,
            generated_level2_key_pairs: gen_level2,
        } = build_governance_keys(governance_keys_input, &mut csprng)?;

        // 7. Validate createPLT requirement.
        match pv {
            ProtocolVersion::P8 => {
                if governance_keys.level_2_keys.create_plt.is_some() {
                    bail!("P8 does not support createPLT authorization.");
                }
            }
            ProtocolVersion::P9 | ProtocolVersion::P10 | ProtocolVersion::P11 => {
                if governance_keys.level_2_keys.create_plt.is_none() {
                    bail!("{:?} requires createPLT authorization.", pv);
                }
            }
            _ => unreachable!("Protocol version validated at construction."),
        }

        // 8. Resolve chain parameters by injecting the foundation account index.
        let chain_params = params.chain.resolve(foundation_idx);

        tracing::info!(
            "Genesis time is set to {}.",
            chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH)
                + chrono::Duration::milliseconds(params.core.genesis_time.millis as i64)
        );

        // 9. Build genesis state and data.
        let initial_state = GenesisStateCPV3 {
            cryptographic_parameters: crypto_params.clone(),
            identity_providers: ip_info_map.clone(),
            anonymity_revokers: ar_info_map.clone(),
            update_keys: governance_keys.clone(),
            chain_parameters: chain_params,
            leadership_election_nonce: params.leadership_election_nonce,
            accounts: accounts_public.clone(),
        };

        let genesis_data = match pv {
            ProtocolVersion::P8 => GenesisData::P8 {
                core: params.core,
                initial_state,
            },
            ProtocolVersion::P9 => GenesisData::P9 {
                core: params.core,
                initial_state,
            },
            ProtocolVersion::P10 => GenesisData::P10 {
                core: params.core,
                initial_state,
            },
            ProtocolVersion::P11 => GenesisData::P11 {
                core: params.core,
                initial_state,
            },
            _ => unreachable!(),
        };

        Ok(GenesisOutputCPV3 {
            crypto_params,
            identity_provider_data: ip_data_list,
            identity_provider_infos: ip_info_map,
            anonymity_revoker_data: ar_data_list,
            anonymity_revoker_infos: ar_info_map,
            account_data,
            accounts_public,
            baker_credentials: baker_creds,
            governance_keys,
            generated_root_key_pairs: gen_root,
            generated_level1_key_pairs: gen_level1,
            generated_level2_key_pairs: gen_level2,
            genesis_data,
        })
    }
}

// ── CPV3 factory functions ────────────────────────────────────────────────────────────

/// Returns a [`GenesisBuilderCPV3`] targeting protocol version **P8**.
pub fn genesis_builder_p8() -> GenesisBuilderCPV3 {
    GenesisBuilderCPV3::new(ProtocolVersion::P8)
}

/// Returns a [`GenesisBuilderCPV3`] targeting protocol version **P9**.
pub fn genesis_builder_p9() -> GenesisBuilderCPV3 {
    GenesisBuilderCPV3::new(ProtocolVersion::P9)
}

/// Returns a [`GenesisBuilderCPV3`] targeting protocol version **P10**.
pub fn genesis_builder_p10() -> GenesisBuilderCPV3 {
    GenesisBuilderCPV3::new(ProtocolVersion::P10)
}

/// Returns a [`GenesisBuilderCPV3`] targeting protocol version **P11**.
pub fn genesis_builder_p11() -> GenesisBuilderCPV3 {
    GenesisBuilderCPV3::new(ProtocolVersion::P11)
}

// ── Internal generation helpers ───────────────────────────────────────────────

/// Output of [`build_identity_providers`].
struct IpBuildOutput {
    data_list: Vec<IpData<IpPairing>>,
    info_map: BTreeMap<IpIdentity, IpInfo<IpPairing>>,
}

/// Output of [`build_anonymity_revokers`].
struct ArBuildOutput {
    data_list: Vec<ArData<ArCurve>>,
    info_map: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
}

/// Output of [`build_accounts`].
struct AccountBuildOutput {
    account_data: Vec<super::types::GenesisAccount>,
    accounts_public: Vec<GenesisAccountPublic>,
    baker_credentials: Vec<BakerCredentials>,
    foundation_index: AccountIndex,
}

fn build_crypto_params(input: Option<CryptoParamsInput>) -> anyhow::Result<GlobalContext<ArCurve>> {
    match input {
        Some(CryptoParamsInput::Existing(p)) => Ok(*p),
        Some(CryptoParamsInput::Generate { genesis_string }) => {
            tracing::info!("Generating cryptographic parameters from genesis string.");
            Ok(GlobalContext::generate(genesis_string))
        }
        None => bail!(
            "Cryptographic parameters not set. Call .with_crypto_params() or \
             .generate_crypto_params() before .build()."
        ),
    }
}

fn build_identity_providers(
    inputs: Vec<IpInputItem>,
    csprng: &mut (impl rand::Rng + rand::CryptoRng),
) -> anyhow::Result<IpBuildOutput> {
    let mut data_list: Vec<IpData<IpPairing>> = Vec::new();
    let mut info_map: BTreeMap<IpIdentity, IpInfo<IpPairing>> = BTreeMap::new();

    for item in inputs {
        match item {
            IpInputItem::ExistingFull(data) => {
                let id = data.public_ip_info.ip_identity;
                ensure!(
                    !info_map.contains_key(&id),
                    "Duplicate identity provider id {}.",
                    id
                );
                info_map.insert(id, data.public_ip_info.clone());
                data_list.push(*data);
            }
            IpInputItem::ExistingPublic(info) => {
                let id = info.ip_identity;
                ensure!(
                    !info_map.contains_key(&id),
                    "Duplicate identity provider id {}.",
                    id
                );
                info_map.insert(id, *info);
            }
            IpInputItem::Fresh { start_id, count } => {
                for n in start_id.0..(start_id.0 + count) {
                    let ip_identity = IpIdentity::from(n);
                    ensure!(
                        !info_map.contains_key(&ip_identity),
                        "Duplicate identity provider {}.",
                        ip_identity
                    );
                    tracing::info!("Generating identity provider {}.", n);
                    let ip_description = mk_dummy_description(format!("Generated IP {n}"));
                    let ip_secret_key =
                        concordium_base::id::ps_sig::SecretKey::<IpPairing>::generate(30, csprng);
                    let ip_verify_key = (&ip_secret_key).into();
                    let ip_cdi_kp_secret = ed25519_dalek::SigningKey::generate(csprng);
                    let ip_cdi_verify_key = ip_cdi_kp_secret.verifying_key();
                    let ip_data = IpData {
                        public_ip_info: IpInfo {
                            ip_identity,
                            ip_description,
                            ip_verify_key,
                            ip_cdi_verify_key,
                        },
                        ip_secret_key,
                        ip_cdi_secret_key: ip_cdi_kp_secret.to_bytes(),
                    };
                    info_map.insert(ip_identity, ip_data.public_ip_info.clone());
                    data_list.push(ip_data);
                }
            }
        }
    }

    Ok(IpBuildOutput {
        data_list,
        info_map,
    })
}

fn build_anonymity_revokers(
    inputs: Vec<ArInputItem>,
    params: &GlobalContext<ArCurve>,
    csprng: &mut (impl rand::Rng + rand::CryptoRng),
) -> anyhow::Result<ArBuildOutput> {
    let mut data_list: Vec<ArData<ArCurve>> = Vec::new();
    let mut info_map: BTreeMap<ArIdentity, ArInfo<ArCurve>> = BTreeMap::new();

    for item in inputs {
        match item {
            ArInputItem::ExistingFull(data) => {
                let id = data.public_ar_info.ar_identity;
                ensure!(
                    !info_map.contains_key(&id),
                    "Duplicate anonymity revoker id {}.",
                    id
                );
                info_map.insert(id, data.public_ar_info.clone());
                data_list.push(*data);
            }
            ArInputItem::ExistingPublic(info) => {
                let id = info.ar_identity;
                ensure!(
                    !info_map.contains_key(&id),
                    "Duplicate anonymity revoker id {}.",
                    id
                );
                info_map.insert(id, *info);
            }
            ArInputItem::Fresh { start_id, count } => {
                for n in u32::from(start_id)..(u32::from(start_id) + count) {
                    let ar_identity = ArIdentity::try_from(n)
                        .map_err(|_| anyhow!("Invalid anonymity revoker ID {n}."))?;
                    ensure!(
                        !info_map.contains_key(&ar_identity),
                        "Duplicate anonymity revoker {}.",
                        ar_identity
                    );
                    tracing::info!("Generating anonymity revoker {}.", n);
                    let ar_description = mk_dummy_description(format!("Generated AR {n}"));
                    let ar_secret_key =
                        id::elgamal::SecretKey::generate(params.elgamal_generator(), csprng);
                    let ar_data = ArData {
                        public_ar_info: ArInfo {
                            ar_identity,
                            ar_description,
                            ar_public_key: (&ar_secret_key).into(),
                        },
                        ar_secret_key,
                    };
                    info_map.insert(ar_identity, ar_data.public_ar_info.clone());
                    data_list.push(ar_data);
                }
            }
        }
    }

    Ok(ArBuildOutput {
        data_list,
        info_map,
    })
}

/// Builds account data from inputs.
///
/// Returns `(full_account_data, public_accounts, baker_credentials, foundation_index)`.
fn build_accounts(
    inputs: Vec<AccountInputItem>,
    params: &GlobalContext<ArCurve>,
    ars: &BTreeMap<ArIdentity, ArInfo<ArCurve>>,
) -> anyhow::Result<AccountBuildOutput> {
    let mut account_data: Vec<super::types::GenesisAccount> = Vec::new();
    let mut accounts_public: Vec<GenesisAccountPublic> = Vec::new();
    let mut baker_credentials: Vec<BakerCredentials> = Vec::new();
    let mut foundation_index: Option<AccountIndex> = None;
    let mut idx: u64 = 0;

    for item in inputs {
        match item {
            AccountInputItem::ExistingFull(boxed) => {
                let ExistingFullAccount {
                    account,
                    balance,
                    stake,
                    restake_earnings,
                    baker_credentials: provided_creds,
                    foundation,
                } = *boxed;
                if foundation {
                    let old = foundation_index.replace(AccountIndex::from(idx));
                    ensure!(
                        old.is_none(),
                        "There are two accounts marked as foundation accounts."
                    );
                }

                let baker = if let Some(stake) = stake {
                    let baker_id = BakerId::from(AccountIndex::from(idx));
                    let creds = if let Some(creds) = provided_creds {
                        ensure!(
                            creds.baker_id == baker_id,
                            "Baker credential baker_id ({}) does not match the assigned account \
                             index ({}).",
                            creds.baker_id,
                            baker_id
                        );
                        creds
                    } else {
                        let mut csprng = rand::thread_rng();
                        BakerCredentials::new(baker_id, BakerKeyPairs::generate(&mut csprng))
                    };
                    let gb = GenesisBakerPublic {
                        aggregation_verify_key: creds.keys.aggregation_verify.clone(),
                        election_verify_key: creds.keys.election_verify.clone(),
                        signature_verify_key: creds.keys.signature_verify.clone(),
                        baker_id,
                        stake,
                        restake_earnings,
                    };
                    baker_credentials.push(creds);
                    Some(gb)
                } else {
                    None
                };

                let ga_public = GenesisAccountPublic {
                    address: account.address,
                    account_threshold: account.account_keys.threshold,
                    credentials: account.credentials.value.clone(),
                    balance,
                    baker,
                };
                account_data.push(account);
                accounts_public.push(ga_public);
                idx += 1;
            }

            AccountInputItem::ExistingPublic {
                account,
                foundation,
            } => {
                if foundation {
                    let old = foundation_index.replace(AccountIndex::from(idx));
                    ensure!(
                        old.is_none(),
                        "There are two accounts marked as foundation accounts."
                    );
                }
                // For assemble mode: only public data is available; no private
                // baker key material to echo back.
                accounts_public.push(account);
                idx += 1;
            }

            AccountInputItem::Fresh(cfg) => {
                if cfg.foundation {
                    ensure!(
                        foundation_index.is_none(),
                        "There are two accounts marked as foundation accounts."
                    );
                    foundation_index = Some(AccountIndex::from(idx));
                }

                let count = cfg.count;
                ensure!(count > 0, "Fresh account batch count cannot be 0.");

                let num_keys = cfg.num_keys;
                let threshold = cfg.threshold;
                ensure!(
                    num_keys >= u8::from(threshold),
                    "Signature threshold must be at most the number of keys."
                );

                let num_bakers = AtomicU64::new(0);
                let params_ref = params;
                let ars_ref = ars;

                let mut batch: Vec<(
                    super::types::GenesisAccount,
                    GenesisAccountPublic,
                    Option<BakerCredentials>,
                )> = (idx..idx + u64::from(count))
                    .map(|n| {
                        let mut csprng = rand::thread_rng();
                        let prf_key = concordium_base::id::dodis_yampolskiy_prf::SecretKey::<
                            ArCurve,
                        >::generate_non_zero(
                            &mut csprng
                        );
                        let prf_exponent = prf_key.prf_exponent(0)?;
                        let cred_id: ArCurve = prf_key.prf(params_ref.elgamal_generator(), 0)?;

                        let created_at = YearMonth::now();
                        let valid_to =
                            YearMonth::new(created_at.year + 5, created_at.month).unwrap();

                        let id_cred_sec = Value::<ArCurve>::generate_non_zero(&mut csprng);
                        let ar_threshold = std::cmp::max(1, u8::try_from(ars_ref.len() - 1)?);
                        let sharing_data = compute_sharing_data(
                            &id_cred_sec,
                            ars_ref,
                            ar_threshold.try_into().unwrap(),
                            &params_ref.on_chain_commitment_key,
                            &mut csprng,
                        );
                        let ar_data = sharing_data
                            .0
                            .into_iter()
                            .map(|sad| {
                                (
                                    sad.ar.ar_identity,
                                    ChainArData {
                                        enc_id_cred_pub_share: sad.encrypted_share,
                                    },
                                )
                            })
                            .collect();

                        let (account_keys, cred_key_info) = {
                            let mut cred_keys = BTreeMap::new();
                            for i in 0..num_keys {
                                cred_keys.insert(KeyIndex(i), KeyPair::generate(&mut csprng));
                            }
                            let cred_data = CredentialData {
                                keys: cred_keys,
                                threshold,
                            };
                            let cred_key_info = cred_data.get_cred_key_info();
                            (AccountKeys::from(cred_data), cred_key_info)
                        };

                        let acc_cred = AccountCredentialWithoutProofs::Normal {
                            cdv: CredentialDeploymentValues {
                                cred_key_info,
                                cred_id,
                                ip_identity: cfg.identity_provider,
                                threshold: 1u8.try_into().unwrap(),
                                ar_data,
                                policy: Policy {
                                    valid_to,
                                    created_at,
                                    policy_vec: BTreeMap::new(),
                                    _phantom: Default::default(),
                                },
                            },
                            commitments: CredentialDeploymentCommitments {
                                cmm_prf: params_ref
                                    .on_chain_commitment_key
                                    .commit(&prf_key, &mut csprng)
                                    .0,
                                cmm_cred_counter: params_ref
                                    .on_chain_commitment_key
                                    .commit(
                                        &Value::<ArCurve>::new(ArCurve::scalar_from_u64(0)),
                                        &mut csprng,
                                    )
                                    .0,
                                cmm_max_accounts: params_ref
                                    .on_chain_commitment_key
                                    .commit(
                                        &Value::<ArCurve>::new(ArCurve::scalar_from_u64(1)),
                                        &mut csprng,
                                    )
                                    .0,
                                cmm_attributes: BTreeMap::new(),
                                cmm_id_cred_sec_sharing_coeff: sharing_data.1,
                            },
                        };

                        let encryption_secret_key = concordium_base::id::elgamal::SecretKey {
                            generator: *params_ref.elgamal_generator(),
                            scalar: prf_exponent,
                        };
                        let aci = AccCredentialInfo {
                            cred_holder_info: CredentialHolderInfo {
                                id_cred: id_cred_sec.into(),
                            },
                            prf_key,
                        };
                        let ga = super::types::GenesisAccount {
                            account_keys,
                            aci,
                            address: account_address_from_registration_id(&cred_id),
                            credentials: Versioned::new(
                                VERSION_0,
                                [(CredentialIndex { index: 0 }, acc_cred)]
                                    .into_iter()
                                    .collect(),
                            ),
                            encryption_public_key: (&encryption_secret_key).into(),
                            encryption_secret_key,
                        };

                        let baker = if let Some(stake) = cfg.stake {
                            ensure!(
                                stake <= cfg.balance,
                                "Initial stake must not be above the initial balance."
                            );
                            num_bakers.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                            let keys = BakerKeyPairs::generate(&mut csprng);
                            let baker_id = BakerId::from(AccountIndex::from(n));
                            let creds = BakerCredentials::new(baker_id, keys);
                            let gb = GenesisBakerPublic {
                                aggregation_verify_key: creds.keys.aggregation_verify.clone(),
                                election_verify_key: creds.keys.election_verify.clone(),
                                signature_verify_key: creds.keys.signature_verify.clone(),
                                baker_id,
                                stake,
                                restake_earnings: cfg.restake_earnings,
                            };
                            Some((gb, creds))
                        } else {
                            None
                        };

                        let (baker_public, baker_creds) = match baker {
                            Some((gb, creds)) => (Some(gb), Some(creds)),
                            None => (None, None),
                        };

                        let ga_public = GenesisAccountPublic {
                            address: account_address_from_registration_id(&cred_id),
                            account_threshold: 1.try_into().unwrap(),
                            credentials: ga.credentials.value.clone(),
                            balance: cfg.balance,
                            baker: baker_public,
                        };

                        Ok((ga, ga_public, baker_creds))
                    })
                    .collect::<anyhow::Result<_>>()?;

                for (ga, ga_public, bc) in batch.drain(..) {
                    account_data.push(ga);
                    accounts_public.push(ga_public);
                    if let Some(creds) = bc {
                        baker_credentials.push(creds);
                    }
                }

                idx += u64::from(count);
            }
        }
    }

    let foundation_index = foundation_index.ok_or_else(|| {
        anyhow!("No account designated as the foundation account. Set `foundation = true` on exactly one account.")
    })?;

    Ok(AccountBuildOutput {
        account_data,
        accounts_public,
        baker_credentials,
        foundation_index,
    })
}

/// Resolves and generates governance keys.
///
/// Returned by [`build_governance_keys`] and [`build_governance_keys_v0`].
struct GovernanceKeysOutput<GK> {
    /// The fully assembled governance key collection.
    keys: GK,
    /// Freshly generated root-level key pairs (empty when pre-existing keys were supplied).
    generated_root_key_pairs: Vec<GeneratedKeyPair>,
    /// Freshly generated level-1 key pairs (empty when pre-existing keys were supplied).
    generated_level1_key_pairs: Vec<GeneratedKeyPair>,
    /// Freshly generated level-2 key pairs (empty when pre-existing keys were supplied).
    generated_level2_key_pairs: Vec<GeneratedKeyPair>,
}

/// Resolves and generates governance keys.
fn build_governance_keys(
    input: GovernanceKeysInput,
    csprng: &mut (impl rand::Rng + rand::CryptoRng),
) -> anyhow::Result<GovernanceKeysOutput<UpdateKeysCollectionCPV1>> {
    match input {
        GovernanceKeysInput::Existing(keys) => Ok(GovernanceKeysOutput {
            keys,
            generated_root_key_pairs: vec![],
            generated_level1_key_pairs: vec![],
            generated_level2_key_pairs: vec![],
        }),
        GovernanceKeysInput::Generate(cfg) => {
            let (root_public, gen_root) = resolve_key_level(&cfg.root.keys, "root", csprng)?;
            ensure!(
                usize::from(u16::from(cfg.root.threshold)) <= root_public.len(),
                "The number of root keys ({}) is less than the root threshold ({}).",
                root_public.len(),
                cfg.root.threshold
            );

            let (level1_public, gen_level1) =
                resolve_key_level(&cfg.level1.keys, "level1", csprng)?;
            ensure!(
                usize::from(u16::from(cfg.level1.threshold)) <= level1_public.len(),
                "The number of level-1 keys ({}) is less than the level-1 threshold ({}).",
                level1_public.len(),
                cfg.level1.threshold
            );

            let (level2_public, gen_level2) =
                resolve_key_level(&cfg.level2.keys, "level2", csprng)?;
            ensure!(
                !level2_public.is_empty(),
                "There must be at least one level-2 key."
            );

            let l2 = &cfg.level2;
            let emergency = l2.emergency.access_structure(&level2_public)?;
            let protocol = l2.protocol.access_structure(&level2_public)?;
            let election_difficulty = l2.election_difficulty.access_structure(&level2_public)?;
            let euro_per_energy = l2.euro_per_energy.access_structure(&level2_public)?;
            let micro_gtu_per_euro = l2.micro_ccd_per_euro.access_structure(&level2_public)?;
            let foundation_account = l2.foundation_account.access_structure(&level2_public)?;
            let mint_distribution = l2.mint_distribution.access_structure(&level2_public)?;
            let transaction_fee_distribution = l2
                .transaction_fee_distribution
                .access_structure(&level2_public)?;
            let param_gas_rewards = l2.gas_rewards.access_structure(&level2_public)?;
            let pool_parameters = l2.pool_parameters.access_structure(&level2_public)?;
            let add_anonymity_revoker =
                l2.add_anonymity_revoker.access_structure(&level2_public)?;
            let add_identity_provider =
                l2.add_identity_provider.access_structure(&level2_public)?;
            let cooldown_parameters = l2.cooldown_parameters.access_structure(&level2_public)?;
            let time_parameters = l2.time_parameters.access_structure(&level2_public)?;
            let create_plt = l2
                .create_plt
                .as_ref()
                .map(|c| c.access_structure(&level2_public))
                .transpose()?;

            let v0 = AuthorizationsV0 {
                keys: level2_public,
                emergency,
                protocol,
                election_difficulty,
                euro_per_energy,
                micro_gtu_per_euro,
                foundation_account,
                mint_distribution,
                transaction_fee_distribution,
                param_gas_rewards,
                pool_parameters,
                add_anonymity_revoker,
                add_identity_provider,
            };
            let level_2_keys = AuthorizationsV1 {
                v0,
                cooldown_parameters,
                time_parameters,
                create_plt,
            };

            let collection = UpdateKeysCollectionSkeleton {
                root_keys: HigherLevelAccessStructure {
                    keys: root_public,
                    threshold: cfg.root.threshold,
                    _phantom: Default::default(),
                },
                level_1_keys: HigherLevelAccessStructure {
                    keys: level1_public,
                    threshold: cfg.level1.threshold,
                    _phantom: Default::default(),
                },
                level_2_keys,
            };

            Ok(GovernanceKeysOutput {
                keys: collection,
                generated_root_key_pairs: gen_root,
                generated_level1_key_pairs: gen_level1,
                generated_level2_key_pairs: gen_level2,
            })
        }
    }
}

/// Processes a list of `GovernanceKeySpec`s into public keys and generated pairs.
///
/// The returned `Vec<GeneratedKeyPair>` carries each pair's index in the
/// final public-key array so callers can write files with the correct name.
fn resolve_key_level(
    specs: &[GovernanceKeySpec],
    ctx: &str,
    csprng: &mut (impl rand::Rng + rand::CryptoRng),
) -> anyhow::Result<(Vec<UpdatePublicKey>, Vec<GeneratedKeyPair>)> {
    let mut public_keys: Vec<UpdatePublicKey> = Vec::new();
    let mut generated: Vec<GeneratedKeyPair> = Vec::new();

    for spec in specs {
        match spec {
            GovernanceKeySpec::Existing(key) => {
                public_keys.push(key.clone());
            }
            GovernanceKeySpec::Fresh { count } => {
                for _ in 0..*count {
                    let index = public_keys.len();
                    let new_key = UpdateKeyPair::generate(csprng);
                    tracing::info!("Generating {} key {}.", ctx, index);
                    public_keys.push((&new_key).into());
                    generated.push(GeneratedKeyPair {
                        index,
                        key_pair: new_key,
                    });
                }
            }
        }
    }

    Ok((public_keys, generated))
}

// ── GenesisBuilderCPV2 ────────────────────────────────────────────────────────

/// Builder for genesis blocks targeting Chain Parameters Version 2 (P6–P7).
///
/// Obtain an instance via [`genesis_builder_p6`] or [`genesis_builder_p7`].
/// All inputs are accepted as in-memory typed values; no filesystem access
/// occurs inside the builder.
pub struct GenesisBuilderCPV2 {
    inner: CommonGenesisBuilder,
    /// Protocol version baked in at construction via a factory function.
    protocol_version: ProtocolVersion,
    /// Typed protocol parameters supplied via [`GenesisBuilderCPV2::with_protocol`].
    protocol_params: Option<super::types::ProtocolParamsCPV2>,
    governance_keys_input: Option<GovernanceKeysInput>,
}

impl GenesisBuilderCPV2 {
    /// Private constructor. Use [`genesis_builder_p6`] or [`genesis_builder_p7`].
    fn new(pv: ProtocolVersion) -> Self {
        Self {
            inner: CommonGenesisBuilder::new(),
            protocol_version: pv,
            protocol_params: None,
            governance_keys_input: None,
        }
    }

    impl_common_builder_methods!();

    // ── Governance keys ───────────────────────────────────────────────────────

    pub fn with_governance_keys(mut self, keys: UpdateKeysCollectionCPV1) -> Self {
        self.governance_keys_input = Some(GovernanceKeysInput::Existing(keys));
        self
    }

    pub fn generate_governance_keys(mut self, config: GovernanceKeysGenerateConfig) -> Self {
        self.governance_keys_input = Some(GovernanceKeysInput::Generate(Box::new(config)));
        self
    }

    pub fn with_governance_keys_input(mut self, input: GovernanceKeysInput) -> Self {
        self.governance_keys_input = Some(input);
        self
    }

    // ── Protocol ──────────────────────────────────────────────────────────────

    /// Set the typed protocol parameters.
    pub fn with_protocol(mut self, params: super::types::ProtocolParamsCPV2) -> Self {
        self.protocol_params = Some(params);
        self
    }

    /// Build the CPV2 genesis block.
    pub fn build(self) -> anyhow::Result<super::output::GenesisOutputCPV2> {
        let mut csprng = rand::thread_rng();

        // 1. Protocol parameters
        let params = self.protocol_params.ok_or_else(|| {
            anyhow!("Protocol parameters not set. Call .with_protocol() before .build().")
        })?;

        // 2. Cryptographic parameters
        let crypto_params = build_crypto_params(self.inner.crypto_params)?;

        // 3. Identity providers
        let IpBuildOutput {
            data_list: identity_provider_data,
            info_map: identity_provider_infos,
        } = build_identity_providers(self.inner.ip_inputs, &mut csprng)?;

        // 4. Anonymity revokers
        let ArBuildOutput {
            data_list: anonymity_revoker_data,
            info_map: anonymity_revoker_infos,
        } = build_anonymity_revokers(self.inner.ar_inputs, &crypto_params, &mut csprng)?;

        // 5. Accounts
        let AccountBuildOutput {
            account_data,
            accounts_public,
            baker_credentials,
            foundation_index: foundation_idx,
        } = build_accounts(
            self.inner.account_inputs,
            &crypto_params,
            &anonymity_revoker_infos,
        )?;

        tracing::info!(
            "There are {} accounts in genesis, {} of which are bakers.",
            accounts_public.len(),
            baker_credentials.len()
        );

        // 6. Governance keys
        let governance_keys_input = self.governance_keys_input.ok_or_else(|| {
            anyhow!(
                "Governance keys not set. Call .with_governance_keys() or \
                 .generate_governance_keys() before .build()."
            )
        })?;

        let GovernanceKeysOutput {
            keys: governance_keys,
            generated_root_key_pairs,
            generated_level1_key_pairs,
            generated_level2_key_pairs,
        } = build_governance_keys(governance_keys_input, &mut csprng)?;

        // 7. CPV2 does not support createPLT authorization.
        if governance_keys.level_2_keys.create_plt.is_some() {
            bail!(
                "{:?} (CPV2) does not support createPLT authorization.",
                self.protocol_version
            );
        }

        // 8. Resolve chain parameters.
        let chain_params = params.chain.resolve(foundation_idx);

        tracing::info!(
            "Genesis time is set to {}.",
            chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH)
                + chrono::Duration::milliseconds(params.core.genesis_time.millis as i64)
        );

        // 9. Build genesis state and data.
        let initial_state = super::types::GenesisStateCPV2 {
            cryptographic_parameters: crypto_params.clone(),
            identity_providers: identity_provider_infos.clone(),
            anonymity_revokers: anonymity_revoker_infos.clone(),
            update_keys: governance_keys.clone(),
            chain_parameters: chain_params,
            leadership_election_nonce: params.leadership_election_nonce,
            accounts: accounts_public.clone(),
        };

        let genesis_data = match self.protocol_version {
            ProtocolVersion::P6 => GenesisData::P6 {
                core: params.core,
                initial_state,
            },
            ProtocolVersion::P7 => GenesisData::P7 {
                core: params.core,
                initial_state,
            },
            _ => unreachable!(),
        };

        Ok(super::output::GenesisOutputCPV2 {
            crypto_params,
            identity_provider_data,
            identity_provider_infos,
            anonymity_revoker_data,
            anonymity_revoker_infos,
            account_data,
            accounts_public,
            baker_credentials,
            governance_keys,
            generated_root_key_pairs,
            generated_level1_key_pairs,
            generated_level2_key_pairs,
            genesis_data,
        })
    }
}

// ── CPV2 factory functions ──────────────────────────────────────────────────────────

/// Returns a [`GenesisBuilderCPV2`] targeting protocol version **P6**.
pub fn genesis_builder_p6() -> GenesisBuilderCPV2 {
    GenesisBuilderCPV2::new(ProtocolVersion::P6)
}

/// Returns a [`GenesisBuilderCPV2`] targeting protocol version **P7**.
pub fn genesis_builder_p7() -> GenesisBuilderCPV2 {
    GenesisBuilderCPV2::new(ProtocolVersion::P7)
}

// ── GenesisBuilderCPV1 ────────────────────────────────────────────────────────

/// Builder for genesis blocks targeting Chain Parameters Version 1 (P4–P5).
///
/// CPV1 uses `AuthorizationsV1` governance keys without createPLT authorization.
/// P4 requires CPV1 (v1) chain parameters; if v0 chain parameters are supplied
/// a clear error is returned — use [`GenesisBuilderCPV0`] for P4 with CPV0 chain
/// parameters (those are handled by Task 4).
///
/// All inputs are accepted as in-memory typed values; no filesystem access
/// occurs inside the builder.
pub struct GenesisBuilderCPV1 {
    inner: CommonGenesisBuilder,
    /// Protocol version baked in at construction via a factory function.
    protocol_version: ProtocolVersion,
    /// Typed protocol parameters supplied via [`GenesisBuilderCPV1::with_protocol`].
    protocol_params: Option<super::types::ProtocolParamsCPV1>,

    governance_keys_input: Option<GovernanceKeysInput>,
}
impl GenesisBuilderCPV1 {
    fn new(pv: ProtocolVersion) -> Self {
        Self {
            inner: CommonGenesisBuilder::new(),
            protocol_version: pv,
            protocol_params: None,
            governance_keys_input: None,
        }
    }

    impl_common_builder_methods!();

    // ── Governance keys ───────────────────────────────────────────────────────

    pub fn with_governance_keys(mut self, keys: UpdateKeysCollectionCPV1) -> Self {
        self.governance_keys_input = Some(GovernanceKeysInput::Existing(keys));
        self
    }

    pub fn generate_governance_keys(mut self, config: GovernanceKeysGenerateConfig) -> Self {
        self.governance_keys_input = Some(GovernanceKeysInput::Generate(Box::new(config)));
        self
    }

    pub fn with_governance_keys_input(mut self, input: GovernanceKeysInput) -> Self {
        self.governance_keys_input = Some(input);
        self
    }

    // ── Protocol ──────────────────────────────────────────────────────────────

    /// Set the typed protocol parameters.
    pub fn with_protocol(mut self, params: super::types::ProtocolParamsCPV1) -> Self {
        self.protocol_params = Some(params);
        self
    }

    /// Build the CPV1 genesis block.
    pub fn build(self) -> anyhow::Result<super::output::GenesisOutputCPV1> {
        let mut csprng = rand::thread_rng();
        let pv = self.protocol_version;

        // 1. Protocol parameters
        let params = self.protocol_params.ok_or_else(|| {
            anyhow!("Protocol parameters not set. Call .with_protocol() before .build().")
        })?;

        // 2. Cryptographic parameters
        let crypto_params = build_crypto_params(self.inner.crypto_params)?;

        // 3. Identity providers
        let IpBuildOutput {
            data_list: ip_data_list,
            info_map: ip_info_map,
        } = build_identity_providers(self.inner.ip_inputs, &mut csprng)?;

        // 4. Anonymity revokers
        let ArBuildOutput {
            data_list: ar_data_list,
            info_map: ar_info_map,
        } = build_anonymity_revokers(self.inner.ar_inputs, &crypto_params, &mut csprng)?;

        // 5. Accounts
        let AccountBuildOutput {
            account_data,
            accounts_public,
            baker_credentials: baker_creds,
            foundation_index: foundation_idx,
        } = build_accounts(self.inner.account_inputs, &crypto_params, &ar_info_map)?;

        tracing::info!(
            "There are {} accounts in genesis, {} of which are bakers.",
            accounts_public.len(),
            baker_creds.len()
        );

        // 6. Governance keys
        let governance_keys_input = self.governance_keys_input.ok_or_else(|| {
            anyhow!(
                "Governance keys not set. Call .with_governance_keys() or \
                 .generate_governance_keys() before .build()."
            )
        })?;

        let GovernanceKeysOutput {
            keys: governance_keys,
            generated_root_key_pairs: gen_root,
            generated_level1_key_pairs: gen_level1,
            generated_level2_key_pairs: gen_level2,
        } = build_governance_keys(governance_keys_input, &mut csprng)?;

        // 7. CPV1 does not support createPLT authorization.
        if governance_keys.level_2_keys.create_plt.is_some() {
            bail!("{:?} (CPV1) does not support createPLT authorization.", pv);
        }

        // 8. Resolve chain parameters.
        let chain_params = params.chain.resolve(foundation_idx);

        tracing::info!(
            "Genesis time is set to {}.",
            chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH)
                + chrono::Duration::milliseconds(params.core.time.millis as i64)
        );

        // 9. Build genesis state and data.
        let initial_state = super::types::GenesisStateCPV1 {
            cryptographic_parameters: crypto_params.clone(),
            identity_providers: ip_info_map.clone(),
            anonymity_revokers: ar_info_map.clone(),
            update_keys: governance_keys.clone(),
            chain_parameters: chain_params,
            leadership_election_nonce: params.leadership_election_nonce,
            accounts: accounts_public.clone(),
        };

        let genesis_data = match pv {
            ProtocolVersion::P4 => GenesisData::P4 {
                core: params.core,
                initial_state,
            },
            ProtocolVersion::P5 => GenesisData::P5 {
                core: params.core,
                initial_state,
            },
            _ => unreachable!(),
        };

        Ok(super::output::GenesisOutputCPV1 {
            crypto_params,
            identity_provider_data: ip_data_list,
            identity_provider_infos: ip_info_map,
            anonymity_revoker_data: ar_data_list,
            anonymity_revoker_infos: ar_info_map,
            account_data,
            accounts_public,
            baker_credentials: baker_creds,
            governance_keys,
            generated_root_key_pairs: gen_root,
            generated_level1_key_pairs: gen_level1,
            generated_level2_key_pairs: gen_level2,
            genesis_data,
        })
    }
}

// ── CPV1 factory functions ──────────────────────────────────────────────────────────

/// Returns a [`GenesisBuilderCPV1`] targeting protocol version **P4**.
/// P4 always uses CPV1 chain parameters.
pub fn genesis_builder_p4() -> GenesisBuilderCPV1 {
    GenesisBuilderCPV1::new(ProtocolVersion::P4)
}

/// Returns a [`GenesisBuilderCPV1`] targeting protocol version **P5**.
pub fn genesis_builder_p5() -> GenesisBuilderCPV1 {
    GenesisBuilderCPV1::new(ProtocolVersion::P5)
}

// ── CPV0 governance key types ─────────────────────────────────────────────────────────────────

/// Level-2 governance key configuration for CPV0 (`AuthorizationsV0`, P1–P3).
///
/// CPV0 does not have `cooldown_parameters`, `time_parameters`, or `create_plt`
/// authorisation entries.
pub struct Level2GovernanceKeysConfigV0 {
    /// Level-2 public keys; each [`GovernanceKeySpec`] entry adds existing or
    /// fresh keys to the shared pool referenced by the access structures below.
    pub keys: Vec<GovernanceKeySpec>,
    /// Keys authorised to trigger emergency updates.
    pub emergency: Level2AccessConfig,
    /// Keys authorised to trigger protocol updates.
    pub protocol: Level2AccessConfig,
    /// Keys authorised to update the election difficulty.
    pub election_difficulty: Level2AccessConfig,
    /// Keys authorised to update the euro-per-energy rate.
    pub euro_per_energy: Level2AccessConfig,
    /// Keys authorised to update the micro-CCD-per-euro rate.
    pub micro_ccd_per_euro: Level2AccessConfig,
    /// Keys authorised to update the foundation account.
    pub foundation_account: Level2AccessConfig,
    /// Keys authorised to update the mint distribution.
    pub mint_distribution: Level2AccessConfig,
    /// Keys authorised to update the transaction fee distribution.
    pub transaction_fee_distribution: Level2AccessConfig,
    /// Keys authorised to update GAS rewards.
    pub gas_rewards: Level2AccessConfig,
    /// Keys authorised to update pool parameters.
    pub pool_parameters: Level2AccessConfig,
    /// Keys authorised to add a new anonymity revoker.
    pub add_anonymity_revoker: Level2AccessConfig,
    /// Keys authorised to add a new identity provider.
    pub add_identity_provider: Level2AccessConfig,
}

/// Full governance key generation configuration for CPV0.
///
/// Passed to [`GovernanceKeysInputCPV0::Generate`].
pub struct GovernanceKeysGenerateConfigCPV0 {
    /// Root key level configuration.
    pub root: GovernanceKeyLevelConfig,
    /// Level-1 key level configuration.
    pub level1: GovernanceKeyLevelConfig,
    /// Level-2 key and access-structure configuration (CPV0 variant).
    pub level2: Level2GovernanceKeysConfigV0,
}

/// How to supply CPV0 governance keys to [`GenesisBuilderCPV0`].
pub enum GovernanceKeysInputCPV0 {
    /// Use a pre-existing, already-built CPV0 governance key collection.
    Existing(super::types::UpdateKeysCollectionCPV0),
    /// Generate governance keys from the given CPV0 configuration.
    Generate(Box<GovernanceKeysGenerateConfigCPV0>),
}

// ── GenesisBuilderCPV0 ────────────────────────────────────────────────────────

/// Builder for genesis blocks targeting Chain Parameters Version 0 (P1–P3).
///
/// CPV0 uses `AuthorizationsV0` governance keys.
/// All inputs are accepted as in-memory typed values; no filesystem access
/// occurs inside the builder.
pub struct GenesisBuilderCPV0 {
    inner: CommonGenesisBuilder,
    /// Protocol version baked in at construction via a factory function.
    protocol_version: ProtocolVersion,
    protocol_params: Option<super::types::ProtocolParamsCPV0>,
    governance_keys_input: Option<GovernanceKeysInputCPV0>,
}

impl GenesisBuilderCPV0 {
    fn new(pv: ProtocolVersion) -> Self {
        Self {
            inner: CommonGenesisBuilder::new(),
            protocol_version: pv,
            protocol_params: None,
            governance_keys_input: None,
        }
    }

    impl_common_builder_methods!();

    // ── Governance keys ───────────────────────────────────────────────────────

    pub fn with_governance_keys(mut self, keys: super::types::UpdateKeysCollectionCPV0) -> Self {
        self.governance_keys_input = Some(GovernanceKeysInputCPV0::Existing(keys));
        self
    }

    pub fn generate_governance_keys(mut self, config: GovernanceKeysGenerateConfigCPV0) -> Self {
        self.governance_keys_input = Some(GovernanceKeysInputCPV0::Generate(Box::new(config)));
        self
    }

    pub fn with_governance_keys_input(mut self, input: GovernanceKeysInputCPV0) -> Self {
        self.governance_keys_input = Some(input);
        self
    }

    // ── Protocol ──────────────────────────────────────────────────────────────

    /// Set the protocol configuration. Must be P1, P2, or P3.
    /// Set the typed protocol parameters.
    pub fn with_protocol(mut self, params: super::types::ProtocolParamsCPV0) -> Self {
        self.protocol_params = Some(params);
        self
    }

    /// Build the CPV0 genesis block.
    pub fn build(self) -> anyhow::Result<super::output::GenesisOutputCPV0> {
        let mut csprng = rand::thread_rng();
        let pv = self.protocol_version;

        // 1. Protocol parameters
        let params = self.protocol_params.ok_or_else(|| {
            anyhow!("Protocol parameters not set. Call .with_protocol() before .build().")
        })?;

        // 2. Cryptographic parameters
        let crypto_params = build_crypto_params(self.inner.crypto_params)?;

        // 3. Identity providers
        let IpBuildOutput {
            data_list: ip_data_list,
            info_map: ip_info_map,
        } = build_identity_providers(self.inner.ip_inputs, &mut csprng)?;

        // 4. Anonymity revokers
        let ArBuildOutput {
            data_list: ar_data_list,
            info_map: ar_info_map,
        } = build_anonymity_revokers(self.inner.ar_inputs, &crypto_params, &mut csprng)?;

        // 5. Accounts
        let AccountBuildOutput {
            account_data,
            accounts_public,
            baker_credentials: baker_creds,
            foundation_index: foundation_idx,
        } = build_accounts(self.inner.account_inputs, &crypto_params, &ar_info_map)?;

        tracing::info!(
            "There are {} accounts in genesis, {} of which are bakers.",
            accounts_public.len(),
            baker_creds.len()
        );

        // 6. Governance keys (CPV0: AuthorizationsV0)
        let governance_keys_input = self.governance_keys_input.ok_or_else(|| {
            anyhow!(
                "Governance keys not set. Call .with_governance_keys() or \
                 .generate_governance_keys() before .build()."
            )
        })?;

        let GovernanceKeysOutput {
            keys: governance_keys,
            generated_root_key_pairs: gen_root,
            generated_level1_key_pairs: gen_level1,
            generated_level2_key_pairs: gen_level2,
        } = build_governance_keys_v0(governance_keys_input, &mut csprng)?;

        // 7. Resolve chain parameters.
        let chain_params = params.chain.resolve(foundation_idx);

        tracing::info!(
            "Genesis time is set to {}.",
            chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH)
                + chrono::Duration::milliseconds(params.core.time.millis as i64)
        );

        // 8. Build genesis state and data.
        let initial_state = super::types::GenesisStateCPV0 {
            cryptographic_parameters: crypto_params.clone(),
            identity_providers: ip_info_map.clone(),
            anonymity_revokers: ar_info_map.clone(),
            update_keys: governance_keys.clone(),
            chain_parameters: chain_params,
            leadership_election_nonce: params.leadership_election_nonce,
            accounts: accounts_public.clone(),
        };

        let genesis_data = match pv {
            ProtocolVersion::P1 => GenesisData::P1 {
                core: params.core,
                initial_state,
            },
            ProtocolVersion::P2 => GenesisData::P2 {
                core: params.core,
                initial_state,
            },
            ProtocolVersion::P3 => GenesisData::P3 {
                core: params.core,
                initial_state,
            },
            _ => unreachable!(),
        };

        Ok(super::output::GenesisOutputCPV0 {
            crypto_params,
            identity_provider_data: ip_data_list,
            identity_provider_infos: ip_info_map,
            anonymity_revoker_data: ar_data_list,
            anonymity_revoker_infos: ar_info_map,
            account_data,
            accounts_public,
            baker_credentials: baker_creds,
            governance_keys,
            generated_root_key_pairs: gen_root,
            generated_level1_key_pairs: gen_level1,
            generated_level2_key_pairs: gen_level2,
            genesis_data,
        })
    }
}

// ── CPV0 factory functions ──────────────────────────────────────────────────────────

/// Returns a [`GenesisBuilderCPV0`] targeting protocol version **P1**.
pub fn genesis_builder_p1() -> GenesisBuilderCPV0 {
    GenesisBuilderCPV0::new(ProtocolVersion::P1)
}

/// Returns a [`GenesisBuilderCPV0`] targeting protocol version **P2**.
pub fn genesis_builder_p2() -> GenesisBuilderCPV0 {
    GenesisBuilderCPV0::new(ProtocolVersion::P2)
}

/// Returns a [`GenesisBuilderCPV0`] targeting protocol version **P3**.
pub fn genesis_builder_p3() -> GenesisBuilderCPV0 {
    GenesisBuilderCPV0::new(ProtocolVersion::P3)
}

/// Resolve and generate CPV0 governance keys (`AuthorizationsV0`).
fn build_governance_keys_v0(
    input: GovernanceKeysInputCPV0,
    csprng: &mut (impl rand::Rng + rand::CryptoRng),
) -> anyhow::Result<GovernanceKeysOutput<super::types::UpdateKeysCollectionCPV0>> {
    match input {
        GovernanceKeysInputCPV0::Existing(keys) => Ok(GovernanceKeysOutput {
            keys,
            generated_root_key_pairs: vec![],
            generated_level1_key_pairs: vec![],
            generated_level2_key_pairs: vec![],
        }),
        GovernanceKeysInputCPV0::Generate(cfg) => {
            let (root_public, gen_root) = resolve_key_level(&cfg.root.keys, "root", csprng)?;
            ensure!(
                usize::from(u16::from(cfg.root.threshold)) <= root_public.len(),
                "The number of root keys ({}) is less than the root threshold ({}).",
                root_public.len(),
                cfg.root.threshold
            );

            let (level1_public, gen_level1) =
                resolve_key_level(&cfg.level1.keys, "level1", csprng)?;
            ensure!(
                usize::from(u16::from(cfg.level1.threshold)) <= level1_public.len(),
                "The number of level-1 keys ({}) is less than the level-1 threshold ({}).",
                level1_public.len(),
                cfg.level1.threshold
            );

            let (level2_public, gen_level2) =
                resolve_key_level(&cfg.level2.keys, "level2", csprng)?;
            ensure!(
                !level2_public.is_empty(),
                "There must be at least one level-2 key."
            );

            let l2 = &cfg.level2;
            let emergency = l2.emergency.access_structure(&level2_public)?;
            let protocol = l2.protocol.access_structure(&level2_public)?;
            let election_difficulty = l2.election_difficulty.access_structure(&level2_public)?;
            let euro_per_energy = l2.euro_per_energy.access_structure(&level2_public)?;
            let micro_gtu_per_euro = l2.micro_ccd_per_euro.access_structure(&level2_public)?;
            let foundation_account = l2.foundation_account.access_structure(&level2_public)?;
            let mint_distribution = l2.mint_distribution.access_structure(&level2_public)?;
            let transaction_fee_distribution = l2
                .transaction_fee_distribution
                .access_structure(&level2_public)?;
            let param_gas_rewards = l2.gas_rewards.access_structure(&level2_public)?;
            let pool_parameters = l2.pool_parameters.access_structure(&level2_public)?;
            let add_anonymity_revoker =
                l2.add_anonymity_revoker.access_structure(&level2_public)?;
            let add_identity_provider =
                l2.add_identity_provider.access_structure(&level2_public)?;

            let level_2_keys = AuthorizationsV0 {
                keys: level2_public,
                emergency,
                protocol,
                election_difficulty,
                euro_per_energy,
                micro_gtu_per_euro,
                foundation_account,
                mint_distribution,
                transaction_fee_distribution,
                param_gas_rewards,
                pool_parameters,
                add_anonymity_revoker,
                add_identity_provider,
            };

            let collection = UpdateKeysCollectionSkeleton {
                root_keys: HigherLevelAccessStructure {
                    keys: root_public,
                    threshold: cfg.root.threshold,
                    _phantom: Default::default(),
                },
                level_1_keys: HigherLevelAccessStructure {
                    keys: level1_public,
                    threshold: cfg.level1.threshold,
                    _phantom: Default::default(),
                },
                level_2_keys,
            };

            Ok(GovernanceKeysOutput {
                keys: collection,
                generated_root_key_pairs: gen_root,
                generated_level1_key_pairs: gen_level1,
                generated_level2_key_pairs: gen_level2,
            })
        }
    }
}
