//! Genesis block generation.
//!
//! This module exposes everything needed to build a Concordium genesis block.
//!
//! # Quick start
//!
//! ```no_run
//! use concordium_rust_sdk::genesis::{genesis_builder_p9, FreshAccountConfig};
//!
//! // Build a P9 genesis block
//! // let output = genesis_builder_p9()
//! //     .generate_crypto_params("My genesis string".to_string())
//! //     .generate_identity_providers(ip_identity, 3)
//! //     .generate_anonymity_revokers(ar_identity, 3)
//! //     .generate_accounts(FreshAccountConfig { ... })
//! //     .generate_governance_keys(governance_cfg)
//! //     .with_protocol(protocol_params)
//! //     .build()?;
//! //
//! // let bytes = concordium_rust_sdk::genesis::serialize_genesis(&output.genesis_data);
//! // let hash  = output.genesis_data.hash();
//! ```

pub mod builder;
pub mod output;
pub mod types;

// ── Builder types ─────────────────────────────────────────────────────────────

pub use builder::{
    genesis_builder_p1, genesis_builder_p10, genesis_builder_p11, genesis_builder_p2,
    genesis_builder_p3, genesis_builder_p4, genesis_builder_p5, genesis_builder_p6,
    genesis_builder_p7, genesis_builder_p8, genesis_builder_p9, AccountInputItem, ArInputItem,
    CryptoParamsInput, FreshAccountConfig, GenesisBuilderCPV0, GenesisBuilderCPV1,
    GenesisBuilderCPV2, GenesisBuilderCPV3, GovernanceKeyLevelConfig, GovernanceKeySpec,
    GovernanceKeysGenerateConfig, GovernanceKeysGenerateConfigCPV0, GovernanceKeysInput,
    GovernanceKeysInputCPV0, IpInputItem, Level2AccessConfig, Level2GovernanceKeysConfig,
    Level2GovernanceKeysConfigV0,
};

// ── Output types ──────────────────────────────────────────────────────────────

pub use output::{
    ArData, GeneratedKeyPair, GenesisOutputCPV0, GenesisOutputCPV1, GenesisOutputCPV2,
    GenesisOutputCPV3, IpData,
};

// ── Genesis data and protocol parameter types ─────────────────────────────────

pub use types::{
    CoreGenesisParametersV0, CoreGenesisParametersV1, FinalizationParameters, GenesisAccount,
    GenesisAccountPublic, GenesisChainParametersV0, GenesisChainParametersV1,
    GenesisChainParametersV2, GenesisChainParametersV3, GenesisData, GenesisStateCPV0,
    GenesisStateCPV1, GenesisStateCPV2, GenesisStateCPV3, ProtocolParamsCPV0, ProtocolParamsCPV1,
    ProtocolParamsCPV2, ProtocolParamsCPV3, RewardParametersCPV0, RewardParametersCPV1,
    RewardParametersCPV2, UpdateKeysCollectionCPV0, UpdateKeysCollectionCPV1,
    UpdateKeysCollectionSkeleton,
};

// ── Serialisation helpers ─────────────────────────────────────────────────────

/// Serialise a genesis block value to its binary representation.
///
/// The returned bytes are suitable for writing to `genesis.dat` file used by concordium-node
/// software.
pub fn serialize_genesis(genesis: &GenesisData) -> Vec<u8> {
    concordium_base::common::to_bytes(genesis)
}
