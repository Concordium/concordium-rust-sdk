//! Integration tests: build CPV3 genesis blocks in memory via factory functions.
//!
//! These tests exercise the library without any filesystem access, using
//! typed protocol parameters (no TOML parsing) and factory functions.

use concordium_rust_sdk::genesis::{
    builder::{
        FreshAccountConfig, GovernanceKeyLevelConfig, GovernanceKeySpec,
        GovernanceKeysGenerateConfig, Level2AccessConfig, Level2GovernanceKeysConfig,
    },
    genesis_builder_p10, genesis_builder_p11, genesis_builder_p8, genesis_builder_p9,
    serialize_genesis, CoreGenesisParametersV1, GenesisChainParametersV3, ProtocolParamsCPV3,
};
use concordium_rust_sdk::{
    common::types::{Amount, Ratio, Timestamp},
    id::types::{ArIdentity, IpIdentity, SignatureThreshold},
    smart_contracts::common::Duration,
    types::{hashes::LeadershipElectionNonce, UpdateKeysIndex, UpdateKeysThreshold},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_access(keys: &[u16], threshold: u16) -> Level2AccessConfig {
    Level2AccessConfig {
        authorized_keys: keys.iter().map(|&i| UpdateKeysIndex { index: i }).collect(),
        threshold: UpdateKeysThreshold::try_from(threshold).unwrap(),
    }
}

fn make_gov_keys(needs_plt: bool) -> GovernanceKeysGenerateConfig {
    let k = &[0u16, 1, 2];
    GovernanceKeysGenerateConfig {
        root: GovernanceKeyLevelConfig {
            threshold: UpdateKeysThreshold::try_from(2u16).unwrap(),
            keys: vec![GovernanceKeySpec::Fresh { count: 3 }],
        },
        level1: GovernanceKeyLevelConfig {
            threshold: UpdateKeysThreshold::try_from(2u16).unwrap(),
            keys: vec![GovernanceKeySpec::Fresh { count: 3 }],
        },
        level2: Level2GovernanceKeysConfig {
            keys: vec![GovernanceKeySpec::Fresh { count: 3 }],
            emergency: make_access(k, 2),
            protocol: make_access(k, 2),
            election_difficulty: make_access(k, 2),
            euro_per_energy: make_access(k, 2),
            micro_ccd_per_euro: make_access(k, 2),
            foundation_account: make_access(k, 2),
            mint_distribution: make_access(k, 2),
            transaction_fee_distribution: make_access(k, 2),
            gas_rewards: make_access(k, 2),
            pool_parameters: make_access(k, 2),
            add_anonymity_revoker: make_access(k, 2),
            add_identity_provider: make_access(k, 2),
            cooldown_parameters: make_access(k, 2),
            time_parameters: make_access(k, 2),
            create_plt: if needs_plt {
                Some(make_access(k, 2))
            } else {
                None
            },
        },
    }
}

fn foundation_account() -> FreshAccountConfig {
    FreshAccountConfig {
        count: 1,
        stake: None,
        balance: Amount::from_micro_ccd(10_000_000_000_000_000u64),
        num_keys: 1,
        threshold: SignatureThreshold::ONE,
        identity_provider: IpIdentity::from(0),
        restake_earnings: false,
        foundation: true,
    }
}

/// Construct typed CPV3 chain parameters without TOML.
///
/// Uses `serde_json` for complex SDK types that have serde derives, then
/// assembles the library's serde-free `GenesisChainParametersV3` directly.
fn make_chain_params_cpv3() -> GenesisChainParametersV3 {
    use concordium_rust_sdk::types::*;
    use serde_json::json;

    let timeout_parameters: TimeoutParameters = serde_json::from_value(json!({
        "base": "2s",
        "increase": 1.2,
        "decrease": 0.8
    }))
    .unwrap();

    let time_parameters: TimeParameters = serde_json::from_value(json!({
        "rewardPeriodLength": 4,
        "mintPerPayday": 2.61157877e-4
    }))
    .unwrap();

    let pool_parameters: PoolParameters = serde_json::from_value(json!({
        "passiveFinalizationCommission": 1.0,
        "passiveBakingCommission": 0.1,
        "passiveTransactionCommission": 0.1,
        "finalizationCommissionRange": {"min": 0.5, "max": 1.0},
        "bakingCommissionRange": {"min": 0.05, "max": 0.1},
        "transactionCommissionRange": {"min": 0.05, "max": 0.2},
        "minimumEquityCapital": "500000000000",
        "capitalBound": 0.10,
        "leverageBound": {"denominator": 1, "numerator": 3}
    }))
    .unwrap();

    let cooldown_parameters: CooldownParameters = serde_json::from_value(json!({
        "poolOwnerCooldown": 800,
        "delegatorCooldown": 1000
    }))
    .unwrap();

    let reward_parameters = {
        use concordium_rust_sdk::types::{
            GASRewardsV1, MintDistributionV1, TransactionFeeDistribution,
        };
        let mint_distribution: MintDistributionV1 =
            serde_json::from_value(json!({ "bakingReward": 0.85, "finalizationReward": 0.05 }))
                .unwrap();
        let transaction_fee_distribution: TransactionFeeDistribution =
            serde_json::from_value(json!({ "baker": 0.45, "gasAccount": 0.45 })).unwrap();
        let gas_rewards: GASRewardsV1 = serde_json::from_value(json!({
            "baker": 0.25, "accountCreation": 0.02, "chainUpdate": 0.005
        }))
        .unwrap();
        concordium_rust_sdk::genesis::RewardParametersCPV2 {
            mint_distribution,
            transaction_fee_distribution,
            gas_rewards,
        }
    };

    let finalization_committee_parameters: FinalizationCommitteeParameters =
        serde_json::from_value(json!({
            "min_finalizers": 4,
            "max_finalizers": 12,
            "finalizers_relative_stake_threshold": 0.002
        }))
        .unwrap();

    let validator_score_parameters: ValidatorScoreParameters =
        serde_json::from_value(json!({ "maxMissedRounds": 10 })).unwrap();

    let euro_per_energy: ExchangeRate = serde_json::from_value(json!(0.00002)).unwrap();
    let micro_ccd_per_euro: ExchangeRate = serde_json::from_value(json!(500_000.0)).unwrap();

    GenesisChainParametersV3 {
        timeout_parameters,
        min_block_time: Duration::from_millis(1_000),
        block_energy_limit: concordium_rust_sdk::types::Energy { energy: 3_000_000 },
        euro_per_energy,
        micro_ccd_per_euro,
        account_creation_limit: 10u16.into(),
        reward_parameters,
        time_parameters,
        pool_parameters,
        cooldown_parameters,
        finalization_committee_parameters,
        validator_score_parameters,
    }
}

/// Build `ProtocolParamsCPV3` from typed values — no TOML involved.
fn make_protocol_params_cpv3() -> ProtocolParamsCPV3 {
    ProtocolParamsCPV3 {
        core: CoreGenesisParametersV1 {
            genesis_time: Timestamp {
                millis: 1_623_222_000_000,
            },
            epoch_duration: Duration::from_millis(3_600_000),
            signature_threshold: Ratio::new(2, 3).unwrap(),
        },
        chain: make_chain_params_cpv3(),
        leadership_election_nonce: LeadershipElectionNonce::from([0u8; 32]),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// AC: P8 genesis built via factory function with typed params (no TOML).
#[test]
fn test_p8_genesis_via_factory() {
    let output = genesis_builder_p8()
        .generate_crypto_params("test-p8".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys(false))
        .with_protocol(make_protocol_params_cpv3())
        .build()
        .expect("P8 build must succeed");

    assert!(!output.identity_provider_data.is_empty());
    assert!(!output.anonymity_revoker_data.is_empty());
    assert!(!output.generated_root_key_pairs.is_empty());

    let bytes = serialize_genesis(&output.genesis_data);
    assert!(!bytes.is_empty(), "serialized genesis must be non-empty");

    let h1 = output.genesis_data.hash();
    let h2 = output.genesis_data.hash();
    assert_eq!(h1, h2, "hash must be deterministic");
}

/// AC: P9 genesis built via `genesis_builder_p9()` with typed params.
#[test]
fn test_p9_genesis_via_factory() {
    let output = genesis_builder_p9()
        .generate_crypto_params("test-p9".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys(true)) // needs createPLT
        .with_protocol(make_protocol_params_cpv3())
        .build()
        .expect("P9 build must succeed");

    assert!(!serialize_genesis(&output.genesis_data).is_empty());
}

/// P10 and P11 via factory functions.
#[test]
fn test_p10_p11_via_factory() {
    for (builder, needs_plt) in [(genesis_builder_p10(), true), (genesis_builder_p11(), true)] {
        let output = builder
            .generate_crypto_params("test-cpv3".to_string())
            .generate_identity_providers(IpIdentity::from(0), 1)
            .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
            .generate_accounts(foundation_account())
            .generate_governance_keys(make_gov_keys(needs_plt))
            .with_protocol(make_protocol_params_cpv3())
            .build()
            .expect("build must succeed");
        assert!(!serialize_genesis(&output.genesis_data).is_empty());
    }
}

/// AC: P9 without createPLT returns a clear error.
#[test]
fn test_p9_requires_create_plt() {
    let result = genesis_builder_p9()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 1)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys(false)) // no createPLT
        .with_protocol(make_protocol_params_cpv3())
        .build();

    assert!(result.is_err());
    assert!(result.err().unwrap().to_string().contains("createPLT"));
}

/// AC: building without protocol parameters returns a clear error.
#[test]
fn test_missing_protocol_params_returns_error() {
    let result = genesis_builder_p8()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 1)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys(false))
        .build(); // no .with_protocol()

    assert!(result.is_err());
    let msg = result.err().unwrap().to_string().to_lowercase();
    assert!(msg.contains("protocol"));
}

/// AC: building without a foundation account returns a clear error.
#[test]
fn test_missing_foundation_returns_error() {
    let no_foundation = FreshAccountConfig {
        foundation: false,
        ..foundation_account()
    };

    let result = genesis_builder_p8()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 1)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(no_foundation)
        .generate_governance_keys(make_gov_keys(false))
        .with_protocol(make_protocol_params_cpv3())
        .build();

    assert!(result.is_err());
    let msg = result.err().unwrap().to_string().to_lowercase();
    assert!(msg.contains("foundation"));
}

/// AC: pre-existing artifacts are echoed back.
#[test]
fn test_preexisting_artifacts_echoed_back() {
    let output = genesis_builder_p8()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys(false))
        .with_protocol(make_protocol_params_cpv3())
        .build()
        .unwrap();

    for ip in &output.identity_provider_data {
        let id = ip.public_ip_info.ip_identity;
        assert!(output.identity_provider_infos.contains_key(&id));
    }
    for ar in &output.anonymity_revoker_data {
        let id = ar.public_ar_info.ar_identity;
        assert!(output.anonymity_revoker_infos.contains_key(&id));
    }
}

/// AC: pre-existing IpData is echoed back.
#[test]
fn test_existing_ip_echoed_back_in_output() {
    let first = genesis_builder_p8()
        .generate_crypto_params("test-echo".to_string())
        .generate_identity_providers(IpIdentity::from(0), 1)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys(false))
        .with_protocol(make_protocol_params_cpv3())
        .build()
        .unwrap();

    let existing_ip = first.identity_provider_data.into_iter().next().unwrap();
    let existing_ip_id = existing_ip.public_ip_info.ip_identity;

    let second = genesis_builder_p8()
        .generate_crypto_params("test-echo".to_string())
        .add_identity_provider(existing_ip)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys(false))
        .with_protocol(make_protocol_params_cpv3())
        .build()
        .expect("second build must succeed");

    assert_eq!(second.identity_provider_data.len(), 1);
    assert_eq!(
        second.identity_provider_data[0].public_ip_info.ip_identity,
        existing_ip_id
    );
}
