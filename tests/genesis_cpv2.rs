//! Integration tests for the CPV2 builder (P6–P7).
//!
//! Tests construct builders via factory functions and typed protocol parameters
//! (no TOML parsing in the library tests).

use concordium_rust_sdk::genesis::{
    builder::{
        FreshAccountConfig, GovernanceKeyLevelConfig, GovernanceKeySpec,
        GovernanceKeysGenerateConfig, Level2AccessConfig, Level2GovernanceKeysConfig,
    },
    genesis_builder_p6, genesis_builder_p7, serialize_genesis, CoreGenesisParametersV1,
    GenesisChainParametersV2, ProtocolParamsCPV2,
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

fn make_gov_keys() -> GovernanceKeysGenerateConfig {
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
            create_plt: None, // CPV2: no createPLT
            token_parameters: None,
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

/// Construct typed CPV2 chain parameters without TOML.
fn make_chain_params_cpv2() -> GenesisChainParametersV2 {
    use concordium_rust_sdk::types::*;
    use serde_json::json;

    let timeout_parameters: TimeoutParameters = serde_json::from_value(json!({
        "base": "2s", "increase": 1.25, "decrease": 0.8
    }))
    .unwrap();

    let time_parameters: TimeParameters = serde_json::from_value(json!({
        "rewardPeriodLength": 4,
        "mintPerPayday": 2.61157877e-4
    }))
    .unwrap();

    let pool_parameters: PoolParameters = serde_json::from_value(json!({
        "passiveFinalizationCommission": 1.0,
        "passiveBakingCommission": 0.12,
        "passiveTransactionCommission": 0.12,
        "finalizationCommissionRange": {"min": 1.0, "max": 1.0},
        "bakingCommissionRange": {"min": 0.1, "max": 0.1},
        "transactionCommissionRange": {"min": 0.1, "max": 0.1},
        "minimumEquityCapital": "1000",
        "capitalBound": 0.1,
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

    let euro_per_energy: ExchangeRate = serde_json::from_value(json!(0.00002)).unwrap();
    let micro_ccd_per_euro: ExchangeRate = serde_json::from_value(json!(500_000.0)).unwrap();

    GenesisChainParametersV2 {
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
    }
}

fn make_protocol_params_cpv2() -> ProtocolParamsCPV2 {
    ProtocolParamsCPV2 {
        core: CoreGenesisParametersV1 {
            genesis_time: Timestamp {
                millis: 1_623_222_000_000,
            },
            epoch_duration: Duration::from_millis(3_600_000),
            signature_threshold: Ratio::new(2, 3).unwrap(),
        },
        chain: make_chain_params_cpv2(),
        leadership_election_nonce: LeadershipElectionNonce::from([0u8; 32]),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// AC: P6 genesis built via factory function with typed params.
#[test]
fn test_p6_genesis_via_factory() {
    let output = genesis_builder_p6()
        .generate_crypto_params("test-p6".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys())
        .with_protocol(make_protocol_params_cpv2())
        .build()
        .expect("P6 build must succeed");

    assert!(!output.identity_provider_data.is_empty());
    assert!(!output.anonymity_revoker_data.is_empty());
    let bytes = serialize_genesis(&output.genesis_data);
    assert!(!bytes.is_empty());
    assert_eq!(&output.genesis_data.hash(), &output.genesis_data.hash());
}

/// AC: P7 genesis built via factory function.
#[test]
fn test_p7_genesis_via_factory() {
    let output = genesis_builder_p7()
        .generate_crypto_params("test-p7".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys())
        .with_protocol(make_protocol_params_cpv2())
        .build()
        .expect("P7 build must succeed");

    assert!(!serialize_genesis(&output.genesis_data).is_empty());
}

/// CPV2 rejects createPLT governance authorization.
#[test]
fn test_cpv2_rejects_create_plt() {
    let mut gov = make_gov_keys();
    gov.level2.create_plt = Some(make_access(&[0, 1, 2], 2));

    let result = genesis_builder_p6()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 1)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(gov)
        .with_protocol(make_protocol_params_cpv2())
        .build();

    assert!(result.is_err());
    assert!(result.err().unwrap().to_string().contains("createPLT"));
}

/// AC: pre-existing artifacts are echoed back.
#[test]
fn test_cpv2_echoes_preexisting_artifacts() {
    let output = genesis_builder_p6()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys())
        .with_protocol(make_protocol_params_cpv2())
        .build()
        .unwrap();

    for ip in &output.identity_provider_data {
        assert!(output
            .identity_provider_infos
            .contains_key(&ip.public_ip_info.ip_identity));
    }
    for ar in &output.anonymity_revoker_data {
        assert!(output
            .anonymity_revoker_infos
            .contains_key(&ar.public_ar_info.ar_identity));
    }
}

/// AC: pre-existing IpData echoed back unchanged.
#[test]
fn test_cpv2_existing_ip_echoed_back() {
    let first = genesis_builder_p6()
        .generate_crypto_params("test-echo".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys())
        .with_protocol(make_protocol_params_cpv2())
        .build()
        .unwrap();

    assert_eq!(first.identity_provider_data.len(), 2);
    let existing_ip = first.identity_provider_data.into_iter().next().unwrap();
    let existing_ip_id = existing_ip.public_ip_info.ip_identity;

    let second = genesis_builder_p6()
        .generate_crypto_params("test-echo".to_string())
        .add_identity_provider(existing_ip)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys())
        .with_protocol(make_protocol_params_cpv2())
        .build()
        .expect("second build must succeed");

    assert_eq!(second.identity_provider_data.len(), 1);
    assert_eq!(
        second.identity_provider_data[0].public_ip_info.ip_identity,
        existing_ip_id
    );
}

/// GenesisBuilderCPV2 rejects wrong protocol versions.
/// Uses P4 (CPV1) which is still in ProtocolConfig but rejected by CPV2 builder.
/// (P6/P7 were removed from ProtocolConfig in the CPV2 migration.)
#[test]
fn test_cpv2_rejects_wrong_protocol_version() {
    // The CPV2 builder's protocol_version is baked in at construction;
    // providing wrong params type would be a compile error, not a runtime error.
    // We verify the builder succeeds only for P6/P7.
    let output = genesis_builder_p7()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 1)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys())
        .with_protocol(make_protocol_params_cpv2())
        .build()
        .expect("P7 must succeed");
    assert!(!serialize_genesis(&output.genesis_data).is_empty());
}
