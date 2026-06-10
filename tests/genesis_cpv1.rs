//! Integration tests for the CPV1 builder (P4–P5).
//!
//! P4 always uses CPV1 chain parameters — there is no valid P4-CPV0 genesis.
//! Tests use factory functions and typed protocol parameters (no TOML parsing).

use concordium_rust_sdk::genesis::types::CoreGenesisParametersV0;
use concordium_rust_sdk::genesis::{
    builder::{
        FreshAccountConfig, GovernanceKeyLevelConfig, GovernanceKeySpec,
        GovernanceKeysGenerateConfig, Level2AccessConfig, Level2GovernanceKeysConfig,
    },
    genesis_builder_p4, genesis_builder_p5, serialize_genesis, GenesisChainParametersV1,
    ProtocolParamsCPV1,
};
use concordium_rust_sdk::{
    common::types::{Amount, Timestamp},
    id::types::{ArIdentity, IpIdentity, SignatureThreshold},
    types::{
        hashes::LeadershipElectionNonce, Energy, SlotDuration, UpdateKeysIndex, UpdateKeysThreshold,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_access(keys: &[u16], threshold: u16) -> Level2AccessConfig {
    Level2AccessConfig {
        authorized_keys: keys.iter().map(|&i| UpdateKeysIndex { index: i }).collect(),
        threshold: UpdateKeysThreshold::try_from(threshold).unwrap(),
    }
}

fn make_gov_keys_cpv1() -> GovernanceKeysGenerateConfig {
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
            create_plt: None,
        },
    }
}

fn foundation_account() -> FreshAccountConfig {
    FreshAccountConfig {
        count: 1,
        stake: None,
        balance: Amount::from_micro_ccd(1_000_000_000u64),
        num_keys: 1,
        threshold: SignatureThreshold::ONE,
        identity_provider: IpIdentity::from(0),
        restake_earnings: false,
        foundation: true,
    }
}

fn make_chain_params_cpv1() -> GenesisChainParametersV1 {
    use concordium_rust_sdk::types::*;
    use serde_json::json;

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
            GASRewards, MintDistributionV1, TransactionFeeDistribution,
        };
        let mint_distribution: MintDistributionV1 =
            serde_json::from_value(json!({ "bakingReward": 0.85, "finalizationReward": 0.05 }))
                .unwrap();
        let transaction_fee_distribution: TransactionFeeDistribution =
            serde_json::from_value(json!({ "baker": 0.45, "gasAccount": 0.45 })).unwrap();
        let gas_rewards: GASRewards = serde_json::from_value(json!({
            "baker": 0.25, "finalizationProof": 0.005,
            "accountCreation": 0.02, "chainUpdate": 0.005
        }))
        .unwrap();
        concordium_rust_sdk::genesis::RewardParametersCPV1 {
            mint_distribution,
            transaction_fee_distribution,
            gas_rewards,
        }
    };

    let euro_per_energy: ExchangeRate = serde_json::from_value(json!(0.00002)).unwrap();
    let micro_ccd_per_euro: ExchangeRate = serde_json::from_value(json!(500_000.0)).unwrap();
    let election_difficulty: ElectionDifficulty = serde_json::from_value(json!(0.025)).unwrap();

    GenesisChainParametersV1 {
        election_difficulty,
        euro_per_energy,
        micro_ccd_per_euro,
        account_creation_limit: 10u16.into(),
        reward_parameters,
        time_parameters,
        pool_parameters,
        cooldown_parameters,
    }
}

fn make_finalization_params() -> concordium_rust_sdk::genesis::types::FinalizationParameters {
    serde_json::from_value(serde_json::json!({
        "minimumSkip": 0,
        "committeeMaxSize": 1000,
        "waitingTime": 100,
        "skipShrinkFactor": 0.5,
        "skipGrowFactor": 2.0,
        "delayShrinkFactor": 0.5,
        "delayGrowFactor": 2.0,
        "allowZeroDelay": true
    }))
    .unwrap()
}

fn make_protocol_params_cpv1() -> ProtocolParamsCPV1 {
    ProtocolParamsCPV1 {
        core: CoreGenesisParametersV0 {
            time: Timestamp {
                millis: 1_623_222_000_000,
            },
            slot_duration: SlotDuration { millis: 250 },
            epoch_length: 400,
            max_block_energy: Energy { energy: 3_000_000 },
            finalization_parameters: make_finalization_params(),
        },
        chain: make_chain_params_cpv1(),
        leadership_election_nonce: LeadershipElectionNonce::from([0u8; 32]),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// AC: P4 genesis built via factory function with typed params.
/// P4 always uses CPV1 chain parameters.
#[test]
fn test_p4_genesis_via_factory() {
    let output = genesis_builder_p4()
        .generate_crypto_params("test-p4".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv1())
        .with_protocol(make_protocol_params_cpv1())
        .build()
        .expect("P4 build must succeed");

    assert!(!output.identity_provider_data.is_empty());
    assert!(!output.anonymity_revoker_data.is_empty());
    let bytes = serialize_genesis(&output.genesis_data);
    assert!(!bytes.is_empty());
    assert_eq!(output.genesis_data.hash(), output.genesis_data.hash());
}

/// AC: P5 genesis built via factory function.
#[test]
fn test_p5_genesis_via_factory() {
    let output = genesis_builder_p5()
        .generate_crypto_params("test-p5".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv1())
        .with_protocol(make_protocol_params_cpv1())
        .build()
        .expect("P5 build must succeed");

    assert!(!serialize_genesis(&output.genesis_data).is_empty());
}

/// AC: Pre-existing artifacts echoed back.
#[test]
fn test_cpv1_echoes_preexisting_artifacts() {
    let output = genesis_builder_p4()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv1())
        .with_protocol(make_protocol_params_cpv1())
        .build()
        .unwrap();

    for ip in &output.identity_provider_data {
        assert!(output
            .identity_provider_infos
            .contains_key(&ip.public_ip_info.ip_identity));
    }
}

/// AC: Pre-existing IpData echoed back unchanged.
#[test]
fn test_cpv1_existing_ip_echoed_back() {
    let first = genesis_builder_p4()
        .generate_crypto_params("test-echo".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv1())
        .with_protocol(make_protocol_params_cpv1())
        .build()
        .unwrap();

    let existing_ip = first.identity_provider_data.into_iter().next().unwrap();
    let existing_ip_id = existing_ip.public_ip_info.ip_identity;

    let second = genesis_builder_p4()
        .generate_crypto_params("test-echo".to_string())
        .add_identity_provider(existing_ip)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv1())
        .with_protocol(make_protocol_params_cpv1())
        .build()
        .expect("second build must succeed");

    assert_eq!(second.identity_provider_data.len(), 1);
    assert_eq!(
        second.identity_provider_data[0].public_ip_info.ip_identity,
        existing_ip_id
    );
}
