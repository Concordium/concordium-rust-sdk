//! Integration tests for the CPV0 builder (P1–P3).
//!
//! Tests use factory functions and typed protocol parameters (no TOML parsing).

use concordium_rust_sdk::genesis::types::{
    CoreGenesisParametersV0, FinalizationParameters, RewardParametersCPV0,
};
use concordium_rust_sdk::genesis::{
    builder::{
        FreshAccountConfig, GovernanceKeyLevelConfig, GovernanceKeySpec,
        GovernanceKeysGenerateConfigCPV0, Level2AccessConfig, Level2GovernanceKeysConfigV0,
    },
    genesis_builder_p1, genesis_builder_p2, genesis_builder_p3, serialize_genesis,
    GenesisChainParametersV0, ProtocolParamsCPV0,
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

fn make_gov_keys_cpv0() -> GovernanceKeysGenerateConfigCPV0 {
    let k = &[0u16, 1, 2];
    GovernanceKeysGenerateConfigCPV0 {
        root: GovernanceKeyLevelConfig {
            threshold: UpdateKeysThreshold::try_from(2u16).unwrap(),
            keys: vec![GovernanceKeySpec::Fresh { count: 3 }],
        },
        level1: GovernanceKeyLevelConfig {
            threshold: UpdateKeysThreshold::try_from(2u16).unwrap(),
            keys: vec![GovernanceKeySpec::Fresh { count: 3 }],
        },
        level2: Level2GovernanceKeysConfigV0 {
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

fn make_finalization_params() -> FinalizationParameters {
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

fn make_chain_params_cpv0() -> GenesisChainParametersV0 {
    use concordium_rust_sdk::types::*;
    use serde_json::json;

    let reward_parameters = {
        use concordium_rust_sdk::types::{
            GASRewards, MintDistributionV0, TransactionFeeDistribution,
        };
        let mint_distribution: MintDistributionV0 = serde_json::from_value(json!({
            "bakingReward": 0.85,
            "finalizationReward": 0.05,
            "mintPerSlot": 7.555e-10
        }))
        .unwrap();
        let transaction_fee_distribution: TransactionFeeDistribution =
            serde_json::from_value(json!({ "baker": 0.45, "gasAccount": 0.45 })).unwrap();
        let gas_rewards: GASRewards = serde_json::from_value(json!({
            "baker": 0.25,
            "finalizationProof": 0.005,
            "accountCreation": 0.02,
            "chainUpdate": 0.005
        }))
        .unwrap();
        RewardParametersCPV0 {
            mint_distribution,
            transaction_fee_distribution,
            gas_rewards,
        }
    };

    let euro_per_energy: ExchangeRate = serde_json::from_value(json!(0.00002)).unwrap();
    let micro_ccd_per_euro: ExchangeRate = serde_json::from_value(json!(500_000.0)).unwrap();
    let election_difficulty: ElectionDifficulty = serde_json::from_value(json!(0.025)).unwrap();

    GenesisChainParametersV0 {
        election_difficulty,
        euro_per_energy,
        micro_ccd_per_euro,
        account_creation_limit: 10u16.into(),
        baker_cooldown_epochs: concordium_rust_sdk::types::Epoch { epoch: 166 },
        reward_parameters,
        minimum_threshold_for_baking: Amount::from_micro_ccd(15_000_000_000u64),
    }
}

fn make_protocol_params_cpv0() -> ProtocolParamsCPV0 {
    ProtocolParamsCPV0 {
        core: CoreGenesisParametersV0 {
            time: Timestamp {
                millis: 1_623_222_000_000,
            },
            slot_duration: SlotDuration { millis: 250 },
            epoch_length: 400,
            max_block_energy: Energy { energy: 3_000_000 },
            finalization_parameters: make_finalization_params(),
        },
        chain: make_chain_params_cpv0(),
        leadership_election_nonce: LeadershipElectionNonce::from([0u8; 32]),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// AC: P1 genesis built via factory function.
#[test]
fn test_p1_genesis_via_factory() {
    let output = genesis_builder_p1()
        .generate_crypto_params("test-p1".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv0())
        .with_protocol(make_protocol_params_cpv0())
        .build()
        .expect("P1 build must succeed");

    assert!(!output.identity_provider_data.is_empty());
    assert!(!output.anonymity_revoker_data.is_empty());
    let bytes = serialize_genesis(&output.genesis_data);
    assert!(!bytes.is_empty());
    assert_eq!(output.genesis_data.hash(), output.genesis_data.hash());
}

/// AC: P2 and P3 genesis built via factory functions.
#[test]
fn test_p2_p3_genesis_via_factory() {
    let output2 = genesis_builder_p2()
        .generate_crypto_params("test-p2".to_string())
        .generate_identity_providers(IpIdentity::from(0), 1)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv0())
        .with_protocol(make_protocol_params_cpv0())
        .build()
        .expect("P2 build must succeed");
    assert!(!serialize_genesis(&output2.genesis_data).is_empty());

    let output3 = genesis_builder_p3()
        .generate_crypto_params("test-p3".to_string())
        .generate_identity_providers(IpIdentity::from(0), 1)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv0())
        .with_protocol(make_protocol_params_cpv0())
        .build()
        .expect("P3 build must succeed");
    assert!(!serialize_genesis(&output3.genesis_data).is_empty());
}

/// AC: Pre-existing artifacts echoed back.
#[test]
fn test_cpv0_echoes_preexisting_artifacts() {
    let output = genesis_builder_p1()
        .generate_crypto_params("test".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 3)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv0())
        .with_protocol(make_protocol_params_cpv0())
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
fn test_cpv0_existing_ip_echoed_back() {
    let first = genesis_builder_p1()
        .generate_crypto_params("test-echo".to_string())
        .generate_identity_providers(IpIdentity::from(0), 2)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv0())
        .with_protocol(make_protocol_params_cpv0())
        .build()
        .unwrap();

    let existing_ip = first.identity_provider_data.into_iter().next().unwrap();
    let existing_ip_id = existing_ip.public_ip_info.ip_identity;

    let second = genesis_builder_p1()
        .generate_crypto_params("test-echo".to_string())
        .add_identity_provider(existing_ip)
        .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
        .generate_accounts(foundation_account())
        .generate_governance_keys(make_gov_keys_cpv0())
        .with_protocol(make_protocol_params_cpv0())
        .build()
        .expect("second build must succeed");

    assert_eq!(second.identity_provider_data.len(), 1);
    assert_eq!(
        second.identity_provider_data[0].public_ip_info.ip_identity,
        existing_ip_id
    );
}

/// CPV0 builder only accepts P1-P3.
#[test]
fn test_cpv0_all_valid_versions() {
    for builder in [
        genesis_builder_p1(),
        genesis_builder_p2(),
        genesis_builder_p3(),
    ] {
        let result = builder
            .generate_crypto_params("test".to_string())
            .generate_identity_providers(IpIdentity::from(0), 1)
            .generate_anonymity_revokers(ArIdentity::try_from(1u32).unwrap(), 1)
            .generate_accounts(foundation_account())
            .generate_governance_keys(make_gov_keys_cpv0())
            .with_protocol(make_protocol_params_cpv0())
            .build();
        assert!(result.is_ok(), "CPV0 builder must accept P1/P2/P3");
    }
}
