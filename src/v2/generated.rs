tonic::include_proto!("concordium.v2");

use crypto_common::{Deserial, Versioned, VERSION_0};
use id::{
    constants::{ArCurve, AttributeKind},
    types::{
        AccountCredentialWithoutProofs, CredentialDeploymentValues,
        InitialCredentialDeploymentValues,
    },
};

use crate::types;

use super::Require;

fn consume<A: Deserial>(bytes: &[u8]) -> Result<A, tonic::Status> {
    let mut cursor = std::io::Cursor::new(bytes);
    let res = A::deserial(&mut cursor);
    match res {
        Ok(v) if cursor.position() == bytes.len() as u64 => Ok(v),
        _ => Err(tonic::Status::internal(
            "Unexpected response from the server.",
        )),
    }
}

impl TryFrom<AccountAddress> for super::AccountAddress {
    type Error = tonic::Status;

    fn try_from(value: AccountAddress) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(addr) => Ok(Self(addr)),
            Err(_) => Err(tonic::Status::internal(
                "Unexpected account address format.",
            )),
        }
    }
}

impl TryFrom<ModuleRef> for super::ModuleRef {
    type Error = tonic::Status;

    fn try_from(value: ModuleRef) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(mod_ref) => Ok(Self::new(mod_ref)),
            Err(_) => Err(tonic::Status::internal(
                "Unexpected module reference format.",
            )),
        }
    }
}

impl From<ContractAddress> for super::ContractAddress {
    fn from(value: ContractAddress) -> Self {
        super::ContractAddress::new(value.index, value.subindex)
    }
}

impl From<Energy> for super::types::Energy {
    fn from(value: Energy) -> Self {
        super::types::Energy {
            energy: value.value,
        }
    }
}

impl From<Slot> for super::types::Slot {
    fn from(value: Slot) -> Self { super::types::Slot { slot: value.value } }
}

impl TryFrom<VersionedModuleSource> for types::smart_contracts::WasmModule {
    type Error = tonic::Status;

    fn try_from(versioned_module: VersionedModuleSource) -> Result<Self, Self::Error> {
        let module = match versioned_module.module.require_owned()? {
            versioned_module_source::Module::V0(versioned_module_source::ModuleSourceV0 {
                value,
            }) => types::smart_contracts::WasmModule {
                version: types::smart_contracts::WasmVersion::V0,
                source:  value.into(),
            },
            versioned_module_source::Module::V1(versioned_module_source::ModuleSourceV1 {
                value,
            }) => types::smart_contracts::WasmModule {
                version: types::smart_contracts::WasmVersion::V1,
                source:  value.into(),
            },
        };
        Ok(module)
    }
}

impl TryFrom<BlockHash> for super::BlockHash {
    type Error = tonic::Status;

    fn try_from(value: BlockHash) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal("Unexpected block hash format.")),
        }
    }
}

impl TryFrom<TransactionHash> for super::hashes::TransactionHash {
    type Error = tonic::Status;

    fn try_from(value: TransactionHash) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal("Unexpected block hash format.")),
        }
    }
}

impl TryFrom<StateHash> for super::hashes::StateHash {
    type Error = tonic::Status;

    fn try_from(value: StateHash) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal("Unexpected state hash format.")),
        }
    }
}

impl From<AbsoluteBlockHeight> for super::AbsoluteBlockHeight {
    fn from(abh: AbsoluteBlockHeight) -> Self { Self { height: abh.value } }
}

impl From<BlockHeight> for super::types::BlockHeight {
    fn from(bh: BlockHeight) -> Self { Self { height: bh.value } }
}

impl From<super::AbsoluteBlockHeight> for AbsoluteBlockHeight {
    fn from(abh: super::AbsoluteBlockHeight) -> Self { Self { value: abh.height } }
}

impl From<super::types::BlockHeight> for BlockHeight {
    fn from(bh: super::types::BlockHeight) -> Self { Self { value: bh.height } }
}

impl From<SequenceNumber> for super::types::Nonce {
    fn from(n: SequenceNumber) -> Self { Self { nonce: n.value } }
}

impl From<Amount> for super::super::common::types::Amount {
    fn from(n: Amount) -> Self { Self { micro_ccd: n.value } }
}

impl From<AccountIndex> for super::types::AccountIndex {
    fn from(n: AccountIndex) -> Self { Self { index: n.value } }
}

impl From<super::types::AccountIndex> for AccountIndex {
    fn from(n: super::types::AccountIndex) -> Self { Self { value: n.index } }
}

impl From<BakerId> for super::types::BakerId {
    fn from(n: BakerId) -> Self { Self { id: n.value.into() } }
}

impl From<super::types::BakerId> for BakerId {
    fn from(n: super::types::BakerId) -> Self { Self { value: n.id.into() } }
}

impl TryFrom<DelegationTarget> for super::types::DelegationTarget {
    type Error = tonic::Status;

    fn try_from(dt: DelegationTarget) -> Result<Self, Self::Error> {
        match dt.target.require_owned()? {
            delegation_target::Target::Passive(_) => Ok(Self::Passive),
            delegation_target::Target::Baker(bid) => Ok(Self::Baker {
                baker_id: bid.into(),
            }),
        }
    }
}

impl TryFrom<EncryptionKey> for id::elgamal::PublicKey<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: EncryptionKey) -> Result<Self, Self::Error> { consume(&value.value) }
}

impl TryFrom<AccountThreshold> for super::types::AccountThreshold {
    type Error = tonic::Status;

    fn try_from(value: AccountThreshold) -> Result<Self, Self::Error> {
        if let Ok(Ok(v)) = u8::try_from(value.value).map(Self::try_from) {
            Ok(v)
        } else {
            Err(tonic::Status::internal("Unexpected account threshold."))
        }
    }
}

impl TryFrom<EncryptedAmount> for encrypted_transfers::types::EncryptedAmount<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: EncryptedAmount) -> Result<Self, Self::Error> { consume(&value.value) }
}

impl TryFrom<BakerElectionVerifyKey> for super::types::BakerElectionVerifyKey {
    type Error = tonic::Status;

    fn try_from(value: BakerElectionVerifyKey) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl TryFrom<BakerSignatureVerifyKey> for super::types::BakerSignatureVerifyKey {
    type Error = tonic::Status;

    fn try_from(value: BakerSignatureVerifyKey) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl TryFrom<BakerAggregationVerifyKey> for super::types::BakerAggregationVerifyKey {
    type Error = tonic::Status;

    fn try_from(value: BakerAggregationVerifyKey) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl TryFrom<EncryptedBalance> for super::types::AccountEncryptedAmount {
    type Error = tonic::Status;

    fn try_from(value: EncryptedBalance) -> Result<Self, Self::Error> {
        let self_amount = value.self_amount.require_owned()?.try_into()?;
        let start_index = value.start_index;
        let aggregated_amount = match (value.aggregated_amount, value.num_aggregated) {
            (Some(aa), Some(si)) => Some((aa.try_into()?, si)),
            (None, None) => None,
            _ => {
                return Err(tonic::Status::internal(
                    "Unexpected response for 'EncryptedBalance'.",
                ))
            }
        };
        let incoming_amounts = value
            .incoming_amounts
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<_, tonic::Status>>()?;
        Ok(Self {
            self_amount,
            start_index,
            aggregated_amount,
            incoming_amounts,
        })
    }
}

impl From<Timestamp> for chrono::DateTime<chrono::Utc> {
    fn from(value: Timestamp) -> Self {
        chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH)
            + chrono::Duration::milliseconds(value.value as i64)
    }
}

impl From<Duration> for chrono::Duration {
    fn from(value: Duration) -> Self { chrono::Duration::milliseconds(value.value as i64) }
}

impl From<Duration> for super::types::SlotDuration {
    fn from(value: Duration) -> Self {
        super::types::SlotDuration {
            millis: value.value,
        }
    }
}

impl From<GenesisIndex> for super::types::GenesisIndex {
    fn from(value: GenesisIndex) -> Self { value.value.into() }
}

impl From<super::types::GenesisIndex> for GenesisIndex {
    fn from(value: super::types::GenesisIndex) -> Self {
        GenesisIndex {
            value: value.into(),
        }
    }
}

impl From<ProtocolVersion> for super::types::ProtocolVersion {
    fn from(value: ProtocolVersion) -> Self {
        match value {
            ProtocolVersion::ProtocolVersion1 => super::types::ProtocolVersion::P1,
            ProtocolVersion::ProtocolVersion2 => super::types::ProtocolVersion::P2,
            ProtocolVersion::ProtocolVersion3 => super::types::ProtocolVersion::P3,
            ProtocolVersion::ProtocolVersion4 => super::types::ProtocolVersion::P4,
        }
    }
}

impl TryFrom<StakePendingChange> for super::types::StakePendingChange {
    type Error = tonic::Status;

    fn try_from(value: StakePendingChange) -> Result<Self, Self::Error> {
        match value.change.require_owned()? {
            stake_pending_change::Change::Reduce(rs) => {
                let new_stake = rs.new_stake.require_owned()?.into();

                Ok(Self::ReduceStake {
                    new_stake,
                    effective_time: rs.effective_time.require_owned()?.into(),
                })
            }
            stake_pending_change::Change::Remove(rs) => Ok(Self::RemoveStake {
                effective_time: rs.into(),
            }),
        }
    }
}

impl TryFrom<BakerInfo> for super::types::BakerInfo {
    type Error = tonic::Status;

    fn try_from(value: BakerInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            baker_id:                     value.baker_id.require_owned()?.into(),
            baker_election_verify_key:    value.election_key.require_owned()?.try_into()?,
            baker_signature_verify_key:   value.signature_key.require_owned()?.try_into()?,
            baker_aggregation_verify_key: value.aggregation_key.require_owned()?.try_into()?,
        })
    }
}

impl From<OpenStatus> for super::types::OpenStatus {
    fn from(os: OpenStatus) -> Self {
        match os {
            OpenStatus::OpenForAll => Self::OpenForAll,
            OpenStatus::ClosedForNew => Self::ClosedForNew,
            OpenStatus::ClosedForAll => Self::ClosedForAll,
        }
    }
}

impl From<AmountFraction> for super::types::AmountFraction {
    fn from(af: AmountFraction) -> Self {
        Self {
            parts_per_hundred_thousands: crate::types::PartsPerHundredThousands {
                parts: af.parts_per_hundred_thousand,
            },
        }
    }
}

impl TryFrom<CommissionRates> for super::types::CommissionRates {
    type Error = tonic::Status;

    fn try_from(value: CommissionRates) -> Result<Self, Self::Error> {
        Ok(Self {
            finalization: value.finalization.require_owned()?.into(),
            baking:       value.baking.require_owned()?.into(),
            transaction:  value.transaction.require_owned()?.into(),
        })
    }
}

impl TryFrom<BakerPoolInfo> for super::types::BakerPoolInfo {
    type Error = tonic::Status;

    fn try_from(value: BakerPoolInfo) -> Result<Self, Self::Error> {
        let open_status = value.open_status().into();
        let metadata_url = value
            .url
            .try_into()
            .map_err(|_| tonic::Status::internal("Unexpected metadata length."))?;
        let commission_rates = value.commission_rates.require_owned()?.try_into()?;
        Ok(Self {
            open_status,
            metadata_url,
            commission_rates,
        })
    }
}

impl TryFrom<AccountStakingInfo> for super::types::AccountStakingInfo {
    type Error = tonic::Status;

    fn try_from(value: AccountStakingInfo) -> Result<Self, Self::Error> {
        match value.staking_info.require_owned()? {
            account_staking_info::StakingInfo::Baker(bsi) => {
                let staked_amount = bsi.staked_amount.require_owned()?.into();
                let restake_earnings = bsi.restake_earnings;
                let baker_info = bsi.baker_info.require_owned()?.try_into()?;
                let pending_change = match bsi.pending_change {
                    None => None,
                    Some(pc) => Some(pc.try_into()?),
                };
                let pool_info = match bsi.pool_info {
                    None => None,
                    Some(bi) => Some(bi.try_into()?),
                };
                Ok(Self::Baker {
                    staked_amount,
                    restake_earnings,
                    baker_info: Box::new(baker_info),
                    pending_change,
                    pool_info,
                })
            }
            account_staking_info::StakingInfo::Delegator(dsi) => {
                let staked_amount = dsi.staked_amount.require_owned()?.into();
                let restake_earnings = dsi.restake_earnings;
                let delegation_target = dsi.target.require_owned()?.try_into()?;
                let pending_change = match dsi.pending_change {
                    None => None,
                    Some(pc) => Some(pc.try_into()?),
                };
                Ok(Self::Delegated {
                    staked_amount,
                    restake_earnings,
                    delegation_target,
                    pending_change,
                })
            }
        }
    }
}

impl TryFrom<Release> for super::types::Release {
    type Error = tonic::Status;

    fn try_from(value: Release) -> Result<Self, Self::Error> {
        Ok(Self {
            timestamp:    value.timestamp.require_owned()?.into(),
            amount:       value.amount.require_owned()?.into(),
            transactions: value
                .transactions
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, tonic::Status>>()?,
        })
    }
}

impl TryFrom<ReleaseSchedule> for super::types::AccountReleaseSchedule {
    type Error = tonic::Status;

    fn try_from(value: ReleaseSchedule) -> Result<Self, Self::Error> {
        Ok(Self {
            total:    value.total.require_owned()?.into(),
            schedule: value
                .schedules
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, tonic::Status>>()?,
        })
    }
}

impl TryFrom<AccountVerifyKey> for id::types::VerifyKey {
    type Error = tonic::Status;

    fn try_from(value: AccountVerifyKey) -> Result<Self, Self::Error> {
        match value.key.require_owned()? {
            account_verify_key::Key::Ed25519Key(v) => Ok(Self::Ed25519VerifyKey(consume(&v)?)),
        }
    }
}

impl TryFrom<SignatureThreshold> for id::types::SignatureThreshold {
    type Error = tonic::Status;

    fn try_from(value: SignatureThreshold) -> Result<Self, Self::Error> {
        if let Ok(v) = u8::try_from(value.value) {
            if v == 0 {
                Err(tonic::Status::internal(
                    "Unexpected zero signature threshold.",
                ))
            } else {
                Ok(Self(v))
            }
        } else {
            Err(tonic::Status::internal("Unexpected signature threshold."))
        }
    }
}

impl TryFrom<ArThreshold> for id::secret_sharing::Threshold {
    type Error = tonic::Status;

    fn try_from(value: ArThreshold) -> Result<Self, Self::Error> {
        if let Ok(v) = u8::try_from(value.value) {
            if v == 0 {
                Err(tonic::Status::internal("Unexpected zero AR threshold."))
            } else {
                Ok(Self(v))
            }
        } else {
            Err(tonic::Status::internal("Unexpected AR threshold."))
        }
    }
}

impl TryFrom<CredentialPublicKeys> for id::types::CredentialPublicKeys {
    type Error = tonic::Status;

    fn try_from(value: CredentialPublicKeys) -> Result<Self, Self::Error> {
        Ok(Self {
            keys:      value
                .keys
                .into_iter()
                .map(|(k, v)| {
                    if let Ok(k) = u8::try_from(k) {
                        let k = k.into();
                        let v = v.try_into()?;
                        Ok((k, v))
                    } else {
                        Err(tonic::Status::internal("Unexpected key index."))
                    }
                })
                .collect::<Result<_, tonic::Status>>()?,
            threshold: value.threshold.require_owned()?.try_into()?,
        })
    }
}

impl TryFrom<CredentialRegistrationId> for super::types::CredentialRegistrationID {
    type Error = tonic::Status;

    fn try_from(value: CredentialRegistrationId) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl TryFrom<CredentialRegistrationId> for ArCurve {
    type Error = tonic::Status;

    fn try_from(value: CredentialRegistrationId) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl From<IdentityProviderIdentity> for id::types::IpIdentity {
    fn from(v: IdentityProviderIdentity) -> Self { Self(v.value) }
}

impl TryFrom<YearMonth> for id::types::YearMonth {
    type Error = tonic::Status;

    fn try_from(value: YearMonth) -> Result<Self, Self::Error> {
        Ok(Self {
            year:  value
                .year
                .try_into()
                .map_err(|_| tonic::Status::internal("Unexpected year."))?,
            month: value
                .month
                .try_into()
                .map_err(|_| tonic::Status::internal("Unexpected year."))?,
        })
    }
}

impl TryFrom<Policy> for id::types::Policy<ArCurve, AttributeKind> {
    type Error = tonic::Status;

    fn try_from(value: Policy) -> Result<Self, Self::Error> {
        Ok(Self {
            valid_to:   value.valid_to.require_owned()?.try_into()?,
            created_at: value.created_at.require_owned()?.try_into()?,
            policy_vec: value
                .attributes
                .into_iter()
                .map(|(k, v)| {
                    let k = id::types::AttributeTag(
                        k.try_into()
                            .map_err(|_| tonic::Status::internal("Unexpected attribute tag."))?,
                    );
                    let v = consume(&v)?;
                    Ok((k, v))
                })
                .collect::<Result<_, tonic::Status>>()?,
            _phantom:   std::marker::PhantomData,
        })
    }
}

impl TryFrom<ChainArData> for id::types::ChainArData<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: ChainArData) -> Result<Self, Self::Error> {
        consume(&value.enc_id_cred_pub_share)
    }
}

impl TryFrom<Commitment> for id::pedersen_commitment::Commitment<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: Commitment) -> Result<Self, Self::Error> { consume(&value.value) }
}

impl TryFrom<CredentialCommitments> for id::types::CredentialDeploymentCommitments<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: CredentialCommitments) -> Result<Self, Self::Error> {
        Ok(Self {
            cmm_prf: value.prf.require_owned()?.try_into()?,
            cmm_cred_counter: value.cred_counter.require_owned()?.try_into()?,
            cmm_max_accounts: value.max_accounts.require_owned()?.try_into()?,
            cmm_attributes: value
                .attributes
                .into_iter()
                .map(|(k, v)| {
                    let k = id::types::AttributeTag(
                        k.try_into()
                            .map_err(|_| tonic::Status::internal("Unexpected attribute tag."))?,
                    );
                    let v = v.try_into()?;
                    Ok((k, v))
                })
                .collect::<Result<_, tonic::Status>>()?,
            cmm_id_cred_sec_sharing_coeff: value
                .id_cred_sec_sharing_coeff
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, tonic::Status>>()?,
        })
    }
}

impl TryFrom<AccountCredential> for AccountCredentialWithoutProofs<ArCurve, AttributeKind> {
    type Error = tonic::Status;

    fn try_from(value: AccountCredential) -> Result<Self, Self::Error> {
        match value.credential_values.require_owned()? {
            account_credential::CredentialValues::Initial(ic) => {
                let icdv = InitialCredentialDeploymentValues {
                    cred_account: ic.keys.require_owned()?.try_into()?,
                    reg_id:       ic.cred_id.require_owned()?.try_into()?,
                    ip_identity:  ic.ip_id.require_owned()?.into(),
                    policy:       ic.policy.require_owned()?.try_into()?,
                };
                Ok(Self::Initial { icdv })
            }
            account_credential::CredentialValues::Normal(nc) => {
                let cdv = CredentialDeploymentValues {
                    cred_key_info: nc.keys.require_owned()?.try_into()?,
                    cred_id:       nc.cred_id.require_owned()?.try_into()?,
                    ip_identity:   nc.ip_id.require_owned()?.into(),
                    threshold:     nc.ar_threshold.require_owned()?.try_into()?,
                    ar_data:       nc
                        .ar_data
                        .into_iter()
                        .map(|(k, v)| {
                            let k = k
                                .try_into()
                                .map_err(|_| tonic::Status::internal("Unexpected AR identity."))?;
                            let v = v.try_into()?;
                            Ok((k, v))
                        })
                        .collect::<Result<_, tonic::Status>>()?,
                    policy:        nc.policy.require_owned()?.try_into()?,
                };
                let commitments = nc.commitments.require_owned()?.try_into()?;
                Ok(Self::Normal { cdv, commitments })
            }
        }
    }
}

impl TryFrom<AccountInfo> for super::types::AccountInfo {
    type Error = tonic::Status;

    fn try_from(value: AccountInfo) -> Result<Self, Self::Error> {
        let AccountInfo {
            sequence_number,
            amount,
            schedule,
            creds,
            threshold,
            encrypted_balance,
            encryption_key,
            index,
            stake,
            address,
        } = value;
        let account_nonce = sequence_number.require_owned()?.into();
        let account_amount = amount.require_owned()?.into();
        let account_release_schedule = schedule.require_owned()?.try_into()?;
        let account_threshold = threshold.require_owned()?.try_into()?;
        let account_encrypted_amount = encrypted_balance.require_owned()?.try_into()?;
        let account_encryption_key = encryption_key.require_owned()?.try_into()?;
        let account_index = index.require_owned()?.into();
        let account_stake = match stake {
            Some(stake) => Some(stake.try_into()?),
            None => None,
        };
        let account_address = address.require_owned()?.try_into()?;
        Ok(Self {
            account_nonce,
            account_amount,
            account_release_schedule,
            account_credentials: creds
                .into_iter()
                .map(|(k, v)| {
                    let k = u8::try_from(k)
                        .map_err(|_| tonic::Status::internal("Unexpected credential index."))?
                        .into();
                    let v = v.try_into()?;
                    Ok((k, Versioned::new(VERSION_0, v)))
                })
                .collect::<Result<_, tonic::Status>>()?,
            account_threshold,
            account_encrypted_amount,
            account_encryption_key,
            account_index,
            account_stake,
            account_address,
        })
    }
}

impl TryFrom<NextAccountSequenceNumber> for types::queries::AccountNonceResponse {
    type Error = tonic::Status;

    fn try_from(value: NextAccountSequenceNumber) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce:     value.sequence_number.require_owned()?.into(),
            all_final: value.all_final,
        })
    }
}

impl TryFrom<ConsensusInfo> for types::queries::ConsensusInfo {
    type Error = tonic::Status;

    fn try_from(value: ConsensusInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            last_finalized_block_height:    value
                .last_finalized_block_height
                .require_owned()?
                .into(),
            block_arrive_latency_e_m_s_d:   value.block_arrive_latency_emsd,
            block_receive_latency_e_m_s_d:  value.block_receive_latency_emsd,
            last_finalized_block:           value
                .last_finalized_block
                .require_owned()?
                .try_into()?,
            block_receive_period_e_m_s_d:   value.block_receive_period_emsd,
            block_arrive_period_e_m_s_d:    value.block_arrive_period_emsd,
            blocks_received_count:          value.blocks_received_count.into(),
            transactions_per_block_e_m_s_d: value.transactions_per_block_emsd,
            finalization_period_e_m_a:      value.finalization_period_ema,
            best_block_height:              value.best_block_height.require_owned()?.into(),
            last_finalized_time:            value.last_finalized_time.map(|v| v.into()),
            finalization_count:             value.finalization_count.into(),
            epoch_duration:                 value.epoch_duration.require_owned()?.into(),
            blocks_verified_count:          value.blocks_verified_count.into(),
            slot_duration:                  value.slot_duration.require_owned()?.into(),
            genesis_time:                   value.genesis_time.require_owned()?.into(),
            finalization_period_e_m_s_d:    value.finalization_period_emsd,
            transactions_per_block_e_m_a:   value.transactions_per_block_ema,
            block_arrive_latency_e_m_a:     value.block_arrive_latency_ema,
            block_receive_latency_e_m_a:    value.block_receive_latency_ema,
            block_arrive_period_e_m_a:      value.block_arrive_period_ema,
            block_receive_period_e_m_a:     value.block_receive_period_ema,
            block_last_arrived_time:        value.block_last_arrived_time.map(|v| v.into()),
            best_block:                     value.best_block.require_owned()?.try_into()?,
            genesis_block:                  value.genesis_block.require_owned()?.try_into()?,
            block_last_received_time:       value.block_last_received_time.map(|v| v.into()),
            protocol_version:               ProtocolVersion::from_i32(value.protocol_version)
                .ok_or_else(|| tonic::Status::internal("Unknown protocol version"))?
                .into(),
            genesis_index:                  value.genesis_index.require_owned()?.into(),
            current_era_genesis_block:      value
                .current_era_genesis_block
                .require_owned()?
                .try_into()?,
            current_era_genesis_time:       value.current_era_genesis_time.require_owned()?.into(),
        })
    }
}

impl TryFrom<CryptographicParameters> for types::queries::CryptographicParameters {
    type Error = tonic::Status;

    fn try_from(value: CryptographicParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            genesis_string:          value.genesis_string,
            on_chain_commitment_key: crypto_common::from_bytes(&mut std::io::Cursor::new(
                &value.on_chain_commitment_key,
            ))
            .map_err(|_| tonic::Status::internal("Invalid on_chain_commitment_key received"))?,

            bulletproof_generators: crypto_common::from_bytes(&mut std::io::Cursor::new(
                &value.bulletproof_generators,
            ))
            .map_err(|_| tonic::Status::internal("Invalid bulletproof_generators received"))?,
        })
    }
}

impl TryFrom<BlockInfo> for types::queries::BlockInfo {
    type Error = tonic::Status;

    fn try_from(value: BlockInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            transactions_size:       value.transactions_size.into(),
            block_parent:            value.parent_block.require_owned()?.try_into()?,
            block_hash:              value.hash.require_owned()?.try_into()?,
            finalized:               value.finalized,
            block_state_hash:        value.state_hash.require_owned()?.try_into()?,
            block_arrive_time:       value.arrive_time.require_owned()?.into(),
            block_receive_time:      value.receive_time.require_owned()?.into(),
            transaction_count:       value.transaction_count.into(),
            transaction_energy_cost: value.transactions_energy_cost.require_owned()?.into(),
            block_slot:              value.slot_number.require_owned()?.into(),
            block_last_finalized:    value.last_finalized_block.require_owned()?.try_into()?,
            block_slot_time:         value.slot_time.require_owned()?.into(),
            block_height:            value.height.require_owned()?.into(),
            era_block_height:        value.era_block_height.require_owned()?.into(),
            genesis_index:           value.genesis_index.require_owned()?.into(),
            block_baker:             value.baker.map(|b| b.into()),
        })
    }
}

impl TryFrom<PoolStatus> for types::BakerPoolStatus {
    type Error = tonic::Status;

    fn try_from(value: PoolStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            baker_id:                   value.baker.require_owned()?.into(),
            baker_address:              value.address.require_owned()?.try_into()?,
            baker_equity_capital:       value.equity_capital.require_owned()?.into(),
            delegated_capital:          value.delegated_capital.require_owned()?.into(),
            delegated_capital_cap:      value.delegated_capital_cap.require_owned()?.into(),
            pool_info:                  value.pool_info.require_owned()?.try_into()?,
            baker_stake_pending_change: value.equity_pending_change.try_into()?,
            current_payday_status:      if let Some(v) = value.current_payday_status {
                Some(v.try_into()?)
            } else {
                None
            },
            all_pool_total_capital:     value.all_pool_total_capital.require_owned()?.into(),
        })
    }
}

impl TryFrom<Option<PoolPendingChange>> for super::types::PoolPendingChange {
    type Error = tonic::Status;

    fn try_from(value: Option<PoolPendingChange>) -> Result<Self, Self::Error> {
        if let Some(value) = value {
            match value.change.require_owned()? {
                pool_pending_change::Change::Reduce(rs) => Ok(Self::ReduceBakerCapital {
                    baker_equity_capital: rs.reduced_equity_capital.require_owned()?.into(),
                    effective_time:       rs.effective_time.require_owned()?.into(),
                }),
                pool_pending_change::Change::Remove(rs) => Ok(Self::RemovePool {
                    effective_time: rs.effective_time.require_owned()?.into(),
                }),
            }
        } else {
            Ok(Self::NoChange)
        }
    }
}

impl TryFrom<PoolCurrentPaydayStatus> for super::types::CurrentPaydayBakerPoolStatus {
    type Error = tonic::Status;

    fn try_from(value: PoolCurrentPaydayStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            blocks_baked:            value.blocks_baked,
            finalization_live:       value.finalization_live,
            transaction_fees_earned: value.transaction_fees_earned.require_owned()?.into(),
            effective_stake:         value.effective_stake.require_owned()?.into(),
            lottery_power:           value.lottery_power,
            baker_equity_capital:    value.baker_equity_capital.require_owned()?.into(),
            delegated_capital:       value.delegated_capital.require_owned()?.into(),
        })
    }
}

impl TryFrom<PassiveDelegationStatus> for super::types::PassiveDelegationStatus {
    type Error = tonic::Status;

    fn try_from(value: PassiveDelegationStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            delegated_capital: value.delegated_capital.require_owned()?.into(),
            commission_rates: value.commission_rates.require_owned()?.try_into()?,
            current_payday_transaction_fees_earned: value
                .current_payday_transaction_fees_earned
                .require_owned()?
                .into(),
            current_payday_delegated_capital: value
                .current_payday_delegated_capital
                .require_owned()?
                .into(),
            all_pool_total_capital: value.all_pool_total_capital.require_owned()?.into(),
        })
    }
}

impl From<&super::endpoints::BlocksAtHeightInput> for BlocksAtHeightRequest {
    fn from(&input: &super::endpoints::BlocksAtHeightInput) -> Self {
        let blocks_at_height = match input {
            super::endpoints::BlocksAtHeightInput::Absolute { height } => {
                blocks_at_height_request::BlocksAtHeight::Absolute(
                    blocks_at_height_request::Absolute {
                        height: Some(height.into()),
                    },
                )
            }

            super::endpoints::BlocksAtHeightInput::Relative {
                height,
                genesis_index,
                restrict,
            } => blocks_at_height_request::BlocksAtHeight::Relative(
                blocks_at_height_request::Relative {
                    height: Some(height.into()),
                    genesis_index: Some(genesis_index.into()),
                    restrict,
                },
            ),
        };
        BlocksAtHeightRequest {
            blocks_at_height: Some(blocks_at_height),
        }
    }
}
