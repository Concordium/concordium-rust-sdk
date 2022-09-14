tonic::include_proto!("concordium.v2");

use super::Require;
use crypto_common::{Deserial, Versioned, VERSION_0};
use id::{
    constants::{ArCurve, AttributeKind, IpPairing},
    types::{
        AccountCredentialWithoutProofs, CredentialDeploymentValues,
        InitialCredentialDeploymentValues,
    },
};
use std::{collections::BTreeMap, marker::PhantomData};

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

impl TryFrom<Address> for super::types::Address {
    type Error = tonic::Status;

    fn try_from(value: Address) -> Result<Self, Self::Error> {
        match value.r#type.require_owned()? {
            address::Type::Account(acc) => Ok(Self::Account(acc.try_into()?)),
            address::Type::Contract(contr) => Ok(Self::Contract(contr.into())),
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

impl TryFrom<VersionedModuleSource> for super::types::smart_contracts::WasmModule {
    type Error = tonic::Status;

    fn try_from(versioned_module: VersionedModuleSource) -> Result<Self, Self::Error> {
        let module = match versioned_module.module.require_owned()? {
            versioned_module_source::Module::V0(versioned_module_source::ModuleSourceV0 {
                value,
            }) => super::types::smart_contracts::WasmModule {
                version: super::types::smart_contracts::WasmVersion::V0,
                source:  value.into(),
            },
            versioned_module_source::Module::V1(versioned_module_source::ModuleSourceV1 {
                value,
            }) => super::types::smart_contracts::WasmModule {
                version: super::types::smart_contracts::WasmVersion::V1,
                source:  value.into(),
            },
        };
        Ok(module)
    }
}

impl From<Parameter> for super::types::smart_contracts::Parameter {
    fn from(value: Parameter) -> Self { value.value.into() }
}

impl TryFrom<InstanceInfo> for super::InstanceInfo {
    type Error = tonic::Status;

    fn try_from(value: InstanceInfo) -> Result<Self, Self::Error> {
        match value.version.require_owned()? {
            instance_info::Version::V0(v0) => Ok(Self::V0 {
                model:         v0.model.require_owned()?.value,
                owner:         v0.owner.require_owned()?.try_into()?,
                amount:        v0.amount.require_owned()?.into(),
                methods:       v0
                    .methods
                    .into_iter()
                    .map(TryFrom::try_from)
                    .collect::<Result<_, tonic::Status>>()?,
                name:          v0.name.require_owned()?.try_into()?,
                source_module: v0.source_module.require_owned()?.try_into()?,
            }),
            instance_info::Version::V1(v1) => Ok(Self::V1 {
                owner:         v1.owner.require_owned()?.try_into()?,
                amount:        v1.amount.require_owned()?.into(),
                methods:       v1
                    .methods
                    .into_iter()
                    .map(TryFrom::try_from)
                    .collect::<Result<_, tonic::Status>>()?,
                name:          v1.name.require_owned()?.try_into()?,
                source_module: v1.source_module.require_owned()?.try_into()?,
            }),
        }
    }
}

impl TryFrom<ReceiveName> for concordium_contracts_common::OwnedReceiveName {
    type Error = tonic::Status;

    fn try_from(value: ReceiveName) -> Result<Self, Self::Error> {
        match Self::new(value.value) {
            Ok(rn) => Ok(rn),
            Err(_) => Err(tonic::Status::internal("Unexpected receive name format.")),
        }
    }
}

impl TryFrom<InitName> for concordium_contracts_common::OwnedContractName {
    type Error = tonic::Status;

    fn try_from(value: InitName) -> Result<Self, Self::Error> {
        match Self::new(value.value) {
            Ok(cn) => Ok(cn),
            Err(_) => Err(tonic::Status::internal("Unexpected contract name format.")),
        }
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
            Err(_) => Err(tonic::Status::internal(
                "Unexpected transaction hash format.",
            )),
        }
    }
}

impl TryFrom<Sha256Hash> for super::hashes::Hash {
    type Error = tonic::Status;

    fn try_from(value: Sha256Hash) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal("Unexpected hash format.")),
        }
    }
}

impl From<AbsoluteBlockHeight> for super::AbsoluteBlockHeight {
    fn from(abh: AbsoluteBlockHeight) -> Self { Self { height: abh.value } }
}

impl From<BlockHeight> for super::types::BlockHeight {
    fn from(bh: BlockHeight) -> Self { Self { height: bh.value } }
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

impl TryFrom<ar_info::ArPublicKey> for id::elgamal::PublicKey<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: ar_info::ArPublicKey) -> Result<Self, Self::Error> { consume(&value.value) }
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

impl TryFrom<ip_info::IpCdiVerifyKey> for ed25519_dalek::PublicKey {
    type Error = tonic::Status;

    fn try_from(value: ip_info::IpCdiVerifyKey) -> Result<Self, Self::Error> {
        Ok(consume(&value.value)?)
    }
}

impl TryFrom<ip_info::IpVerifyKey> for id::ps_sig::PublicKey<IpPairing> {
    type Error = tonic::Status;

    fn try_from(value: ip_info::IpVerifyKey) -> Result<Self, Self::Error> {
        Ok(consume(&value.value)?)
    }
}

impl TryFrom<UpdatePublicKey> for super::types::UpdatePublicKey {
    type Error = tonic::Status;

    fn try_from(value: UpdatePublicKey) -> Result<Self, Self::Error> {
        Ok(super::types::UpdatePublicKey {
            public: id::types::VerifyKey::Ed25519VerifyKey(consume(&value.value)?),
        })
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

impl TryFrom<TransactionStatus> for super::types::TransactionStatus {
    type Error = tonic::Status;

    fn try_from(value: TransactionStatus) -> Result<Self, Self::Error> {
        match value.status.require_owned()? {
            transaction_status::Status::Received(_) => {
                Ok(super::types::TransactionStatus::Received)
            }
            transaction_status::Status::Finalized(f) => {
                let mut summaries: BTreeMap<super::BlockHash, super::types::BlockItemSummary> =
                    BTreeMap::new();
                let o = f.outcome.require_owned()?;
                let k = o.block_hash.require_owned()?.try_into()?;
                let v = o.outcome.require_owned()?.try_into()?;
                summaries.insert(k, v);
                Ok(super::types::TransactionStatus::Finalized(summaries))
            }
            transaction_status::Status::Committed(cs) => {
                let mut summaries: BTreeMap<super::BlockHash, super::types::BlockItemSummary> =
                    BTreeMap::new();
                for o in cs.outcomes {
                    let k = o.block_hash.require_owned()?.try_into()?;
                    let v = o.outcome.require_owned()?.try_into()?;
                    summaries.insert(k, v);
                }
                Ok(super::types::TransactionStatus::Committed(summaries))
            }
        }
    }
}

impl TryFrom<BlockItemSummary> for super::types::BlockItemSummary {
    type Error = tonic::Status;

    fn try_from(value: BlockItemSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            index:       value.index.require_owned()?.into(),
            energy_cost: value.energy_cost.require_owned()?.into(),
            hash:        value.hash.require_owned()?.try_into()?,
            details:     match value.details.require_owned()? {
                block_item_summary::Details::AccountTransaction(v) => {
                    super::types::BlockItemSummaryDetails::AccountTransaction(
                        super::types::AccountTransactionDetails {
                            cost:    v.cost.require_owned()?.into(),
                            sender:  v.sender.require_owned()?.try_into()?,
                            effects: v.effects.require_owned()?.try_into()?,
                        },
                    )
                }
                block_item_summary::Details::AccountCreation(v) => {
                    super::types::BlockItemSummaryDetails::AccountCreation(
                        super::types::AccountCreationDetails {
                            credential_type: v.credential_type().into(),
                            address:         v.address.require_owned()?.try_into()?,
                            reg_id:          v.reg_id.require_owned()?.try_into()?,
                        },
                    )
                }
                block_item_summary::Details::Update(v) => {
                    super::types::BlockItemSummaryDetails::Update(super::types::UpdateDetails {
                        effective_time: v.effective_time.require_owned()?.into(),
                        payload:        v.payload.require_owned()?.try_into()?,
                    })
                }
            },
        })
    }
}

impl TryFrom<UpdatePayload> for super::types::UpdatePayload {
    type Error = tonic::Status;

    fn try_from(value: UpdatePayload) -> Result<Self, Self::Error> {
        Ok(match value.payload.require_owned()? {
            update_payload::Payload::ProtocolUpdate(v) => {
                Self::Protocol(super::types::ProtocolUpdate {
                    message: v.message,
                    specification_url: v.specification_url,
                    specification_hash: v.specification_hash.require_owned()?.try_into()?,
                    specification_auxiliary_data: v.specification_auxiliary_data,
                })
            }
            update_payload::Payload::ElectionDifficultyUpdate(v) => {
                Self::ElectionDifficulty(super::types::ElectionDifficulty {
                    parts_per_hundred_thousands: super::types::PartsPerHundredThousands::new(
                        v.value.require_owned()?.parts_per_hundred_thousand,
                    )
                    .ok_or(tonic::Status::internal(
                        "Invalid election difficulty. Above 100_000 parts per hundres thousands.",
                    ))?,
                })
            }
            update_payload::Payload::EuroPerEnergyUpdate(v) => {
                let value = v.value.require_owned()?;
                Self::EuroPerEnergy(super::types::ExchangeRate {
                    numerator:   value.numerator,
                    denominator: value.denominator,
                })
            }
            update_payload::Payload::MicroCcdPerEuroUpdate(v) => {
                let value = v.value.require_owned()?;
                Self::MicroGTUPerEuro(super::types::ExchangeRate {
                    numerator:   value.numerator,
                    denominator: value.denominator,
                })
            }
            update_payload::Payload::FoundationAccountUpdate(v) => {
                Self::FoundationAccount(v.try_into()?)
            }
            update_payload::Payload::MintDistributionUpdate(v) => {
                Self::MintDistribution(super::types::MintDistributionV0 {
                    mint_per_slot:       v.mint_distribution.require_owned()?.try_into()?,
                    baking_reward:       v.baking_reward.require_owned()?.into(),
                    finalization_reward: v.finalization_reward.require_owned()?.into(),
                })
            }
            update_payload::Payload::TransactionFeeDistributionUpdate(v) => {
                Self::TransactionFeeDistribution(super::types::TransactionFeeDistribution {
                    baker:       v.baker.require_owned()?.into(),
                    gas_account: v.gas_account.require_owned()?.into(),
                })
            }
            update_payload::Payload::GasRewardsUpdate(v) => {
                Self::GASRewards(super::types::GASRewards {
                    baker:              v.baker.require_owned()?.into(),
                    finalization_proof: v.finalization_proof.require_owned()?.into(),
                    account_creation:   v.account_creation.require_owned()?.into(),
                    chain_update:       v.chain_update.require_owned()?.into(),
                })
            }
            update_payload::Payload::BakerStakeThresholdUpdate(v) => {
                Self::BakerStakeThreshold(super::types::BakerParameters {
                    minimum_threshold_for_baking: v.baker_stake_threshold.require_owned()?.into(),
                })
            }
            update_payload::Payload::RootUpdate(v) => {
                Self::Root(match v.update_type.require_owned()? {
                    update_payload::root_update_payload::UpdateType::RootKeysUpdate(u) => {
                        super::types::RootUpdate::RootKeysUpdate(
                            super::types::HigherLevelAccessStructure {
                                keys:      u
                                    .keys
                                    .into_iter()
                                    .map(TryInto::try_into)
                                    .collect::<Result<_, tonic::Status>>()?,
                                threshold: u.threshold.require_owned()?.try_into()?,
                                _phantom:  PhantomData,
                            },
                        )
                    }
                    update_payload::root_update_payload::UpdateType::Level1KeysUpdate(u) => {
                        super::types::RootUpdate::Level1KeysUpdate(
                            super::types::HigherLevelAccessStructure {
                                keys:      u
                                    .keys
                                    .into_iter()
                                    .map(TryInto::try_into)
                                    .collect::<Result<_, tonic::Status>>()?,
                                threshold: u.threshold.require_owned()?.try_into()?,
                                _phantom:  PhantomData,
                            },
                        )
                    }
                    update_payload::root_update_payload::UpdateType::Level2KeysUpdateV0(u) => {
                        super::types::RootUpdate::Level2KeysUpdate(Box::new(u.try_into()?))
                    }
                    update_payload::root_update_payload::UpdateType::Level2KeysUpdateV1(u) => {
                        super::types::RootUpdate::Level2KeysUpdateV1(Box::new(u.try_into()?))
                    }
                })
            }
            update_payload::Payload::Level1RootUpdate(v) => {
                Self::Level1(match v.update_type.require_owned()? {
                    update_payload::level1_update_payload::UpdateType::Level1KeysUpdate(u) => {
                        super::types::Level1Update::Level1KeysUpdate(
                            super::types::HigherLevelAccessStructure {
                                keys:      u
                                    .keys
                                    .into_iter()
                                    .map(TryInto::try_into)
                                    .collect::<Result<_, tonic::Status>>()?,
                                threshold: u.threshold.require_owned()?.try_into()?,
                                _phantom:  PhantomData,
                            },
                        )
                    }
                    update_payload::level1_update_payload::UpdateType::Level2KeysUpdateV0(u) => {
                        super::types::Level1Update::Level2KeysUpdate(Box::new(u.try_into()?))
                    }
                    update_payload::level1_update_payload::UpdateType::Level2KeysUpdateV1(u) => {
                        super::types::Level1Update::Level2KeysUpdateV1(Box::new(u.try_into()?))
                    }
                })
            }
            update_payload::Payload::AddAnonymityRevokerUpdate(v) => {
                Self::AddAnonymityRevoker(Box::new(v.try_into()?))
            }
            update_payload::Payload::AddIdentityProviderUpdate(v) => {
                Self::AddIdentityProvider(Box::new(v.try_into()?))
            }
            update_payload::Payload::CooldownParametersCpv1Update(v) => {
                Self::CooldownParametersCPV1(super::types::CooldownParameters {
                    pool_owner_cooldown: v.pool_owner_cooldown.require_owned()?.into(),
                    delegator_cooldown:  v.delegator_cooldown.require_owned()?.into(),
                })
            }
            update_payload::Payload::PoolParametersCpv1Update(v) => {
                let commission_bounds = v.commission_bounds.require_owned()?;
                let leverage_bound = v.leverage_bound.require_owned()?.value.require_owned()?;
                Self::PoolParametersCPV1(super::types::PoolParameters {
                    passive_finalization_commission: v
                        .passive_finalization_commission
                        .require_owned()?
                        .into(),
                    passive_baking_commission:       v
                        .passive_baking_commission
                        .require_owned()?
                        .into(),
                    passive_transaction_commission:  v
                        .passive_transaction_commission
                        .require_owned()?
                        .into(),
                    commission_bounds:               super::types::CommissionRanges {
                        finalization: commission_bounds.finalization.require_owned()?.try_into()?,
                        baking:       commission_bounds.baking.require_owned()?.try_into()?,
                        transaction:  commission_bounds.transaction.require_owned()?.try_into()?,
                    },
                    minimum_equity_capital:          v
                        .minimum_equity_capital
                        .require_owned()?
                        .into(),
                    capital_bound:                   v.capital_bound.require_owned()?.try_into()?,
                    leverage_bound:                  super::types::LeverageFactor {
                        numerator:   leverage_bound.numerator,
                        denominator: leverage_bound.denominator,
                    },
                })
            }
            update_payload::Payload::TimeParametersCpv1Update(v) => {
                Self::TimeParametersCPV1(super::types::TimeParameters {
                    reward_period_length: super::types::RewardPeriodLength {
                        reward_period_epochs: super::types::Epoch {
                            epoch: v
                                .reward_period_length
                                .require_owned()?
                                .value
                                .require_owned()?
                                .value,
                        },
                    },
                    mint_per_payday:      v.mint_per_payday.require_owned()?.try_into()?,
                })
            }
            update_payload::Payload::MintDistributionCpv1Update(v) => {
                Self::MintDistributionCPV1(super::types::MintDistributionV1 {
                    baking_reward:       v.baking_reward.require_owned()?.into(),
                    finalization_reward: v.finalization_reward.require_owned()?.into(),
                })
            }
        })
    }
}

impl TryFrom<CapitalBound> for super::types::CapitalBound {
    type Error = tonic::Status;

    fn try_from(value: CapitalBound) -> Result<Self, Self::Error> {
        Ok(Self {
            bound: value.value.require_owned()?.into(),
        })
    }
}

impl TryFrom<InclusiveRangeAmountFraction>
    for super::types::InclusiveRange<super::types::AmountFraction>
{
    type Error = tonic::Status;

    fn try_from(value: InclusiveRangeAmountFraction) -> Result<Self, Self::Error> {
        Ok(Self {
            min: value.min.require_owned()?.into(),
            max: value.max.require_owned()?.into(),
        })
    }
}

impl From<DurationSeconds> for super::types::DurationSeconds {
    fn from(value: DurationSeconds) -> Self {
        Self {
            seconds: value.value,
        }
    }
}

impl TryFrom<IpInfo> for id::types::IpInfo<IpPairing> {
    type Error = tonic::Status;

    fn try_from(value: IpInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            ip_identity:       id::types::IpIdentity(value.identity.require_owned()?.value),
            ip_description:    value.description.require_owned()?.into(),
            ip_verify_key:     value.verify_key.require_owned()?.try_into()?,
            ip_cdi_verify_key: value.cdi_verify_key.require_owned()?.try_into()?,
        })
    }
}

impl TryFrom<ArInfo> for id::types::ArInfo<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: ArInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            ar_identity:    id::types::ArIdentity::try_from(value.identity.require_owned()?.value)
                .map_err(|e| tonic::Status::internal(e))?,
            ar_description: value.description.require_owned()?.into(),
            ar_public_key:  value.public_key.require_owned()?.try_into()?,
        })
    }
}

impl From<Description> for id::types::Description {
    fn from(value: Description) -> Self {
        Self {
            name:        value.name,
            url:         value.url,
            description: value.description,
        }
    }
}

impl TryFrom<AuthorizationsV0> for super::types::AuthorizationsV0 {
    type Error = tonic::Status;

    fn try_from(value: AuthorizationsV0) -> Result<Self, Self::Error> {
        Ok(Self {
            keys: value
                .keys
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, tonic::Status>>()?,
            emergency: value.emergency.require_owned()?.try_into()?,
            protocol: value.protocol.require_owned()?.try_into()?,
            election_difficulty: value
                .parameter_election_difficulty
                .require_owned()?
                .try_into()?,
            euro_per_energy: value
                .parameter_euro_per_energy
                .require_owned()?
                .try_into()?,
            micro_gtu_per_euro: value
                .parameter_micro_ccd_per_euro
                .require_owned()?
                .try_into()?,
            foundation_account: value
                .parameter_foundation_account
                .require_owned()?
                .try_into()?,
            mint_distribution: value
                .parameter_mint_distribution
                .require_owned()?
                .try_into()?,
            transaction_fee_distribution: value
                .parameter_transaction_fee_distribution
                .require_owned()?
                .try_into()?,
            param_gas_rewards: value.parameter_gas_rewards.require_owned()?.try_into()?,
            pool_parameters: value.pool_parameters.require_owned()?.try_into()?,
            add_anonymity_revoker: value.add_anonymity_revoker.require_owned()?.try_into()?,
            add_identity_provider: value.add_identity_provider.require_owned()?.try_into()?,
        })
    }
}

impl TryFrom<AuthorizationsV1> for super::types::AuthorizationsV1 {
    type Error = tonic::Status;

    fn try_from(value: AuthorizationsV1) -> Result<Self, Self::Error> {
        Ok(Self {
            v0:                  value.v0.require_owned()?.try_into()?,
            cooldown_parameters: value.parameter_cooldown.require_owned()?.try_into()?,
            time_parameters:     value.parameter_time.require_owned()?.try_into()?,
        })
    }
}

impl TryFrom<AccessStructure> for super::types::AccessStructure {
    type Error = tonic::Status;

    fn try_from(value: AccessStructure) -> Result<Self, Self::Error> {
        let authorized_keys = value
            .access_public_keys
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, tonic::Status>>()?;
        let threshold = value.access_threshold.require_owned()?.try_into()?;
        Ok(Self {
            authorized_keys,
            threshold,
        })
    }
}

impl TryFrom<UpdateKeysIndex> for super::types::UpdateKeysIndex {
    type Error = tonic::Status;

    fn try_from(value: UpdateKeysIndex) -> Result<Self, Self::Error> {
        Ok(Self {
            index: value.value.try_into().map_err(|_| {
                tonic::Status::internal("Invalid update keys index: could not fit into a u16.")
            })?,
        })
    }
}

impl TryFrom<UpdateKeysThreshold> for super::types::UpdateKeysThreshold {
    type Error = tonic::Status;

    fn try_from(value: UpdateKeysThreshold) -> Result<Self, Self::Error> {
        Ok(Self {
            threshold: value
                .value
                .try_into()
                .map_err(|_| tonic::Status::internal("Threshold could not fit into a u16."))?,
        })
    }
}

impl TryFrom<MintRate> for super::types::MintRate {
    type Error = tonic::Status;

    fn try_from(value: MintRate) -> Result<Self, Self::Error> {
        Ok(Self {
            mantissa: value.mantissa,
            exponent: value.exponent.try_into().map_err(|_| {
                tonic::Status::internal(
                    "Invalid exponent value. Could not be represented in an u8.",
                )
            })?,
        })
    }
}

impl From<TransactionTime> for super::super::common::types::TransactionTime {
    fn from(value: TransactionTime) -> Self {
        Self {
            seconds: value.value,
        }
    }
}

impl From<CredentialType> for super::types::CredentialType {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Initial => Self::Initial,
            CredentialType::Normal => Self::Normal,
        }
    }
}

impl TryFrom<AccountTransactionEffects> for super::types::AccountTransactionEffects {
    type Error = tonic::Status;

    fn try_from(value: AccountTransactionEffects) -> Result<Self, Self::Error> {
        match value.effect.require_owned()? {
            account_transaction_effects::Effect::None(n) => Ok(Self::None {
                transaction_type: {
                    match n.transaction_type {
                        None => None,
                        Some(tt) => Some(tt.try_into()?),
                    }
                },
                reject_reason:    n.reject_reason.require_owned()?.try_into()?,
            }),
            account_transaction_effects::Effect::AccountTransfer(at) => {
                let amount = at.amount.require_owned()?.into();
                let to = at.receiver.require_owned()?.try_into()?;
                match at.memo {
                    None => Ok(Self::AccountTransfer { amount, to }),
                    Some(memo) => Ok(Self::AccountTransferWithMemo {
                        amount,
                        to,
                        memo: memo.try_into()?,
                    }),
                }
            }
            account_transaction_effects::Effect::ModuleDeployed(module_ref) => {
                Ok(Self::ModuleDeployed {
                    module_ref: module_ref.try_into()?,
                })
            }
            account_transaction_effects::Effect::ContractInitialized(cie) => {
                Ok(Self::ContractInitialized {
                    data: super::types::ContractInitializedEvent {
                        contract_version: cie.contract_version().into(),
                        origin_ref:       cie.origin_ref.require_owned()?.try_into()?,
                        address:          cie.address.require_owned()?.into(),
                        amount:           cie.amount.require_owned()?.into(),
                        init_name:        cie.init_name.require_owned()?.try_into()?,
                        events:           cie.events.into_iter().map(Into::into).collect(),
                    },
                })
            }
            account_transaction_effects::Effect::ContractUpdateIssued(cui) => {
                let effects = cui
                    .effects
                    .into_iter()
                    .map(|e| {
                        Ok(match e.element.require_owned()? {
                            contract_trace_element::Element::Updated(u) => {
                                super::types::ContractTraceElement::Updated {
                                    data: u.try_into()?,
                                }
                            }
                            contract_trace_element::Element::Transferred(t) => {
                                super::types::ContractTraceElement::Transferred {
                                    from:   t.sender.require_owned()?.into(),
                                    amount: t.amount.require_owned()?.into(),
                                    to:     t.receiver.require_owned()?.try_into()?,
                                }
                            }
                            contract_trace_element::Element::Interrupted(i) => {
                                super::types::ContractTraceElement::Interrupted {
                                    address: i.address.require_owned()?.into(),
                                    events:  i.events.into_iter().map(Into::into).collect(),
                                }
                            }
                            contract_trace_element::Element::Resumed(r) => {
                                super::types::ContractTraceElement::Resumed {
                                    address: r.address.require_owned()?.into(),
                                    success: r.success,
                                }
                            }
                        })
                    })
                    .collect::<Result<_, tonic::Status>>()?;
                Ok(Self::ContractUpdateIssued { effects })
            }
            account_transaction_effects::Effect::BakerAdded(ba) => {
                let baker_added_event = super::types::BakerAddedEvent {
                    keys_event:       ba.keys_event.require_owned()?.try_into()?,
                    stake:            ba.stake.require_owned()?.into(),
                    restake_earnings: ba.restake_earnings,
                };
                Ok(Self::BakerAdded {
                    data: Box::new(baker_added_event),
                })
            }
            account_transaction_effects::Effect::BakerRemoved(baker_id) => Ok(Self::BakerRemoved {
                baker_id: baker_id.into(),
            }),
            account_transaction_effects::Effect::BakerStakeUpdated(bsu) => {
                let data = match bsu.update {
                    None => None,
                    Some(d) => Some(super::types::BakerStakeUpdatedData {
                        baker_id:  d.baker_id.require_owned()?.into(),
                        new_stake: d.new_stake.require_owned()?.into(),
                        increased: d.increased,
                    }),
                };
                Ok(Self::BakerStakeUpdated { data })
            }
            account_transaction_effects::Effect::BakerRestakeEarningsUpdated(breu) => {
                Ok(Self::BakerRestakeEarningsUpdated {
                    baker_id:         breu.baker_id.require_owned()?.into(),
                    restake_earnings: breu.restake_earnings,
                })
            }
            account_transaction_effects::Effect::BakerKeysUpdated(keys_event) => {
                Ok(Self::BakerKeysUpdated {
                    data: Box::new(keys_event.try_into()?),
                })
            }
            account_transaction_effects::Effect::EncryptedAmountTransferred(eat) => {
                let removed = Box::new(eat.removed.require_owned()?.try_into()?);
                let added = Box::new(eat.added.require_owned()?.try_into()?);
                match eat.memo {
                    None => Ok(Self::EncryptedAmountTransferred { removed, added }),
                    Some(memo) => Ok(Self::EncryptedAmountTransferredWithMemo {
                        removed,
                        added,
                        memo: memo.try_into()?,
                    }),
                }
            }
            account_transaction_effects::Effect::TransferredToEncrypted(esaae) => {
                Ok(Self::TransferredToEncrypted {
                    data: Box::new(super::types::EncryptedSelfAmountAddedEvent {
                        account:    esaae.account.require_owned()?.try_into()?,
                        new_amount: esaae.new_amount.require_owned()?.try_into()?,
                        amount:     esaae.amount.require_owned()?.into(),
                    }),
                })
            }
            account_transaction_effects::Effect::TransferredToPublic(ttp) => {
                Ok(Self::TransferredToPublic {
                    removed: Box::new(ttp.removed.require_owned()?.try_into()?),
                    amount:  ttp.amount.require_owned()?.into(),
                })
            }
            account_transaction_effects::Effect::TransferredWithSchedule(tws) => {
                let to = tws.receiver.require_owned()?.try_into()?;
                let amount = tws
                    .amount
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, tonic::Status>>()?;
                match tws.memo {
                    None => Ok(Self::TransferredWithSchedule { to, amount }),
                    Some(memo) => Ok(Self::TransferredWithScheduleAndMemo {
                        to,
                        amount,
                        memo: memo.try_into()?,
                    }),
                }
            }
            account_transaction_effects::Effect::CredentialKeysUpdated(cri) => {
                Ok(Self::CredentialKeysUpdated {
                    cred_id: cri.try_into()?,
                })
            }
            account_transaction_effects::Effect::CredentialsUpdated(cu) => {
                Ok(Self::CredentialsUpdated {
                    new_cred_ids:     cu
                        .new_cred_ids
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, tonic::Status>>()?,
                    removed_cred_ids: cu
                        .removed_cred_ids
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, tonic::Status>>()?,
                    new_threshold:    cu.new_threshold.require_owned()?.try_into()?,
                })
            }
            account_transaction_effects::Effect::DataRegistered(rd) => Ok(Self::DataRegistered {
                data: rd.try_into()?,
            }),
            account_transaction_effects::Effect::BakerConfigured(bc) => Ok(Self::BakerConfigured {
                data: bc
                    .events
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, tonic::Status>>()?,
            }),
            account_transaction_effects::Effect::DelegationConfigured(dc) => {
                Ok(Self::DelegationConfigured {
                    data: dc
                        .events
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, tonic::Status>>()?,
                })
            }
        }
    }
}

impl TryFrom<DelegationEvent> for super::types::DelegationEvent {
    type Error = tonic::Status;

    fn try_from(value: DelegationEvent) -> Result<Self, Self::Error> {
        Ok(match value.event.require_owned()? {
            delegation_event::Event::DelegationStakeIncreased(v) => {
                Self::DelegationStakeIncreased {
                    delegator_id: v.delegator_id.require_owned()?.try_into()?,
                    new_stake:    v.new_stake.require_owned()?.into(),
                }
            }
            delegation_event::Event::DelegationStakeDecreased(v) => {
                Self::DelegationStakeDecreased {
                    delegator_id: v.delegator_id.require_owned()?.try_into()?,
                    new_stake:    v.new_stake.require_owned()?.into(),
                }
            }
            delegation_event::Event::DelegationSetRestakeEarnings(v) => {
                Self::DelegationSetRestakeEarnings {
                    delegator_id:     v.delegator_id.require_owned()?.try_into()?,
                    restake_earnings: v.restake_earnings,
                }
            }
            delegation_event::Event::DelegationSetDelegationTarget(v) => {
                Self::DelegationSetDelegationTarget {
                    delegator_id:      v.delegator_id.require_owned()?.try_into()?,
                    delegation_target: v.delegation_target.require_owned()?.try_into()?,
                }
            }
            delegation_event::Event::DelegationAdded(v) => Self::DelegationAdded {
                delegator_id: v.try_into()?,
            },
            delegation_event::Event::DelegationRemoved(v) => Self::DelegationRemoved {
                delegator_id: v.try_into()?,
            },
        })
    }
}

impl TryFrom<DelegatorId> for super::types::DelegatorId {
    type Error = tonic::Status;

    fn try_from(value: DelegatorId) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id.require_owned()?.into(),
        })
    }
}

impl TryFrom<BakerEvent> for super::types::BakerEvent {
    type Error = tonic::Status;

    fn try_from(value: BakerEvent) -> Result<Self, Self::Error> {
        Ok(match value.event.require_owned()? {
            baker_event::Event::BakerAdded(v) => Self::BakerAdded {
                data: Box::new(super::types::BakerAddedEvent {
                    keys_event:       v.keys_event.require_owned()?.try_into()?,
                    stake:            v.stake.require_owned()?.into(),
                    restake_earnings: v.restake_earnings,
                }),
            },
            baker_event::Event::BakerRemoved(v) => Self::BakerRemoved { baker_id: v.into() },
            baker_event::Event::BakerStakeIncreased(v) => Self::BakerStakeIncreased {
                baker_id:  v.baker_id.require_owned()?.into(),
                new_stake: v.new_stake.require_owned()?.into(),
            },
            baker_event::Event::BakerStakeDecreased(v) => Self::BakerStakeDecreased {
                baker_id:  v.baker_id.require_owned()?.into(),
                new_stake: v.new_stake.require_owned()?.into(),
            },
            baker_event::Event::BakerRestakeEarningsUpdated(v) => {
                Self::BakerRestakeEarningsUpdated {
                    baker_id:         v.baker_id.require_owned()?.into(),
                    restake_earnings: v.restake_earnings,
                }
            }
            baker_event::Event::BakerKeysUpdated(v) => Self::BakerKeysUpdated {
                data: Box::new(v.try_into()?),
            },
            baker_event::Event::BakerSetOpenStatus(v) => {
                let open_status = v.open_status().into();
                Self::BakerSetOpenStatus {
                    baker_id: v.baker_id.require_owned()?.into(),
                    open_status,
                }
            }
            baker_event::Event::BakerSetMetadataUrl(v) => Self::BakerSetMetadataURL {
                baker_id:     v.baker_id.require_owned()?.into(),
                metadata_url: v.url.try_into().map_err(|e| {
                    tonic::Status::invalid_argument(format!("Invalid argument: {}", e))
                })?,
            },
            baker_event::Event::BakerSetTransactionFeeCommission(v) => {
                Self::BakerSetTransactionFeeCommission {
                    baker_id:                   v.baker_id.require_owned()?.into(),
                    transaction_fee_commission: v
                        .transaction_fee_commission
                        .require_owned()?
                        .into(),
                }
            }
            baker_event::Event::BakerSetBakingRewardCommission(v) => {
                Self::BakerSetBakingRewardCommission {
                    baker_id:                 v.baker_id.require_owned()?.into(),
                    baking_reward_commission: v.baking_reward_commission.require_owned()?.into(),
                }
            }
            baker_event::Event::BakerSetFinalizationRewardCommission(v) => {
                Self::BakerSetFinalizationRewardCommission {
                    baker_id: v.baker_id.require_owned()?.into(),
                    finalization_reward_commission: v
                        .finalization_reward_commission
                        .require_owned()?
                        .into(),
                }
            }
        })
    }
}

impl TryFrom<RegisteredData> for super::types::RegisteredData {
    type Error = tonic::Status;

    fn try_from(value: RegisteredData) -> Result<Self, Self::Error> {
        Ok(value
            .value
            .try_into()
            .map_err(|e| tonic::Status::invalid_argument(format!("{}", e)))?)
    }
}

impl TryFrom<NewRelease>
    for (
        super::super::common::types::Timestamp,
        super::super::common::types::Amount,
    )
{
    type Error = tonic::Status;

    fn try_from(value: NewRelease) -> Result<Self, Self::Error> {
        let timestamp = super::super::common::types::Timestamp {
            millis: value.timestamp.require_owned()?.value,
        };
        Ok((timestamp, value.amount.require_owned()?.into()))
    }
}

impl TryFrom<EncryptedAmountRemovedEvent> for super::types::EncryptedAmountRemovedEvent {
    type Error = tonic::Status;

    fn try_from(value: EncryptedAmountRemovedEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            account:      value.account.require_owned()?.try_into()?,
            new_amount:   value.new_amount.require_owned()?.try_into()?,
            input_amount: value.input_amount.require_owned()?.try_into()?,
            up_to_index:  encrypted_transfers::types::EncryptedAmountAggIndex {
                index: value.up_to_index,
            },
        })
    }
}

impl TryFrom<NewEncryptedAmountEvent> for super::types::NewEncryptedAmountEvent {
    type Error = tonic::Status;

    fn try_from(value: NewEncryptedAmountEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            receiver:         value.receiver.require_owned()?.try_into()?,
            new_index:        encrypted_transfers::types::EncryptedAmountIndex {
                index: value.new_index,
            },
            encrypted_amount: value.encrypted_amount.require_owned()?.try_into()?,
        })
    }
}

impl TryFrom<Memo> for super::types::Memo {
    type Error = tonic::Status;

    fn try_from(value: Memo) -> Result<Self, Self::Error> {
        value
            .value
            .try_into()
            .map_err(|_| tonic::Status::invalid_argument("Memo is invalid because it is too big."))
    }
}
impl TryFrom<BakerKeysEvent> for super::types::BakerKeysEvent {
    type Error = tonic::Status;

    fn try_from(value: BakerKeysEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            baker_id:        value.baker_id.require_owned()?.into(),
            account:         value.account.require_owned()?.try_into()?,
            sign_key:        value.sign_key.require_owned()?.try_into()?,
            election_key:    value.election_key.require_owned()?.try_into()?,
            aggregation_key: value.aggregation_key.require_owned()?.try_into()?,
        })
    }
}

impl TryFrom<InstanceUpdatedEvent> for super::types::InstanceUpdatedEvent {
    type Error = tonic::Status;

    fn try_from(value: InstanceUpdatedEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_version: value.contract_version().into(),
            address:          value.address.require_owned()?.into(),
            instigator:       value.instigator.require_owned()?.try_into()?,
            amount:           value.amount.require_owned()?.into(),
            message:          value.parameter.require_owned()?.into(),
            receive_name:     value.receive_name.require_owned()?.try_into()?,
            events:           value.events.into_iter().map(Into::into).collect(),
        })
    }
}

impl From<ContractVersion> for super::types::smart_contracts::WasmVersion {
    fn from(value: ContractVersion) -> Self {
        match value {
            ContractVersion::V0 => Self::V0,
            ContractVersion::V1 => Self::V1,
        }
    }
}

impl From<ContractEvent> for super::types::smart_contracts::ContractEvent {
    fn from(value: ContractEvent) -> Self { value.value.into() }
}

impl TryFrom<RejectReason> for super::types::RejectReason {
    type Error = tonic::Status;

    fn try_from(value: RejectReason) -> Result<Self, Self::Error> {
        Ok(match value.reason.require_owned()? {
            reject_reason::Reason::ModuleNotWf(_) => Self::ModuleNotWF,
            reject_reason::Reason::ModuleHashAlreadyExists(v) => Self::ModuleHashAlreadyExists {
                contents: v.try_into()?,
            },
            reject_reason::Reason::InvalidAccountReference(v) => Self::InvalidAccountReference {
                contents: v.try_into()?,
            },
            reject_reason::Reason::InvalidInitMethod(v) => Self::InvalidInitMethod {
                contents: (
                    v.module_ref.require_owned()?.try_into()?,
                    v.init_name.require_owned()?.try_into()?,
                ),
            },
            reject_reason::Reason::InvalidReceiveMethod(v) => Self::InvalidReceiveMethod {
                contents: (
                    v.module_ref.require_owned()?.try_into()?,
                    v.receive_name.require_owned()?.try_into()?,
                ),
            },
            reject_reason::Reason::InvalidModuleReference(v) => Self::InvalidModuleReference {
                contents: v.try_into()?,
            },
            reject_reason::Reason::InvalidContractAddress(v) => {
                Self::InvalidContractAddress { contents: v.into() }
            }
            reject_reason::Reason::RuntimeFailure(_) => Self::RuntimeFailure,
            reject_reason::Reason::AmountTooLarge(v) => Self::AmountTooLarge {
                contents: (
                    v.address.require_owned()?.try_into()?,
                    v.amount.require_owned()?.into(),
                ),
            },
            reject_reason::Reason::SerializationFailure(_) => Self::SerializationFailure,
            reject_reason::Reason::OutOfEnergy(_) => Self::OutOfEnergy,
            reject_reason::Reason::RejectedInit(v) => Self::RejectedInit {
                reject_reason: v.reject_reason,
            },
            reject_reason::Reason::RejectedReceive(v) => Self::RejectedReceive {
                reject_reason:    v.reject_reason,
                contract_address: v.contract_address.require_owned()?.into(),
                receive_name:     v.receive_name.require_owned()?.try_into()?,
                parameter:        v.parameter.require_owned()?.into(),
            },
            reject_reason::Reason::InvalidProof(_) => Self::InvalidProof,
            reject_reason::Reason::AlreadyABaker(v) => Self::AlreadyABaker { contents: v.into() },
            reject_reason::Reason::NotABaker(v) => Self::NotABaker {
                contents: v.try_into()?,
            },
            reject_reason::Reason::InsufficientBalanceForBakerStake(_) => {
                Self::InsufficientBalanceForBakerStake
            }
            reject_reason::Reason::StakeUnderMinimumThresholdForBaking(_) => {
                Self::StakeUnderMinimumThresholdForBaking
            }
            reject_reason::Reason::BakerInCooldown(_) => Self::BakerInCooldown,
            reject_reason::Reason::DuplicateAggregationKey(v) => Self::DuplicateAggregationKey {
                contents: Box::new(v.try_into()?),
            },
            reject_reason::Reason::NonExistentCredentialId(_) => Self::NonExistentCredentialID,
            reject_reason::Reason::KeyIndexAlreadyInUse(_) => Self::KeyIndexAlreadyInUse,
            reject_reason::Reason::InvalidAccountThreshold(_) => Self::InvalidAccountThreshold,
            reject_reason::Reason::InvalidCredentialKeySignThreshold(_) => {
                Self::InvalidCredentialKeySignThreshold
            }
            reject_reason::Reason::InvalidEncryptedAmountTransferProof(_) => {
                Self::InvalidEncryptedAmountTransferProof
            }
            reject_reason::Reason::InvalidTransferToPublicProof(_) => {
                Self::InvalidTransferToPublicProof
            }
            reject_reason::Reason::EncryptedAmountSelfTransfer(v) => {
                Self::EncryptedAmountSelfTransfer {
                    contents: v.try_into()?,
                }
            }
            reject_reason::Reason::InvalidIndexOnEncryptedTransfer(_) => {
                Self::InvalidIndexOnEncryptedTransfer
            }
            reject_reason::Reason::ZeroScheduledAmount(_) => Self::ZeroScheduledAmount,
            reject_reason::Reason::NonIncreasingSchedule(_) => Self::NonIncreasingSchedule,
            reject_reason::Reason::FirstScheduledReleaseExpired(_) => {
                Self::FirstScheduledReleaseExpired
            }
            reject_reason::Reason::ScheduledSelfTransfer(v) => Self::ScheduledSelfTransfer {
                contents: v.try_into()?,
            },
            reject_reason::Reason::InvalidCredentials(_) => Self::InvalidCredentials,
            reject_reason::Reason::DuplicateCredIds(v) => Self::DuplicateCredIDs {
                contents: v
                    .ids
                    .into_iter()
                    .map(TryFrom::try_from)
                    .collect::<Result<_, tonic::Status>>()?,
            },
            reject_reason::Reason::NonExistentCredIds(v) => Self::NonExistentCredIDs {
                contents: v
                    .ids
                    .into_iter()
                    .map(TryFrom::try_from)
                    .collect::<Result<_, tonic::Status>>()?,
            },
            reject_reason::Reason::RemoveFirstCredential(_) => Self::RemoveFirstCredential,
            reject_reason::Reason::CredentialHolderDidNotSign(_) => {
                Self::CredentialHolderDidNotSign
            }
            reject_reason::Reason::NotAllowedMultipleCredentials(_) => {
                Self::NotAllowedMultipleCredentials
            }
            reject_reason::Reason::NotAllowedToReceiveEncrypted(_) => {
                Self::NotAllowedToReceiveEncrypted
            }
            reject_reason::Reason::NotAllowedToHandleEncrypted(_) => {
                Self::NotAllowedToHandleEncrypted
            }
            reject_reason::Reason::MissingBakerAddParameters(_) => Self::MissingBakerAddParameters,
            reject_reason::Reason::FinalizationRewardCommissionNotInRange(_) => {
                Self::FinalizationRewardCommissionNotInRange
            }
            reject_reason::Reason::BakingRewardCommissionNotInRange(_) => {
                Self::BakingRewardCommissionNotInRange
            }
            reject_reason::Reason::TransactionFeeCommissionNotInRange(_) => {
                Self::TransactionFeeCommissionNotInRange
            }
            reject_reason::Reason::AlreadyADelegator(_) => Self::AlreadyADelegator,
            reject_reason::Reason::InsufficientBalanceForDelegationStake(_) => {
                Self::InsufficientBalanceForDelegationStake
            }
            reject_reason::Reason::MissingDelegationAddParameters(_) => {
                Self::MissingDelegationAddParameters
            }
            reject_reason::Reason::InsufficientDelegationStake(_) => {
                Self::InsufficientDelegationStake
            }
            reject_reason::Reason::DelegatorInCooldown(_) => Self::DelegatorInCooldown,
            reject_reason::Reason::NotADelegator(v) => Self::NotADelegator {
                address: v.try_into()?,
            },
            reject_reason::Reason::DelegationTargetNotABaker(v) => {
                Self::DelegationTargetNotABaker { target: v.into() }
            }
            reject_reason::Reason::StakeOverMaximumThresholdForPool(_) => {
                Self::StakeOverMaximumThresholdForPool
            }
            reject_reason::Reason::PoolWouldBecomeOverDelegated(_) => {
                Self::PoolWouldBecomeOverDelegated
            }
            reject_reason::Reason::PoolClosed(_) => Self::PoolClosed,
        })
    }
}

impl TryFrom<NextAccountSequenceNumber> for super::types::queries::AccountNonceResponse {
    type Error = tonic::Status;

    fn try_from(value: NextAccountSequenceNumber) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce:     value.sequence_number.require_owned()?.into(),
            all_final: value.all_final,
        })
    }
}

impl TryFrom<i32> for super::types::TransactionType {
    type Error = tonic::Status;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::DeployModule,
            1 => Self::InitContract,
            2 => Self::Update,
            3 => Self::Transfer,
            4 => Self::AddBaker,
            5 => Self::RemoveBaker,
            6 => Self::UpdateBakerStake,
            7 => Self::UpdateBakerRestakeEarnings,
            8 => Self::UpdateBakerKeys,
            9 => Self::UpdateCredentialKeys,
            10 => Self::EncryptedAmountTransfer,
            11 => Self::TransferToEncrypted,
            12 => Self::TransferToPublic,
            13 => Self::TransferWithSchedule,
            14 => Self::UpdateCredentials,
            15 => Self::RegisterData,
            16 => Self::TransferWithMemo,
            17 => Self::EncryptedAmountTransferWithMemo,
            18 => Self::TransferWithScheduleAndMemo,
            19 => Self::ConfigureBaker,
            20 => Self::ConfigureDelegation,
            n => {
                return Err(tonic::Status::invalid_argument(format!(
                    "{} is not a valid index for a TransactionType",
                    n
                )))
            }
        })
    }
}

impl From<block_item_summary::TransactionIndex> for super::types::TransactionIndex {
    fn from(value: block_item_summary::TransactionIndex) -> Self { Self { index: value.value } }
}

impl From<Energy> for super::types::Energy {
    fn from(value: Energy) -> Self {
        Self {
            energy: value.value,
        }
    }
}
impl TryFrom<ConsensusInfo> for super::types::queries::ConsensusInfo {
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
