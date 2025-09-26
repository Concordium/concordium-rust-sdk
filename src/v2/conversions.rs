//! Helpers and trait implementations to convert from proto generated types to
//! their Rust equivalents.

use super::{generated::*, upward::Upward, Require};
use crate::types::{
    queries::{ConcordiumBFTDetails, ProtocolVersionInt},
    AccountReleaseSchedule, ActiveBakerPoolStatus, UpdateKeysCollectionSkeleton,
};
use chrono::TimeZone;
use concordium_base::{
    base,
    common::{Deserial, Versioned, VERSION_0},
    id::{
        constants::{ArCurve, AttributeKind, IpPairing},
        types::{
            AccountCredentialWithoutProofs, CredentialDeploymentValues,
            InitialCredentialDeploymentValues,
        },
    },
    smart_contracts::WasmVersionInt,
    updates,
};
use cooldown::CooldownStatus;
use std::collections::{BTreeMap, BTreeSet};

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

/// Convert from the 0-based protobuf representation to the 1-based internal
/// representation of a [ProtocolVersionInt].
fn protocol_version_int_from_enum(tag_number: i32) -> Result<ProtocolVersionInt, tonic::Status> {
    if tag_number < 0 {
        Err(tonic::Status::internal(format!(
            "Invalid protocol version: {tag_number}"
        )))
    } else {
        Ok(ProtocolVersionInt(tag_number as u64 + 1))
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

impl From<super::ContractAddress> for ContractAddress {
    fn from(value: super::ContractAddress) -> Self {
        Self {
            index: value.index,
            subindex: value.subindex,
        }
    }
}

impl TryFrom<Address> for super::types::Address {
    type Error = tonic::Status;

    fn try_from(value: Address) -> Result<Self, Self::Error> {
        match value.r#type.require()? {
            address::Type::Account(acc) => Ok(Self::Account(acc.try_into()?)),
            address::Type::Contract(contr) => Ok(Self::Contract(contr.into())),
        }
    }
}

impl TryFrom<ModuleRef> for super::ModuleReference {
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

impl From<Slot> for super::types::Slot {
    fn from(value: Slot) -> Self {
        super::types::Slot { slot: value.value }
    }
}

impl TryFrom<VersionedModuleSource> for super::types::smart_contracts::WasmModule {
    type Error = tonic::Status;

    fn try_from(versioned_module: VersionedModuleSource) -> Result<Self, Self::Error> {
        use super::types::smart_contracts::WasmVersion;
        let module = match versioned_module.module.require()? {
            versioned_module_source::Module::V0(versioned_module_source::ModuleSourceV0 {
                value,
            }) => super::types::smart_contracts::WasmModule {
                version: WasmVersion::V0,
                source: value.into(),
            },
            versioned_module_source::Module::V1(versioned_module_source::ModuleSourceV1 {
                value,
            }) => super::types::smart_contracts::WasmModule {
                version: WasmVersion::V1,
                source: value.into(),
            },
        };
        Ok(module)
    }
}

impl TryFrom<Parameter> for super::types::smart_contracts::OwnedParameter {
    type Error = tonic::Status;

    fn try_from(value: Parameter) -> Result<Self, Self::Error> {
        Self::try_from(value.value).map_err(
            |e: concordium_base::smart_contracts::ExceedsParameterSize| {
                tonic::Status::invalid_argument(e.to_string())
            },
        )
    }
}

impl TryFrom<InstanceInfo> for super::InstanceInfo {
    type Error = tonic::Status;

    fn try_from(value: InstanceInfo) -> Result<Self, Self::Error> {
        match value.version.require()? {
            instance_info::Version::V0(v0) => Ok(Self::V0 {
                model: v0.model.require()?.value,
                owner: v0.owner.require()?.try_into()?,
                amount: v0.amount.require()?.into(),
                methods: v0
                    .methods
                    .into_iter()
                    .map(TryFrom::try_from)
                    .collect::<Result<_, tonic::Status>>()?,
                name: v0.name.require()?.try_into()?,
                source_module: v0.source_module.require()?.try_into()?,
            }),
            instance_info::Version::V1(v1) => Ok(Self::V1 {
                owner: v1.owner.require()?.try_into()?,
                amount: v1.amount.require()?.into(),
                methods: v1
                    .methods
                    .into_iter()
                    .map(TryFrom::try_from)
                    .collect::<Result<_, tonic::Status>>()?,
                name: v1.name.require()?.try_into()?,
                source_module: v1.source_module.require()?.try_into()?,
            }),
        }
    }
}

impl TryFrom<ReceiveName> for concordium_base::contracts_common::OwnedReceiveName {
    type Error = tonic::Status;

    fn try_from(value: ReceiveName) -> Result<Self, Self::Error> {
        match Self::new(value.value) {
            Ok(rn) => Ok(rn),
            Err(_) => Err(tonic::Status::internal("Unexpected receive name format.")),
        }
    }
}

impl TryFrom<InitName> for concordium_base::contracts_common::OwnedContractName {
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

impl TryFrom<AccountTransactionSignHash> for super::hashes::TransactionSignHash {
    type Error = tonic::Status;

    fn try_from(value: AccountTransactionSignHash) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal(
                "Unexpected account transaction sign hash format.",
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

impl TryFrom<StateHash> for super::hashes::StateHash {
    type Error = tonic::Status;

    fn try_from(value: StateHash) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal("Unexpected state hash format.")),
        }
    }
}

impl TryFrom<LeadershipElectionNonce> for super::hashes::LeadershipElectionNonce {
    type Error = tonic::Status;

    fn try_from(value: LeadershipElectionNonce) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal(
                "Unexpected leadership election nonce format.",
            )),
        }
    }
}

impl From<AbsoluteBlockHeight> for super::AbsoluteBlockHeight {
    fn from(abh: AbsoluteBlockHeight) -> Self {
        Self { height: abh.value }
    }
}

impl From<BlockHeight> for super::types::BlockHeight {
    fn from(bh: BlockHeight) -> Self {
        Self { height: bh.value }
    }
}

impl From<super::AbsoluteBlockHeight> for AbsoluteBlockHeight {
    fn from(abh: super::AbsoluteBlockHeight) -> Self {
        Self { value: abh.height }
    }
}

impl From<super::RelativeBlockHeight> for block_hash_input::RelativeHeight {
    fn from(relative_block_height: super::RelativeBlockHeight) -> Self {
        Self {
            genesis_index: Some(relative_block_height.genesis_index.into()),
            height: Some(relative_block_height.height.into()),
            restrict: relative_block_height.restrict,
        }
    }
}

impl From<super::types::BlockHeight> for BlockHeight {
    fn from(bh: super::types::BlockHeight) -> Self {
        Self { value: bh.height }
    }
}

impl From<SequenceNumber> for super::types::Nonce {
    fn from(n: SequenceNumber) -> Self {
        Self { nonce: n.value }
    }
}

impl From<Amount> for super::super::common::types::Amount {
    fn from(n: Amount) -> Self {
        Self { micro_ccd: n.value }
    }
}

impl From<AccountIndex> for super::types::AccountIndex {
    fn from(n: AccountIndex) -> Self {
        Self { index: n.value }
    }
}

impl From<super::types::AccountIndex> for AccountIndex {
    fn from(n: super::types::AccountIndex) -> Self {
        Self { value: n.index }
    }
}

impl From<BakerId> for super::types::BakerId {
    fn from(n: BakerId) -> Self {
        Self { id: n.value.into() }
    }
}

impl From<super::types::BakerId> for BakerId {
    fn from(n: super::types::BakerId) -> Self {
        Self { value: n.id.into() }
    }
}

impl TryFrom<DelegationTarget> for super::types::DelegationTarget {
    type Error = tonic::Status;

    fn try_from(dt: DelegationTarget) -> Result<Self, Self::Error> {
        match dt.target.require()? {
            delegation_target::Target::Passive(_) => Ok(Self::Passive),
            delegation_target::Target::Baker(bid) => Ok(Self::Baker {
                baker_id: bid.into(),
            }),
        }
    }
}

impl TryFrom<EncryptionKey> for crate::id::elgamal::PublicKey<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: EncryptionKey) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl TryFrom<ar_info::ArPublicKey> for crate::id::elgamal::PublicKey<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: ar_info::ArPublicKey) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
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

impl TryFrom<EncryptedAmount> for crate::encrypted_transfers::types::EncryptedAmount<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: EncryptedAmount) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
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
        let self_amount = value.self_amount.require()?.try_into()?;
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

impl TryFrom<Duration> for chrono::Duration {
    type Error = tonic::Status;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        chrono::TimeDelta::try_milliseconds(value.value as i64).ok_or_else(|| {
            tonic::Status::internal("Unexpected response for 'Duration': Duration out of bounds.")
        })
    }
}

impl From<Duration> for super::types::SlotDuration {
    fn from(value: Duration) -> Self {
        super::types::SlotDuration {
            millis: value.value,
        }
    }
}

impl From<Duration> for concordium_base::contracts_common::Duration {
    fn from(value: Duration) -> Self {
        concordium_base::contracts_common::Duration::from_millis(value.value)
    }
}

impl From<GenesisIndex> for super::types::GenesisIndex {
    fn from(value: GenesisIndex) -> Self {
        value.value.into()
    }
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
            ProtocolVersion::ProtocolVersion5 => super::types::ProtocolVersion::P5,
            ProtocolVersion::ProtocolVersion6 => super::types::ProtocolVersion::P6,
            ProtocolVersion::ProtocolVersion7 => super::types::ProtocolVersion::P7,
            ProtocolVersion::ProtocolVersion8 => super::types::ProtocolVersion::P8,
            ProtocolVersion::ProtocolVersion9 => super::types::ProtocolVersion::P9,
        }
    }
}

impl From<super::types::ProtocolVersion> for ProtocolVersion {
    fn from(value: super::types::ProtocolVersion) -> Self {
        match value {
            super::types::ProtocolVersion::P1 => ProtocolVersion::ProtocolVersion1,
            super::types::ProtocolVersion::P2 => ProtocolVersion::ProtocolVersion2,
            super::types::ProtocolVersion::P3 => ProtocolVersion::ProtocolVersion3,
            super::types::ProtocolVersion::P4 => ProtocolVersion::ProtocolVersion4,
            super::types::ProtocolVersion::P5 => ProtocolVersion::ProtocolVersion5,
            super::types::ProtocolVersion::P6 => ProtocolVersion::ProtocolVersion6,
            super::types::ProtocolVersion::P7 => ProtocolVersion::ProtocolVersion7,
            super::types::ProtocolVersion::P8 => ProtocolVersion::ProtocolVersion8,
            super::types::ProtocolVersion::P9 => ProtocolVersion::ProtocolVersion9,
        }
    }
}

impl TryFrom<StakePendingChange> for super::types::StakePendingChange {
    type Error = tonic::Status;

    fn try_from(value: StakePendingChange) -> Result<Self, Self::Error> {
        match value.change.require()? {
            stake_pending_change::Change::Reduce(rs) => Ok(Self::ReduceStake {
                new_stake: rs.new_stake.require()?.into(),
                effective_time: rs.effective_time.require()?.try_into()?,
            }),
            stake_pending_change::Change::Remove(rs) => {
                let effective_time = rs.try_into()?;
                Ok(Self::RemoveStake { effective_time })
            }
        }
    }
}

impl TryFrom<BakerInfo> for super::types::BakerInfo {
    type Error = tonic::Status;

    fn try_from(value: BakerInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            baker_id: value.baker_id.require()?.into(),
            baker_election_verify_key: value.election_key.require()?.try_into()?,
            baker_signature_verify_key: value.signature_key.require()?.try_into()?,
            baker_aggregation_verify_key: value.aggregation_key.require()?.try_into()?,
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
        Self::new_unchecked(af.parts_per_hundred_thousand)
    }
}

impl From<AmountFraction> for super::types::PartsPerHundredThousands {
    fn from(af: AmountFraction) -> Self {
        Self::new_unchecked(af.parts_per_hundred_thousand)
    }
}

impl TryFrom<CommissionRates> for super::types::CommissionRates {
    type Error = tonic::Status;

    fn try_from(value: CommissionRates) -> Result<Self, Self::Error> {
        Ok(Self {
            finalization: value.finalization.require()?.into(),
            baking: value.baking.require()?.into(),
            transaction: value.transaction.require()?.into(),
        })
    }
}

impl TryFrom<BakerPoolInfo> for super::types::BakerPoolInfo {
    type Error = tonic::Status;

    fn try_from(value: BakerPoolInfo) -> Result<Self, Self::Error> {
        let open_status = Upward::from(OpenStatus::try_from(value.open_status).ok())
            .map(super::types::OpenStatus::from);
        let metadata_url = value
            .url
            .try_into()
            .map_err(|_| tonic::Status::internal("Unexpected metadata length."))?;
        let commission_rates = value.commission_rates.require()?.try_into()?;
        Ok(Self {
            open_status,
            metadata_url,
            commission_rates,
        })
    }
}

impl TryFrom<account_staking_info::StakingInfo> for super::types::AccountStakingInfo {
    type Error = tonic::Status;

    fn try_from(value: account_staking_info::StakingInfo) -> Result<Self, Self::Error> {
        match value {
            account_staking_info::StakingInfo::Baker(bsi) => {
                let staked_amount = bsi.staked_amount.require()?.into();
                let restake_earnings = bsi.restake_earnings;
                let baker_info = bsi.baker_info.require()?.try_into()?;
                let pending_change = match bsi.pending_change {
                    None => None,
                    Some(pc) => Some(pc.try_into()?),
                };
                let pool_info = match bsi.pool_info {
                    None => None,
                    Some(bi) => Some(bi.try_into()?),
                };
                let is_suspended = bsi.is_suspended;
                Ok(Self::Baker {
                    staked_amount,
                    restake_earnings,
                    baker_info: Box::new(baker_info),
                    pending_change,
                    pool_info,
                    is_suspended,
                })
            }
            account_staking_info::StakingInfo::Delegator(dsi) => {
                let staked_amount = dsi.staked_amount.require()?.into();
                let restake_earnings = dsi.restake_earnings;
                let delegation_target = dsi.target.require()?.try_into()?;
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
            timestamp: value.timestamp.require()?.try_into()?,
            amount: value.amount.require()?.into(),
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
            total: value.total.require()?.into(),
            schedule: value
                .schedules
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, tonic::Status>>()?,
        })
    }
}

impl TryFrom<AccountVerifyKey> for crate::id::types::VerifyKey {
    type Error = tonic::Status;

    fn try_from(value: AccountVerifyKey) -> Result<Self, Self::Error> {
        match value.key.require()? {
            account_verify_key::Key::Ed25519Key(v) => Ok(Self::Ed25519VerifyKey(consume(&v)?)),
        }
    }
}

impl TryFrom<ip_info::IpCdiVerifyKey> for ed25519_dalek::VerifyingKey {
    type Error = tonic::Status;

    fn try_from(value: ip_info::IpCdiVerifyKey) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl TryFrom<ip_info::IpVerifyKey> for crate::id::ps_sig::PublicKey<IpPairing> {
    type Error = tonic::Status;

    fn try_from(value: ip_info::IpVerifyKey) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl TryFrom<UpdatePublicKey> for super::types::UpdatePublicKey {
    type Error = tonic::Status;

    fn try_from(value: UpdatePublicKey) -> Result<Self, Self::Error> {
        Ok(super::types::UpdatePublicKey {
            public: crate::id::types::VerifyKey::Ed25519VerifyKey(consume(&value.value)?),
        })
    }
}

impl TryFrom<SignatureThreshold> for crate::id::types::SignatureThreshold {
    type Error = tonic::Status;

    fn try_from(value: SignatureThreshold) -> Result<Self, Self::Error> {
        if let Ok(v) = u8::try_from(value.value) {
            crate::id::types::SignatureThreshold::try_from(v)
                .map_err(|_| tonic::Status::internal("Unexpected zero signature threshold."))
        } else {
            Err(tonic::Status::internal("Unexpected signature threshold."))
        }
    }
}

impl TryFrom<ArThreshold> for crate::id::secret_sharing::Threshold {
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

impl TryFrom<CredentialPublicKeys> for crate::id::types::CredentialPublicKeys {
    type Error = tonic::Status;

    fn try_from(value: CredentialPublicKeys) -> Result<Self, Self::Error> {
        Ok(Self {
            keys: value
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
            threshold: value.threshold.require()?.try_into()?,
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

impl From<IdentityProviderIdentity> for crate::id::types::IpIdentity {
    fn from(v: IdentityProviderIdentity) -> Self {
        Self(v.value)
    }
}

impl TryFrom<YearMonth> for crate::id::types::YearMonth {
    type Error = tonic::Status;

    fn try_from(value: YearMonth) -> Result<Self, Self::Error> {
        Ok(Self {
            year: value
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

impl TryFrom<Policy> for crate::id::types::Policy<ArCurve, AttributeKind> {
    type Error = tonic::Status;

    fn try_from(value: Policy) -> Result<Self, Self::Error> {
        Ok(Self {
            valid_to: value.valid_to.require()?.try_into()?,
            created_at: value.created_at.require()?.try_into()?,
            policy_vec: value
                .attributes
                .into_iter()
                .map(|(k, v)| {
                    let k = crate::id::types::AttributeTag(
                        k.try_into()
                            .map_err(|_| tonic::Status::internal("Unexpected attribute tag."))?,
                    );
                    let v = AttributeKind(String::from_utf8(v).map_err(|_| {
                        tonic::Status::internal("Invalid attribute value. Expected UTF8 encoding")
                    })?);
                    Ok((k, v))
                })
                .collect::<Result<_, tonic::Status>>()?,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl TryFrom<ChainArData> for crate::id::types::ChainArData<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: ChainArData) -> Result<Self, Self::Error> {
        consume(&value.enc_id_cred_pub_share)
    }
}

impl TryFrom<Commitment> for crate::id::pedersen_commitment::Commitment<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: Commitment) -> Result<Self, Self::Error> {
        consume(&value.value)
    }
}

impl TryFrom<CredentialCommitments> for crate::id::types::CredentialDeploymentCommitments<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: CredentialCommitments) -> Result<Self, Self::Error> {
        Ok(Self {
            cmm_prf: value.prf.require()?.try_into()?,
            cmm_cred_counter: value.cred_counter.require()?.try_into()?,
            cmm_max_accounts: value.max_accounts.require()?.try_into()?,
            cmm_attributes: value
                .attributes
                .into_iter()
                .map(|(k, v)| {
                    let k = crate::id::types::AttributeTag(
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

impl TryFrom<AccountCredential> for Upward<AccountCredentialWithoutProofs<ArCurve, AttributeKind>> {
    type Error = tonic::Status;

    fn try_from(message: AccountCredential) -> Result<Self, Self::Error> {
        let key = message
            .credential_values
            .map(super::id::types::AccountCredentialWithoutProofs::try_from)
            .transpose()?;
        Ok(Upward::from(key))
    }
}

impl TryFrom<account_credential::CredentialValues>
    for AccountCredentialWithoutProofs<ArCurve, AttributeKind>
{
    type Error = tonic::Status;

    fn try_from(cred: account_credential::CredentialValues) -> Result<Self, Self::Error> {
        match cred {
            account_credential::CredentialValues::Initial(ic) => {
                let icdv = InitialCredentialDeploymentValues {
                    cred_account: ic.keys.require()?.try_into()?,
                    reg_id: ic.cred_id.require()?.try_into()?,
                    ip_identity: ic.ip_id.require()?.into(),
                    policy: ic.policy.require()?.try_into()?,
                };
                Ok(AccountCredentialWithoutProofs::Initial { icdv })
            }
            account_credential::CredentialValues::Normal(nc) => {
                let cdv = CredentialDeploymentValues {
                    cred_key_info: nc.keys.require()?.try_into()?,
                    cred_id: nc.cred_id.require()?.try_into()?,
                    ip_identity: nc.ip_id.require()?.into(),
                    threshold: nc.ar_threshold.require()?.try_into()?,
                    ar_data: nc
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
                    policy: nc.policy.require()?.try_into()?,
                };
                let commitments = nc.commitments.require()?.try_into()?;
                Ok(AccountCredentialWithoutProofs::Normal { cdv, commitments })
            }
        }
    }
}

impl From<Timestamp> for concordium_base::common::types::Timestamp {
    fn from(value: Timestamp) -> Self {
        value.value.into()
    }
}

impl From<concordium_base::common::types::Timestamp> for Timestamp {
    fn from(value: concordium_base::common::types::Timestamp) -> Self {
        Timestamp {
            value: value.millis,
        }
    }
}

impl TryFrom<Timestamp> for chrono::DateTime<chrono::Utc> {
    type Error = tonic::Status;

    fn try_from(value: Timestamp) -> Result<Self, Self::Error> {
        let ts = chrono::Utc.timestamp_millis_opt(
            value
                .value
                .try_into()
                .map_err(|_| tonic::Status::internal("Timestamp out of range."))?,
        );
        ts.single()
            .ok_or_else(|| tonic::Status::internal("Ambiguous time."))
    }
}

impl TryFrom<DelegatorInfo> for super::types::DelegatorInfo {
    type Error = tonic::Status;

    fn try_from(delegator: DelegatorInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            account: delegator.account.require()?.try_into()?,
            stake: delegator.stake.require()?.into(),
            pending_change: delegator
                .pending_change
                .map(TryFrom::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<DelegatorRewardPeriodInfo> for super::types::DelegatorRewardPeriodInfo {
    type Error = tonic::Status;

    fn try_from(delegator: DelegatorRewardPeriodInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            account: delegator.account.require()?.try_into()?,
            stake: delegator.stake.require()?.into(),
        })
    }
}

impl From<CooldownStatus> for super::types::CooldownStatus {
    fn from(cds: CooldownStatus) -> Self {
        match cds {
            CooldownStatus::Cooldown => Self::Cooldown,
            CooldownStatus::PreCooldown => Self::PreCooldown,
            CooldownStatus::PrePreCooldown => Self::PrePreCooldown,
        }
    }
}

impl TryFrom<Cooldown> for super::types::Cooldown {
    type Error = tonic::Status;

    fn try_from(cd: Cooldown) -> Result<Self, Self::Error> {
        Ok(Self {
            status: Upward::from(CooldownStatus::try_from(cd.status).ok())
                .map(super::types::CooldownStatus::from),
            end_time: cd.end_time.require()?.into(),
            amount: cd.amount.require()?.into(),
        })
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
            cooldowns,
            available_balance,
            tokens,
        } = value;
        let account_nonce = sequence_number.require()?.into();
        let account_amount = amount.require()?.into();
        let account_release_schedule: AccountReleaseSchedule = schedule.require()?.try_into()?;
        let account_threshold = threshold.require()?.try_into()?;
        let account_encrypted_amount = encrypted_balance.require()?.try_into()?;
        let account_encryption_key = encryption_key.require()?.try_into()?;
        let account_index = index.require()?.into();
        let account_stake: Option<Upward<super::types::AccountStakingInfo>> = match stake {
            Some(stake) => Some(Upward::from(
                stake.staking_info.map(TryInto::try_into).transpose()?,
            )),
            None => None,
        };
        let account_address = address.require()?.try_into()?;
        let mut cds: Vec<super::types::Cooldown> = Vec::with_capacity(cooldowns.len());
        for cooldown in cooldowns.into_iter() {
            cds.push(cooldown.try_into()?)
        }
        let cooldowns = cds;

        // The available balance is only provided as convenience and in case the
        // calculation of it changes in the future. It should be present if the node
        // is version 7 (or later). If the available balance is not present,
        // we calculate it manually instead.
        // If we up the minimum supported node version to version 7, we can remove this
        // fallback calculation and instead require the available balance field to
        // always be present.
        let available_balance = available_balance.map(|ab| ab.into()).unwrap_or_else(|| {
            let active_stake = if let Some(Upward::Known(staking_info)) = &account_stake {
                staking_info.staked_amount()
            } else {
                Default::default()
            };

            let inactive_stake = cooldowns.iter().map(|cd| cd.amount).sum();

            let staked_amount = active_stake + inactive_stake;

            // The locked amount is the maximum of the amount in the release schedule and
            // the total amount that is actively staked or in cooldown (inactive stake).
            let locked_amount = Ord::max(account_release_schedule.total, staked_amount);

            // According to the protobuf documentation:
            // The available (unencrypted) balance of the account is the balance minus the
            // locked amount.
            account_amount - locked_amount
        });

        let tokens = tokens
            .into_iter()
            .map(|token| token.try_into())
            .collect::<Result<_, _>>()?;
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
            cooldowns,
            available_balance,
            tokens,
        })
    }
}

impl TryFrom<BlockItemStatus> for super::types::TransactionStatus {
    type Error = tonic::Status;

    fn try_from(value: BlockItemStatus) -> Result<Self, Self::Error> {
        match value.status.require()? {
            block_item_status::Status::Received(_) => Ok(super::types::TransactionStatus::Received),
            block_item_status::Status::Finalized(f) => {
                let mut summaries: BTreeMap<super::BlockHash, super::types::BlockItemSummary> =
                    BTreeMap::new();
                let o = f.outcome.require()?;
                let k = o.block_hash.require()?.try_into()?;
                let v = o.outcome.require()?.try_into()?;
                summaries.insert(k, v);
                Ok(super::types::TransactionStatus::Finalized(summaries))
            }
            block_item_status::Status::Committed(cs) => {
                let mut summaries: BTreeMap<super::BlockHash, super::types::BlockItemSummary> =
                    BTreeMap::new();
                for o in cs.outcomes {
                    let k = o.block_hash.require()?.try_into()?;
                    let v = o.outcome.require()?.try_into()?;
                    summaries.insert(k, v);
                }
                Ok(super::types::TransactionStatus::Committed(summaries))
            }
        }
    }
}

impl TryFrom<AccountTransactionPayload> for concordium_base::transactions::EncodedPayload {
    type Error = tonic::Status;

    fn try_from(value: AccountTransactionPayload) -> Result<Self, Self::Error> {
        use concordium_base::transactions::PayloadLike;
        match value.payload.require()? {
            account_transaction_payload::Payload::RawPayload(rp) => {
                Self::try_from(rp).map_err(|_| {
                    tonic::Status::invalid_argument("Payload size exceeds maximum allowed.")
                })
            }
            account_transaction_payload::Payload::DeployModule(dm) => {
                let module = match dm.module.require()? {
                    versioned_module_source::Module::V0(source) => {
                        concordium_base::smart_contracts::WasmModule {
                            version: concordium_base::smart_contracts::WasmVersion::V0,
                            source: source.value.into(),
                        }
                    }
                    versioned_module_source::Module::V1(source) => {
                        concordium_base::smart_contracts::WasmModule {
                            version: concordium_base::smart_contracts::WasmVersion::V1,
                            source: source.value.into(),
                        }
                    }
                };
                Ok(concordium_base::transactions::Payload::DeployModule { module }.encode())
            }
            account_transaction_payload::Payload::InitContract(ic) => {
                let payload = concordium_base::transactions::InitContractPayload {
                    amount: ic.amount.require()?.into(),
                    mod_ref: ic.module_ref.require()?.try_into()?,
                    init_name: ic.init_name.require()?.try_into()?,
                    param: ic.parameter.require()?.try_into()?,
                };
                Ok(concordium_base::transactions::Payload::InitContract { payload }.encode())
            }
            account_transaction_payload::Payload::UpdateContract(uc) => {
                let payload = concordium_base::transactions::UpdateContractPayload {
                    amount: uc.amount.require()?.into(),
                    address: uc.address.require()?.into(),
                    receive_name: uc.receive_name.require()?.try_into()?,
                    message: uc.parameter.require()?.try_into()?,
                };
                Ok(concordium_base::transactions::Payload::Update { payload }.encode())
            }
            account_transaction_payload::Payload::Transfer(t) => {
                let payload = concordium_base::transactions::Payload::Transfer {
                    to_address: t.receiver.require()?.try_into()?,
                    amount: t.amount.require()?.into(),
                };
                Ok(payload.encode())
            }
            account_transaction_payload::Payload::TransferWithMemo(t) => {
                let payload = concordium_base::transactions::Payload::TransferWithMemo {
                    to_address: t.receiver.require()?.try_into()?,
                    amount: t.amount.require()?.into(),
                    memo: t.memo.require()?.try_into()?,
                };
                Ok(payload.encode())
            }
            account_transaction_payload::Payload::RegisterData(t) => {
                let payload = concordium_base::transactions::Payload::RegisterData {
                    data: t.try_into()?,
                };
                Ok(payload.encode())
            }
        }
    }
}

impl TryFrom<Signature> for concordium_base::common::types::Signature {
    type Error = tonic::Status;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        if value.value.len() <= usize::from(u16::MAX) {
            Ok(Self { sig: value.value })
        } else {
            Err(tonic::Status::invalid_argument("Signature is too large."))
        }
    }
}

impl TryFrom<AccountTransactionSignature> for concordium_base::common::types::TransactionSignature {
    type Error = tonic::Status;

    fn try_from(value: AccountTransactionSignature) -> Result<Self, Self::Error> {
        let signatures = value
            .signatures
            .into_iter()
            .map(|(ci, m)| {
                let ci = u8::try_from(ci)
                    .map_err(|_| tonic::Status::invalid_argument("Invalid credential index."))?;
                let cred_sigs = m
                    .signatures
                    .into_iter()
                    .map(|(ki, sig)| {
                        let ki = u8::try_from(ki)
                            .map_err(|_| tonic::Status::invalid_argument("Invalid key index."))?;
                        let sig = sig.try_into()?;
                        Ok::<_, tonic::Status>((ki.into(), sig))
                    })
                    .collect::<Result<_, _>>()?;
                Ok::<_, tonic::Status>((ci.into(), cred_sigs))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { signatures })
    }
}

impl TryFrom<AccountTransaction>
    for concordium_base::transactions::AccountTransaction<
        concordium_base::transactions::EncodedPayload,
    >
{
    type Error = tonic::Status;

    fn try_from(value: AccountTransaction) -> Result<Self, Self::Error> {
        let payload: concordium_base::transactions::EncodedPayload =
            value.payload.require()?.try_into()?;
        let payload_size = payload.size();
        let header = {
            let header = value.header.require()?;
            let sender = header.sender.require()?.try_into()?;
            let nonce = header.sequence_number.require()?.into();
            let energy_amount = header.energy_amount.require()?.into();
            let expiry = header.expiry.require()?.into();
            concordium_base::transactions::TransactionHeader {
                sender,
                nonce,
                energy_amount,
                payload_size,
                expiry,
            }
        };
        Ok(Self {
            signature: value.signature.require()?.try_into()?,
            header,
            payload,
        })
    }
}

impl TryFrom<CredentialDeployment>
    for crate::id::types::AccountCredentialMessage<
        crate::id::constants::IpPairing,
        crate::id::constants::ArCurve,
        crate::id::constants::AttributeKind,
    >
{
    type Error = tonic::Status;

    fn try_from(value: CredentialDeployment) -> Result<Self, Self::Error> {
        let message_expiry = value.message_expiry.require()?.into();
        let credential_deployment::Payload::RawPayload(data) = value.payload.require()?;
        let credential = consume(&data)?;
        Ok(Self {
            message_expiry,
            credential,
        })
    }
}

impl TryFrom<SignatureMap> for concordium_base::updates::UpdateInstructionSignature {
    type Error = tonic::Status;

    fn try_from(value: SignatureMap) -> Result<Self, Self::Error> {
        let signatures = value
            .signatures
            .into_iter()
            .map(|(k, sig)| {
                let k = u16::try_from(k)
                    .map_err(|_| tonic::Status::invalid_argument("Update key index too large."))?;
                let sig = sig.try_into()?;
                Ok::<_, tonic::Status>((k.into(), sig))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { signatures })
    }
}

impl TryFrom<UpdateInstruction> for concordium_base::updates::UpdateInstruction {
    type Error = tonic::Status;

    fn try_from(value: UpdateInstruction) -> Result<Self, Self::Error> {
        let header = value.header.require()?;
        let update_instruction_payload::Payload::RawPayload(payload) =
            value.payload.require()?.payload.require()?;
        let header = concordium_base::updates::UpdateHeader {
            seq_number: header.sequence_number.require()?.into(),
            effective_time: header.effective_time.require()?.into(),
            timeout: header.timeout.require()?.into(),
            payload_size: (payload.len() as u32).into(), /* as is safe since
                                                          * this is coming from the node, from
                                                          * a block */
        };
        let signatures: concordium_base::updates::UpdateInstructionSignature =
            value.signatures.require()?.try_into()?;
        let payload = updates::EncodedUpdatePayload::from(payload);
        Ok(Self {
            header,
            payload,
            signatures,
        })
    }
}

impl TryFrom<BlockItem>
    for Upward<
        concordium_base::transactions::BlockItem<concordium_base::transactions::EncodedPayload>,
    >
{
    type Error = tonic::Status;

    fn try_from(value: BlockItem) -> Result<Self, Self::Error> {
        if let Some(item) = value.block_item {
            Ok(Upward::Known(item.try_into()?))
        } else {
            Ok(Upward::Unknown(()))
        }
    }
}

impl TryFrom<block_item::BlockItem>
    for concordium_base::transactions::BlockItem<concordium_base::transactions::EncodedPayload>
{
    type Error = tonic::Status;

    fn try_from(item: block_item::BlockItem) -> Result<Self, Self::Error> {
        type Item =
            concordium_base::transactions::BlockItem<concordium_base::transactions::EncodedPayload>;
        let out = match item {
            block_item::BlockItem::AccountTransaction(at) => {
                Item::AccountTransaction(at.try_into()?)
            }
            block_item::BlockItem::CredentialDeployment(cd) => {
                Item::CredentialDeployment(Box::new(cd.try_into()?))
            }
            block_item::BlockItem::UpdateInstruction(ui) => Item::UpdateInstruction(ui.try_into()?),
        };
        Ok(out)
    }
}

impl TryFrom<AccountTransactionDetails> for super::types::AccountTransactionDetails {
    type Error = tonic::Status;

    fn try_from(v: AccountTransactionDetails) -> Result<Self, Self::Error> {
        Ok(Self {
            cost: v.cost.require()?.into(),
            sender: v.sender.require()?.try_into()?,
            effects: Upward::from(v.effects.map(TryFrom::try_from).transpose()?),
        })
    }
}

impl TryFrom<BlockItemSummary> for super::types::BlockItemSummary {
    type Error = tonic::Status;

    fn try_from(value: BlockItemSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            index: value.index.require()?.into(),
            energy_cost: value.energy_cost.require()?.into(),
            hash: value.hash.require()?.try_into()?,
            details: Upward::from(value.details.map(TryFrom::try_from).transpose()?),
        })
    }
}

impl TryFrom<block_item_summary::Details> for super::types::BlockItemSummaryDetails {
    type Error = tonic::Status;

    fn try_from(value: block_item_summary::Details) -> Result<Self, Self::Error> {
        let out = match value {
            block_item_summary::Details::AccountTransaction(v) => {
                super::types::BlockItemSummaryDetails::AccountTransaction(v.try_into()?)
            }
            block_item_summary::Details::AccountCreation(v) => {
                super::types::BlockItemSummaryDetails::AccountCreation(
                    super::types::AccountCreationDetails {
                        credential_type: v.credential_type().into(),
                        address: v.address.require()?.try_into()?,
                        reg_id: v.reg_id.require()?.try_into()?,
                    },
                )
            }
            block_item_summary::Details::Update(v) => {
                super::types::BlockItemSummaryDetails::Update(super::types::UpdateDetails {
                    effective_time: v.effective_time.require()?.into(),
                    payload: Upward::from(
                        v.payload
                            .map(super::types::UpdatePayload::try_from)
                            .transpose()?,
                    ),
                })
            }
            block_item_summary::Details::TokenCreation(v) => {
                super::types::BlockItemSummaryDetails::TokenCreationDetails(
                    super::types::TokenCreationDetails {
                        create_plt: v.create_plt.require()?.try_into()?,
                        events: v
                            .events
                            .into_iter()
                            .map(TryInto::try_into)
                            .collect::<Result<_, tonic::Status>>()?,
                    },
                )
            }
        };
        Ok(out)
    }
}

impl TryFrom<ElectionDifficulty> for super::types::ElectionDifficulty {
    type Error = tonic::Status;

    fn try_from(value: ElectionDifficulty) -> Result<Self, Self::Error> {
        Self::new(value.value.require()?.parts_per_hundred_thousand).ok_or_else(|| {
            tonic::Status::internal("Election difficulty more than 1, which is not allowed.")
        })
    }
}

impl TryFrom<UpdatePayload> for super::types::UpdatePayload {
    type Error = tonic::Status;

    fn try_from(value: UpdatePayload) -> Result<Self, Self::Error> {
        Ok(match value.payload.require()? {
            update_payload::Payload::ProtocolUpdate(v) => Self::Protocol(v.try_into()?),
            update_payload::Payload::ElectionDifficultyUpdate(v) => {
                Self::ElectionDifficulty(v.try_into()?)
            }
            update_payload::Payload::EuroPerEnergyUpdate(v) => Self::EuroPerEnergy(v.try_into()?),
            update_payload::Payload::MicroCcdPerEuroUpdate(v) => {
                Self::MicroGTUPerEuro(v.try_into()?)
            }
            update_payload::Payload::FoundationAccountUpdate(v) => {
                Self::FoundationAccount(v.try_into()?)
            }
            update_payload::Payload::MintDistributionUpdate(v) => {
                Self::MintDistribution(v.try_into()?)
            }
            update_payload::Payload::TransactionFeeDistributionUpdate(v) => {
                Self::TransactionFeeDistribution(v.try_into()?)
            }
            update_payload::Payload::GasRewardsUpdate(v) => Self::GASRewards(v.try_into()?),
            update_payload::Payload::BakerStakeThresholdUpdate(v) => {
                Self::BakerStakeThreshold(v.try_into()?)
            }
            update_payload::Payload::RootUpdate(v) => {
                Self::Root(match v.update_type.require()? {
                    root_update::UpdateType::RootKeysUpdate(u) => {
                        super::types::RootUpdate::RootKeysUpdate(u.try_into()?)
                    }
                    root_update::UpdateType::Level1KeysUpdate(u) => {
                        super::types::RootUpdate::Level1KeysUpdate(u.try_into()?)
                    }
                    root_update::UpdateType::Level2KeysUpdateV0(u) => {
                        super::types::RootUpdate::Level2KeysUpdate(Box::new(u.try_into()?))
                    }
                    root_update::UpdateType::Level2KeysUpdateV1(u) => {
                        super::types::RootUpdate::Level2KeysUpdateV1(Box::new(u.try_into()?))
                    }
                })
            }
            update_payload::Payload::Level1Update(v) => {
                Self::Level1(match v.update_type.require()? {
                    level1_update::UpdateType::Level1KeysUpdate(u) => {
                        super::types::Level1Update::Level1KeysUpdate(u.try_into()?)
                    }
                    level1_update::UpdateType::Level2KeysUpdateV0(u) => {
                        super::types::Level1Update::Level2KeysUpdate(Box::new(u.try_into()?))
                    }
                    level1_update::UpdateType::Level2KeysUpdateV1(u) => {
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
                Self::CooldownParametersCPV1(v.try_into()?)
            }
            update_payload::Payload::PoolParametersCpv1Update(v) => {
                Self::PoolParametersCPV1(v.try_into()?)
            }
            update_payload::Payload::TimeParametersCpv1Update(v) => {
                Self::TimeParametersCPV1(v.try_into()?)
            }
            update_payload::Payload::MintDistributionCpv1Update(v) => {
                Self::MintDistributionCPV1(v.try_into()?)
            }
            update_payload::Payload::GasRewardsCpv2Update(v) => Self::GASRewardsCPV2(v.try_into()?),
            update_payload::Payload::TimeoutParametersUpdate(v) => {
                Self::TimeoutParametersCPV2(v.try_into()?)
            }
            update_payload::Payload::MinBlockTimeUpdate(v) => Self::MinBlockTimeCPV2(v.into()),
            update_payload::Payload::BlockEnergyLimitUpdate(v) => {
                Self::BlockEnergyLimitCPV2(v.into())
            }
            update_payload::Payload::FinalizationCommitteeParametersUpdate(v) => {
                Self::FinalizationCommitteeParametersCPV2(v.try_into()?)
            }
            update_payload::Payload::ValidatorScoreParametersUpdate(v) => {
                Self::ValidatorScoreParametersCPV3(v.try_into()?)
            }
            update_payload::Payload::CreatePltUpdate(create_plt) => {
                Self::CreatePlt(create_plt.try_into()?)
            }
        })
    }
}

impl TryFrom<super::generated::plt::CreatePlt> for concordium_base::updates::CreatePlt {
    type Error = tonic::Status;

    fn try_from(value: super::generated::plt::CreatePlt) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: value.token_id.require()?.try_into()?,
            token_module: value.token_module.require()?.try_into()?,
            decimals: value.decimals.try_into().map_err(|_| {
                tonic::Status::internal("Unexpected integer size for token decimals.")
            })?,
            initialization_parameters: value.initialization_parameters.require()?.into(),
        })
    }
}

impl TryFrom<CapitalBound> for super::types::CapitalBound {
    type Error = tonic::Status;

    fn try_from(value: CapitalBound) -> Result<Self, Self::Error> {
        Ok(Self {
            bound: value.value.require()?.into(),
        })
    }
}

impl TryFrom<InclusiveRangeAmountFraction>
    for super::types::InclusiveRange<super::types::AmountFraction>
{
    type Error = tonic::Status;

    fn try_from(value: InclusiveRangeAmountFraction) -> Result<Self, Self::Error> {
        let min = value.min.require()?.into();
        let max = value.max.require()?.into();
        if min <= max {
            Ok(Self { min, max })
        } else {
            Err(tonic::Status::internal(
                "Lower bound must not be more than the upper bound.",
            ))
        }
    }
}

impl From<DurationSeconds> for super::types::DurationSeconds {
    fn from(value: DurationSeconds) -> Self {
        Self {
            seconds: value.value,
        }
    }
}

impl TryFrom<IpInfo> for crate::id::types::IpInfo<IpPairing> {
    type Error = tonic::Status;

    fn try_from(value: IpInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            ip_identity: crate::id::types::IpIdentity(value.identity.require()?.value),
            ip_description: value.description.require()?.into(),
            ip_verify_key: value.verify_key.require()?.try_into()?,
            ip_cdi_verify_key: value.cdi_verify_key.require()?.try_into()?,
        })
    }
}

impl TryFrom<ArInfo> for crate::id::types::ArInfo<ArCurve> {
    type Error = tonic::Status;

    fn try_from(value: ArInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            ar_identity: crate::id::types::ArIdentity::try_from(value.identity.require()?.value)
                .map_err(tonic::Status::internal)?,
            ar_description: value.description.require()?.into(),
            ar_public_key: value.public_key.require()?.try_into()?,
        })
    }
}

impl From<Description> for crate::id::types::Description {
    fn from(value: Description) -> Self {
        Self {
            name: value.name,
            url: value.url,
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
            emergency: value.emergency.require()?.try_into()?,
            protocol: value.protocol.require()?.try_into()?,
            election_difficulty: value.parameter_consensus.require()?.try_into()?,
            euro_per_energy: value.parameter_euro_per_energy.require()?.try_into()?,
            micro_gtu_per_euro: value.parameter_micro_ccd_per_euro.require()?.try_into()?,
            foundation_account: value.parameter_foundation_account.require()?.try_into()?,
            mint_distribution: value.parameter_mint_distribution.require()?.try_into()?,
            transaction_fee_distribution: value
                .parameter_transaction_fee_distribution
                .require()?
                .try_into()?,
            param_gas_rewards: value.parameter_gas_rewards.require()?.try_into()?,
            pool_parameters: value.pool_parameters.require()?.try_into()?,
            add_anonymity_revoker: value.add_anonymity_revoker.require()?.try_into()?,
            add_identity_provider: value.add_identity_provider.require()?.try_into()?,
        })
    }
}

impl TryFrom<AuthorizationsV1> for super::types::AuthorizationsV1 {
    type Error = tonic::Status;

    fn try_from(value: AuthorizationsV1) -> Result<Self, Self::Error> {
        Ok(Self {
            v0: value.v0.require()?.try_into()?,
            cooldown_parameters: value.parameter_cooldown.require()?.try_into()?,
            time_parameters: value.parameter_time.require()?.try_into()?,
            create_plt: value.create_plt.map(|x| x.try_into()).transpose()?,
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
        let threshold = value.access_threshold.require()?.try_into()?;
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
        Self::try_from(
            u16::try_from(value.value)
                .map_err(|_| tonic::Status::internal("Threshold could not fit into a u16."))?,
        )
        .map_err(|_| tonic::Status::invalid_argument("UpdateKeysThreshold cannot be 0."))
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
        match value.effect.require()? {
            account_transaction_effects::Effect::None(n) => Ok(Self::None {
                transaction_type: {
                    match n.transaction_type {
                        None => None,
                        Some(tt) => Some(
                            super::types::TransactionType::try_from(tt)
                                .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?,
                        ),
                    }
                },
                reject_reason: n
                    .reject_reason
                    .map(super::types::RejectReason::try_from)
                    .transpose()?
                    .into(),
            }),
            account_transaction_effects::Effect::AccountTransfer(at) => {
                let amount = at.amount.require()?.into();
                let to = at.receiver.require()?.try_into()?;
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
                        contract_version: u8::try_from(cie.contract_version)
                            .map(WasmVersionInt)
                            .map_err(|err| {
                                tonic::Status::internal(format!(
                                    "Could not map contract version from i32 to u8: {err}"
                                ))
                            })?,
                        origin_ref: cie.origin_ref.require()?.try_into()?,
                        address: cie.address.require()?.into(),
                        amount: cie.amount.require()?.into(),
                        init_name: cie.init_name.require()?.try_into()?,
                        events: cie.events.into_iter().map(Into::into).collect(),
                        parameter: cie.parameter.map(TryInto::try_into).transpose()?,
                    },
                })
            }
            account_transaction_effects::Effect::ContractUpdateIssued(cui) => {
                let effects = cui
                    .effects
                    .into_iter()
                    .map(|trace| {
                        Ok(Upward::from(
                            trace
                                .element
                                .map(super::types::ContractTraceElement::try_from)
                                .transpose()?,
                        ))
                    })
                    .collect::<Result<_, tonic::Status>>()?;
                Ok(Self::ContractUpdateIssued { effects })
            }
            account_transaction_effects::Effect::BakerAdded(ba) => {
                let baker_added_event = super::types::BakerAddedEvent {
                    keys_event: ba.keys_event.require()?.try_into()?,
                    stake: ba.stake.require()?.into(),
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
                        baker_id: d.baker_id.require()?.into(),
                        new_stake: d.new_stake.require()?.into(),
                        increased: d.increased,
                    }),
                };
                Ok(Self::BakerStakeUpdated { data })
            }
            account_transaction_effects::Effect::BakerRestakeEarningsUpdated(breu) => {
                Ok(Self::BakerRestakeEarningsUpdated {
                    baker_id: breu.baker_id.require()?.into(),
                    restake_earnings: breu.restake_earnings,
                })
            }
            account_transaction_effects::Effect::BakerKeysUpdated(keys_event) => {
                Ok(Self::BakerKeysUpdated {
                    data: Box::new(keys_event.try_into()?),
                })
            }
            account_transaction_effects::Effect::EncryptedAmountTransferred(eat) => {
                let removed = Box::new(eat.removed.require()?.try_into()?);
                let added = Box::new(eat.added.require()?.try_into()?);
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
                        account: esaae.account.require()?.try_into()?,
                        new_amount: esaae.new_amount.require()?.try_into()?,
                        amount: esaae.amount.require()?.into(),
                    }),
                })
            }
            account_transaction_effects::Effect::TransferredToPublic(ttp) => {
                Ok(Self::TransferredToPublic {
                    removed: Box::new(ttp.removed.require()?.try_into()?),
                    amount: ttp.amount.require()?.into(),
                })
            }
            account_transaction_effects::Effect::TransferredWithSchedule(tws) => {
                let to = tws.receiver.require()?.try_into()?;
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
                    new_cred_ids: cu
                        .new_cred_ids
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, tonic::Status>>()?,
                    removed_cred_ids: cu
                        .removed_cred_ids
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, tonic::Status>>()?,
                    new_threshold: cu.new_threshold.require()?.try_into()?,
                })
            }
            account_transaction_effects::Effect::DataRegistered(rd) => Ok(Self::DataRegistered {
                data: rd.try_into()?,
            }),
            account_transaction_effects::Effect::BakerConfigured(bc) => Ok(Self::BakerConfigured {
                data: bc
                    .events
                    .into_iter()
                    .map(|event| {
                        Ok(Upward::from(
                            event
                                .event
                                .map(super::types::BakerEvent::try_from)
                                .transpose()?,
                        ))
                    })
                    .collect::<Result<_, tonic::Status>>()?,
            }),
            account_transaction_effects::Effect::DelegationConfigured(dc) => {
                Ok(Self::DelegationConfigured {
                    data: dc
                        .events
                        .into_iter()
                        .map(|event| {
                            Ok(Upward::from(
                                event
                                    .event
                                    .map(super::types::DelegationEvent::try_from)
                                    .transpose()?,
                            ))
                        })
                        .collect::<Result<_, tonic::Status>>()?,
                })
            }
            account_transaction_effects::Effect::TokenUpdateEffect(token_effect) => {
                Ok(Self::TokenUpdate {
                    events: token_effect
                        .events
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, tonic::Status>>()?,
                })
            }
        }
    }
}

impl TryFrom<contract_trace_element::Element> for super::types::ContractTraceElement {
    type Error = tonic::Status;

    fn try_from(element: contract_trace_element::Element) -> Result<Self, Self::Error> {
        Ok(match element {
            contract_trace_element::Element::Updated(u) => {
                super::types::ContractTraceElement::Updated {
                    data: u.try_into()?,
                }
            }
            contract_trace_element::Element::Transferred(t) => {
                super::types::ContractTraceElement::Transferred {
                    from: t.sender.require()?.into(),
                    amount: t.amount.require()?.into(),
                    to: t.receiver.require()?.try_into()?,
                }
            }
            contract_trace_element::Element::Interrupted(i) => {
                super::types::ContractTraceElement::Interrupted {
                    address: i.address.require()?.into(),
                    events: i.events.into_iter().map(Into::into).collect(),
                }
            }
            contract_trace_element::Element::Resumed(r) => {
                super::types::ContractTraceElement::Resumed {
                    address: r.address.require()?.into(),
                    success: r.success,
                }
            }
            contract_trace_element::Element::Upgraded(r) => {
                super::types::ContractTraceElement::Upgraded {
                    address: r.address.require()?.into(),
                    from: r.from.require()?.try_into()?,
                    to: r.to.require()?.try_into()?,
                }
            }
        })
    }
}

impl TryFrom<delegation_event::Event> for super::types::DelegationEvent {
    type Error = tonic::Status;

    fn try_from(value: delegation_event::Event) -> Result<Self, Self::Error> {
        Ok(match value {
            delegation_event::Event::DelegationStakeIncreased(v) => {
                Self::DelegationStakeIncreased {
                    delegator_id: v.delegator_id.require()?.try_into()?,
                    new_stake: v.new_stake.require()?.into(),
                }
            }
            delegation_event::Event::DelegationStakeDecreased(v) => {
                Self::DelegationStakeDecreased {
                    delegator_id: v.delegator_id.require()?.try_into()?,
                    new_stake: v.new_stake.require()?.into(),
                }
            }
            delegation_event::Event::DelegationSetRestakeEarnings(v) => {
                Self::DelegationSetRestakeEarnings {
                    delegator_id: v.delegator_id.require()?.try_into()?,
                    restake_earnings: v.restake_earnings,
                }
            }
            delegation_event::Event::DelegationSetDelegationTarget(v) => {
                Self::DelegationSetDelegationTarget {
                    delegator_id: v.delegator_id.require()?.try_into()?,
                    delegation_target: v.delegation_target.require()?.try_into()?,
                }
            }
            delegation_event::Event::DelegationAdded(v) => Self::DelegationAdded {
                delegator_id: v.try_into()?,
            },
            delegation_event::Event::DelegationRemoved(v) => Self::DelegationRemoved {
                delegator_id: v.try_into()?,
            },
            delegation_event::Event::BakerRemoved(v) => Self::BakerRemoved {
                baker_id: v.baker_id.require()?.into(),
            },
        })
    }
}

impl TryFrom<DelegatorId> for super::types::DelegatorId {
    type Error = tonic::Status;

    fn try_from(value: DelegatorId) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id.require()?.into(),
        })
    }
}

impl TryFrom<baker_event::Event> for super::types::BakerEvent {
    type Error = tonic::Status;

    fn try_from(value: baker_event::Event) -> Result<Self, Self::Error> {
        Ok(match value {
            baker_event::Event::BakerAdded(v) => Self::BakerAdded {
                data: Box::new(super::types::BakerAddedEvent {
                    keys_event: v.keys_event.require()?.try_into()?,
                    stake: v.stake.require()?.into(),
                    restake_earnings: v.restake_earnings,
                }),
            },
            baker_event::Event::BakerRemoved(v) => Self::BakerRemoved { baker_id: v.into() },
            baker_event::Event::BakerStakeIncreased(v) => Self::BakerStakeIncreased {
                baker_id: v.baker_id.require()?.into(),
                new_stake: v.new_stake.require()?.into(),
            },
            baker_event::Event::BakerStakeDecreased(v) => Self::BakerStakeDecreased {
                baker_id: v.baker_id.require()?.into(),
                new_stake: v.new_stake.require()?.into(),
            },
            baker_event::Event::BakerRestakeEarningsUpdated(v) => {
                Self::BakerRestakeEarningsUpdated {
                    baker_id: v.baker_id.require()?.into(),
                    restake_earnings: v.restake_earnings,
                }
            }
            baker_event::Event::BakerKeysUpdated(v) => Self::BakerKeysUpdated {
                data: Box::new(v.try_into()?),
            },
            baker_event::Event::BakerSetOpenStatus(v) => {
                let open_status = Upward::from(OpenStatus::try_from(v.open_status).ok())
                    .map(super::types::OpenStatus::from);
                Self::BakerSetOpenStatus {
                    baker_id: v.baker_id.require()?.into(),
                    open_status,
                }
            }
            baker_event::Event::BakerSetMetadataUrl(v) => Self::BakerSetMetadataURL {
                baker_id: v.baker_id.require()?.into(),
                metadata_url: v.url.try_into().map_err(|e| {
                    tonic::Status::invalid_argument(format!("Invalid argument: {}", e))
                })?,
            },
            baker_event::Event::BakerSetTransactionFeeCommission(v) => {
                Self::BakerSetTransactionFeeCommission {
                    baker_id: v.baker_id.require()?.into(),
                    transaction_fee_commission: v.transaction_fee_commission.require()?.into(),
                }
            }
            baker_event::Event::BakerSetBakingRewardCommission(v) => {
                Self::BakerSetBakingRewardCommission {
                    baker_id: v.baker_id.require()?.into(),
                    baking_reward_commission: v.baking_reward_commission.require()?.into(),
                }
            }
            baker_event::Event::BakerSetFinalizationRewardCommission(v) => {
                Self::BakerSetFinalizationRewardCommission {
                    baker_id: v.baker_id.require()?.into(),
                    finalization_reward_commission: v
                        .finalization_reward_commission
                        .require()?
                        .into(),
                }
            }
            baker_event::Event::DelegationRemoved(v) => Self::DelegationRemoved {
                delegator_id: v.delegator_id.require()?.try_into()?,
            },
            baker_event::Event::BakerSuspended(v) => Self::BakerSuspended {
                baker_id: v.baker_id.require()?.into(),
            },
            baker_event::Event::BakerResumed(v) => Self::BakerResumed {
                baker_id: v.baker_id.require()?.into(),
            },
        })
    }
}

impl TryFrom<RegisteredData> for super::types::RegisteredData {
    type Error = tonic::Status;

    fn try_from(value: RegisteredData) -> Result<Self, Self::Error> {
        value
            .value
            .try_into()
            .map_err(|e| tonic::Status::invalid_argument(format!("{}", e)))
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
            millis: value.timestamp.require()?.value,
        };
        Ok((timestamp, value.amount.require()?.into()))
    }
}

impl TryFrom<EncryptedAmountRemovedEvent> for super::types::EncryptedAmountRemovedEvent {
    type Error = tonic::Status;

    fn try_from(value: EncryptedAmountRemovedEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            account: value.account.require()?.try_into()?,
            new_amount: value.new_amount.require()?.try_into()?,
            input_amount: value.input_amount.require()?.try_into()?,
            up_to_index: crate::encrypted_transfers::types::EncryptedAmountAggIndex {
                index: value.up_to_index,
            },
        })
    }
}

impl TryFrom<NewEncryptedAmountEvent> for super::types::NewEncryptedAmountEvent {
    type Error = tonic::Status;

    fn try_from(value: NewEncryptedAmountEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            receiver: value.receiver.require()?.try_into()?,
            new_index: crate::encrypted_transfers::types::EncryptedAmountIndex {
                index: value.new_index,
            },
            encrypted_amount: value.encrypted_amount.require()?.try_into()?,
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
            baker_id: value.baker_id.require()?.into(),
            account: value.account.require()?.try_into()?,
            sign_key: value.sign_key.require()?.try_into()?,
            election_key: value.election_key.require()?.try_into()?,
            aggregation_key: value.aggregation_key.require()?.try_into()?,
        })
    }
}

impl TryFrom<InstanceUpdatedEvent> for super::types::InstanceUpdatedEvent {
    type Error = tonic::Status;

    fn try_from(value: InstanceUpdatedEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            contract_version: u8::try_from(value.contract_version)
                .map(WasmVersionInt)
                .map_err(|err| {
                    tonic::Status::internal(format!(
                        "Could not map contract version from i32 to u8: {err}"
                    ))
                })?,
            address: value.address.require()?.into(),
            instigator: value.instigator.require()?.try_into()?,
            amount: value.amount.require()?.into(),
            message: value.parameter.require()?.try_into()?,
            receive_name: value.receive_name.require()?.try_into()?,
            events: value.events.into_iter().map(Into::into).collect(),
        })
    }
}

impl From<ContractEvent> for super::types::smart_contracts::ContractEvent {
    fn from(value: ContractEvent) -> Self {
        value.value.into()
    }
}

impl TryFrom<RejectReason> for super::types::RejectReason {
    type Error = tonic::Status;

    fn try_from(value: RejectReason) -> Result<Self, Self::Error> {
        Ok(match value.reason.require()? {
            reject_reason::Reason::ModuleNotWf(_) => Self::ModuleNotWF,
            reject_reason::Reason::ModuleHashAlreadyExists(v) => Self::ModuleHashAlreadyExists {
                contents: v.try_into()?,
            },
            reject_reason::Reason::InvalidAccountReference(v) => Self::InvalidAccountReference {
                contents: v.try_into()?,
            },
            reject_reason::Reason::InvalidInitMethod(v) => Self::InvalidInitMethod {
                contents: (
                    v.module_ref.require()?.try_into()?,
                    v.init_name.require()?.try_into()?,
                ),
            },
            reject_reason::Reason::InvalidReceiveMethod(v) => Self::InvalidReceiveMethod {
                contents: (
                    v.module_ref.require()?.try_into()?,
                    v.receive_name.require()?.try_into()?,
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
                contents: (v.address.require()?.try_into()?, v.amount.require()?.into()),
            },
            reject_reason::Reason::SerializationFailure(_) => Self::SerializationFailure,
            reject_reason::Reason::OutOfEnergy(_) => Self::OutOfEnergy,
            reject_reason::Reason::RejectedInit(v) => Self::RejectedInit {
                reject_reason: v.reject_reason,
            },
            reject_reason::Reason::RejectedReceive(v) => Self::RejectedReceive {
                reject_reason: v.reject_reason,
                contract_address: v.contract_address.require()?.into(),
                receive_name: v.receive_name.require()?.try_into()?,
                parameter: v.parameter.require()?.try_into()?,
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
            reject_reason::Reason::NonExistentTokenId(token_id) => Self::NonExistentTokenId {
                token_id: token_id.try_into()?,
            },
            reject_reason::Reason::TokenUpdateTransactionFailed(token_module_reject_reason) => {
                Self::TokenUpdateTransactionFailed {
                    reject_reason: token_module_reject_reason.try_into()?,
                }
            }
        })
    }
}

impl TryFrom<NextAccountSequenceNumber> for super::types::queries::AccountNonceResponse {
    type Error = tonic::Status;

    fn try_from(value: NextAccountSequenceNumber) -> Result<Self, Self::Error> {
        Ok(Self {
            nonce: value.sequence_number.require()?.into(),
            all_final: value.all_final,
        })
    }
}

impl From<block_item_summary::TransactionIndex> for super::types::TransactionIndex {
    fn from(value: block_item_summary::TransactionIndex) -> Self {
        Self { index: value.value }
    }
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
        let protocol_version = protocol_version_int_from_enum(value.protocol_version)?;
        Ok(Self {
            last_finalized_block_height: value.last_finalized_block_height.require()?.into(),
            block_arrive_latency_e_m_s_d: value.block_arrive_latency_emsd,
            block_receive_latency_e_m_s_d: value.block_receive_latency_emsd,
            last_finalized_block: value.last_finalized_block.require()?.try_into()?,
            block_receive_period_e_m_s_d: value.block_receive_period_emsd,
            block_arrive_period_e_m_s_d: value.block_arrive_period_emsd,
            blocks_received_count: value.blocks_received_count.into(),
            transactions_per_block_e_m_s_d: value.transactions_per_block_emsd,
            finalization_period_e_m_a: value.finalization_period_ema,
            best_block_height: value.best_block_height.require()?.into(),
            last_finalized_time: value
                .last_finalized_time
                .map(|v| v.try_into())
                .transpose()?,
            finalization_count: value.finalization_count.into(),
            epoch_duration: value.epoch_duration.require()?.try_into()?,
            blocks_verified_count: value.blocks_verified_count.into(),
            slot_duration: value.slot_duration.map(Into::into),
            genesis_time: value.genesis_time.require()?.try_into()?,
            finalization_period_e_m_s_d: value.finalization_period_emsd,
            transactions_per_block_e_m_a: value.transactions_per_block_ema,
            block_arrive_latency_e_m_a: value.block_arrive_latency_ema,
            block_receive_latency_e_m_a: value.block_receive_latency_ema,
            block_arrive_period_e_m_a: value.block_arrive_period_ema,
            block_receive_period_e_m_a: value.block_receive_period_ema,
            block_last_arrived_time: value
                .block_last_arrived_time
                .map(|v| v.try_into())
                .transpose()?,
            best_block: value.best_block.require()?.try_into()?,
            genesis_block: value.genesis_block.require()?.try_into()?,
            block_last_received_time: value
                .block_last_received_time
                .map(|v| v.try_into())
                .transpose()?,
            protocol_version,
            genesis_index: value.genesis_index.require()?.into(),
            current_era_genesis_block: value.current_era_genesis_block.require()?.try_into()?,
            current_era_genesis_time: value.current_era_genesis_time.require()?.try_into()?,
            concordium_bft_status: if protocol_version <= super::types::ProtocolVersion::P5.into() {
                None
            } else {
                Some(ConcordiumBFTDetails {
                    current_timeout_duration: value
                        .current_timeout_duration
                        .require()?
                        .try_into()?,
                    current_round: value.current_round.require()?.into(),
                    current_epoch: value.current_epoch.require()?.into(),
                    trigger_block_time: value.trigger_block_time.require()?.try_into()?,
                })
            },
        })
    }
}

impl TryFrom<InvokeInstanceResponse> for super::types::smart_contracts::InvokeContractResult {
    type Error = tonic::Status;

    fn try_from(response: InvokeInstanceResponse) -> Result<Self, Self::Error> {
        use super::types::smart_contracts::{InvokeContractResult, ReturnValue};
        let result = match response.result.require()? {
            invoke_instance_response::Result::Failure(value) => InvokeContractResult::Failure {
                return_value: value.return_value.map(|b| ReturnValue { value: b }),
                reason: Upward::from(value.reason.map(TryFrom::try_from).transpose()?),
                used_energy: value.used_energy.require()?.into(),
            },
            invoke_instance_response::Result::Success(value) => InvokeContractResult::Success {
                return_value: value.return_value.map(|b| ReturnValue { value: b }),
                events: value
                    .effects
                    .into_iter()
                    .map(|trace| {
                        Ok(Upward::from(
                            trace
                                .element
                                .map(super::types::ContractTraceElement::try_from)
                                .transpose()?,
                        ))
                    })
                    .collect::<Result<_, tonic::Status>>()?,
                used_energy: value.used_energy.require()?.into(),
            },
        };
        Ok(result)
    }
}

impl TryFrom<CryptographicParameters> for super::types::CryptographicParameters {
    type Error = tonic::Status;

    fn try_from(value: CryptographicParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            genesis_string: value.genesis_string,
            on_chain_commitment_key: concordium_base::common::from_bytes(
                &mut std::io::Cursor::new(&value.on_chain_commitment_key),
            )
            .map_err(|_| tonic::Status::internal("Invalid on_chain_commitment_key received"))?,

            bulletproof_generators: concordium_base::common::from_bytes(&mut std::io::Cursor::new(
                &value.bulletproof_generators,
            ))
            .map_err(|_| tonic::Status::internal("Invalid bulletproof_generators received"))?,
        })
    }
}

impl TryFrom<CredentialsPerBlockLimit> for super::types::CredentialsPerBlockLimit {
    type Error = tonic::Status;

    fn try_from(value: CredentialsPerBlockLimit) -> Result<Self, Self::Error> {
        Ok(Self {
            limit: value.value.try_into().map_err(|_| {
                tonic::Status::internal("Unexpectedly large account creation limit")
            })?,
        })
    }
}

impl TryFrom<ChainParametersV0> for super::ChainParametersV0 {
    type Error = tonic::Status;

    fn try_from(value: ChainParametersV0) -> Result<Self, Self::Error> {
        Ok(Self {
            election_difficulty: value.election_difficulty.require()?.try_into()?,
            euro_per_energy: value.euro_per_energy.require()?.try_into()?,
            micro_ccd_per_euro: value.micro_ccd_per_euro.require()?.try_into()?,
            baker_cooldown_epochs: value.baker_cooldown_epochs.require()?.into(),
            account_creation_limit: value.account_creation_limit.require()?.try_into()?,
            mint_distribution: value.mint_distribution.require()?.try_into()?,
            transaction_fee_distribution: value
                .transaction_fee_distribution
                .require()?
                .try_into()?,
            gas_rewards: value.gas_rewards.require()?.try_into()?,
            foundation_account: value.foundation_account.require()?.try_into()?,
            minimum_threshold_for_baking: value.minimum_threshold_for_baking.require()?.into(),
            keys: UpdateKeysCollectionSkeleton {
                root_keys: value.root_keys.require()?.try_into()?,
                level_1_keys: value.level1_keys.require()?.try_into()?,
                level_2_keys: value.level2_keys.require()?.try_into()?,
            },
        })
    }
}

impl TryFrom<ChainParametersV1> for super::ChainParametersV1 {
    type Error = tonic::Status;

    fn try_from(value: ChainParametersV1) -> Result<Self, Self::Error> {
        Ok(Self {
            election_difficulty: value.election_difficulty.require()?.try_into()?,
            euro_per_energy: value.euro_per_energy.require()?.try_into()?,
            micro_ccd_per_euro: value.micro_ccd_per_euro.require()?.try_into()?,
            pool_parameters: value.pool_parameters.require()?.try_into()?,
            account_creation_limit: value.account_creation_limit.require()?.try_into()?,
            mint_distribution: value.mint_distribution.require()?.try_into()?,
            transaction_fee_distribution: value
                .transaction_fee_distribution
                .require()?
                .try_into()?,
            gas_rewards: value.gas_rewards.require()?.try_into()?,
            foundation_account: value.foundation_account.require()?.try_into()?,
            time_parameters: value.time_parameters.require()?.try_into()?,
            cooldown_parameters: value.cooldown_parameters.require()?.try_into()?,
            keys: UpdateKeysCollectionSkeleton {
                root_keys: value.root_keys.require()?.try_into()?,
                level_1_keys: value.level1_keys.require()?.try_into()?,
                level_2_keys: value.level2_keys.require()?.try_into()?,
            },
        })
    }
}

impl TryFrom<ChainParametersV2> for super::ChainParametersV2 {
    type Error = tonic::Status;

    fn try_from(value: ChainParametersV2) -> Result<Self, Self::Error> {
        let consensus_parameters = value.consensus_parameters.require()?;

        Ok(Self {
            timeout_parameters: consensus_parameters
                .timeout_parameters
                .require()?
                .try_into()?,
            min_block_time: consensus_parameters.min_block_time.require()?.into(),
            block_energy_limit: consensus_parameters.block_energy_limit.require()?.into(),
            euro_per_energy: value.euro_per_energy.require()?.try_into()?,
            micro_ccd_per_euro: value.micro_ccd_per_euro.require()?.try_into()?,
            pool_parameters: value.pool_parameters.require()?.try_into()?,
            account_creation_limit: value.account_creation_limit.require()?.try_into()?,
            mint_distribution: value.mint_distribution.require()?.try_into()?,
            transaction_fee_distribution: value
                .transaction_fee_distribution
                .require()?
                .try_into()?,
            gas_rewards: value.gas_rewards.require()?.try_into()?,
            foundation_account: value.foundation_account.require()?.try_into()?,
            time_parameters: value.time_parameters.require()?.try_into()?,
            cooldown_parameters: value.cooldown_parameters.require()?.try_into()?,
            finalization_committee_parameters: value
                .finalization_committee_parameters
                .require()?
                .try_into()?,
            keys: UpdateKeysCollectionSkeleton {
                root_keys: value.root_keys.require()?.try_into()?,
                level_1_keys: value.level1_keys.require()?.try_into()?,
                level_2_keys: value.level2_keys.require()?.try_into()?,
            },
        })
    }
}

impl TryFrom<ChainParametersV3> for super::ChainParametersV3 {
    type Error = tonic::Status;

    fn try_from(value: ChainParametersV3) -> Result<Self, Self::Error> {
        let consensus_parameters = value.consensus_parameters.require()?;

        Ok(Self {
            timeout_parameters: consensus_parameters
                .timeout_parameters
                .require()?
                .try_into()?,
            min_block_time: consensus_parameters.min_block_time.require()?.into(),
            block_energy_limit: consensus_parameters.block_energy_limit.require()?.into(),
            euro_per_energy: value.euro_per_energy.require()?.try_into()?,
            micro_ccd_per_euro: value.micro_ccd_per_euro.require()?.try_into()?,
            pool_parameters: value.pool_parameters.require()?.try_into()?,
            account_creation_limit: value.account_creation_limit.require()?.try_into()?,
            mint_distribution: value.mint_distribution.require()?.try_into()?,
            transaction_fee_distribution: value
                .transaction_fee_distribution
                .require()?
                .try_into()?,
            gas_rewards: value.gas_rewards.require()?.try_into()?,
            foundation_account: value.foundation_account.require()?.try_into()?,
            time_parameters: value.time_parameters.require()?.try_into()?,
            cooldown_parameters: value.cooldown_parameters.require()?.try_into()?,
            finalization_committee_parameters: value
                .finalization_committee_parameters
                .require()?
                .try_into()?,
            validator_score_parameters: value.validator_score_parameters.require()?.try_into()?,
            keys: UpdateKeysCollectionSkeleton {
                root_keys: value.root_keys.require()?.try_into()?,
                level_1_keys: value.level1_keys.require()?.try_into()?,
                level_2_keys: value.level2_keys.require()?.try_into()?,
            },
        })
    }
}

impl TryFrom<ChainParameters> for super::ChainParameters {
    type Error = tonic::Status;

    fn try_from(value: ChainParameters) -> Result<Self, Self::Error> {
        match value.parameters.require()? {
            chain_parameters::Parameters::V0(v0) => Ok(Self::V0(v0.try_into()?)),
            chain_parameters::Parameters::V1(v1) => Ok(Self::V1(v1.try_into()?)),
            chain_parameters::Parameters::V2(v2) => Ok(Self::V2(v2.try_into()?)),
            chain_parameters::Parameters::V3(v3) => Ok(Self::V3(v3.try_into()?)),
        }
    }
}

impl TryFrom<FinalizationSummaryParty> for super::types::FinalizationSummaryParty {
    type Error = tonic::Status;

    fn try_from(value: FinalizationSummaryParty) -> Result<Self, Self::Error> {
        Ok(Self {
            baker_id: value.baker.require()?.into(),
            weight: value.weight,
            signed: value.signed,
        })
    }
}

impl From<FinalizationIndex> for super::types::FinalizationIndex {
    fn from(value: FinalizationIndex) -> Self {
        value.value.into()
    }
}

impl TryFrom<BlockFinalizationSummary> for Option<super::types::FinalizationSummary> {
    type Error = tonic::Status;

    fn try_from(value: BlockFinalizationSummary) -> Result<Self, Self::Error> {
        match value.summary.require()? {
            block_finalization_summary::Summary::None(_) => Ok(None),
            block_finalization_summary::Summary::Record(r) => {
                Ok(Some(super::types::FinalizationSummary {
                    block_pointer: r.block.require()?.try_into()?,
                    index: r.index.require()?.into(),
                    delay: r.delay.require()?.into(),
                    finalizers: r
                        .finalizers
                        .into_iter()
                        .map(super::types::FinalizationSummaryParty::try_from)
                        .collect::<Result<_, tonic::Status>>()?,
                }))
            }
        }
    }
}

impl TryFrom<BlockInfo> for super::types::queries::BlockInfo {
    type Error = tonic::Status;

    fn try_from(value: BlockInfo) -> Result<Self, Self::Error> {
        let protocol_version = protocol_version_int_from_enum(value.protocol_version)?;

        Ok(Self {
            transactions_size: value.transactions_size.into(),
            block_parent: value.parent_block.require()?.try_into()?,
            block_hash: value.hash.require()?.try_into()?,
            finalized: value.finalized,
            block_state_hash: value.state_hash.require()?.try_into()?,
            block_arrive_time: value.arrive_time.require()?.try_into()?,
            block_receive_time: value.receive_time.require()?.try_into()?,
            transaction_count: value.transaction_count.into(),
            transaction_energy_cost: value.transactions_energy_cost.require()?.into(),
            block_slot: if protocol_version <= super::types::ProtocolVersion::P5.into() {
                Some(value.slot_number.require()?.into())
            } else {
                None
            },
            block_last_finalized: value.last_finalized_block.require()?.try_into()?,
            block_slot_time: value.slot_time.require()?.try_into()?,
            block_height: value.height.require()?.into(),
            era_block_height: value.era_block_height.require()?.into(),
            genesis_index: value.genesis_index.require()?.into(),
            block_baker: value.baker.map(|b| b.into()),
            protocol_version,
            round: if protocol_version >= super::types::ProtocolVersion::P6.into() {
                Some(value.round.require()?.into())
            } else {
                None
            },
            epoch: if protocol_version >= super::types::ProtocolVersion::P6.into() {
                Some(value.epoch.require()?.into())
            } else {
                None
            },
        })
    }
}

impl TryFrom<PoolInfoResponse> for super::types::BakerPoolStatus {
    type Error = tonic::Status;

    fn try_from(value: PoolInfoResponse) -> Result<Self, Self::Error> {
        // The active baker pool status is present iff the pool info is present in the
        // response.
        let active_baker_pool_status = match value.pool_info {
            None => None,
            Some(pi) => Some(ActiveBakerPoolStatus {
                baker_equity_capital: value.equity_capital.require()?.into(),
                delegated_capital: value.delegated_capital.require()?.into(),
                delegated_capital_cap: value.delegated_capital_cap.require()?.into(),
                pool_info: pi.try_into()?,
                baker_stake_pending_change: value.equity_pending_change.try_into()?,
            }),
        };

        Ok(Self {
            baker_id: value.baker.require()?.into(),
            baker_address: value.address.require()?.try_into()?,
            active_baker_pool_status,
            current_payday_status: if let Some(v) = value.current_payday_info {
                Some(v.try_into()?)
            } else {
                None
            },
            all_pool_total_capital: value.all_pool_total_capital.require()?.into(),
        })
    }
}

impl TryFrom<Option<PoolPendingChange>> for super::types::PoolPendingChange {
    type Error = tonic::Status;

    fn try_from(value: Option<PoolPendingChange>) -> Result<Self, Self::Error> {
        if let Some(value) = value {
            match value.change.require()? {
                pool_pending_change::Change::Reduce(rs) => Ok(Self::ReduceBakerCapital {
                    baker_equity_capital: rs.reduced_equity_capital.require()?.into(),
                    effective_time: rs.effective_time.require()?.try_into()?,
                }),
                pool_pending_change::Change::Remove(rs) => Ok(Self::RemovePool {
                    effective_time: rs.effective_time.require()?.try_into()?,
                }),
            }
        } else {
            Ok(Self::NoChange)
        }
    }
}

impl TryFrom<PoolCurrentPaydayInfo> for super::types::CurrentPaydayBakerPoolStatus {
    type Error = tonic::Status;

    fn try_from(value: PoolCurrentPaydayInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            blocks_baked: value.blocks_baked,
            finalization_live: value.finalization_live,
            transaction_fees_earned: value.transaction_fees_earned.require()?.into(),
            effective_stake: value.effective_stake.require()?.into(),
            lottery_power: value.lottery_power,
            baker_equity_capital: value.baker_equity_capital.require()?.into(),
            delegated_capital: value.delegated_capital.require()?.into(),
            commission_rates: value.commission_rates.require()?.try_into()?,
        })
    }
}

impl TryFrom<PassiveDelegationInfo> for super::types::PassiveDelegationStatus {
    type Error = tonic::Status;

    fn try_from(value: PassiveDelegationInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            delegated_capital: value.delegated_capital.require()?.into(),
            commission_rates: value.commission_rates.require()?.try_into()?,
            current_payday_transaction_fees_earned: value
                .current_payday_transaction_fees_earned
                .require()?
                .into(),
            current_payday_delegated_capital: value
                .current_payday_delegated_capital
                .require()?
                .into(),
            all_pool_total_capital: value.all_pool_total_capital.require()?.into(),
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

impl TryFrom<TokenomicsInfo> for super::types::RewardsOverview {
    type Error = tonic::Status;

    fn try_from(value: TokenomicsInfo) -> Result<Self, Self::Error> {
        match value.tokenomics.require()? {
            tokenomics_info::Tokenomics::V0(value) => Ok(Self::V0 {
                data: super::types::CommonRewardData {
                    protocol_version: protocol_version_int_from_enum(value.protocol_version)?,
                    total_amount: value.total_amount.require()?.into(),
                    total_encrypted_amount: value.total_encrypted_amount.require()?.into(),
                    baking_reward_account: value.baking_reward_account.require()?.into(),
                    finalization_reward_account: value
                        .finalization_reward_account
                        .require()?
                        .into(),
                    gas_account: value.gas_account.require()?.into(),
                },
            }),
            tokenomics_info::Tokenomics::V1(value) => Ok(Self::V1 {
                common: super::types::CommonRewardData {
                    protocol_version: protocol_version_int_from_enum(value.protocol_version)?,
                    total_amount: value.total_amount.require()?.into(),
                    total_encrypted_amount: value.total_encrypted_amount.require()?.into(),
                    baking_reward_account: value.baking_reward_account.require()?.into(),
                    finalization_reward_account: value
                        .finalization_reward_account
                        .require()?
                        .into(),
                    gas_account: value.gas_account.require()?.into(),
                },
                foundation_transaction_rewards: value
                    .foundation_transaction_rewards
                    .require()?
                    .into(),
                next_payday_time: value.next_payday_time.require()?.try_into()?,
                next_payday_mint_rate: value.next_payday_mint_rate.require()?.try_into()?,
                total_staked_capital: value.total_staked_capital.require()?.into(),
            }),
        }
    }
}

impl TryFrom<Branch> for super::types::queries::Branch {
    type Error = tonic::Status;

    fn try_from(value: Branch) -> Result<Self, Self::Error> {
        // Tracking the branches which to visit next.
        let mut next = Vec::new();
        // For building a depth first search order of the tree.
        let mut dfs = Vec::new();

        // First we build a depth first search order of the tree.
        next.extend(value.children.iter());
        dfs.push(&value);
        while let Some(value) = next.pop() {
            dfs.push(value);
            next.extend(value.children.iter());
        }

        // Using depth first we build the new tree.
        let mut nodes = Vec::new();
        while let Some(value) = dfs.pop() {
            let mut children = Vec::new();
            for _ in 0..value.children.len() {
                // If a node have children, they should already be pushed and this is safe.
                children.push(nodes.pop().require()?);
            }

            let node = Self {
                block_hash: value.block_hash.clone().require()?.try_into()?,
                children,
            };
            nodes.push(node)
        }

        // Only one node should be left and is the root of the tree.
        let root = nodes.pop().require()?;
        Ok(root)
    }
}

impl TryFrom<election_info::Baker> for super::types::BirkBaker {
    type Error = tonic::Status;

    fn try_from(info: election_info::Baker) -> Result<Self, Self::Error> {
        Ok(Self {
            baker_id: info.baker.require()?.into(),
            baker_lottery_power: info.lottery_power,
            baker_account: info.account.require()?.try_into()?,
        })
    }
}

impl TryFrom<ElectionInfo> for super::types::BirkParameters {
    type Error = tonic::Status;

    fn try_from(info: ElectionInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            election_difficulty: info.election_difficulty.map(|x| x.try_into()).transpose()?,
            election_nonce: info.election_nonce.require()?.try_into()?,
            bakers: info
                .baker_election_info
                .into_iter()
                .map(|c| c.try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<block_special_event::AccountAmounts>
    for BTreeMap<super::AccountAddress, super::Amount>
{
    type Error = tonic::Status;

    fn try_from(message: block_special_event::AccountAmounts) -> Result<Self, Self::Error> {
        fn mapper(
            entry: block_special_event::account_amounts::Entry,
        ) -> Result<(super::AccountAddress, super::Amount), tonic::Status> {
            Ok((
                entry.account.require()?.try_into()?,
                entry.amount.require()?.into(),
            ))
        }

        message
            .entries
            .into_iter()
            .map(mapper)
            .collect::<Result<_, _>>()
    }
}

impl TryFrom<block_special_event::Event> for super::types::SpecialTransactionOutcome {
    type Error = tonic::Status;

    fn try_from(special_event: block_special_event::Event) -> Result<Self, Self::Error> {
        let event = match special_event {
            block_special_event::Event::BakingRewards(event) => Self::BakingRewards {
                baker_rewards: event.baker_rewards.require()?.try_into()?,
                remainder: event.remainder.require()?.into(),
            },
            block_special_event::Event::Mint(event) => Self::Mint {
                mint_baking_reward: event.mint_baking_reward.require()?.into(),
                mint_finalization_reward: event.mint_finalization_reward.require()?.into(),
                mint_platform_development_charge: event
                    .mint_platform_development_charge
                    .require()?
                    .into(),
                foundation_account: event.foundation_account.require()?.try_into()?,
            },
            block_special_event::Event::FinalizationRewards(event) => Self::FinalizationRewards {
                finalization_rewards: event.finalization_rewards.require()?.try_into()?,
                remainder: event.remainder.require()?.into(),
            },
            block_special_event::Event::BlockReward(event) => Self::BlockReward {
                transaction_fees: event.transaction_fees.require()?.into(),
                old_gas_account: event.old_gas_account.require()?.into(),
                new_gas_account: event.new_gas_account.require()?.into(),
                baker_reward: event.baker_reward.require()?.into(),
                foundation_charge: event.foundation_charge.require()?.into(),
                baker: event.baker.require()?.try_into()?,
                foundation_account: event.foundation_account.require()?.try_into()?,
            },
            block_special_event::Event::PaydayFoundationReward(event) => {
                Self::PaydayFoundationReward {
                    foundation_account: event.foundation_account.require()?.try_into()?,
                    development_charge: event.development_charge.require()?.into(),
                }
            }
            block_special_event::Event::PaydayAccountReward(event) => Self::PaydayAccountReward {
                account: event.account.require()?.try_into()?,
                transaction_fees: event.transaction_fees.require()?.into(),
                baker_reward: event.baker_reward.require()?.into(),
                finalization_reward: event.finalization_reward.require()?.into(),
            },
            block_special_event::Event::BlockAccrueReward(event) => Self::BlockAccrueReward {
                transaction_fees: event.transaction_fees.require()?.into(),
                old_gas_account: event.old_gas_account.require()?.into(),
                new_gas_account: event.new_gas_account.require()?.into(),
                baker_reward: event.baker_reward.require()?.into(),
                passive_reward: event.passive_reward.require()?.into(),
                foundation_charge: event.foundation_charge.require()?.into(),
                baker_id: event.baker.require()?.into(),
            },
            block_special_event::Event::PaydayPoolReward(event) => Self::PaydayPoolReward {
                pool_owner: event.pool_owner.map(|b| b.into()),
                transaction_fees: event.transaction_fees.require()?.into(),
                baker_reward: event.baker_reward.require()?.into(),
                finalization_reward: event.finalization_reward.require()?.into(),
            },
            block_special_event::Event::ValidatorSuspended(event) => Self::ValidatorSuspended {
                baker_id: event.baker_id.require()?.into(),
                account: event.account.require()?.try_into()?,
            },
            block_special_event::Event::ValidatorPrimedForSuspension(event) => {
                Self::ValidatorPrimedForSuspension {
                    baker_id: event.baker_id.require()?.into(),
                    account: event.account.require()?.try_into()?,
                }
            }
        };
        Ok(event)
    }
}

impl TryFrom<BlockSpecialEvent> for Upward<super::types::SpecialTransactionOutcome> {
    type Error = tonic::Status;

    fn try_from(message: BlockSpecialEvent) -> Result<Self, Self::Error> {
        let event = message
            .event
            .map(super::types::SpecialTransactionOutcome::try_from)
            .transpose()?;
        Ok(Upward::from(event))
    }
}

impl<K> TryFrom<HigherLevelKeys> for updates::HigherLevelAccessStructure<K> {
    type Error = tonic::Status;

    fn try_from(message: HigherLevelKeys) -> Result<Self, Self::Error> {
        Ok(Self {
            keys: message
                .keys
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            threshold: message.threshold.require()?.try_into()?,
            _phantom: Default::default(),
        })
    }
}

impl TryFrom<ProtocolUpdate> for updates::ProtocolUpdate {
    type Error = tonic::Status;

    fn try_from(value: ProtocolUpdate) -> Result<Self, Self::Error> {
        let message = value.message;
        let specification_url = value.specification_url;
        let specification_hash = value.specification_hash.require()?.try_into()?;
        let specification_auxiliary_data = value.specification_auxiliary_data;
        Ok(Self {
            message,
            specification_url,
            specification_hash,
            specification_auxiliary_data,
        })
    }
}

impl TryFrom<ExchangeRate> for base::ExchangeRate {
    type Error = tonic::Status;

    fn try_from(value: ExchangeRate) -> Result<Self, Self::Error> {
        let ratio = value.value.require()?;
        Self::new(ratio.numerator, ratio.denominator)
            .ok_or_else(|| tonic::Status::internal("Not a valid exchange rate."))
    }
}

impl TryFrom<MintDistributionCpv0> for base::MintDistributionV0 {
    type Error = tonic::Status;

    fn try_from(value: MintDistributionCpv0) -> Result<Self, Self::Error> {
        Ok(Self {
            mint_per_slot: value.mint_per_slot.require()?.try_into()?,
            baking_reward: value.baking_reward.require()?.into(),
            finalization_reward: value.finalization_reward.require()?.into(),
        })
    }
}

impl TryFrom<MintDistributionCpv1> for base::MintDistributionV1 {
    type Error = tonic::Status;

    fn try_from(value: MintDistributionCpv1) -> Result<Self, Self::Error> {
        Ok(Self {
            baking_reward: value.baking_reward.require()?.into(),
            finalization_reward: value.finalization_reward.require()?.into(),
        })
    }
}

impl TryFrom<TransactionFeeDistribution> for updates::TransactionFeeDistribution {
    type Error = tonic::Status;

    fn try_from(value: TransactionFeeDistribution) -> Result<Self, Self::Error> {
        Ok(Self {
            baker: value.baker.require()?.into(),
            gas_account: value.gas_account.require()?.into(),
        })
    }
}

impl TryFrom<GasRewards> for updates::GASRewards {
    type Error = tonic::Status;

    fn try_from(value: GasRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            baker: value.baker.require()?.into(),
            finalization_proof: value.finalization_proof.require()?.into(),
            account_creation: value.account_creation.require()?.into(),
            chain_update: value.chain_update.require()?.into(),
        })
    }
}

impl TryFrom<GasRewardsCpv2> for updates::GASRewardsV1 {
    type Error = tonic::Status;

    fn try_from(value: GasRewardsCpv2) -> Result<Self, Self::Error> {
        Ok(Self {
            baker: value.baker.require()?.into(),
            account_creation: value.account_creation.require()?.into(),
            chain_update: value.chain_update.require()?.into(),
        })
    }
}

impl TryFrom<TimeoutParameters> for updates::TimeoutParameters {
    type Error = tonic::Status;

    fn try_from(value: TimeoutParameters) -> Result<Self, Self::Error> {
        let base = value.timeout_base.require()?.into();
        let increase = value.timeout_increase.require()?.try_into()?;
        let decrease = value.timeout_decrease.require()?.try_into()?;
        Self::new(base, increase, decrease).map_err(|err| tonic::Status::internal(err.to_string()))
    }
}

impl TryFrom<Ratio> for concordium_base::common::types::Ratio {
    type Error = tonic::Status;

    fn try_from(value: Ratio) -> Result<Self, Self::Error> {
        Self::new(value.numerator, value.denominator)
            .map_err(|err| tonic::Status::internal(err.to_string()))
    }
}

impl TryFrom<FinalizationCommitteeParameters> for updates::FinalizationCommitteeParameters {
    type Error = tonic::Status;

    fn try_from(value: FinalizationCommitteeParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            min_finalizers: value.minimum_finalizers,
            max_finalizers: value.maximum_finalizers,
            finalizers_relative_stake_threshold: value
                .finalizer_relative_stake_threshold
                .require()?
                .into(),
        })
    }
}

impl TryFrom<ValidatorScoreParameters> for updates::ValidatorScoreParameters {
    type Error = tonic::Status;

    fn try_from(value: ValidatorScoreParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            max_missed_rounds: value.maximum_missed_rounds,
        })
    }
}

impl TryFrom<PoolParametersCpv1> for updates::PoolParameters {
    type Error = tonic::Status;

    fn try_from(value: PoolParametersCpv1) -> Result<Self, Self::Error> {
        Ok(Self {
            passive_finalization_commission: value
                .passive_finalization_commission
                .require()?
                .into(),
            passive_baking_commission: value.passive_baking_commission.require()?.into(),
            passive_transaction_commission: value.passive_transaction_commission.require()?.into(),
            commission_bounds: value.commission_bounds.require()?.try_into()?,
            minimum_equity_capital: value.minimum_equity_capital.require()?.into(),
            capital_bound: value.capital_bound.require()?.try_into()?,
            leverage_bound: value.leverage_bound.require()?.try_into()?,
        })
    }
}

impl TryFrom<LeverageFactor> for super::types::LeverageFactor {
    type Error = tonic::Status;

    fn try_from(value: LeverageFactor) -> Result<Self, Self::Error> {
        let ratio = value.value.require()?;
        Self::new(ratio.numerator, ratio.denominator)
            .ok_or_else(|| tonic::Status::internal("Invalid leverage factor."))
    }
}

impl TryFrom<CommissionRanges> for super::types::CommissionRanges {
    type Error = tonic::Status;

    fn try_from(value: CommissionRanges) -> Result<Self, Self::Error> {
        Ok(Self {
            finalization: value.finalization.require()?.try_into()?,
            baking: value.baking.require()?.try_into()?,
            transaction: value.transaction.require()?.try_into()?,
        })
    }
}

impl TryFrom<BakerStakeThreshold> for updates::BakerParameters {
    type Error = tonic::Status;

    fn try_from(value: BakerStakeThreshold) -> Result<Self, Self::Error> {
        Ok(Self {
            minimum_threshold_for_baking: value.baker_stake_threshold.require()?.into(),
        })
    }
}

impl TryFrom<CooldownParametersCpv1> for updates::CooldownParameters {
    type Error = tonic::Status;

    fn try_from(value: CooldownParametersCpv1) -> Result<Self, Self::Error> {
        Ok(Self {
            pool_owner_cooldown: value.pool_owner_cooldown.require()?.into(),
            delegator_cooldown: value.delegator_cooldown.require()?.into(),
        })
    }
}

impl TryFrom<TimeParametersCpv1> for updates::TimeParameters {
    type Error = tonic::Status;

    fn try_from(value: TimeParametersCpv1) -> Result<Self, Self::Error> {
        Ok(Self {
            reward_period_length: value.reward_period_length.require()?.try_into()?,
            mint_per_payday: value.mint_per_payday.require()?.try_into()?,
        })
    }
}

impl TryFrom<RewardPeriodLength> for updates::RewardPeriodLength {
    type Error = tonic::Status;

    fn try_from(value: RewardPeriodLength) -> Result<Self, Self::Error> {
        Ok(Self::from(base::Epoch::from(value.value.require()?)))
    }
}

impl From<Epoch> for base::Epoch {
    fn from(value: Epoch) -> Self {
        Self { epoch: value.value }
    }
}

impl From<Round> for base::Round {
    fn from(value: Round) -> Self {
        Self { round: value.value }
    }
}

impl TryFrom<PendingUpdate> for super::types::queries::PendingUpdate {
    type Error = tonic::Status;

    fn try_from(message: PendingUpdate) -> Result<Self, Self::Error> {
        let effective_time = message.effective_time.require()?.into();
        let effect = message
            .effect
            .map(super::types::queries::PendingUpdateEffect::try_from)
            .transpose()?
            .into();
        Ok(Self {
            effective_time,
            effect,
        })
    }
}

impl TryFrom<pending_update::Effect> for super::types::queries::PendingUpdateEffect {
    type Error = tonic::Status;

    fn try_from(effect: pending_update::Effect) -> Result<Self, Self::Error> {
        use super::types::queries::PendingUpdateEffect;
        let out = match effect {
            pending_update::Effect::RootKeys(e) => PendingUpdateEffect::RootKeys(e.try_into()?),
            pending_update::Effect::Level1Keys(l1) => {
                PendingUpdateEffect::Level1Keys(l1.try_into()?)
            }
            pending_update::Effect::Level2KeysCpv0(l2) => {
                PendingUpdateEffect::Level2KeysCPV0(l2.try_into()?)
            }
            pending_update::Effect::Level2KeysCpv1(l2) => {
                PendingUpdateEffect::Level2KeysCPV1(l2.try_into()?)
            }
            pending_update::Effect::Protocol(p) => PendingUpdateEffect::Protocol(p.try_into()?),
            pending_update::Effect::ElectionDifficulty(ed) => {
                PendingUpdateEffect::ElectionDifficulty(ed.try_into()?)
            }
            pending_update::Effect::EuroPerEnergy(ee) => {
                PendingUpdateEffect::EuroPerEnergy(ee.try_into()?)
            }
            pending_update::Effect::MicroCcdPerEuro(mpe) => {
                PendingUpdateEffect::MicroCcdPerEnergy(mpe.try_into()?)
            }
            pending_update::Effect::FoundationAccount(fa) => {
                PendingUpdateEffect::FoundationAccount(fa.try_into()?)
            }
            pending_update::Effect::MintDistributionCpv0(md) => {
                PendingUpdateEffect::MintDistributionV0(md.try_into()?)
            }
            pending_update::Effect::MintDistributionCpv1(md) => {
                PendingUpdateEffect::MintDistributionV1(md.try_into()?)
            }
            pending_update::Effect::TransactionFeeDistribution(tfd) => {
                PendingUpdateEffect::TransactionFeeDistribution(tfd.try_into()?)
            }
            pending_update::Effect::GasRewards(gr) => {
                PendingUpdateEffect::GasRewards(gr.try_into()?)
            }
            pending_update::Effect::PoolParametersCpv0(pp) => {
                PendingUpdateEffect::PoolParametersV0(pp.try_into()?)
            }
            pending_update::Effect::PoolParametersCpv1(pp) => {
                PendingUpdateEffect::PoolParametersV1(pp.try_into()?)
            }
            pending_update::Effect::AddAnonymityRevoker(aar) => {
                PendingUpdateEffect::AddAnonymityRevoker(aar.try_into()?)
            }
            pending_update::Effect::AddIdentityProvider(aidp) => {
                PendingUpdateEffect::AddIdentityProvider(Box::new(aidp.try_into()?))
            }
            pending_update::Effect::CooldownParameters(cdp) => {
                PendingUpdateEffect::CooldownParameters(cdp.try_into()?)
            }
            pending_update::Effect::TimeParameters(tp) => {
                PendingUpdateEffect::TimeParameters(tp.try_into()?)
            }
            pending_update::Effect::GasRewardsCpv2(update) => {
                PendingUpdateEffect::GasRewardsV1(update.try_into()?)
            }
            pending_update::Effect::TimeoutParameters(update) => {
                PendingUpdateEffect::TimeoutParameters(update.try_into()?)
            }
            pending_update::Effect::MinBlockTime(update) => {
                PendingUpdateEffect::MinBlockTime(update.into())
            }
            pending_update::Effect::BlockEnergyLimit(update) => {
                PendingUpdateEffect::BlockEnergyLimit(update.into())
            }
            pending_update::Effect::FinalizationCommitteeParameters(update) => {
                PendingUpdateEffect::FinalizationCommitteeParameters(update.try_into()?)
            }
            pending_update::Effect::ValidatorScoreParameters(update) => {
                PendingUpdateEffect::ValidatorScoreParameters(update.try_into()?)
            }
        };
        Ok(out)
    }
}

impl From<SequenceNumber> for super::types::UpdateSequenceNumber {
    fn from(message: SequenceNumber) -> Self {
        message.value.into()
    }
}

impl From<UpdateSequenceNumber> for super::types::UpdateSequenceNumber {
    fn from(message: UpdateSequenceNumber) -> Self {
        message.value.into()
    }
}

impl TryFrom<NextUpdateSequenceNumbers> for super::types::queries::NextUpdateSequenceNumbers {
    type Error = tonic::Status;

    fn try_from(message: NextUpdateSequenceNumbers) -> Result<Self, Self::Error> {
        Ok(Self {
            root_keys: message.root_keys.require()?.into(),
            level_1_keys: message.level1_keys.require()?.into(),
            level_2_keys: message.level2_keys.require()?.into(),
            protocol: message.protocol.require()?.into(),
            election_difficulty: message.election_difficulty.require()?.into(),
            euro_per_energy: message.euro_per_energy.require()?.into(),
            micro_ccd_per_euro: message.micro_ccd_per_euro.require()?.into(),
            foundation_account: message.foundation_account.require()?.into(),
            mint_distribution: message.mint_distribution.require()?.into(),
            transaction_fee_distribution: message.transaction_fee_distribution.require()?.into(),
            gas_rewards: message.gas_rewards.require()?.into(),
            pool_parameters: message.pool_parameters.require()?.into(),
            add_anonymity_revoker: message.add_anonymity_revoker.require()?.into(),
            add_identity_provider: message.add_identity_provider.require()?.into(),
            cooldown_parameters: message.cooldown_parameters.require()?.into(),
            time_parameters: message.time_parameters.require()?.into(),
            timeout_parameters: message.timeout_parameters.require()?.into(),
            min_block_time: message.min_block_time.require()?.into(),
            block_energy_limit: message.block_energy_limit.require()?.into(),
            finalization_committee_parameters: message
                .finalization_committee_parameters
                .require()?
                .into(),
            validator_score_parameters: message
                .validator_score_parameters
                .map(Into::into)
                .unwrap_or_default(),
            protocol_level_tokens: message
                .protocol_level_tokens
                .map(Into::into)
                .unwrap_or_default(),
        })
    }
}

impl TryFrom<QuorumSignature> for super::types::block_certificates::QuorumSignature {
    type Error = tonic::Status;

    fn try_from(message: QuorumSignature) -> Result<Self, Self::Error> {
        consume(&message.value)
    }
}

impl TryFrom<QuorumCertificate> for super::types::block_certificates::QuorumCertificate {
    type Error = tonic::Status;

    fn try_from(message: QuorumCertificate) -> Result<Self, Self::Error> {
        Ok(Self {
            block_hash: message.block_hash.require()?.try_into()?,
            round: message.round.require()?.into(),
            epoch: message.epoch.require()?.into(),
            aggregate_signature: message.aggregate_signature.require()?.try_into()?,
            signatories: message
                .signatories
                .into_iter()
                .map(From::from)
                .collect::<BTreeSet<super::types::BakerId>>(),
        })
    }
}

impl TryFrom<SuccessorProof> for super::hashes::SuccessorProof {
    type Error = tonic::Status;

    fn try_from(message: SuccessorProof) -> Result<Self, Self::Error> {
        match message.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal(
                "Unexpected successor proof format.",
            )),
        }
    }
}

impl TryFrom<EpochFinalizationEntry> for super::types::block_certificates::EpochFinalizationEntry {
    type Error = tonic::Status;

    fn try_from(message: EpochFinalizationEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            finalized_qc: message.finalized_qc.require()?.try_into()?,
            successor_qc: message.successor_qc.require()?.try_into()?,
            successor_proof: message.successor_proof.require()?.try_into()?,
        })
    }
}

impl TryFrom<FinalizerRound> for super::types::block_certificates::FinalizerRound {
    type Error = tonic::Status;

    fn try_from(message: FinalizerRound) -> Result<Self, Self::Error> {
        Ok(Self {
            round: message.round.require()?.into(),
            finalizers: message
                .finalizers
                .into_iter()
                .map(From::from)
                .collect::<Vec<super::types::BakerId>>(),
        })
    }
}

impl TryFrom<TimeoutSignature> for super::types::block_certificates::TimeoutSignature {
    type Error = tonic::Status;

    fn try_from(message: TimeoutSignature) -> Result<Self, Self::Error> {
        consume(&message.value)
    }
}

impl TryFrom<TimeoutCertificate> for super::types::block_certificates::TimeoutCertificate {
    type Error = tonic::Status;

    fn try_from(message: TimeoutCertificate) -> Result<Self, Self::Error> {
        Ok(
            Self {
                round: message.round.require()?.into(),
                min_epoch: message.min_epoch.require()?.into(),
                qc_rounds_first_epoch:
                    message
                        .qc_rounds_first_epoch
                        .into_iter()
                        .map(TryFrom::try_from)
                        .collect::<Result<
                            Vec<super::types::block_certificates::FinalizerRound>,
                            tonic::Status,
                        >>()?,
                qc_rounds_second_epoch:
                    message
                        .qc_rounds_second_epoch
                        .into_iter()
                        .map(TryFrom::try_from)
                        .collect::<Result<
                            Vec<super::types::block_certificates::FinalizerRound>,
                            tonic::Status,
                        >>()?,
                aggregate_signature: message.aggregate_signature.require()?.try_into()?,
            },
        )
    }
}

impl TryFrom<BlockCertificates> for super::types::block_certificates::BlockCertificates {
    type Error = tonic::Status;

    fn try_from(message: BlockCertificates) -> Result<Self, Self::Error> {
        Ok(Self {
            quorum_certificate: message
                .quorum_certificate
                .map(TryFrom::try_from)
                .transpose()?,
            timeout_certificate: message
                .timeout_certificate
                .map(TryFrom::try_from)
                .transpose()?,
            epoch_finalization_entry: message
                .epoch_finalization_entry
                .map(TryFrom::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<WinningBaker> for super::types::WinningBaker {
    type Error = tonic::Status;

    fn try_from(wb: WinningBaker) -> Result<Self, Self::Error> {
        Ok(Self {
            round: wb.round.require()?.value.into(),
            winner: super::types::BakerId {
                id: wb.winner.require()?.value.into(),
            },
            present: wb.present,
        })
    }
}

impl TryFrom<AccountPending> for super::types::AccountPending {
    type Error = tonic::Status;

    fn try_from(pending: AccountPending) -> Result<Self, Self::Error> {
        Ok(Self {
            account_index: pending.account_index.require()?.into(),
            first_timestamp: pending.first_timestamp.require()?.into(),
        })
    }
}

impl TryFrom<BakerRewardPeriodInfo> for super::types::BakerRewardPeriodInfo {
    type Error = tonic::Status;

    fn try_from(message: BakerRewardPeriodInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            baker: message.baker.require()?.try_into()?,
            effective_stake: message.effective_stake.require()?.into(),
            commission_rates: message.commission_rates.require()?.try_into()?,
            equity_capital: message.equity_capital.require()?.into(),
            delegated_capital: message.delegated_capital.require()?.into(),
            is_finalizer: message.is_finalizer,
        })
    }
}

impl From<FinalizerIndex> for super::types::block_certificates::raw::FinalizerIndex {
    fn from(value: FinalizerIndex) -> Self {
        Self { index: value.value }
    }
}

impl TryFrom<QuorumMessage> for super::types::block_certificates::raw::QuorumMessage {
    type Error = tonic::Status;

    fn try_from(message: QuorumMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            signature: message.signature.require()?.try_into()?,
            block: message.block.require()?.try_into()?,
            finalizer: message.finalizer.require()?.into(),
            round: message.round.require()?.into(),
            epoch: message.epoch.require()?.into(),
        })
    }
}

impl TryFrom<RawQuorumCertificate> for super::types::block_certificates::raw::QuorumCertificate {
    type Error = tonic::Status;

    fn try_from(value: RawQuorumCertificate) -> Result<Self, Self::Error> {
        Ok(Self {
            block_hash: value.block_hash.require()?.try_into()?,
            round: value.round.require()?.into(),
            epoch: value.epoch.require()?.into(),
            aggregate_signature: value.aggregate_signature.require()?.try_into()?,
            signatories: value.signatories.into_iter().map(From::from).collect(),
        })
    }
}

impl TryFrom<RawTimeoutCertificate> for super::types::block_certificates::raw::TimeoutCertificate {
    type Error = tonic::Status;

    fn try_from(value: RawTimeoutCertificate) -> Result<Self, Self::Error> {
        Ok(Self {
            round: value.round.require()?.into(),
            min_epoch: value.min_epoch.require()?.into(),
            qc_rounds_first_epoch: value
                .qc_rounds_first_epoch
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            qc_rounds_second_epoch: value
                .qc_rounds_second_epoch
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            aggregate_signature: value.aggregate_signature.require()?.try_into()?,
        })
    }
}

impl TryFrom<RawFinalizerRound> for super::types::block_certificates::raw::FinalizerRound {
    type Error = tonic::Status;

    fn try_from(value: RawFinalizerRound) -> Result<Self, Self::Error> {
        Ok(Self {
            round: value.round.require()?.into(),
            finalizers: value.finalizers.into_iter().map(From::from).collect(),
        })
    }
}

impl TryFrom<BlockSignature> for super::types::block_certificates::raw::BlockSignature {
    type Error = tonic::Status;

    fn try_from(message: BlockSignature) -> Result<Self, Self::Error> {
        consume(&message.value)
    }
}

impl TryFrom<TimeoutMessage> for super::types::block_certificates::raw::TimeoutMessage {
    type Error = tonic::Status;

    fn try_from(value: TimeoutMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            finalizer: value.finalizer.require()?.into(),
            round: value.round.require()?.into(),
            epoch: value.epoch.require()?.into(),
            quorum_certificate: value.quorum_certificate.require()?.try_into()?,
            signature: value.signature.require()?.try_into()?,
            message_signature: value.message_signature.require()?.try_into()?,
        })
    }
}

impl TryFrom<RawFinalizationEntry> for super::types::block_certificates::raw::FinalizationEntry {
    type Error = tonic::Status;

    fn try_from(value: RawFinalizationEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            finalized_qc: value.finalized_qc.require()?.try_into()?,
            successor_qc: value.successor_qc.require()?.try_into()?,
            successor_proof: value.successor_proof.require()?.try_into()?,
        })
    }
}

impl TryFrom<TimeoutMessages> for super::types::block_certificates::raw::TimeoutMessages {
    type Error = tonic::Status;

    fn try_from(value: TimeoutMessages) -> Result<Self, Self::Error> {
        Ok(Self {
            first_epoch: value.first_epoch.require()?.into(),
            first_epoch_timeouts: value
                .first_epoch_timeouts
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            second_epoch_timeouts: value
                .second_epoch_timeouts
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<PersistentRoundStatus> for super::types::queries::PersistentRoundStatus {
    type Error = tonic::Status;

    fn try_from(value: PersistentRoundStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            last_signed_quorum_message: value
                .last_signed_quorum_message
                .map(TryFrom::try_from)
                .transpose()?,
            last_signed_timeout_message: value
                .last_signed_timeout_message
                .map(TryFrom::try_from)
                .transpose()?,
            last_baked_round: value.last_baked_round.require()?.into(),
            latest_timeout: value.latest_timeout.map(TryFrom::try_from).transpose()?,
        })
    }
}

impl TryFrom<RoundTimeout> for super::types::queries::RoundTimeout {
    type Error = tonic::Status;

    fn try_from(value: RoundTimeout) -> Result<Self, Self::Error> {
        Ok(Self {
            timeout_certificate: value.timeout_certificate.require()?.try_into()?,
            quorum_certificate: value.quorum_certificate.require()?.try_into()?,
        })
    }
}

impl TryFrom<RoundStatus> for super::types::queries::RoundStatus {
    type Error = tonic::Status;

    fn try_from(value: RoundStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            current_round: value.current_round.require()?.into(),
            highest_certified_block: value.highest_certified_block.require()?.try_into()?,
            previous_round_timeout: value
                .previous_round_timeout
                .map(TryFrom::try_from)
                .transpose()?,
            round_eligible_to_bake: value.round_eligible_to_bake,
            current_epoch: value.current_epoch.require()?.into(),
            last_epoch_finalization_entry: value
                .last_epoch_finalization_entry
                .map(TryFrom::try_from)
                .transpose()?,
            current_timeout: value.current_timeout.require()?.into(),
        })
    }
}

impl TryFrom<BlockTableSummary> for super::types::queries::BlockTableSummary {
    type Error = tonic::Status;

    fn try_from(value: BlockTableSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            dead_block_cache_size: value.dead_block_cache_size,
            live_blocks: value
                .live_blocks
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<RoundExistingBlock> for super::types::queries::RoundExistingBlock {
    type Error = tonic::Status;

    fn try_from(value: RoundExistingBlock) -> Result<Self, Self::Error> {
        Ok(Self {
            round: value.round.require()?.into(),
            baker: value.baker.require()?.into(),
            block: value.block.require()?.try_into()?,
        })
    }
}

impl TryFrom<RoundExistingQc> for super::types::queries::RoundExistingQC {
    type Error = tonic::Status;

    fn try_from(value: RoundExistingQc) -> Result<Self, Self::Error> {
        Ok(Self {
            round: value.round.require()?.into(),
            epoch: value.epoch.require()?.into(),
        })
    }
}

impl TryFrom<FullBakerInfo> for super::types::queries::FullBakerInfo {
    type Error = tonic::Status;

    fn try_from(value: FullBakerInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            baker_identity: value.baker_identity.require()?.into(),
            election_verify_key: value.election_verify_key.require()?.try_into()?,
            signature_verify_key: value.signature_verify_key.require()?.try_into()?,
            aggregation_verify_key: value.aggregation_verify_key.require()?.try_into()?,
            stake: value.stake.require()?.into(),
        })
    }
}

impl TryFrom<FinalizationCommitteeHash> for concordium_base::hashes::FinalizationCommitteeHash {
    type Error = tonic::Status;

    fn try_from(value: FinalizationCommitteeHash) -> Result<Self, Self::Error> {
        match value.value.try_into() {
            Ok(hash) => Ok(Self::new(hash)),
            Err(_) => Err(tonic::Status::internal(
                "Unexpected finalization committee hash format.",
            )),
        }
    }
}

impl TryFrom<BakersAndFinalizers> for super::types::queries::BakersAndFinalizers {
    type Error = tonic::Status;

    fn try_from(value: BakersAndFinalizers) -> Result<Self, Self::Error> {
        Ok(Self {
            bakers: value
                .bakers
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            finalizers: value.finalizers.into_iter().map(From::from).collect(),
            baker_total_stake: value.baker_total_stake.require()?.into(),
            finalizer_total_stake: value.finalizer_total_stake.require()?.into(),
            finalization_committee_hash: value.finalization_committee_hash.require()?.try_into()?,
        })
    }
}

impl TryFrom<EpochBakers> for super::types::queries::EpochBakers {
    type Error = tonic::Status;

    fn try_from(value: EpochBakers) -> Result<Self, Self::Error> {
        Ok(Self {
            previous_epoch_bakers: value.previous_epoch_bakers.require()?.try_into()?,
            current_epoch_bakers: value
                .current_epoch_bakers
                .map(TryFrom::try_from)
                .transpose()?,
            next_epoch_bakers: value.next_epoch_bakers.map(TryFrom::try_from).transpose()?,
            next_payday: value.next_payday.require()?.into(),
        })
    }
}

impl TryFrom<BranchBlocks> for Vec<super::BlockHash> {
    type Error = tonic::Status;

    fn try_from(value: BranchBlocks) -> Result<Self, Self::Error> {
        value
            .blocks_at_branch_height
            .into_iter()
            .map(TryFrom::try_from)
            .collect()
    }
}

impl TryFrom<ConsensusDetailedStatus> for super::types::queries::ConsensusDetailedStatus {
    type Error = tonic::Status;

    fn try_from(value: ConsensusDetailedStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            genesis_block: value.genesis_block.require()?.try_into()?,
            persistent_round_status: value.persistent_round_status.require()?.try_into()?,
            round_status: value.round_status.require()?.try_into()?,
            non_finalized_transaction_count: value.non_finalized_transaction_count,
            transaction_table_purge_counter: value.transaction_table_purge_counter,
            block_table: value.block_table.require()?.try_into()?,
            branches: value
                .branches
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            round_existing_blocks: value
                .round_existing_blocks
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            round_existing_qcs: value
                .round_existing_qcs
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            genesis_block_height: value.genesis_block_height.require()?.into(),
            last_finalized_block: value.last_finalized_block.require()?.try_into()?,
            last_finalized_block_height: value.last_finalized_block_height.require()?.into(),
            latest_finalization_entry: value
                .latest_finalization_entry
                .map(TryFrom::try_from)
                .transpose()?,
            epoch_bakers: value.epoch_bakers.require()?.try_into()?,
            timeout_messages: value.timeout_messages.map(TryFrom::try_from).transpose()?,
            terminal_block: value.terminal_block.map(TryFrom::try_from).transpose()?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_try_from_branch() {
        use crate::types::queries::Branch as QBranch;

        let from = Branch {
            block_hash: Some(BlockHash {
                value: vec![0u8; 32],
            }),
            children: vec![
                Branch {
                    block_hash: Some(BlockHash {
                        value: vec![1u8; 32],
                    }),
                    children: vec![],
                },
                Branch {
                    block_hash: Some(BlockHash {
                        value: vec![2u8; 32],
                    }),
                    children: vec![Branch {
                        block_hash: Some(BlockHash {
                            value: vec![3u8; 32],
                        }),
                        children: vec![],
                    }],
                },
            ],
        };

        let to_target = QBranch {
            block_hash: [0u8; 32].into(),
            children: vec![
                QBranch {
                    block_hash: [2u8; 32].into(),
                    children: vec![QBranch {
                        block_hash: [3u8; 32].into(),
                        children: vec![],
                    }],
                },
                QBranch {
                    block_hash: [1u8; 32].into(),
                    children: vec![],
                },
            ],
        };
        let to = QBranch::try_from(from).expect("Failed to convert branch");

        assert_eq!(to, to_target);
    }
}
