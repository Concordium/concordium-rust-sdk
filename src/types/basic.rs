use crypto_common::{
    derive::{SerdeBase16Serialize, Serial, Serialize},
    deserial_string,
    types::Amount,
    Buffer, Deserial, Get, ParseResult, Put, ReadBytesExt, SerdeDeserialize, SerdeSerialize,
    Serial,
};
use derive_more::{Add, Display, From, FromStr, Into};
use rand::{CryptoRng, Rng};
use random_oracle::RandomOracle;
use std::{convert::TryFrom, fmt};
use thiserror::Error;

/// Duration of a slot in milliseconds.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct SlotDuration {
    pub millis: u64,
}

impl From<SlotDuration> for chrono::Duration {
    fn from(s: SlotDuration) -> Self {
        // this is technically iffy in cases
        // where slot duration would exceed
        // i64::MAX. But that will not
        // happen.
        Self::milliseconds(s.millis as i64)
    }
}

/// Duration in seconds.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct DurationSeconds {
    pub seconds: u64,
}

impl From<DurationSeconds> for chrono::Duration {
    fn from(s: DurationSeconds) -> Self {
        // this is technically iffy in cases
        // where duration would exceed
        // i64::MAX. But that will not
        // happen.
        Self::seconds(s.seconds as i64)
    }
}

/// Internal short id of the baker.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct BakerId {
    pub id: AccountIndex,
}

/// Internal short id of the delegator.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct DelegatorId {
    pub id: AccountIndex,
}

/// A unicode representation of a Url.
/// The Utf8 encoding of the Url must be at most
/// [`MAX_URL_TEXT_LENGTH`](crate::constants::MAX_URL_TEXT_LENGTH) bytes.
#[derive(
    SerdeSerialize,
    SerdeDeserialize,
    Serial,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Debug,
    Display,
    Into,
)]
#[serde(try_from = "String", into = "String")]
pub struct UrlText {
    #[string_size_length = 2]
    url: String,
}

impl Deserial for UrlText {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        anyhow::ensure!(
            usize::from(len) <= crate::constants::MAX_URL_TEXT_LENGTH,
            "URL length exceeds maximum allowed."
        );
        let url = deserial_string(source, len.into())?;
        Ok(Self { url })
    }
}

impl TryFrom<String> for UrlText {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        anyhow::ensure!(
            value.as_bytes().len() <= crate::constants::MAX_URL_TEXT_LENGTH,
            "URL length exceeds maximum allowed."
        );
        Ok(Self { url: value })
    }
}

/// The status of whether a baking pool allows delegators to join.
#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
#[repr(u8)]
pub enum OpenStatus {
    /// New delegators may join the pool.
    OpenForAll   = 0,
    /// New delegators may not join, but existing delegators are kept.
    ClosedForNew = 1,
    /// No delegators are allowed.
    ClosedForAll = 2,
}

impl Serial for OpenStatus {
    fn serial<B: Buffer>(&self, out: &mut B) { (*self as u8).serial(out) }
}

impl Deserial for OpenStatus {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        match tag {
            0 => Ok(Self::OpenForAll),
            1 => Ok(Self::ClosedForNew),
            2 => Ok(Self::ClosedForAll),
            _ => anyhow::bail!("Unrecognized OpenStatus tag {}", tag),
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", tag = "delegateType")]
pub enum DelegationTarget {
    #[serde(rename = "L-Pool")]
    /// Delegate to the lock-up pool.
    LPool,
    #[serde(rename = "Baker")]
    /// Delegate to a specific baker.
    Baker {
        #[serde(rename = "bakerId")]
        baker_id: BakerId,
    },
}

impl Serial for DelegationTarget {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            DelegationTarget::LPool => 0u8.serial(out),
            DelegationTarget::Baker { baker_id } => {
                1u8.serial(out);
                baker_id.serial(out)
            }
        }
    }
}

impl Deserial for DelegationTarget {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        match tag {
            0 => Ok(Self::LPool),
            1 => {
                let baker_id = source.get()?;
                Ok(Self::Baker { baker_id })
            }
            _ => anyhow::bail!("Unrecognized delegation target tag: {}", tag),
        }
    }
}

/// Additional information about a baking pool.
/// This information is added with the introduction of delegation.
#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BakerPoolInfo {
    /// Whether the pool allows delegators.
    open_status:      OpenStatus,
    /// The URL that links to the metadata about the pool.
    metadata_url:     UrlText,
    /// The commission rates charged by the pool owner.
    commission_rates: CommissionRates,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
/// Information about the delegated stake of the account.
pub struct AccountStakingDelegationInfo {
    staked_amount:     Amount,
    restake_earnings:  bool,
    delegation_target: BakerId,
}

/// Slot number
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct Slot {
    pub slot: u64,
}

/// Epoch number
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct Epoch {
    pub epoch: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct Nonce {
    pub nonce: u64,
}

impl Nonce {
    /// Get the next nonce.
    pub fn next(self) -> Self {
        Self {
            nonce: self.nonce + 1,
        }
    }

    /// Increase the nonce to the next nonce.
    pub fn next_mut(&mut self) { self.nonce += 1; }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
/// Equivalent of a transaction nonce but for update instructions. Update
/// sequence numbers are per update type.
pub struct UpdateSequenceNumber {
    pub number: u64,
}

impl UpdateSequenceNumber {
    /// Get the next sequence number. This is marked as must_use to prevent
    /// mistakes in combination with next_mut.
    #[must_use]
    pub fn next(self) -> Self {
        Self {
            number: self.number + 1,
        }
    }

    /// Increase the sequence number.
    pub fn next_mut(&mut self) { self.number += 1; }
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Into, Serial)]
/// The minimum number of credentials that need to sign any transaction coming
/// from an associated account.
pub struct AccountThreshold {
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    threshold: u8,
}

impl Deserial for AccountThreshold {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let threshold: u8 = source.get()?;
        anyhow::ensure!(threshold != 0, "Account threshold cannot be 0.");
        Ok(AccountThreshold { threshold })
    }
}

impl TryFrom<u8> for AccountThreshold {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == 0 {
            Err("Account threshold cannot be 0.")
        } else {
            Ok(AccountThreshold { threshold: value })
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct CredentialsPerBlockLimit {
    pub limit: u16,
}

/// Height of a block. Last genesis block is at height 0, a child of a block at
/// height n is at height n+1. This height counts from the last protocol update.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct BlockHeight {
    pub height: u64,
}

/// Type indicating the index of a (re)genesis block.
/// The initial genesis block has index `0` and each subsequent regenesis
/// has an incrementally higher index.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct GenesisIndex {
    pub height: u32,
}

/// An enumeration of the supported versions of the consensus protocol.
/// Binary and JSON serializations are as Word64 corresponding to the protocol
/// number.
#[derive(
    SerdeSerialize, SerdeDeserialize, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Display,
)]
#[serde(into = "u64", try_from = "u64")]
pub enum ProtocolVersion {
    #[display(fmt = "P1")]
    P1,
    #[display(fmt = "P2")]
    P2,
    #[display(fmt = "P3")]
    P3,
    #[display(fmt = "P4")]
    P4,
}

#[derive(Debug, Error, Display)]
/// A structure to represent conversion errors when converting integers to
/// protocol versions.
pub struct UnknownProtocolVersion {
    /// The version that was attempted to be converted, but is not supported.
    version: u64,
}

impl TryFrom<u64> for ProtocolVersion {
    type Error = UnknownProtocolVersion;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProtocolVersion::P1),
            2 => Ok(ProtocolVersion::P2),
            3 => Ok(ProtocolVersion::P3),
            4 => Ok(ProtocolVersion::P4),
            version => Err(UnknownProtocolVersion { version }),
        }
    }
}

impl From<ProtocolVersion> for u64 {
    fn from(pv: ProtocolVersion) -> Self {
        match pv {
            ProtocolVersion::P1 => 1,
            ProtocolVersion::P2 => 2,
            ProtocolVersion::P3 => 3,
            ProtocolVersion::P4 => 4,
        }
    }
}

impl Serial for ProtocolVersion {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let n: u64 = (*self).into();
        out.put(&n);
    }
}

impl Deserial for ProtocolVersion {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let n: u64 = source.get()?;
        let pv = ProtocolVersion::try_from(n)?;
        Ok(pv)
    }
}

pub struct ChainParameterVersion0;
pub struct ChainParameterVersion1;

/// Height of a block since chain genesis.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct AbsoluteBlockHeight {
    pub height: u64,
}

impl AbsoluteBlockHeight {
    /// Get the next height.
    pub fn next(self) -> Self {
        AbsoluteBlockHeight {
            height: 1 + self.height,
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
/// Index of the account in the account table. These are assigned sequentially
/// in the order of creation of accounts. The first account has index 0.
pub struct AccountIndex {
    pub index: u64,
}

/// Energy measure.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into, Add)]
pub struct Energy {
    pub energy: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into, Default, Hash,
)]
/// Contract index. The default implementation produces contract index 0.
pub struct ContractIndex {
    pub index: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into, Default, Hash,
)]
/// Contract subindex. The default implementation produces contract index 0.
pub struct ContractSubIndex {
    pub sub_index: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct ContractAddress {
    pub index:    ContractIndex,
    pub subindex: ContractSubIndex,
}

impl ContractAddress {
    pub fn new(index: ContractIndex, subindex: ContractSubIndex) -> Self {
        Self { index, subindex }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "type", content = "address")]
/// Either an account or contract address. Some operations are allowed on both
/// types of items, hence the need for this type.
pub enum Address {
    #[serde(rename = "AddressAccount")]
    Account(id::types::AccountAddress),
    #[serde(rename = "AddressContract")]
    Contract(ContractAddress),
}

/// Position of the transaction in a block.
#[derive(SerdeSerialize, SerdeDeserialize, Debug, Serialize, Clone, Copy)]
#[serde(transparent)]
pub struct TransactionIndex {
    pub index: u64,
}

pub type AggregateSigPairing = id::constants::IpPairing;

/// FIXME: Move higher up in the dependency
#[derive(SerdeBase16Serialize, Serialize)]
pub struct BakerAggregationSignKey {
    pub(crate) sign_key: aggregate_sig::SecretKey<AggregateSigPairing>,
}

impl BakerAggregationSignKey {
    pub fn generate<T: Rng>(csprng: &mut T) -> Self {
        Self {
            sign_key: aggregate_sig::SecretKey::generate(csprng),
        }
    }

    /// Prove knowledge of the baker aggregation signing key with respect to the
    /// challenge given via the random oracle.
    pub fn prove<T: Rng>(
        &self,
        csprng: &mut T,
        random_oracle: &mut RandomOracle,
    ) -> aggregate_sig::Proof<AggregateSigPairing> {
        self.sign_key.prove(csprng, random_oracle)
    }
}

/// FIXME: Move higher up in the dependency
#[derive(SerdeBase16Serialize, Serialize, Clone, Debug)]
pub struct BakerAggregationVerifyKey {
    pub(crate) verify_key: aggregate_sig::PublicKey<AggregateSigPairing>,
}

impl From<&BakerAggregationSignKey> for BakerAggregationVerifyKey {
    fn from(secret: &BakerAggregationSignKey) -> Self {
        Self {
            verify_key: aggregate_sig::PublicKey::from_secret(&secret.sign_key),
        }
    }
}

/// FIXME: Move higher up in the dependency
#[derive(SerdeBase16Serialize, Serialize)]
pub struct BakerSignatureSignKey {
    pub(crate) sign_key: ed25519_dalek::SecretKey,
}

impl BakerSignatureSignKey {
    pub fn generate<T: CryptoRng + Rng>(csprng: &mut T) -> Self {
        Self {
            sign_key: ed25519_dalek::SecretKey::generate(csprng),
        }
    }
}

/// FIXME: Move higher up in the dependency
#[derive(SerdeBase16Serialize, Serialize, Clone, Debug)]
pub struct BakerSignatureVerifyKey {
    pub(crate) verify_key: ed25519_dalek::PublicKey,
}

impl From<&BakerSignatureSignKey> for BakerSignatureVerifyKey {
    fn from(secret: &BakerSignatureSignKey) -> Self {
        Self {
            verify_key: ed25519_dalek::PublicKey::from(&secret.sign_key),
        }
    }
}

/// FIXME: Move higher up in the dependency
#[derive(SerdeBase16Serialize, Serialize)]
pub struct BakerElectionSignKey {
    pub(crate) sign_key: ecvrf::SecretKey,
}

impl BakerElectionSignKey {
    pub fn generate<T: CryptoRng + Rng>(csprng: &mut T) -> Self {
        Self {
            sign_key: ecvrf::SecretKey::generate(csprng),
        }
    }
}

/// FIXME: Move higher up in the dependency
#[derive(SerdeBase16Serialize, Serialize, Clone, Debug)]
pub struct BakerElectionVerifyKey {
    pub(crate) verify_key: ecvrf::PublicKey,
}

impl From<&BakerElectionSignKey> for BakerElectionVerifyKey {
    fn from(secret: &BakerElectionSignKey) -> Self {
        Self {
            verify_key: ecvrf::PublicKey::from(&secret.sign_key),
        }
    }
}

/// Baker keys containing both public and secret keys.
/// This is used to construct `BakerKeysPayload` for adding and updating baker
/// keys. It is also used to build the `BakerCredentials` required to have a
/// concordium node running as a baker.
///
/// Note: This type contains unencrypted secret keys and should be treated
/// carefully.
#[derive(SerdeSerialize, Serialize)]
pub struct BakerKeyPairs {
    #[serde(rename = "signatureSignKey")]
    pub signature_sign:     BakerSignatureSignKey,
    #[serde(rename = "signatureVerifyKey")]
    pub signature_verify:   BakerSignatureVerifyKey,
    #[serde(rename = "electionPrivateKey")]
    pub election_sign:      BakerElectionSignKey,
    #[serde(rename = "electionVerifyKey")]
    pub election_verify:    BakerElectionVerifyKey,
    #[serde(rename = "aggregationSignKey")]
    pub aggregation_sign:   BakerAggregationSignKey,
    #[serde(rename = "aggregationVerifyKey")]
    pub aggregation_verify: BakerAggregationVerifyKey,
}

impl BakerKeyPairs {
    /// Generate key pairs needed for becoming a baker.
    pub fn generate<T: Rng + CryptoRng>(csprng: &mut T) -> Self {
        let signature_sign = BakerSignatureSignKey::generate(csprng);
        let signature_verify = BakerSignatureVerifyKey::from(&signature_sign);
        let election_sign = BakerElectionSignKey::generate(csprng);
        let election_verify = BakerElectionVerifyKey::from(&election_sign);
        let aggregation_sign = BakerAggregationSignKey::generate(csprng);
        let aggregation_verify = BakerAggregationVerifyKey::from(&aggregation_sign);
        BakerKeyPairs {
            signature_sign,
            signature_verify,
            election_sign,
            election_verify,
            aggregation_sign,
            aggregation_verify,
        }
    }
}

/// Baker credentials type, which can be serialized to JSON and used by a
/// concordium-node for baking.
///
/// Note: This type contains unencrypted secret keys and should be treated
/// carefully.
#[derive(SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub struct BakerCredentials {
    baker_id: BakerId,
    #[serde(flatten)]
    keys:     BakerKeyPairs,
}

impl BakerCredentials {
    pub fn new(baker_id: BakerId, keys: BakerKeyPairs) -> Self {
        BakerCredentials { baker_id, keys }
    }
}

/// FIXME: Move to somewhere else in the dependency. This belongs to rust-src.
#[derive(SerdeBase16Serialize, Serialize, Debug, Clone)]
pub struct CredentialRegistrationID(id::constants::ArCurve);

impl fmt::Display for CredentialRegistrationID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = hex::encode(&crypto_common::to_bytes(self));
        s.fmt(f)
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Serialize, Clone, Into, From)]
#[serde(transparent)]
/// A single public key that can sign updates.
pub struct UpdatePublicKey {
    pub public: id::types::VerifyKey,
}

#[derive(Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize, Serial, Into)]
#[serde(transparent)]
pub struct UpdateKeysThreshold {
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    pub(crate) threshold: u16,
}

impl Deserial for UpdateKeysThreshold {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let threshold = source.get()?;
        anyhow::ensure!(threshold != 0, "Threshold cannot be 0.");
        Ok(Self { threshold })
    }
}

#[derive(
    Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(transparent)]
pub struct UpdateKeysIndex {
    pub index: u16,
}

#[derive(Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
pub struct ElectionDifficulty {
    parts_per_hundred_thousands: PartsPerHundredThousands,
}

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq)]
pub struct PartsPerHundredThousands {
    pub(crate) parts: u32,
}

impl Serial for PartsPerHundredThousands {
    fn serial<B: Buffer>(&self, out: &mut B) { self.parts.serial(out) }
}

impl Deserial for PartsPerHundredThousands {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let parts: u32 = source.get()?;
        anyhow::ensure!(
            parts <= 100_000,
            "No more than 100_000 parts per hundred thousand."
        );
        Ok(Self { parts })
    }
}

/// Display the value as a fraction.
impl fmt::Display for PartsPerHundredThousands {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x = rust_decimal::Decimal::try_new(self.parts.into(), 5).map_err(|_| fmt::Error)?;
        x.fmt(f)
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone, Copy)]
pub struct CommissionRates {
    /// Fraction of finalization rewards charged by the pool owner.
    #[serde(rename = "finalizationCommission")]
    finalization: AmountFraction,
    /// Fraction of baking rewards charged by the pool owner.
    #[serde(rename = "bakingCommission")]
    baking:       AmountFraction,
    /// Fraction of transaction rewards charged by the pool owner.
    #[serde(rename = "transactionCommission")]
    transaction:  AmountFraction,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
/// Ranges of allowed commission values that pools may choose from.
pub struct CommissionRanges {
    /// The range of allowed finalization commissions.
    #[serde(rename = "finalizationCommissionRange")]
    finalization: InclusiveRange<AmountFraction>,
    /// The range of allowed baker commissions.
    #[serde(rename = "bakingCommissionRange")]
    baking:       InclusiveRange<AmountFraction>,
    /// The range of allowed transaction commissions.
    #[serde(rename = "transactionCommissionRange")]
    transaction:  InclusiveRange<AmountFraction>,
}

#[derive(Debug, Copy, Clone, SerdeSerialize, SerdeDeserialize)]
pub struct InclusiveRange<T> {
    min: T,
    max: T,
}

impl<T: Ord> InclusiveRange<T> {
    pub fn contains(&self, x: &T) -> bool { &self.min <= x && x <= &self.max }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone, Copy)]
pub struct ExchangeRate {
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    pub numerator:   u64,
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    pub denominator: u64,
}

impl Deserial for ExchangeRate {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let numerator = source.get()?;
        let denominator = source.get()?;
        anyhow::ensure!(
            numerator != 0 && denominator != 0 && num::integer::gcd(numerator, denominator) == 1,
            "Invalid exchange rate."
        );
        Ok(Self {
            numerator,
            denominator,
        })
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone, Copy)]
#[serde(try_from = "leverage_factor_json::LeverageFactorRaw")]
pub struct LeverageFactor {
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    pub numerator:   u64,
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    pub denominator: u64,
}

mod leverage_factor_json {
    #[derive(super::SerdeDeserialize)]
    pub struct LeverageFactorRaw {
        pub numerator:   u64,
        pub denominator: u64,
    }

    impl std::convert::TryFrom<LeverageFactorRaw> for super::LeverageFactor {
        type Error = anyhow::Error;

        fn try_from(value: LeverageFactorRaw) -> Result<Self, Self::Error> {
            let numerator = value.numerator;
            let denominator = value.denominator;
            anyhow::ensure!(
                numerator >= denominator
                    && denominator != 0
                    && num::integer::gcd(numerator, denominator) == 1,
                "Invalid leverage factor."
            );
            Ok(super::LeverageFactor {
                numerator,
                denominator,
            })
        }
    }
}

impl Deserial for LeverageFactor {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let numerator = source.get()?;
        let denominator = source.get()?;
        anyhow::ensure!(
            numerator >= denominator
                && denominator != 0
                && num::integer::gcd(numerator, denominator) == 1,
            "Invalid leverage factor."
        );
        Ok(Self {
            numerator,
            denominator,
        })
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MintDistributionV0 {
    mint_per_slot:       MintRate,
    baking_reward:       AmountFraction,
    finalization_reward: AmountFraction,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MintDistributionV1 {
    baking_reward:       AmountFraction,
    finalization_reward: AmountFraction,
}

impl Deserial for MintDistributionV0 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mint_per_slot = source.get()?;
        let baking_reward: AmountFraction = source.get()?;
        let finalization_reward: AmountFraction = source.get()?;
        anyhow::ensure!(
            (baking_reward + finalization_reward).is_some(),
            "Reward fractions exceed 100%."
        );
        Ok(Self {
            mint_per_slot,
            baking_reward,
            finalization_reward,
        })
    }
}

impl Deserial for MintDistributionV1 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let baking_reward: AmountFraction = source.get()?;
        let finalization_reward: AmountFraction = source.get()?;
        anyhow::ensure!(
            (baking_reward + finalization_reward).is_some(),
            "Reward fractions exceed 100%."
        );
        Ok(Self {
            baking_reward,
            finalization_reward,
        })
    }
}

pub trait MintDistributionFamily {
    type Output;
}

impl MintDistributionFamily for ChainParameterVersion0 {
    type Output = MintDistributionV0;
}

impl MintDistributionFamily for ChainParameterVersion1 {
    type Output = MintDistributionV1;
}

pub type MintDistribution<CPV> = <CPV as MintDistributionFamily>::Output;

#[derive(Debug, Serialize, Clone, Copy)]
pub struct MintRate {
    pub mantissa: u32,
    pub exponent: u8,
}

#[derive(
    Default, Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize, Serialize, PartialEq, Eq,
)]
#[serde(transparent)]
pub struct AmountFraction {
    pub(crate) parts_per_hundred_thousands: PartsPerHundredThousands,
}

#[derive(Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[repr(transparent)]
/// A bound on the relative share of the total staked capital that a baker can
/// have as its stake. This is required to be greater than 0.
pub struct CapitalBound {
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    pub bound: AmountFraction,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
/// Sequential index of finalization.
pub struct FinalizationIndex {
    pub index: u64,
}

/// Add two parts, checking that the result is still less than 100_000.
impl std::ops::Add for PartsPerHundredThousands {
    type Output = Option<Self>;

    fn add(self, rhs: Self) -> Self::Output {
        let parts = self.parts.checked_add(rhs.parts)?;
        if parts <= 100_000 {
            Some(PartsPerHundredThousands { parts })
        } else {
            None
        }
    }
}

/// Add two reward fractions checking that they sum up to no more than 1.
impl std::ops::Add for AmountFraction {
    type Output = Option<Self>;

    fn add(self, rhs: Self) -> Self::Output {
        let parts_per_hundred_thousands =
            (self.parts_per_hundred_thousands + rhs.parts_per_hundred_thousands)?;
        Some(AmountFraction {
            parts_per_hundred_thousands,
        })
    }
}

impl SerdeSerialize for PartsPerHundredThousands {
    /// FIXME: This instance needs to be improved and tested.
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let decimal = rust_decimal::Decimal::try_new(self.parts.into(), 5)
            .map_err(serde::ser::Error::custom)?;
        SerdeSerialize::serialize(&decimal, ser)
    }
}

impl<'de> SerdeDeserialize<'de> for PartsPerHundredThousands {
    fn deserialize<D: serde::Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        let mut f: rust_decimal::Decimal =
            SerdeDeserialize::deserialize(des).map_err(serde::de::Error::custom)?;
        f.normalize_assign();
        if f.scale() > 5 {
            return Err(serde::de::Error::custom(
                "Parts per thousand should not have more than 5 decimals.",
            ));
        }
        if !f.is_sign_positive() && !f.is_zero() {
            return Err(serde::de::Error::custom(
                "Parts per thousand should not be negative.",
            ));
        }
        f.set_scale(5).map_err(serde::de::Error::custom)?;
        if f.mantissa() > 100_000 {
            return Err(serde::de::Error::custom(
                "Parts per thousand out of bounds.",
            ));
        }
        Ok(PartsPerHundredThousands {
            parts: f.mantissa() as u32,
        })
    }
}

impl SerdeSerialize for MintRate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer, {
        let x = rust_decimal::Decimal::try_new(self.mantissa.into(), self.exponent.into())
            .map_err(serde::ser::Error::custom)?;
        SerdeSerialize::serialize(&x, serializer)
    }
}

impl<'de> SerdeDeserialize<'de> for MintRate {
    fn deserialize<D>(des: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>, {
        let mut f: rust_decimal::Decimal = SerdeDeserialize::deserialize(des)?;
        // FIXME: exponents will only be 28 at most for this type, so it is not entirely
        // compatible with the Haskell code.
        f.normalize_assign();
        if let Ok(exponent) = u8::try_from(f.scale()) {
            if let Ok(mantissa) = u32::try_from(f.mantissa()) {
                Ok(MintRate { mantissa, exponent })
            } else {
                Err(serde::de::Error::custom(
                    "Unsupported mantissa range for MintRate.",
                ))
            }
        } else {
            Err(serde::de::Error::custom(
                "Unsupported exponent range for MintRate.",
            ))
        }
    }
}
