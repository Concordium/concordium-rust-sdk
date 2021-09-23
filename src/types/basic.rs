use crypto_common::{
    derive::{SerdeBase16Serialize, Serial, Serialize},
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

/// Internal short id of the baker.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct BakerId {
    pub id: u64,
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
            version => Err(UnknownProtocolVersion { version }),
        }
    }
}

impl From<ProtocolVersion> for u64 {
    fn from(pv: ProtocolVersion) -> Self {
        match pv {
            ProtocolVersion::P1 => 1,
            ProtocolVersion::P2 => 2,
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

/// Height of a block since chain genesis.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into)]
pub struct AbsoluteBlockHeight {
    pub height: u64,
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
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into, Default,
)]
/// Contract index. The default implementation produces contract index 0.
pub struct ContractIndex {
    pub index: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(transparent)]
#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, FromStr, Display, From, Into, Default,
)]
/// Contract subindex. The default implementation produces contract index 0.
pub struct ContractSubIndex {
    pub sub_index: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
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

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(transparent)]
/// A single public key that can sign updates.
pub struct UpdatePublicKey {
    public: id::types::VerifyKey,
}

#[derive(Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
pub struct UpdateKeysThreshold {
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    threshold: u16,
}

#[derive(Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct UpdateKeysIndex {
    pub index: u16,
}

#[derive(Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
pub struct ElectionDifficulty {
    parts_per_hundred_thousands: PartsPerHundredThousands,
}

#[derive(Debug, Clone, Copy)]
pub struct PartsPerHundredThousands {
    parts: u32,
}

/// Display the value as a fraction.
impl fmt::Display for PartsPerHundredThousands {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x = rust_decimal::Decimal::try_new(self.parts.into(), 5).map_err(|_| fmt::Error)?;
        x.fmt(f)
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
pub struct ExchangeRate {
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    pub numerator:   u64,
    #[serde(deserialize_with = "crate::internal::deserialize_non_default::deserialize")]
    pub denominator: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MintDistribution {
    mint_per_slot:       MintRate,
    baking_reward:       RewardFraction,
    finalization_reward: RewardFraction,
}

#[derive(Debug, Clone, Copy)]
pub struct MintRate {
    pub mantissa: u32,
    pub exponent: u8,
}

#[derive(Debug, Clone, Copy, SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
pub struct RewardFraction {
    parts_per_hundred_thousands: PartsPerHundredThousands,
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
impl std::ops::Add for RewardFraction {
    type Output = Option<Self>;

    fn add(self, rhs: Self) -> Self::Output {
        let parts_per_hundred_thousands =
            (self.parts_per_hundred_thousands + rhs.parts_per_hundred_thousands)?;
        Some(RewardFraction {
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
