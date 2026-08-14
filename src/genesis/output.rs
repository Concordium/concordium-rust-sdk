//! Output types returned by genesis builders.
use super::types::{
    GenesisAccount, GenesisAccountPublic, GenesisData, UpdateKeysCollectionCPV0,
    UpdateKeysCollectionCPV1,
};
use crate::types::{BakerCredentials, UpdateKeyPair};
use concordium_base::id::{
    constants::{ArCurve, IpPairing},
    types::{ArIdentity, ArInfo, GlobalContext, IpIdentity, IpInfo},
};
use std::collections::BTreeMap;

// Re-export relevant SDK types for callers
pub use concordium_base::id::types::{ArData, IpData};

/// A freshly generated governance key pair and its index in the key array.
#[derive(Debug)]
pub struct GeneratedKeyPair {
    /// Zero-based index of this key in its level's key array
    /// (accounting for pre-existing keys that came before it).
    pub index: usize,
    /// The generated key pair (contains both public and private key).
    pub key_pair: UpdateKeyPair,
}

/// The shared output produced by `GenesisBuilderCPV*::build`.
///
/// Contains every artifact that went into the genesis block.
pub struct GenesisOutputCPV<GK> {
    /// Global cryptographic parameters (generators, commitment keys).
    pub crypto_params: GlobalContext<ArCurve>,
    /// Full identity provider data for IPs supplied as `ExistingFull` or freshly
    /// generated. Empty in assemble mode (public-only inputs).
    pub identity_provider_data: Vec<IpData<IpPairing>>,
    /// Public identity provider info for all IPs (always populated).
    pub identity_provider_infos: BTreeMap<IpIdentity, IpInfo<IpPairing>>,
    /// Full anonymity revoker data for ARs supplied as `ExistingFull` or freshly
    /// generated. Empty in assemble mode.
    pub anonymity_revoker_data: Vec<ArData<ArCurve>>,
    /// Public anonymity revoker info for all ARs (always populated).
    pub anonymity_revoker_infos: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
    /// Full account data for accounts supplied as `ExistingFull` or freshly
    /// generated. Empty in assemble mode.
    pub account_data: Vec<GenesisAccount>,
    /// Public account data for all accounts (always populated).
    pub accounts_public: Vec<GenesisAccountPublic>,
    /// Baker credentials for all baker accounts.
    pub baker_credentials: Vec<BakerCredentials>,
    /// The governance key collection.
    pub governance_keys: GK,
    /// Freshly generated root-level key pairs with their positions. Empty when
    /// governance keys were supplied pre-existing.
    pub generated_root_key_pairs: Vec<GeneratedKeyPair>,
    /// Freshly generated level-1 key pairs with their positions.
    pub generated_level1_key_pairs: Vec<GeneratedKeyPair>,
    /// Freshly generated level-2 key pairs with their positions.
    pub generated_level2_key_pairs: Vec<GeneratedKeyPair>,
    /// The assembled genesis block value.
    pub genesis_data: GenesisData,
}

/// The output produced by [`super::GenesisBuilderCPV0::build`].
///
/// Contains every artifact that went into the genesis block — including
/// pre-existing ones echoed back — plus the typed [`GenesisData`] value.
/// Governance keys are typed for CPV0 ([`AuthorizationsV0`](crate::types::AuthorizationsV0)),
/// covering P1–P3.
pub type GenesisOutputCPV0 = GenesisOutputCPV<UpdateKeysCollectionCPV0>;

/// The output produced by [`super::GenesisBuilderCPV1::build`].
///
/// Contains every artifact that went into the genesis block — including
/// pre-existing ones echoed back — plus the typed [`GenesisData`] value.
/// Governance keys are typed for CPV1 ([`AuthorizationsV1`](crate::types::AuthorizationsV1),
/// `create_plt` must be absent). Covers P4 (CPV1 chain parameters) and P5.
pub type GenesisOutputCPV1 = GenesisOutputCPV<UpdateKeysCollectionCPV1>;

/// The output produced by [`super::GenesisBuilderCPV2::build`].
///
/// Contains every artifact that went into the genesis block — including
/// pre-existing ones echoed back — plus the typed [`GenesisData`] value.
/// Governance keys are typed for CPV2 ([`AuthorizationsV1`](crate::types::AuthorizationsV1),
/// `create_plt` must be absent). Covers P6–P7.
pub type GenesisOutputCPV2 = GenesisOutputCPV<UpdateKeysCollectionCPV1>;

/// The output produced by [`super::GenesisBuilderCPV3::build`].
///
/// Contains every artifact that went into the genesis block — including
/// pre-existing ones echoed back — plus the typed [`GenesisData`] value.
/// Governance keys are typed for CPV3 ([`AuthorizationsV1`](crate::types::AuthorizationsV1)).
/// P8 omits `create_plt`; P9–P10 require `create_plt`; P11 additionally requires
/// `token_parameters` authorization and a `max_lock_duration` chain parameter.
pub type GenesisOutputCPV3 = GenesisOutputCPV<UpdateKeysCollectionCPV1>;
