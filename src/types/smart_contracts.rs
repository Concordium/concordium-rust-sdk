//! Types related to smart contracts.

use super::hashes;
use crate::constants::*;
/// Re-export of common helper functionality for smart contract, such as types
/// and serialization specific for smart contracts.
pub use concordium_contracts_common;
use crypto_common::{
    derive,
    derive::{Serial, Serialize},
    types::Amount,
    Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
};
use derive_more::*;
use id::types::AccountAddress;
use sha2::Digest;
use std::convert::{TryFrom, TryInto};

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Copy, Clone, Display)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub enum WasmVersion {
    #[display = "V0"]
    V0 = 0u8,
    #[display = "V1"]
    V1,
}

impl schemars::JsonSchema for WasmVersion {
    fn schema_name() -> String { "WasmVersion".into() }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        u8::json_schema(gen)
    }
}

/// V0 is the default version of smart contracts.
impl Default for WasmVersion {
    fn default() -> Self { Self::V0 }
}

impl From<WasmVersion> for u8 {
    fn from(x: WasmVersion) -> Self { x as u8 }
}

impl TryFrom<u8> for WasmVersion {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            _ => anyhow::bail!("Only versions 0 and 1 of smart contracts are supported."),
        }
    }
}

impl Serial for WasmVersion {
    #[inline(always)]
    fn serial<B: Buffer>(&self, out: &mut B) { u32::from(u8::from(*self)).serial(out) }
}

impl Deserial for WasmVersion {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x = u32::deserial(source)?;
        let tag = u8::try_from(x)?;
        tag.try_into()
    }
}

#[derive(Clone, SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(
    try_from = "instance_parser::InstanceInfoHelper",
    into = "instance_parser::InstanceInfoHelper"
)]
/// Information about an existing smart contract instance.
pub enum InstanceInfo {
    V0 {
        model:         Vec<u8>,
        owner:         AccountAddress,
        amount:        Amount,
        methods:       std::collections::BTreeSet<ReceiveName>,
        name:          InitName,
        source_module: ModuleRef,
    },
    V1 {
        owner:         AccountAddress,
        amount:        Amount,
        methods:       std::collections::BTreeSet<ReceiveName>,
        name:          InitName,
        source_module: ModuleRef,
    },
}

impl schemars::JsonSchema for InstanceInfo {
    fn schema_name() -> String { "InstanceInfo".into() }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        instance_parser::InstanceInfoHelper::json_schema(gen)
    }
}

mod instance_parser {
    use super::*;
    #[derive(SerdeSerialize, SerdeDeserialize, Debug, schemars::JsonSchema)]
    #[serde(rename_all = "camelCase", tag = "version")]
    /// Helper struct to derive JSON instances for super::InstanceInfo.
    pub struct InstanceInfoHelper {
        #[serde(default)]
        version:       WasmVersion,
        model:         Option<String>,
        owner:         AccountAddress,
        amount:        Amount,
        methods:       std::collections::BTreeSet<ReceiveName>,
        name:          InitName,
        source_module: ModuleRef,
    }

    impl From<InstanceInfo> for InstanceInfoHelper {
        fn from(ii: InstanceInfo) -> Self {
            match ii {
                InstanceInfo::V0 {
                    model,
                    owner,
                    amount,
                    methods,
                    name,
                    source_module,
                } => Self {
                    version: WasmVersion::V0,
                    model: Some(hex::encode(&model)),
                    owner,
                    amount,
                    methods,
                    name,
                    source_module,
                },
                InstanceInfo::V1 {
                    owner,
                    amount,
                    methods,
                    name,
                    source_module,
                } => Self {
                    version: WasmVersion::V1,
                    model: None,
                    owner,
                    amount,
                    methods,
                    name,
                    source_module,
                },
            }
        }
    }

    impl TryFrom<InstanceInfoHelper> for InstanceInfo {
        type Error = anyhow::Error;

        fn try_from(value: InstanceInfoHelper) -> Result<Self, Self::Error> {
            match value.version {
                WasmVersion::V0 => {
                    if let Some(model) = value.model {
                        let model = hex::decode(&model)?;
                        Ok(Self::V0 {
                            model,
                            owner: value.owner,
                            amount: value.amount,
                            methods: value.methods,
                            name: value.name,
                            source_module: value.source_module,
                        })
                    } else {
                        anyhow::bail!("V0 instances must have a model.")
                    }
                }
                WasmVersion::V1 => Ok(Self::V1 {
                    owner:         value.owner,
                    amount:        value.amount,
                    methods:       value.methods,
                    name:          value.name,
                    source_module: value.source_module,
                }),
            }
        }
    }
}

/// FIXME: Add structure.
#[derive(
    SerdeSerialize, SerdeDeserialize, Serial, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone,
)]
#[serde(into = "String", try_from = "String")]
#[derive(schemars::JsonSchema)]
#[schemars(transparent)]
pub struct ReceiveName {
    #[string_size_length = 2]
    pub name: String,
}

impl From<ReceiveName> for String {
    fn from(n: ReceiveName) -> Self { n.name }
}

impl<'a> From<&'a ReceiveName> for &'a str {
    fn from(n: &'a ReceiveName) -> Self { n.name.as_str() }
}

impl TryFrom<String> for ReceiveName {
    type Error = concordium_contracts_common::NewReceiveNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        concordium_contracts_common::ReceiveName::is_valid_receive_name(value.as_str())?;
        Ok(ReceiveName { name: value })
    }
}

impl Deserial for ReceiveName {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let name = crypto_common::deserial_string(source, len.into())?;
        concordium_contracts_common::ReceiveName::is_valid_receive_name(name.as_str())
            .map_err(|x| anyhow::anyhow!(x))?;
        Ok(ReceiveName { name })
    }
}

#[derive(
    SerdeSerialize, SerdeDeserialize, Eq, PartialEq, Ord, PartialOrd, Hash, Serial, Debug, Clone,
)]
#[serde(into = "String", try_from = "String")]
/// FIXME: Add structure.
#[derive(schemars::JsonSchema)]
#[schemars(transparent)]
pub struct InitName {
    #[string_size_length = 2]
    name: String,
}

impl From<InitName> for String {
    fn from(n: InitName) -> Self { n.name }
}

impl<'a> From<&'a InitName> for &'a str {
    fn from(n: &'a InitName) -> Self { n.name.as_str() }
}

impl TryFrom<String> for InitName {
    type Error = concordium_contracts_common::NewContractNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        concordium_contracts_common::ContractName::is_valid_contract_name(value.as_str())?;
        Ok(InitName { name: value })
    }
}

impl Deserial for InitName {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let name = crypto_common::deserial_string(source, len.into())?;
        concordium_contracts_common::ContractName::is_valid_contract_name(name.as_str())
            .map_err(|x| anyhow::anyhow!(x))?;
        Ok(InitName { name })
    }
}

/// FIXME: Move to Wasm, and check size also in JSON deserialization
#[derive(SerdeSerialize, SerdeDeserialize, derive::Serial, Debug, Clone, AsRef, Into, From)]
#[serde(transparent)]
pub struct Parameter {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 2]
    bytes: Vec<u8>,
}

impl schemars::JsonSchema for Parameter {
    fn schema_name() -> String { "Parameter".into() }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::*;
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(
                StringValidation {
                    max_length: Some(MAX_PARAMETER_LEN as u32),
                    min_length: Some(0),
                    pattern:    Some("^([0-9]?[a-f]?)*$".into()), /* TODO: This is not
                                                                   * completely precise.
                                                                   * Should ensure even
                                                                   * length as well. */
                }
                .into(),
            ),
            ..SchemaObject::default()
        })
    }
}

/// Manual implementation to ensure size limit.
impl Deserial for Parameter {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x: u16 = source.get()?;
        anyhow::ensure!(
            usize::from(x) <= MAX_PARAMETER_LEN,
            "Parameter size exceeds maximum allowed size."
        );
        let bytes = crypto_common::deserial_bytes(source, x.into())?;
        Ok(Parameter { bytes })
    }
}

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ModuleRefMarker {}

/// Reference to a deployed Wasm module on the chain.
pub type ModuleRef = hashes::HashBytes<ModuleRefMarker>;

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, AsRef, Into)]
#[serde(transparent)]
/// An event logged by a smart contract initialization.
pub struct ContractEvent {
    #[serde(with = "crate::internal::byte_array_hex")]
    bytes: Vec<u8>,
}

impl schemars::JsonSchema for ContractEvent {
    fn schema_name() -> String { "ContractEvent".into() }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::*;
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(
                StringValidation {
                    max_length: None,
                    min_length: Some(0),
                    pattern:    Some("^([0-9]?[a-f]?)*$".into()), /* TODO: Does not ensure even
                                                                   * length */
                }
                .into(),
            ),
            ..SchemaObject::default()
        })
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Clone, Debug, AsRef, From, Into)]
#[serde(transparent)]
/// Unparsed Wasm module source.
/// FIXME: Make this structured based on what we have in wasm-chain-integration.
pub struct ModuleSource {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 4]
    bytes: Vec<u8>,
}

impl ModuleSource {
    pub fn size(&self) -> u64 { self.bytes.len() as u64 }
}

impl Deserial for ModuleSource {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let s: u32 = source.get()?;
        anyhow::ensure!(
            s <= MAX_WASM_MODULE_SIZE,
            "Maximum size of a Wasm module is {}",
            MAX_WASM_MODULE_SIZE
        );
        let bytes = crypto_common::deserial_bytes(source, s as usize)?;
        Ok(ModuleSource { bytes })
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize, Clone, Debug)]
/// Unparsed module with a version indicating what operations are allowed.
/// FIXME: Make this structured based on what we have in wasm-chain-integration.
pub struct WasmModule {
    pub version: WasmVersion,
    pub source:  ModuleSource,
}

impl WasmModule {
    /// Get the identifier of the module. This identifier is used to refer to
    /// the module on the chain, e.g., when initializing a new contract
    /// instance.
    pub fn get_module_ref(&self) -> ModuleRef {
        let mut hasher = sha2::Sha256::new();
        self.serial(&mut hasher);
        ModuleRef::from(<[u8; 32]>::from(hasher.finalize()))
    }
}
