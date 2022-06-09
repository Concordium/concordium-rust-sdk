//! Types related to smart contracts.

use super::{hashes, Address, ContractAddress, ContractTraceElement, Energy, RejectReason};
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

mod instance_parser {
    use super::*;
    #[derive(SerdeSerialize, SerdeDeserialize, Debug)]
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

#[derive(
    SerdeSerialize, SerdeDeserialize, Serial, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Clone,
)]
#[serde(into = "String", try_from = "String")]
/// FIXME: Add structure.
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

// FIXME: Move to Wasm, and check size also in JSON deserialization
#[derive(
    SerdeSerialize, SerdeDeserialize, derive::Serial, Debug, Clone, AsRef, Into, From, Default,
)]
#[serde(transparent)]
/// A smart contract parameter. The [Default] implementation produces an empty
/// parameter.
pub struct Parameter {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 2]
    bytes: Vec<u8>,
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

#[derive(SerdeSerialize, SerdeDeserialize, Clone)]
/// Data needed to invoke the contract.
pub struct ContractContext {
    /// Invoker of the contract. If this is not supplied then the contract will
    /// be invoked, by an account with address 0, no credentials and
    /// sufficient amount of CCD to cover the transfer amount. If given, the
    /// relevant address must exist in the blockstate.
    pub invoker:   Option<Address>,
    /// Contract to invoke.
    pub contract:  ContractAddress,
    /// Amount to invoke the contract with.
    #[serde(default = "return_zero_amount")]
    pub amount:    Amount,
    /// Which entrypoint to invoke.
    pub method:    ReceiveName,
    /// And with what parameter.
    #[serde(default)]
    pub parameter: Parameter,
    /// And what amount of energy to allow for execution. This should be small
    /// enough so that it can be converted to interpreter energy.
    #[serde(default = "return_default_invoke_energy")]
    pub energy:    Energy,
}

pub const DEFAULT_INVOKE_ENERGY: Energy = Energy { energy: 10_000_000 };
pub const MAX_ALLOWED_INVOKE_ENERGY: Energy = Energy {
    energy: 100_000_000_000,
};

impl ContractContext {
    /// Construct a minimal context with defaults for omitted values. The
    /// defaults are
    /// - the [`invoker`](ContractContext::invoker) is set to [`None`]
    /// - the [`amount`](ContractContext::amount) is set to `0CCD`
    /// - the [`parameter`](ContractContext::parameter) is set to the empty
    ///   parameter
    /// - the [`energy`](ContractContext::energy) is set to
    ///   [`DEFAULT_INVOKE_ENERGY`]
    pub fn new(contract: ContractAddress, method: ReceiveName) -> Self {
        Self {
            invoker: None,
            contract,
            amount: Amount::from_micro_ccd(0),
            method,
            parameter: Parameter::default(),
            energy: DEFAULT_INVOKE_ENERGY,
        }
    }
}

fn return_zero_amount() -> Amount { Amount::from_micro_ccd(0) }
fn return_default_invoke_energy() -> Energy { DEFAULT_INVOKE_ENERGY }

#[derive(SerdeDeserialize, SerdeSerialize, Debug, Clone, Into)]
#[serde(transparent)]
pub struct ReturnValue {
    #[serde(with = "crate::internal::byte_array_hex")]
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, SerdeDeserialize)]
#[serde(tag = "tag")]
pub enum InvokeContractResult {
    #[serde(rename = "success", rename_all = "camelCase")]
    Success {
        return_value: Option<ReturnValue>,
        #[serde(deserialize_with = "contract_trace_via_events::deserialize")]
        events:       Vec<ContractTraceElement>,
        used_energy:  Energy,
    },
    #[serde(rename = "failure", rename_all = "camelCase")]
    Failure {
        return_value: Option<ReturnValue>,
        reason:       RejectReason,
        used_energy:  Energy,
    },
}

mod contract_trace_via_events {
    use super::*;
    use serde::de::Error;
    /// Deserialize (via Serde) chrono::Duration in milliseconds as an i64.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        des: D,
    ) -> Result<Vec<ContractTraceElement>, D::Error> {
        let xs = Vec::<super::super::summary_helper::Event>::deserialize(des)?;
        xs.into_iter()
            .map(ContractTraceElement::try_from)
            .collect::<Result<_, _>>()
            .map_err(|e| D::Error::custom(format!("Conversion failure: {}", e)))
    }
}
