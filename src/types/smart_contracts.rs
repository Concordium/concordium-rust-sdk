//! Types related to smart contracts.

use super::hashes;
use crate::constants::*;
use crypto_common::{
    derive,
    derive::{Serial, Serialize},
    types::Amount,
    Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
};
use derive_more::*;
use id::types::AccountAddress;
use std::convert::TryFrom;

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// Information about an existing smart contract instance.
pub struct InstanceInfo {
    #[serde(with = "crate::internal::byte_array_hex")]
    pub model:         Vec<u8>,
    pub owner:         AccountAddress,
    pub amount:        Amount,
    pub methods:       std::collections::BTreeSet<ReceiveName>,
    pub name:          InitName,
    pub source_module: ModuleRef,
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
        concordium_contracts_common::is_valid_receive_name(value.as_str())?;
        Ok(ReceiveName { name: value })
    }
}

impl Deserial for ReceiveName {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let name = crypto_common::deserial_string(source, len.into())?;
        concordium_contracts_common::is_valid_receive_name(name.as_str())
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
        concordium_contracts_common::is_valid_contract_name(value.as_str())?;
        Ok(InitName { name: value })
    }
}

impl Deserial for InitName {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let name = crypto_common::deserial_string(source, len.into())?;
        concordium_contracts_common::is_valid_contract_name(name.as_str())
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
    pub version: u32,
    pub source:  ModuleSource,
}
