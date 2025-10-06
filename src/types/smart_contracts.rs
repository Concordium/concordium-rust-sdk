//! Types related to smart contracts.
use super::{Address, ContractAddress, Energy, RejectReason};
#[cfg(feature = "serde_deprecated")]
use concordium_base::common::{SerdeDeserialize, SerdeSerialize};
pub use concordium_base::smart_contracts::*;
use concordium_base::{
    common::types::Amount, id::types::AccountAddress, transactions::UpdateContractPayload,
};
/// Re-export of common helper functionality for smart contract, such as types
/// and serialization specific for smart contracts.
pub use concordium_contracts_common::{
    self, ContractName, ModuleReference, OwnedContractName, OwnedParameter, OwnedReceiveName,
    ReceiveName,
};
use concordium_contracts_common::{Cursor, Deserial, Get, ParseError, ParseResult};
use derive_more::*;
use std::convert::TryFrom;
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde_deprecated", derive(SerdeSerialize, SerdeDeserialize))]
#[cfg_attr(
    feature = "serde_deprecated",
    serde(
        try_from = "instance_parser::InstanceInfoHelper",
        into = "instance_parser::InstanceInfoHelper"
    )
)]
/// Information about an existing smart contract instance.
pub enum InstanceInfo {
    V0 {
        model: Vec<u8>,
        owner: AccountAddress,
        amount: Amount,
        methods: std::collections::BTreeSet<OwnedReceiveName>,
        name: OwnedContractName,
        source_module: ModuleReference,
    },
    V1 {
        owner: AccountAddress,
        amount: Amount,
        methods: std::collections::BTreeSet<OwnedReceiveName>,
        name: OwnedContractName,
        source_module: ModuleReference,
    },
}
impl InstanceInfo {
    /// The amount of CCD owned by the instance.
    pub fn amount(&self) -> Amount {
        match self {
            InstanceInfo::V0 { amount, .. } => *amount,
            InstanceInfo::V1 { amount, .. } => *amount,
        }
    }
    /// The source module of the instance.
    pub fn source_module(&self) -> ModuleReference {
        match self {
            InstanceInfo::V0 { source_module, .. } => *source_module,
            InstanceInfo::V1 { source_module, .. } => *source_module,
        }
    }
    /// Entrypoints supported by the instance. This returns the full name of the
    /// function that is suitable for inclusion in a transaction.
    pub fn entrypoints(&self) -> &std::collections::BTreeSet<OwnedReceiveName> {
        match self {
            InstanceInfo::V0 { methods, .. } => methods,
            InstanceInfo::V1 { methods, .. } => methods,
        }
    }
    /// Get the name of the contract, i.e., the name of the init function that
    /// was used to create the instance.
    pub fn name(&self) -> &OwnedContractName {
        match self {
            InstanceInfo::V0 { name, .. } => name,
            InstanceInfo::V1 { name, .. } => name,
        }
    }
}
mod instance_parser {
    use super::*;
    #[derive(Debug)]
    #[cfg_attr(feature = "serde_deprecated", derive(SerdeSerialize, SerdeDeserialize))]
    #[cfg_attr(
        feature = "serde_deprecated",
        serde(rename_all = "camelCase", tag = "version")
    )]
    /// Helper struct to derive JSON instances for super::InstanceInfo.
    pub struct InstanceInfoHelper {
        #[cfg_attr(feature = "serde_deprecated", serde(default))]
        version: WasmVersion,
        model: Option<String>,
        owner: AccountAddress,
        amount: Amount,
        methods: std::collections::BTreeSet<OwnedReceiveName>,
        name: OwnedContractName,
        source_module: ModuleReference,
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
                    model: Some(hex::encode(model)),
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
                        let model = hex::decode(model)?;
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
                    owner: value.owner,
                    amount: value.amount,
                    methods: value.methods,
                    name: value.name,
                    source_module: value.source_module,
                }),
            }
        }
    }
}
#[derive(Clone)]
#[cfg_attr(feature = "serde_deprecated", derive(SerdeSerialize, SerdeDeserialize))]
/// Data needed to invoke the contract.
pub struct ContractContext {
    /// Invoker of the contract. If this is not supplied then the contract will
    /// be invoked, by an account with address 0, no credentials and
    /// sufficient amount of CCD to cover the transfer amount. If given, the
    /// relevant address must exist in the blockstate.
    pub invoker: Option<Address>,
    /// Contract to invoke.
    pub contract: ContractAddress,
    /// Amount to invoke the contract with.
    #[cfg_attr(feature = "serde_deprecated", serde(default = "return_zero_amount"))]
    pub amount: Amount,
    /// Which entrypoint to invoke.
    pub method: OwnedReceiveName,
    /// And with what parameter.
    #[cfg_attr(feature = "serde_deprecated", serde(default))]
    pub parameter: OwnedParameter,
    /// The energy to allow for execution. If not set the node decides on the
    /// maximum amount.
    pub energy: Option<Energy>,
}
pub const DEFAULT_INVOKE_ENERGY: Energy = Energy { energy: 10_000_000 };
impl ContractContext {
    /// Construct a minimal context with defaults for omitted values. The
    /// defaults are
    /// - the [`invoker`](ContractContext::invoker) is set to [`None`]
    /// - the [`amount`](ContractContext::amount) is set to `0CCD`
    /// - the [`parameter`](ContractContext::parameter) is set to the empty
    ///   parameter
    pub fn new(contract: ContractAddress, method: OwnedReceiveName) -> Self {
        Self {
            invoker: None,
            contract,
            amount: Amount::zero(),
            method,
            parameter: OwnedParameter::default(),
            energy: None,
        }
    }
    /// Construct a new contract context from an update contract payload.
    /// The arguments are
    ///
    /// - `sender` - the account sending the transaction
    /// - `energy` - the energy allowed for execution.
    /// - `payload` - the update contract payload to derive arguments from.
    pub fn new_from_payload(
        sender: AccountAddress,
        energy: impl Into<Option<Energy>>,
        payload: UpdateContractPayload,
    ) -> Self {
        Self {
            invoker: Some(sender.into()),
            contract: payload.address,
            amount: payload.amount,
            method: payload.receive_name,
            parameter: payload.message,
            energy: energy.into(),
        }
    }
}
fn return_zero_amount() -> Amount {
    Amount::from_micro_ccd(0)
}
#[derive(Debug, Clone, Into, From)]
#[cfg_attr(feature = "serde_deprecated", derive(SerdeDeserialize, SerdeSerialize))]
#[cfg_attr(feature = "serde_deprecated", serde(transparent))]
pub struct ReturnValue {
    #[cfg_attr(
        feature = "serde_deprecated",
        serde(with = "crate::internal::byte_array_hex")
    )]
    pub value: Vec<u8>,
}
impl ReturnValue {
    pub fn parse<T: Deserial>(&self) -> ParseResult<T> {
        let mut cursor = Cursor::new(&self.value);
        let res = cursor.get()?;
        if cursor.offset != self.value.len() {
            return Err(ParseError::default());
        }
        Ok(res)
    }
}
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_deprecated", derive(SerdeDeserialize))]
#[cfg_attr(feature = "serde_deprecated", serde(tag = "tag"))]
pub enum InvokeContractResult {
    #[cfg_attr(
        feature = "serde_deprecated",
        serde(rename = "success", rename_all = "camelCase")
    )]
    Success {
        return_value: Option<ReturnValue>,
        #[cfg_attr(
            feature = "serde_deprecated",
            serde(deserialize_with = "contract_trace_via_events::deserialize")
        )]
        events: Vec<ContractTraceElement>,
        used_energy: Energy,
    },
    #[cfg_attr(
        feature = "serde_deprecated",
        serde(rename = "failure", rename_all = "camelCase")
    )]
    Failure {
        return_value: Option<ReturnValue>,
        reason: RejectReason,
        used_energy: Energy,
    },
}
impl InvokeContractResult {
    /// Retrieve the amount of energy used for the call.
    pub fn used_energy(&self) -> Energy {
        match self {
            InvokeContractResult::Success { used_energy, .. } => *used_energy,
            InvokeContractResult::Failure { used_energy, .. } => *used_energy,
        }
    }
}
#[cfg(feature = "serde_deprecated")]
mod contract_trace_via_events {
    use super::*;
    use serde::de::Error;
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
