//! Types related to smart contracts.

use super::{Address, ContractAddress, Energy, RejectReason};
pub use concordium_base::smart_contracts::*;
use concordium_base::{
    common::{types::Amount, SerdeDeserialize, SerdeSerialize},
    id::types::AccountAddress,
    transactions::UpdateContractPayload,
};
/// Re-export of common helper functionality for smart contract, such as types
/// and serialization specific for smart contracts.
pub use concordium_contracts_common::{
    self, ContractName, ModuleReference, OwnedContractName, OwnedParameter, OwnedReceiveName,
    ReceiveName,
};
use derive_more::*;
use std::convert::TryFrom;

#[derive(Clone, SerdeSerialize, SerdeDeserialize, Debug, PartialEq, Eq)]
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
        methods:       std::collections::BTreeSet<OwnedReceiveName>,
        name:          OwnedContractName,
        source_module: ModuleReference,
    },
    V1 {
        owner:         AccountAddress,
        amount:        Amount,
        methods:       std::collections::BTreeSet<OwnedReceiveName>,
        name:          OwnedContractName,
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
    #[derive(SerdeSerialize, SerdeDeserialize, Debug)]
    #[serde(rename_all = "camelCase", tag = "version")]
    /// Helper struct to derive JSON instances for super::InstanceInfo.
    pub struct InstanceInfoHelper {
        #[serde(default)]
        version:       WasmVersion,
        model:         Option<String>,
        owner:         AccountAddress,
        amount:        Amount,
        methods:       std::collections::BTreeSet<OwnedReceiveName>,
        name:          OwnedContractName,
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
    pub method:    OwnedReceiveName,
    /// And with what parameter.
    #[serde(default)]
    pub parameter: OwnedParameter,
    /// And what amount of energy to allow for execution. This should be small
    /// enough so that it can be converted to interpreter energy.
    #[serde(default = "return_default_invoke_energy")]
    pub energy:    Energy,
}

pub const DEFAULT_INVOKE_ENERGY: Energy = Energy { energy: 10_000_000 };

impl ContractContext {
    /// Construct a minimal context with defaults for omitted values. The
    /// defaults are
    /// - the [`invoker`](ContractContext::invoker) is set to [`None`]
    /// - the [`amount`](ContractContext::amount) is set to `0CCD`
    /// - the [`parameter`](ContractContext::parameter) is set to the empty
    ///   parameter
    /// - the [`energy`](ContractContext::energy) is set to
    ///   [`DEFAULT_INVOKE_ENERGY`]
    pub fn new(contract: ContractAddress, method: OwnedReceiveName) -> Self {
        Self {
            invoker: None,
            contract,
            amount: Amount::zero(),
            method,
            parameter: OwnedParameter::default(),
            energy: DEFAULT_INVOKE_ENERGY,
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
        energy: Energy,
        payload: UpdateContractPayload,
    ) -> Self {
        Self {
            invoker: Some(sender.into()),
            contract: payload.address,
            amount: payload.amount,
            method: payload.receive_name,
            parameter: payload.message,
            energy,
        }
    }
}

fn return_zero_amount() -> Amount { Amount::from_micro_ccd(0) }
fn return_default_invoke_energy() -> Energy { DEFAULT_INVOKE_ENERGY }

#[derive(SerdeDeserialize, SerdeSerialize, Debug, Clone, Into, From)]
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

impl InvokeContractResult {
    /// Retrieve the amount of energy used for the call.
    pub fn used_energy(&self) -> Energy {
        match self {
            InvokeContractResult::Success { used_energy, .. } => *used_energy,
            InvokeContractResult::Failure { used_energy, .. } => *used_energy,
        }
    }
}

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
