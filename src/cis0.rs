//! This module contains types and functions for interacting with smart
//! contracts following the [CIS-0](https://proposals.concordium.software/CIS/cis-0.html) specification.

use crate::{
    types::{self as sdk_types, smart_contracts::ContractContext},
    v2::{BlockIdentifier, QueryResponse},
};
use concordium_base::{
    base::Energy,
    contracts_common::{Amount, ContractName, EntrypointName, OwnedReceiveName, ParseError},
};
use sdk_types::{smart_contracts, ContractAddress};
use smart_contracts::concordium_contracts_common as contracts_common;
use std::convert::{From, TryFrom};
use thiserror::*;

/// The query result type for whether a smart contract supports a standard.
#[derive(Debug, Clone)]
pub enum SupportResult {
    /// The standard is not supported.
    NoSupport,
    /// The standard is supported by the current contract address.
    Support,
    /// The standard is supported by using another contract address.
    SupportBy(Vec<ContractAddress>),
}

impl SupportResult {
    /// Return whether the result is [`Support`](Self::Support) or not.
    pub fn is_support(&self) -> bool { matches!(self, &Self::Support) }
}

impl contracts_common::Serial for SupportResult {
    fn serial<W: contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            SupportResult::NoSupport => out.write_u8(0u8),
            SupportResult::Support => out.write_u8(1u8),
            SupportResult::SupportBy(addrs) => {
                out.write_u8(2)?;
                out.write_u8(addrs.len() as u8)?;
                for addr in addrs {
                    addr.serial(out)?;
                }
                Ok(())
            }
        }
    }
}

impl contracts_common::Deserial for SupportResult {
    fn deserial<R: contracts_common::Read>(source: &mut R) -> contracts_common::ParseResult<Self> {
        match source.read_u8()? {
            0u8 => Ok(Self::NoSupport),
            1u8 => Ok(Self::Support),
            2u8 => {
                let len = source.read_u8()?;
                let mut out = Vec::new();
                for _ in 0..len {
                    out.push(ContractAddress::deserial(source)?);
                }
                Ok(Self::SupportBy(out))
            }
            _ => Err(contracts_common::ParseError {}),
        }
    }
}

/// The response which is sent back when calling the contract function
/// `supports`. It consists of a list of results corresponding to the list of
/// queries.
#[derive(Debug, Clone)]
pub struct SupportsQueryResponse {
    /// List of support results corresponding to the list of queries.
    pub results: Vec<SupportResult>,
}

impl contracts_common::Deserial for SupportsQueryResponse {
    fn deserial<R: contracts_common::Read>(source: &mut R) -> contracts_common::ParseResult<Self> {
        let len = u16::deserial(source)?;
        let mut results = Vec::new();
        for _ in 0..len {
            results.push(SupportResult::deserial(source)?)
        }
        Ok(Self { results })
    }
}

impl contracts_common::Serial for SupportsQueryResponse {
    fn serial<W: contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        (self.results.len() as u16).serial(out)?;
        for result in &self.results {
            result.serial(out)?;
        }
        Ok(())
    }
}

/// Identifier for a smart contract standard.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum StandardIdentifier {
    CIS0,
    CIS1,
    CIS2,
    Other(String),
}

impl std::fmt::Display for StandardIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StandardIdentifier::CIS0 => f.write_str("CIS-0"),
            StandardIdentifier::CIS1 => f.write_str("CIS-1"),
            StandardIdentifier::CIS2 => f.write_str("CIS-2"),
            StandardIdentifier::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Error, Debug, Clone)]
/// The standard name is invalid and could not be parsed.
#[error("Invalid CIS standard name.")]
pub struct InvalidStandardName;

impl std::str::FromStr for StandardIdentifier {
    type Err = InvalidStandardName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CIS-0" => Ok(Self::CIS0),
            "CIS-1" => Ok(Self::CIS1),
            "CIS-2" => Ok(Self::CIS2),
            other if other.is_ascii() && other.len() <= 255 => Ok(Self::Other(other.into())),
            _ => Err(InvalidStandardName),
        }
    }
}

impl contracts_common::Serial for StandardIdentifier {
    fn serial<W: contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            StandardIdentifier::CIS0 => {
                out.write_u8(5)?; // length
                out.write_all(b"CIS-0")
            }
            StandardIdentifier::CIS1 => {
                out.write_u8(5)?; // length
                out.write_all(b"CIS-1")
            }
            StandardIdentifier::CIS2 => {
                out.write_u8(5)?; // length
                out.write_all(b"CIS-2")
            }
            StandardIdentifier::Other(s) => {
                out.write_u8(s.len() as u8)?;
                out.write_all(s.as_bytes())
            }
        }
    }
}

#[derive(Error, Debug)]
/// Errors that may occur when querying a contract.
pub enum SupportsError {
    #[error("The name of the contract is not valid and thus the contract does not support CIS-0.")]
    ContractNameInvalid,
    #[error("Parameter size exceeds maximum allowed. Too many ids.")]
    InvalidParameter,
    #[error("Query error: {0}")]
    QueryError(#[from] super::v2::QueryError),
    #[error("Contract reject.")]
    ContractReject,
    #[error("No return. This is a V0 contract, and V0 contracts do not support CIS-0.")]
    NoReturn,
    #[error("Parsing result failed.")]
    ParseError(#[from] ParseError),
    #[error("The contract return an inconsistent result.")]
    InvalidResponse,
}

/// Return whether the contract supports standards in the list
/// at the end of the given block.
///
/// In case of success the return list of [`SupportsQueryResponse`] values
/// will have the same length as the input list of `ids`.
pub async fn supports_multi(
    client: &mut super::v2::Client,
    bi: &BlockIdentifier,
    addr: ContractAddress,
    name: ContractName<'_>,
    ids: &[StandardIdentifier],
) -> Result<super::v2::QueryResponse<SupportsQueryResponse>, SupportsError> {
    use contracts_common::{Deserial, Serial};
    let method = OwnedReceiveName::construct(name, EntrypointName::new_unchecked("supports"))
        .map_err(|_| SupportsError::ContractNameInvalid)?;
    let mut parameters = Vec::new();
    (ids.len() as u16)
        .serial(&mut parameters)
        .map_err(|_| SupportsError::InvalidParameter)?;
    for id in ids {
        id.serial(&mut parameters)
            .map_err(|_| SupportsError::InvalidParameter)?;
    }
    let parameter = smart_contracts::Parameter::try_from(parameters)
        .map_err(|_| SupportsError::InvalidParameter)?;
    let ctx = ContractContext {
        invoker: None,
        contract: addr,
        amount: Amount::from_micro_ccd(0),
        method,
        parameter,
        energy: Energy::from(500_000u64),
    };
    let res = client.invoke_instance(bi, &ctx).await?;
    match res.response {
        smart_contracts::InvokeContractResult::Success { return_value, .. } => match return_value {
            Some(rv) => {
                let response =
                    SupportsQueryResponse::deserial(&mut contracts_common::Cursor::new(&rv.value))?;
                if response.results.len() != ids.len() {
                    return Err(SupportsError::InvalidResponse);
                }
                Ok(QueryResponse {
                    block_hash: res.block_hash,
                    response,
                })
            }
            None => Err(SupportsError::NoReturn),
        },
        smart_contracts::InvokeContractResult::Failure { .. } => Err(SupportsError::ContractReject),
    }
}

/// A simplified version of [`supports_multi`] that only supports
/// querying for a single standard, but has a simpler API.
pub async fn supports(
    client: &mut super::v2::Client,
    bi: &BlockIdentifier,
    addr: ContractAddress,
    name: ContractName<'_>,
    ids: StandardIdentifier,
) -> Result<super::v2::QueryResponse<SupportResult>, SupportsError> {
    let mut response = supports_multi(client, bi, addr, name, &[ids]).await?;
    if let Some(r) = response.response.results.pop() {
        Ok(QueryResponse {
            block_hash: response.block_hash,
            response:   r,
        })
    } else {
        Err(SupportsError::InvalidResponse)
    }
}
