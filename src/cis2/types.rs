//! This module contains types and their implementations related to the CIS-2
//! Token standard.

use crate::types::{
    hashes::Hash,
    smart_contracts::concordium_contracts_common::{
        deserial_vector_no_length, serial_vector_no_length, AccountAddress, Address,
        ContractAddress, Deserial, OwnedReceiveName, ParseError, Read, Serial, Write,
    },
};
use derive_more::{AsRef, Display, From};
use num::ToPrimitive;
use num_bigint::BigUint;
use num_traits::Zero;
use std::{convert::TryFrom, ops, str::FromStr};
use thiserror::*;

/// CIS-2 token amount with serialization as according to CIS-2.
///
/// According to the CIS-2 specification, a token amount can be in the range
/// from 0 to 2^256 - 1.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, From, Display)]
pub struct TokenAmount(pub BigUint);

impl From<TokenAmount> for BigUint {
    fn from(v: TokenAmount) -> BigUint { v.0 }
}

impl From<u8> for TokenAmount {
    fn from(v: u8) -> TokenAmount { TokenAmount(v.into()) }
}

impl From<u16> for TokenAmount {
    fn from(v: u16) -> TokenAmount { TokenAmount(v.into()) }
}

impl From<u32> for TokenAmount {
    fn from(v: u32) -> TokenAmount { TokenAmount(v.into()) }
}

impl From<u64> for TokenAmount {
    fn from(v: u64) -> TokenAmount { TokenAmount(v.into()) }
}

impl ops::Add<Self> for TokenAmount {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output { TokenAmount(self.0 + rhs.0) }
}

impl ops::AddAssign for TokenAmount {
    fn add_assign(&mut self, other: Self) { self.0 += other.0 }
}

impl ops::Sub<Self> for TokenAmount {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output { TokenAmount(self.0 - rhs.0) }
}

impl ops::SubAssign for TokenAmount {
    fn sub_assign(&mut self, other: Self) { self.0 -= other.0 }
}

impl ops::Mul<Self> for TokenAmount {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output { TokenAmount(self.0 * rhs.0) }
}

impl ops::MulAssign for TokenAmount {
    fn mul_assign(&mut self, other: Self) { self.0 *= other.0 }
}

impl ops::Div<Self> for TokenAmount {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output { TokenAmount(self.0 / rhs.0) }
}

impl ops::DivAssign for TokenAmount {
    fn div_assign(&mut self, other: Self) { self.0 /= other.0 }
}

impl Serial for TokenAmount {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let mut value = self.0.clone();
        for _ in 0..37 {
            let mut byte = (value.clone() % BigUint::from(128u8)).to_u8().unwrap(); // Safe to unwrap since we have truncated
            value >>= 7;
            if !value.is_zero() {
                byte |= 0b1000_0000;
            }
            out.write_u8(byte)?;

            if value.is_zero() {
                return Ok(());
            }
        }
        Err(W::Err::default())
    }
}

impl Deserial for TokenAmount {
    fn deserial<R: Read>(source: &mut R) -> concordium_contracts_common::ParseResult<Self> {
        let mut result = BigUint::zero();
        for i in 0..37 {
            let byte = source.read_u8()?;
            let value_byte = BigUint::from(byte & 0b0111_1111);
            result += value_byte << (i * 7);

            if byte & 0b1000_0000 == 0 {
                return Ok(TokenAmount::from(result));
            }
        }
        Err(concordium_contracts_common::ParseError {})
    }
}

/// CIS2 Token ID can be up to 255 bytes in size.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TokenIdVec(pub Vec<u8>);

/// Error from parsing a token ID bytes from a hex encoded string.
#[derive(Debug, Error)]
pub enum ParseTokenIdVecError {
    #[error("Invalid hex string: {0}")]
    ParseIntError(#[from] hex::FromHexError),
    #[error("Token ID too large. Maximum allowed size is 255 bytes. {0} bytes were provided.")]
    TooManyBytes(usize),
}

/// Parse a Token ID from a hex encoded string.
impl FromStr for TokenIdVec {
    type Err = ParseTokenIdVecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() > 255 {
            Err(ParseTokenIdVecError::TooManyBytes(bytes.len()))
        } else {
            Ok(TokenIdVec(bytes))
        }
    }
}

/// Display the token ID as a hex string.
impl std::fmt::Display for TokenIdVec {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Serialize the token ID according to CIS2 specification.
impl Serial for TokenIdVec {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// Deserialize bytes to a Token ID according to CIS2 specification.
impl Deserial for TokenIdVec {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let tokens_id_length = u8::deserial(source)?;
        let bytes = deserial_vector_no_length(source, tokens_id_length.into())?;
        Ok(TokenIdVec(bytes))
    }
}

/// The different errors found in CIS2.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum Cis2ErrorRejectReason {
    /// Invalid token id (Error code: -42000001).
    #[error("Invalid token ID.")]
    InvalidTokenId,
    /// The balance of the token owner is insufficient for the transfer (Error
    /// code: -42000002).
    #[error("Insufficient funds for the transfer.")]
    InsufficientFunds,
    /// Sender is unauthorized to call this function (Error code: -42000003).
    #[error("Sender is unauthorized to call this function.")]
    Unauthorized,
    /// Unknown error code for CIS2.
    #[error("Non-CIS2 error code: {0}")]
    Other(i32),
}

/// Convert Cis2Error into a reject with error code:
/// - [`InvalidTokenId`](Cis2ErrorRejectReason::InvalidTokenId): `-42000001`
/// - [`InsufficientFunds`](Cis2ErrorRejectReason::InsufficientFunds):
///   `-42000002`
/// - [`Unauthorized`](Cis2ErrorRejectReason::Unauthorized): `-42000003`
impl From<i32> for Cis2ErrorRejectReason {
    fn from(error_code: i32) -> Self {
        match error_code {
            -42000001 => Cis2ErrorRejectReason::InvalidTokenId,
            -42000002 => Cis2ErrorRejectReason::InsufficientFunds,
            -42000003 => Cis2ErrorRejectReason::Unauthorized,
            other => Cis2ErrorRejectReason::Other(other),
        }
    }
}

/// Additional data which can be included for each transfer in the
/// transfer parameter for the CIS2 contract function `transfer`.
/// Allows up to `u16::MAX` number of bytes.
#[derive(Debug, Clone, AsRef)]
pub struct AdditionalData {
    data: Vec<u8>,
}

/// Error for constructing a new [`AdditionalData`](AdditionalData).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid byte length, must be withing a length of u16::MAX.")]
pub struct NewAdditionalDataError;

impl AdditionalData {
    /// Construct a new AdditionalData.
    /// Ensures the length of the provided bytes are within `u16::MAX`.
    pub fn new(data: Vec<u8>) -> Result<Self, NewAdditionalDataError> {
        if data.len() > u16::MAX.into() {
            return Err(NewAdditionalDataError);
        }
        Ok(AdditionalData { data })
    }

    /// Construct a new AdditionalData.
    /// Without ensuring the length of the provided bytes are within `u16::MAX`.
    pub fn new_unchecked(data: Vec<u8>) -> Self { AdditionalData { data } }
}

/// Serialization for the additional data, serialized as according to the CIS2
/// specification.
impl Serial for AdditionalData {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u16::try_from(self.data.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.data, out)
    }
}

/// Error for constructing a [`AdditionalData`](AdditionalData) from a string.
#[derive(Debug, Error)]
pub enum FromStrAdditionalDataError {
    /// Invalid hex string was provided.
    #[error("Failed to parse hex encoding: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    /// Unable to construct  [`AdditionalData`](AdditionalData).
    #[error("Failed constructing data: {0}")]
    InvalidData(#[from] NewAdditionalDataError),
}

/// Parse the additional data from a hex string.
impl FromStr for AdditionalData {
    type Err = FromStrAdditionalDataError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = hex::decode(s)?.to_vec();
        Ok(AdditionalData::new(data)?)
    }
}

/// Address to receive an amount of tokens, it differs from the [`Address`] type
/// by additionally requiring a contract receive function name when the address
/// is a contract address.
#[derive(Debug, Clone)]
pub enum Receiver {
    Account(AccountAddress),
    Contract(ContractAddress, OwnedReceiveName),
}

impl Serial for Receiver {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Receiver::Account(address) => {
                0u8.serial(out)?;
                address.serial(out)
            }
            Receiver::Contract(address, owned_receive_name) => {
                1u8.serial(out)?;
                address.serial(out)?;
                owned_receive_name.as_receive_name().serial(out)
            }
        }
    }
}

/// A description of a transfer according to the CIS2 specification.
#[derive(Debug)]
pub struct Transfer {
    /// The ID of the token type to transfer.
    pub token_id: TokenIdVec,
    /// The amount of tokens to transfer.
    pub amount:   TokenAmount,
    /// The address currently owning the tokens being transferred.
    pub from:     Address,
    /// The receiver for the tokens being transferred.
    pub to:       Receiver,
    /// Additional data to include for the transfer.
    pub data:     AdditionalData,
}

/// Serialization of a transfer, according to the CIS2 specification.
impl Serial for Transfer {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.token_id.serial(out)?;
        self.amount.serial(out)?;
        self.from.serial(out)?;
        self.to.serial(out)?;
        self.data.serial(out)?;
        Ok(())
    }
}

/// Error for constructing a new [`TransferParams`](TransferParams).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of transfers, must be withing a length of u16::MAX.")]
pub struct NewTransferParamsError;

/// The parameter type for the NFT contract function `CIS2-NFT.transfer`.
#[derive(Debug, AsRef)]
pub struct TransferParams(Vec<Transfer>);

impl TransferParams {
    /// Construct a new TransferParams.
    /// Ensures the length of the provided transfers are within `u16::MAX`.
    pub fn new(transfers: Vec<Transfer>) -> Result<Self, NewTransferParamsError> {
        if transfers.len() > u16::MAX.into() {
            return Err(NewTransferParamsError);
        }
        Ok(Self(transfers))
    }

    /// Construct a new TransferParams.
    /// Without ensuring the length of the provided tranfers are within
    /// `u16::MAX`.
    pub fn new_unchecked(transfers: Vec<Transfer>) -> Self { Self(transfers) }
}

/// Serialization of the transfer parameter, according to the CIS2
/// specification.
impl Serial for TransferParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u16::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// The type of update for an operator update.
#[derive(Debug, Clone, Copy, Display)]
pub enum OperatorUpdate {
    /// Remove the operator.
    Remove,
    /// Add an address as an operator.
    Add,
}

/// Serialization of the transfer parameter, according to the CIS2
/// specification.
impl Serial for OperatorUpdate {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            OperatorUpdate::Remove => out.write_u8(0),
            OperatorUpdate::Add => out.write_u8(1),
        }
    }
}

/// The deserialization of an operator update, according to the CIS2
/// specification.
impl Deserial for OperatorUpdate {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let discriminant = source.read_u8()?;
        match discriminant {
            0 => Ok(OperatorUpdate::Remove),
            1 => Ok(OperatorUpdate::Add),
            _ => Err(ParseError::default()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UpdateOperator {
    /// The update for this operator.
    pub update:   OperatorUpdate,
    /// The address which is either added or removed as an operator.
    /// Note: The address for whom this will become an operator is the sender of
    /// the contract transaction.
    pub operator: Address,
}

/// Serialization of the update operator parameter item, according to the CIS2
/// specification.
impl Serial for UpdateOperator {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.update.serial(out)?;
        self.operator.serial(out)
    }
}

/// The parameter type for the NFT contract function `CIS2-NFT.updateOperator`.
#[derive(Debug, AsRef)]
pub struct UpdateOperatorParams(Vec<UpdateOperator>);

/// Error for constructing a new [`UpdateOperatorParams`](UpdateOperatorParams).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of operator updates, must be withing a length of u16::MAX.")]
pub struct NewUpdateOperatorParamsError;

impl UpdateOperatorParams {
    /// Construct a new UpdateOperatorParams.
    /// Ensures the length of the provided updates are within `u16::MAX`.
    pub fn new(updates: Vec<UpdateOperator>) -> Result<Self, NewUpdateOperatorParamsError> {
        if updates.len() > u16::MAX.into() {
            return Err(NewUpdateOperatorParamsError);
        }
        Ok(Self(updates))
    }

    /// Construct a new UpdateOperatorParams.
    /// Without ensuring the length of the provided updates are within
    /// `u16::MAX`.
    pub fn new_unchecked(updates: Vec<UpdateOperator>) -> Self { Self(updates) }
}

/// Serialization of the updateOperator parameter, according to the CIS2
/// specification.
impl Serial for UpdateOperatorParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u16::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// A query for the balance of a given address for a given token.
#[derive(Debug, Clone)]
pub struct BalanceOfQuery {
    /// The ID of the token for which to query the balance of.
    pub token_id: TokenIdVec,
    /// The address for which to query the balance of.
    pub address:  Address,
}

/// Serialization of a balanceOf query, according to the CIS2
/// specification.
impl Serial for BalanceOfQuery {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.token_id.serial(out)?;
        self.address.serial(out)?;
        Ok(())
    }
}

/// The parameter type for the NFT contract function `CIS2-NFT.balanceOf`.
#[derive(Debug, Clone, AsRef)]
pub struct BalanceOfQueryParams(Vec<BalanceOfQuery>);

/// Error for constructing a new [`BalanceOfQueryParams`](BalanceOfQueryParams).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of queries, must be withing a length of u16::MAX.")]
pub struct NewBalanceOfQueryParamsError;

impl BalanceOfQueryParams {
    /// Construct a new BalanceOfQueryParams.
    /// Ensures the length of the provided queries are within `u16::MAX`.
    pub fn new(queries: Vec<BalanceOfQuery>) -> Result<Self, NewBalanceOfQueryParamsError> {
        if queries.len() > u16::MAX.into() {
            return Err(NewBalanceOfQueryParamsError);
        }
        Ok(Self(queries))
    }

    /// Construct a new BalanceOfQueryParams.
    /// Without ensuring the length of the provided queries are within
    /// `u16::MAX`.
    pub fn new_unchecked(queries: Vec<BalanceOfQuery>) -> Self { Self(queries) }
}

/// Serialization of the balanceOf parameter, according to the CIS2
/// specification.
impl Serial for BalanceOfQueryParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u16::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// The response which is sent back when calling the contract function
/// `balanceOf`.
/// It consists of the list of token amounts in the same order as the queries.
#[derive(Debug, PartialEq, Eq, AsRef)]
pub struct BalanceOfQueryResponse(Vec<TokenAmount>);

/// Error for constructing a new
/// [`BalanceOfQueryResponse`](BalanceOfQueryResponse).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of results, must be withing a length of u16::MAX.")]
pub struct NewBalanceOfQueryResponseError;

impl BalanceOfQueryResponse {
    /// Construct a new BalanceOfQueryResponse.
    /// Ensures the length of the provided results is within `u16::MAX`.
    pub fn new(results: Vec<TokenAmount>) -> Result<Self, NewBalanceOfQueryResponseError> {
        if results.len() > u16::MAX.into() {
            return Err(NewBalanceOfQueryResponseError);
        }
        Ok(Self(results))
    }

    /// Construct a new BalanceOfQueryResponse.
    /// Without ensuring the length of the provided results is within
    /// `u16::MAX`.
    pub fn new_unchecked(results: Vec<TokenAmount>) -> Self { Self(results) }
}

/// Deserialization for BalanceOfQueryResponse according to the CIS2
/// specification.
impl Deserial for BalanceOfQueryResponse {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let len = source.read_u16()?;
        let mut results = Vec::with_capacity(len.into());
        for _ in 0..len {
            results.push(TokenAmount::deserial(source)?)
        }
        Ok(BalanceOfQueryResponse::new_unchecked(results))
    }
}

/// A query for the operator of a given address for a given token.
#[derive(Debug, Clone)]
pub struct OperatorOfQuery {
    /// The ID of the token for which to query the balance of.
    pub owner:   Address,
    /// The address for which to check for being an operator of the owner.
    pub address: Address,
}

/// Serialization of a operatorOf query, according to the CIS2
/// specification.
impl Serial for OperatorOfQuery {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.owner.serial(out)?;
        self.address.serial(out)?;
        Ok(())
    }
}

/// The parameter type for the NFT contract function `CIS2-NFT.operatorOf`.
#[derive(Debug, Clone, AsRef)]
pub struct OperatorOfQueryParams(Vec<OperatorOfQuery>);

/// Error for constructing a new
/// [`OperatorOfQueryParams`](OperatorOfQueryParams).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of queries, must be withing a length of u16::MAX.")]
pub struct NewOperatorOfQueryParamsError;

impl OperatorOfQueryParams {
    /// Construct a new OperatorOfQueryParams.
    /// Ensures the length of the provided queries are within `u16::MAX`.
    pub fn new(queries: Vec<OperatorOfQuery>) -> Result<Self, NewOperatorOfQueryParamsError> {
        if queries.len() > u16::MAX.into() {
            return Err(NewOperatorOfQueryParamsError);
        }
        Ok(Self(queries))
    }

    /// Construct a new OperatorOfQueryParams.
    /// Without ensuring the length of the provided queries are within
    /// `u16::MAX`.
    pub fn new_unchecked(queries: Vec<OperatorOfQuery>) -> Self { Self(queries) }
}

/// Serialization of the operatorOf parameter, according to the CIS2
/// specification.
impl Serial for OperatorOfQueryParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u16::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// The response which is sent back when calling the contract function
/// `operatorOf`.
/// It consists of the list of results in the same order and length as the
/// queries in the parameter.
#[derive(Debug, Clone, AsRef)]
pub struct OperatorOfQueryResponse(Vec<bool>);

/// Error for constructing a new
/// [`OperatorOfQueryResponse`](OperatorOfQueryResponse).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of results, must be withing a length of u16::MAX.")]
pub struct NewOperatorOfQueryResponseError;

impl OperatorOfQueryResponse {
    /// Construct a new OperatorOfQueryResponse.
    /// Ensures the length of the provided results is within `u16::MAX`.
    pub fn new(results: Vec<bool>) -> Result<Self, NewOperatorOfQueryResponseError> {
        if results.len() > u16::MAX.into() {
            return Err(NewOperatorOfQueryResponseError);
        }
        Ok(Self(results))
    }

    /// Construct a new OperatorOfQueryResponse.
    /// Without ensuring the length of the provided results is within
    /// `u16::MAX`.
    pub fn new_unchecked(results: Vec<bool>) -> Self { Self(results) }
}

/// Deserialization for OperatorOfQueryResponse according to the CIS2
/// specification.
impl Deserial for OperatorOfQueryResponse {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let len = source.read_u16()?;
        let mut results = Vec::with_capacity(len.into());
        for _ in 0..len {
            results.push(bool::deserial(source)?)
        }
        Ok(OperatorOfQueryResponse::new_unchecked(results))
    }
}

/// A query for token metadata for a given token.
pub type TokenMetadataQuery = TokenIdVec;

/// The parameter type for the NFT contract function `CIS2-NFT.operatorOf`.
#[derive(Debug, Clone, From, AsRef)]
pub struct TokenMetadataQueryParams(Vec<TokenMetadataQuery>);

/// Error for constructing a new
/// [`TokenMetadataQueryParams`](TokenMetadataQueryParams).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of queries, must be withing a length of u16::MAX.")]
pub struct NewTokenMetadataQueryParamsError;

impl TokenMetadataQueryParams {
    /// Construct a new TokenMetadataQueryParams.
    /// Ensures the length of the provided queries are within `u16::MAX`.
    pub fn new(queries: Vec<TokenMetadataQuery>) -> Result<Self, NewTokenMetadataQueryParamsError> {
        if queries.len() > u16::MAX.into() {
            return Err(NewTokenMetadataQueryParamsError);
        }
        Ok(Self(queries))
    }

    /// Construct a new TokenMetadataQueryParams.
    /// Without ensuring the length of the provided queries are within
    /// `u16::MAX`.
    pub fn new_unchecked(queries: Vec<TokenMetadataQuery>) -> Self { Self(queries) }
}

/// Serialization of the operatorOf parameter, according to the CIS2
/// specification.
impl Serial for TokenMetadataQueryParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u16::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// The response which is sent back when calling the contract function
/// `tokenMetadata`.
/// It consists of the list of queries paired with their corresponding result.
#[derive(Debug, Clone, AsRef)]
pub struct TokenMetadataQueryResponse(Vec<MetadataUrl>);

/// Error for constructing a new
/// [`TokenMetadataQueryResponse`](TokenMetadataQueryResponse).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of results, must be withing a length of u16::MAX.")]
pub struct NewTokenMetadataQueryResponseError;

impl TokenMetadataQueryResponse {
    /// Construct a new TokenMetadataQueryResponse.
    /// Ensures the length of the provided results is within `u16::MAX`.
    pub fn new(results: Vec<MetadataUrl>) -> Result<Self, NewTokenMetadataQueryResponseError> {
        if results.len() > u16::MAX.into() {
            return Err(NewTokenMetadataQueryResponseError);
        }
        Ok(Self(results))
    }

    /// Construct a new TokenMetadataQueryResponse.
    /// Without ensuring the length of the provided results is within
    /// `u16::MAX`.
    pub fn new_unchecked(results: Vec<MetadataUrl>) -> Self { Self(results) }
}

/// Deserialization for TokenMetadataQueryResponse according to the CIS2
/// specification.
impl Deserial for TokenMetadataQueryResponse {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let len = source.read_u16()?;
        let mut results = Vec::with_capacity(len.into());
        for _ in 0..len {
            results.push(MetadataUrl::deserial(source)?)
        }
        Ok(TokenMetadataQueryResponse::new_unchecked(results))
    }
}

/// A URL for the metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataUrl {
    /// The url encoded according to CIS2.
    url:  String,
    /// An optional checksum of the content found at the URL.
    hash: Option<Hash>,
}

/// Error for constructing a new
/// [`MetadataUrl`](MetadataUrl).
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of results, must be withing a length of u16::MAX.")]
pub struct NewMetadataUrlError;

impl MetadataUrl {
    /// Construct a new MetadataUrl.
    /// Ensures the length of the url is within `u16::MAX`.
    pub fn new(url: String, hash: Option<Hash>) -> Result<Self, NewMetadataUrlError> {
        if url.len() > u16::MAX.into() {
            return Err(NewMetadataUrlError);
        }
        Ok(Self { url, hash })
    }

    /// Construct a new MetadataUrl.
    /// Without ensuring the length of the url is within `u16::MAX`.
    pub fn new_unchecked(url: String, hash: Option<Hash>) -> Self { Self { url, hash } }

    /// Get the metadata content url.
    pub fn url(&self) -> &str { &self.url }

    /// Get the metadata content hash.
    pub fn hash(&self) -> Option<Hash> { self.hash }
}

/// Deserialization for MetadataUrl according to the CIS2 specification.
impl Deserial for MetadataUrl {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let len = source.read_u16()?;
        let mut bytes = Vec::with_capacity(len.into());
        for _ in 0..len {
            bytes.push(source.read_u8()?)
        }
        let url = String::from_utf8(bytes)?;
        let hash = Option::<[u8; 32]>::deserial(source)?.map(|b| b.into());
        Ok(MetadataUrl::new_unchecked(url, hash))
    }
}

/// Smart contract logged event, part of the CIS2 specification.
#[derive(Debug, Display)]
pub enum Event {
    /// Transfer of an amount of tokens
    #[display(
        fmt = "Transferred token with ID {} from {} to {}",
        token_id,
        "display_address(from)",
        "display_address(to)"
    )]
    Transfer {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        from:     Address,
        to:       Address,
    },
    /// Minting an amount of tokens
    #[display(
        fmt = "Minted token with ID {} for {}",
        token_id,
        "display_address(owner)"
    )]
    Mint {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        owner:    Address,
    },
    /// Burning an amount of tokens
    #[display(
        fmt = "Burned token with ID {} for {}",
        token_id,
        "display_address(owner)"
    )]
    Burn {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        owner:    Address,
    },
    /// Add/Remove an address as operator for some other address.
    #[display(
        fmt = "{} {} as operator for {}",
        update,
        "display_address(operator)",
        "display_address(owner)"
    )]
    UpdateOperator {
        update:   OperatorUpdate,
        owner:    Address,
        operator: Address,
    },
    /// Provide an URL with the metadata for a certain token.
    #[display(
        fmt = "Added metadata url {} ({}) for token with ID {}",
        "metadata_url.url",
        "display_hash(metadata_url.hash)",
        token_id
    )]
    TokenMetadata {
        token_id:     TokenIdVec,
        metadata_url: MetadataUrl,
    },
    /// Custom event outside of the CIS2 specification.
    #[display(fmt = "Unknown event: Event is not part of CIS2 specification")]
    Unknown,
}

fn display_hash(hash_opt: Option<Hash>) -> String {
    if let Some(hash) = hash_opt {
        format!("with hash {}", hash)
    } else {
        "without hash".to_string()
    }
}

/// Deserialize the contract events as according to the CIS2 specification.
impl Deserial for Event {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let discriminant = u8::deserial(source)?;
        match discriminant {
            0 => Ok(Event::Transfer {
                token_id: TokenIdVec::deserial(source)?,
                amount:   TokenAmount::deserial(source)?,
                from:     Address::deserial(source)?,
                to:       Address::deserial(source)?,
            }),
            1 => Ok(Event::Mint {
                token_id: TokenIdVec::deserial(source)?,
                amount:   TokenAmount::deserial(source)?,
                owner:    Address::deserial(source)?,
            }),
            2 => Ok(Event::Burn {
                token_id: TokenIdVec::deserial(source)?,
                amount:   TokenAmount::deserial(source)?,
                owner:    Address::deserial(source)?,
            }),
            3 => Ok(Event::UpdateOperator {
                update:   OperatorUpdate::deserial(source)?,
                owner:    Address::deserial(source)?,
                operator: Address::deserial(source)?,
            }),
            4 => Ok(Event::TokenMetadata {
                token_id:     TokenIdVec::deserial(source)?,
                metadata_url: MetadataUrl::deserial(source)?,
            }),
            _ => Ok(Event::Unknown),
        }
    }
}

/// Display the Address using either the display for account address or contract
/// address.
fn display_address(a: &Address) -> String {
    match a {
        Address::Account(addr) => format!("{}", addr),
        Address::Contract(addr) => format!("{}", addr),
    }
}
