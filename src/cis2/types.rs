use crate::types::smart_contracts::concordium_contracts_common::{
    deserial_vector_no_length, serial_vector_no_length, AccountAddress, Address, ContractAddress,
    Deserial, OwnedReceiveName, ParseError, Read, Serial, Write,
};
use std::{convert::TryFrom, fmt::Display, str::FromStr};
use thiserror::*;

/// CIS2 Amount of tokens.
pub type TokenAmount = u64;

/// CIS2 Token ID can be up to 255 bytes in size.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TokenIdVec(pub Vec<u8>);

/// Error from parsing a token ID bytes from a hex encoded string.
#[derive(Debug, Error)]
pub enum ParseTokenIdVecError {
    #[error("Invalid hex string: {0}")]
    ParseIntError(#[from] hex::FromHexError),
    #[error("Token ID too large. Maximum allowed size is 255 bytes. {0} bytes was provided.")]
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
        write!(f, "{}", hex::encode(&self.0))?;
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
    InvalidTokenId,
    /// The balance of the token owner is insufficient for the transfer (Error
    /// code: -42000002).
    InsufficientFunds,
    /// Sender is unauthorized to call this function (Error code: -42000003).
    Unauthorized,
    /// Unknown error code for CIS2.
    Other(i32),
}

impl std::fmt::Display for Cis2ErrorRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Cis2ErrorRejectReason::*;
        match self {
            InvalidTokenId => write!(f, "Invalid token ID"),
            InsufficientFunds => write!(f, "Insufficient funds for the transfer"),
            Unauthorized => write!(f, "Sender is unauthorized to call this function"),
            Other(e) => write!(f, "Non-CIS2 error code: {}", e),
        }
    }
}

/// Convert Cis2Error into a reject with error code:
/// - InvalidTokenId: -42000001
/// - InsufficientFunds: -42000002
/// - Unauthorized: -42000003
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

/// The parameter for the NFT Contract function "CIS2-NFT.mint".
/// Important: this is specific to this NFT smart contract and contract
/// functions for minting are not part of the CIS2 specification.
#[derive(Debug)]
pub struct MintParams {
    pub owner:     Address,
    pub token_ids: Vec<TokenIdVec>,
}

/// Serialization for the minting contract function parameter.
/// Must match the serialization specified in the NFT smart contract.
impl Serial for MintParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.owner.serial(out)?;
        let len = u8::try_from(self.token_ids.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.token_ids, out)
    }
}

/// Additional data bytes which can be included for each transfer in the
/// transfer parameter for the CIS2 contract function "transfer".
#[derive(Debug, Clone)]
pub struct AdditionalData {
    pub data: Vec<u8>,
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

/// Parse the additional data from a hex string.
impl FromStr for AdditionalData {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(AdditionalData {
            data: hex::decode(s)?.to_vec(),
        })
    }
}

/// Address to receive an amount of tokens, it differs by the Address type by
/// additionally requiring a contract receive function name when the address is
/// a contract address.
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
            Receiver::Contract(address, receive_name) => {
                1u8.serial(out)?;
                address.serial(out)?;
                receive_name.as_ref().serial(out)
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
    pub amount:   u64,
    /// The address currently owning the tokens being transferred.
    pub from:     Address,
    /// The receiver for the tokens being transferred.
    pub to:       Receiver,
    /// Additional data to include for the transfer
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

/// The parameter type for the NFT contract function `CIS2-NFT.transfer`.
#[derive(Debug)]
pub struct TransferParams(pub Vec<Transfer>);

impl From<Vec<Transfer>> for TransferParams {
    fn from(transfers: Vec<Transfer>) -> Self { TransferParams(transfers) }
}

impl AsRef<[Transfer]> for TransferParams {
    fn as_ref(&self) -> &[Transfer] { &self.0 }
}

/// Serialization of the transfer parameter, according to the CIS2
/// specification.
impl Serial for TransferParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// The type of update for an operator update.
#[derive(Debug, Clone, Copy)]
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

impl Display for OperatorUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let str = match self {
            OperatorUpdate::Remove => "Remove",
            OperatorUpdate::Add => "Add",
        };
        write!(f, "{}", str)
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
#[derive(Debug)]
pub struct UpdateOperatorParams(pub Vec<UpdateOperator>);

/// Serialization of the updateOperator parameter, according to the CIS2
/// specification.
impl Serial for UpdateOperatorParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

impl From<Vec<UpdateOperator>> for UpdateOperatorParams {
    fn from(transfers: Vec<UpdateOperator>) -> Self { UpdateOperatorParams(transfers) }
}

impl AsRef<[UpdateOperator]> for UpdateOperatorParams {
    fn as_ref(&self) -> &[UpdateOperator] { &self.0 }
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
#[derive(Debug, Clone)]
pub struct BalanceOfQueryParams(pub Vec<BalanceOfQuery>);

/// Serialization of the balanceOf parameter, according to the CIS2
/// specification.
impl Serial for BalanceOfQueryParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

impl From<Vec<BalanceOfQuery>> for BalanceOfQueryParams {
    fn from(queries: Vec<BalanceOfQuery>) -> Self { BalanceOfQueryParams(queries) }
}

impl AsRef<[BalanceOfQuery]> for BalanceOfQueryParams {
    fn as_ref(&self) -> &[BalanceOfQuery] { &self.0 }
}

/// The response which is sent back when calling the contract function
/// `balanceOf`.
/// It consists of the list of token amounts in the same order as the queries.
#[derive(Debug)]
pub struct BalanceOfQueryResponse(pub Vec<TokenAmount>);

impl From<Vec<TokenAmount>> for BalanceOfQueryResponse {
    fn from(results: Vec<TokenAmount>) -> Self { BalanceOfQueryResponse(results) }
}

impl AsRef<[TokenAmount]> for BalanceOfQueryResponse {
    fn as_ref(&self) -> &[TokenAmount] { &self.0 }
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
        Ok(BalanceOfQueryResponse(results))
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
#[derive(Debug, Clone)]
pub struct OperatorOfQueryParams(pub Vec<OperatorOfQuery>);

/// Serialization of the operatorOf parameter, according to the CIS2
/// specification.
impl Serial for OperatorOfQueryParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

impl From<Vec<OperatorOfQuery>> for OperatorOfQueryParams {
    fn from(queries: Vec<OperatorOfQuery>) -> Self { OperatorOfQueryParams(queries) }
}

impl AsRef<[OperatorOfQuery]> for OperatorOfQueryParams {
    fn as_ref(&self) -> &[OperatorOfQuery] { &self.0 }
}

/// The response which is sent back when calling the contract function
/// `operatorOf`.
/// It consists of the list of result in the same order and length as the
/// queries in the parameter.
#[derive(Debug, Clone)]
pub struct OperatorOfQueryResponse(pub Vec<bool>);

impl From<Vec<bool>> for OperatorOfQueryResponse {
    fn from(results: Vec<bool>) -> Self { OperatorOfQueryResponse(results) }
}

impl AsRef<[bool]> for OperatorOfQueryResponse {
    fn as_ref(&self) -> &[bool] { &self.0 }
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
        Ok(OperatorOfQueryResponse::from(results))
    }
}

/// The parameter type for the NFT contract function `CIS2-NFT.operatorOf`.
#[derive(Debug, Clone)]
pub struct TokenMetadataQueryParams(pub Vec<TokenIdVec>);

/// Serialization of the operatorOf parameter, according to the CIS2
/// specification.
impl Serial for TokenMetadataQueryParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

impl From<Vec<TokenIdVec>> for TokenMetadataQueryParams {
    fn from(queries: Vec<TokenIdVec>) -> Self { TokenMetadataQueryParams(queries) }
}

impl AsRef<[TokenIdVec]> for TokenMetadataQueryParams {
    fn as_ref(&self) -> &[TokenIdVec] { &self.0 }
}

/// The response which is sent back when calling the contract function
/// `tokenMetadata`.
/// It consists of the list of queries paired with their corresponding result.
#[derive(Debug, Clone)]
pub struct TokenMetadataQueryResponse(pub Vec<MetadataUrl>);

impl From<Vec<MetadataUrl>> for TokenMetadataQueryResponse {
    fn from(results: Vec<MetadataUrl>) -> Self { TokenMetadataQueryResponse(results) }
}

impl AsRef<[MetadataUrl]> for TokenMetadataQueryResponse {
    fn as_ref(&self) -> &[MetadataUrl] { &self.0 }
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
        Ok(TokenMetadataQueryResponse::from(results))
    }
}

type Sha256 = [u8; 32];

/// A URL for the metadata.
#[derive(Debug, Clone)]
pub struct MetadataUrl {
    /// The url encoded according to CIS2.
    pub url:  String,
    /// An optional checksum of the content found at the URL.
    pub hash: Option<Sha256>,
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
        let hash = Option::<Sha256>::deserial(source)?;
        Ok(MetadataUrl { url, hash })
    }
}

/// Smart contract logged event, part of the CIS2 specification.
#[derive(Debug)]
pub enum Event {
    /// Transfer of an amount of tokens
    Transfer {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        from:     Address,
        to:       Address,
    },
    /// Minting an amount of tokens
    Mint {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        owner:    Address,
    },
    /// Burning an amount of tokens
    Burn {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        owner:    Address,
    },
    /// Add/Remove an address as operator for some other address.
    UpdateOperator {
        update:   OperatorUpdate,
        owner:    Address,
        operator: Address,
    },
    /// Provide an URL with the metadata for a certain token.
    TokenMetadata {
        token_id:     TokenIdVec,
        metadata_url: MetadataUrl,
    },
    /// Custom event outside of the CIS2 specification.
    Unknown,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Event::Transfer {
                token_id,
                from,
                to,
                amount: _,
            } => {
                write!(
                    f,
                    "Transferred token with ID {} from {} to {}",
                    token_id,
                    address_display(from),
                    address_display(to)
                )?;
            }
            Event::Mint {
                token_id,
                amount: _,
                owner,
            } => {
                write!(
                    f,
                    "Minted token with ID {} for {}",
                    token_id,
                    address_display(owner)
                )?;
            }
            Event::Burn {
                token_id,
                amount: _,
                owner,
            } => {
                write!(
                    f,
                    "Burned token with ID {} for {}",
                    token_id,
                    address_display(owner)
                )?;
            }
            Event::UpdateOperator {
                update,
                owner,
                operator,
            } => {
                write!(
                    f,
                    "{} {} as operator for {}",
                    update,
                    address_display(operator),
                    address_display(owner)
                )?;
            }
            Event::TokenMetadata {
                token_id,
                metadata_url,
            } => {
                let hash = if let Some(hash) = metadata_url.hash {
                    format!("with hash {}", hex::encode(hash))
                } else {
                    "without hash".to_string()
                };
                write!(
                    f,
                    "Added metadata url {} ({}) for token with ID {}",
                    metadata_url.url, hash, token_id
                )?;
            }
            Event::Unknown => {
                write!(f, "Unknown event: Event is not part of CIS2 specification")?;
            }
        }
        Ok(())
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
fn address_display(a: &Address) -> String {
    match a {
        Address::Account(addr) => format!("{}", addr),
        Address::Contract(addr) => format!("{}", addr),
    }
}
