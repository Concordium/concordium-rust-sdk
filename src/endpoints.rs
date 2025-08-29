//! Wrapper for the node's GRPC API. The return values are parsed and wrapped in
//! structured values.
use crate::types;
use derive_more::From;
use thiserror::Error;
use tonic::metadata::errors::InvalidMetadataValue;
pub use tonic::transport::{Endpoint, Error};

#[derive(Error, Debug)]
/// Authentication, connection, or response parsing error.
pub enum RPCError {
    #[error("Call failed: {0}")]
    CallError(#[from] tonic::Status),
    #[error(transparent)]
    InvalidMetadata(#[from] InvalidMetadataValue),
    #[error("Error parsing JSON result: {0}")]
    ParseError(#[from] anyhow::Error),
}

impl From<serde_json::Error> for RPCError {
    fn from(x: serde_json::Error) -> Self {
        Self::ParseError(x.into())
    }
}

impl From<semver::Error> for RPCError {
    fn from(x: semver::Error) -> Self {
        Self::ParseError(x.into())
    }
}

impl RPCError {
    /// Return whether the error indicates the item being sent is invalid.
    /// Retrying a request in this case will likely not succeed.
    ///
    /// Although some conditions like that are transient.
    pub fn is_invalid_argument(&self) -> bool {
        match self {
            RPCError::CallError(e) => {
                matches!(e.code(), tonic::Code::InvalidArgument)
            }
            RPCError::InvalidMetadata(_) => false,
            RPCError::ParseError(_) => false,
        }
    }

    /// Return whether the object already exists at the node.
    /// Retrying a request in this case will likely not succeed.
    pub fn is_duplicate(&self) -> bool {
        match self {
            RPCError::CallError(e) => {
                matches!(e.code(), tonic::Code::AlreadyExists)
            }
            RPCError::InvalidMetadata(_) => false,
            RPCError::ParseError(_) => false,
        }
    }
}

#[derive(Error, Debug)]
/// Errors that can occur when making queries. This can either be a general
/// connection/authentication error, or the requested item is not found.
pub enum QueryError {
    #[error("RPC error: {0}")]
    /// A general RPC error occurred.
    RPCError(#[from] RPCError),
    #[error("Requested object not found.")]
    /// The requested item was not found.
    NotFound,
}

impl QueryError {
    /// Whether this error indicates an object was not found.
    pub fn is_not_found(&self) -> bool {
        match self {
            QueryError::RPCError(c) => {
                if let RPCError::CallError(ce) = c {
                    ce.code() == tonic::Code::NotFound
                } else {
                    false
                }
            }
            QueryError::NotFound => true,
        }
    }
}

impl From<tonic::Status> for QueryError {
    fn from(s: tonic::Status) -> Self {
        Self::RPCError(s.into())
    }
}

impl From<InvalidMetadataValue> for QueryError {
    fn from(s: InvalidMetadataValue) -> Self {
        Self::RPCError(s.into())
    }
}

/// Result a GRPC query. This is a simple alias for [std::Result](https://doc.rust-lang.org/std/result/enum.Result.html)
/// that fixes the error type to be [RPCError].
pub type RPCResult<A> = Result<A, RPCError>;

/// Result a GRPC query where the item lookup might fail.
/// This is a simple alias for [std::Result](https://doc.rust-lang.org/std/result/enum.Result.html) that fixes the error type to be [`QueryError`].
pub type QueryResult<A> = Result<A, QueryError>;

/// Input to the
/// [`get_blocks_at_height`](crate::v2::Client::get_blocks_at_height) query.
#[derive(Clone, Copy, Debug, From)]
pub enum BlocksAtHeightInput {
    Absolute {
        /// Height from the beginning of the chain.
        height: types::AbsoluteBlockHeight,
    },
    /// Query relative to an explicit genesis index.
    Relative {
        /// Genesis index to start from.
        genesis_index: types::GenesisIndex,
        /// Height starting from the genesis block at the genesis index.
        height: types::BlockHeight,
        /// Whether to return results only from the specified genesis index
        /// (`true`), or allow results from more recent genesis indices
        /// as well (`false`).
        restrict: bool,
    },
}
