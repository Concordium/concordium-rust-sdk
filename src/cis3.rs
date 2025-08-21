//! This module contains types and functions for interacting with smart
//! contracts following the [CIS-3](https://proposals.concordium.software/CIS/cis-3.html) specification.
use crate::{
    contract_client::{ContractClient, ContractTransactionMetadata},
    types::{self as sdk_types, transactions},
    v2::{self, IntoBlockIdentifier},
};
use concordium_base::{
    base::Energy,
    cis3_types::{
        NewSupportsPermitQueryParamsError, PermitParams, SupportsPermitQueryParams,
        SupportsPermitRepsonse,
    },
    contracts_common::{Address, Amount, OwnedEntrypointName},
    smart_contracts::OwnedParameter,
    transactions::{AccountTransaction, EncodedPayload},
};
use sdk_types::smart_contracts;
use smart_contracts::concordium_contracts_common;
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
/// A marker type to indicate that a [`ContractClient`] is a client for a `CIS3`
/// contract.
pub enum Cis3Type {}

/// A wrapper around the client representing a CIS3 token smart contract, which
/// provides functions for interaction specific to CIS3 contracts.
///
/// Note that cloning is cheap and is, therefore, the intended way of sharing
/// this type between multiple tasks.
///
/// See also [`ContractClient`] for generic methods available for any contract.
pub type Cis3Contract = ContractClient<Cis3Type>;

/// Error which can occur when calling [`permit`](Cis3Contract::permit).
#[derive(Error, Debug)]
pub enum Cis3PermitError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] concordium_contracts_common::NewReceiveNameError),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] crate::endpoints::RPCError),
}

/// Error which can occur when calling [`permit`](Cis3Contract::permit_dry_run).
#[derive(Error, Debug)]
pub enum Cis3PermitDryRunError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] concordium_contracts_common::NewReceiveNameError),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] crate::endpoints::RPCError),

    /// An error occurred when querying the node.
    #[error("RPC error: {0}")]
    QueryError(#[from] crate::endpoints::QueryError),

    /// The node rejected the invocation.
    #[error("Rejected by the node: {0:?}.")]
    NodeRejected(v2::Upward<sdk_types::RejectReason>),
}

/// Error which can occur when calling
/// [`supportsPermit`](Cis3Contract::supports_permit).
#[derive(Debug, Error)]
pub enum Cis3SupportsPermitError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] concordium_contracts_common::NewReceiveNameError),

    /// The parameter is invalid.
    #[error("Invalid supportsPermit parameter: {0}")]
    InvalidParams(#[from] NewSupportsPermitQueryParamsError),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] super::v2::QueryError),

    /// The returned bytes from invoking the smart contract could not be parsed.
    #[error("Failed parsing the response.")]
    ResponseParseError(#[from] concordium_contracts_common::ParseError),

    /// The node rejected the invocation.
    #[error("Rejected by the node: {0:?}.")]
    NodeRejected(v2::Upward<sdk_types::RejectReason>),
}

// This is implemented manually, since deriving it using thiserror requires
// `RejectReason` to implement std::error::Error.
impl From<v2::Upward<sdk_types::RejectReason>> for Cis3SupportsPermitError {
    fn from(err: v2::Upward<sdk_types::RejectReason>) -> Self { Self::NodeRejected(err) }
}

// This is implemented manually, since deriving it using thiserror requires
// `RejectReason` to implement std::error::Error.
impl From<v2::Upward<sdk_types::RejectReason>> for Cis3PermitDryRunError {
    fn from(err: v2::Upward<sdk_types::RejectReason>) -> Self { Self::NodeRejected(err) }
}

impl Cis3Contract {
    /// Like [`permit`](Self::permit) except it only dry-runs the transaction
    /// to get the response and, in case of success, amount of energy used
    /// for execution.
    ///
    /// # Arguments
    ///
    /// * `bi` - The block to query. The query will be executed in the state of
    ///   the chain at the end of the block.
    /// * `sender` - The (sponsor) address that is invoking the entrypoint.
    /// * `params` - The parameters for the permit invocation. Includes the
    ///   signature of the sponsoree, the address of the sponsoree, and the
    ///   signed message.
    pub async fn permit_dry_run(
        &mut self,
        bi: impl IntoBlockIdentifier,
        sender: Address,
        params: PermitParams,
    ) -> Result<Energy, Cis3PermitDryRunError> {
        let parameter = OwnedParameter::from_serial(&params)
            .expect("A PermitParams should always be serializable");
        let ir = self
            .invoke_raw::<Cis3PermitDryRunError>(
                "permit",
                Amount::zero(),
                Some(sender),
                parameter,
                bi,
            )
            .await?;
        match ir {
            smart_contracts::InvokeContractResult::Success { used_energy, .. } => Ok(used_energy),
            smart_contracts::InvokeContractResult::Failure { reason, .. } => Err(reason.into()),
        }
    }

    /// Construct **and send** a CIS3 sponsored transaction. This function takes
    /// a signature from the sponsoree along with their account address, and
    /// the signed message to be executed by the contract. Returns a [`Result`]
    /// with the transaction hash.
    ///
    /// # Arguments
    ///
    /// * `signer` - The account keys (of the sponsor) to use for signing the
    ///   smart contract update transaction.
    /// * `metadata` - Metadata for constructing the transaction.
    /// * `params` - The parameters for the permit invocation. Includes the
    ///   signature of the sponsoree, the address of the sponsoree, and the
    ///   signed message.
    pub async fn permit(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &ContractTransactionMetadata,
        params: PermitParams,
    ) -> Result<sdk_types::hashes::TransactionHash, Cis3PermitError> {
        let permit = self.make_permit(signer, metadata, params)?;
        let hash = self.client.send_account_transaction(permit).await?;
        Ok(hash)
    }

    /// Construct a CIS3 sponsored transaction. This function takes a signature
    /// from the sponsoree along with their account address, and the signed
    /// message to be executed by the contract. Returns a [`Result`] with the
    /// transaction hash.
    ///
    /// # Arguments
    ///
    /// * `signer` - The account keys (of the sponsor) to use for signing the
    ///   smart contract update transaction.
    /// * `metadata` - Metadata for constructing the transaction.
    /// * `params` - The parameters for the permit invocation. Includes the
    ///   signature of the sponsoree, the address of the sponsoree, and the
    ///   signed message.
    pub fn make_permit(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &ContractTransactionMetadata,
        params: PermitParams,
    ) -> Result<AccountTransaction<EncodedPayload>, Cis3PermitError> {
        let message = smart_contracts::OwnedParameter::from_serial(&params)
            .expect("A PermitParams should always be serializable");
        self.make_update_raw(signer, metadata, "permit", message)
    }

    /// Invoke the CIS3 `supportsPermit` query given a list of entrypoints to
    /// query.
    ///
    /// Note: the query is executed locally by the node and does not produce a
    /// transaction on-chain.
    ///
    /// # Arguments
    ///
    /// * `bi` - The block to query. The query will be executed in the state of
    ///   the chain at the end of the block.
    /// * `entrypoints` - A list queries to execute.
    pub async fn supports_permit(
        &mut self,
        bi: impl IntoBlockIdentifier,
        entrypoints: Vec<OwnedEntrypointName>,
    ) -> Result<SupportsPermitRepsonse, Cis3SupportsPermitError> {
        let parameter = SupportsPermitQueryParams::new(entrypoints)?;
        let message = OwnedParameter::from_serial(&parameter).map_err(|_| {
            Cis3SupportsPermitError::InvalidParams(NewSupportsPermitQueryParamsError)
        })?;
        self.view_raw("supportsPermit", message, bi).await
    }

    /// Like [`supports_permit`](Self::supports_permit), but only queries a
    /// single entrypoint, and returns a bool indicating whether the entrypoint
    /// is supported.
    pub async fn supports_permit_single(
        &mut self,
        bi: impl IntoBlockIdentifier,
        entrypoint: OwnedEntrypointName,
    ) -> Result<bool, Cis3SupportsPermitError> {
        only_one(self.supports_permit(bi, vec![entrypoint]).await?)
    }
}

/// Extract an element from the given vector if the vector has exactly one
/// element. Otherwise raise a parse error.
fn only_one<A, V: AsRef<Vec<A>>>(res: V) -> Result<A, Cis3SupportsPermitError>
where
    Vec<A>: From<V>, {
    let err =
        Cis3SupportsPermitError::ResponseParseError(concordium_contracts_common::ParseError {});
    if res.as_ref().len() > 1 {
        Err(err)
    } else {
        Vec::from(res).pop().ok_or(err)
    }
}
