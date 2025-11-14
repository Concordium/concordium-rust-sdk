//! Types and functions used in Concordium verifiable presentation protocol version 1.
use crate::v2::{self, RPCError};
use concordium_base::web3id::v1::anchor::{
    VerificationAuditRecord, VerificationRequest, VerificationRequestData,
};
use concordium_base::{
    base::Nonce,
    common::{
        cbor::{self, CborSerializationError},
        types::TransactionTime,
    },
    contracts_common::AccountAddress,
    hashes::TransactionHash,
    transactions::{send, BlockItem, ExactSizeTransactionSigner, TooLargeError},
};
use std::collections::HashMap;

#[derive(thiserror::Error, Debug)]
pub enum CreateAnchorError {
    #[error("node query error: {0}")]
    Query(#[from] v2::QueryError),
    #[error("data register transaction data is too large: {0}")]
    TooLarge(#[from] TooLargeError),
    #[error("CBOR serialization error: {0}")]
    CborSerialization(#[from] CborSerializationError),
}

impl From<RPCError> for CreateAnchorError {
    fn from(err: RPCError) -> Self {
        CreateAnchorError::Query(err.into())
    }
}

/// Metadata for transaction submission.
pub struct AnchorTransactionMetadata<S: ExactSizeTransactionSigner> {
    /// The signer object used to sign the on-chain anchor transaction. This must correspond to the `sender` account below.
    pub signer: S,
    /// The sender account of the anchor transaction.
    pub sender: AccountAddress,
    /// The sequence number for the sender account to use.
    pub account_sequence_number: Nonce,
    /// The transaction expiry time.
    pub expiry: TransactionTime,
}

/// Submit verification request anchor (VRA) and return the verification request.
/// Notice that the VRA will only be submitted, it is not included on-chain yet when
/// the function returns. The transaction hash is returned
/// in [`VerificationRequest::anchor_transaction_hash`] and the transaction must
/// be tracked until finalization before the verification request is usable
/// (waiting for finalization can be done in the app that receives the verification request
/// to create a verifiable presentation).
pub async fn create_verification_request_and_submit_anchor<S: ExactSizeTransactionSigner>(
    client: &mut v2::Client,
    anchor_transaction_metadata: AnchorTransactionMetadata<S>,
    verification_request_data: VerificationRequestData,
    public_info: HashMap<String, cbor::value::Value>,
) -> Result<VerificationRequest, CreateAnchorError> {
    let verification_request_anchor = verification_request_data.to_anchor(public_info);
    let cbor = cbor::cbor_encode(&verification_request_anchor)?;
    let register_data = cbor.try_into()?;

    let tx = send::register_data(
        &anchor_transaction_metadata.signer,
        anchor_transaction_metadata.sender,
        anchor_transaction_metadata.account_sequence_number,
        anchor_transaction_metadata.expiry,
        register_data,
    );
    let block_item = BlockItem::AccountTransaction(tx);

    // Submit the transaction to the chain.
    let transaction_hash = client.send_block_item(&block_item).await?;

    Ok(VerificationRequest {
        context: verification_request_data.context,
        subject_claims: verification_request_data.subject_claims,
        anchor_transaction_hash: transaction_hash,
    })
}

/// Submit verification audit anchor (VAA).
/// Notice that the VAA will only be submitted, it is not included on-chain yet when
/// the function returns. The transaction must
/// be tracked until finalization for the audit record to be registered successfully.
pub async fn submit_verification_audit_record_anchor<S: ExactSizeTransactionSigner>(
    client: &mut v2::Client,
    anchor_transaction_metadata: AnchorTransactionMetadata<S>,
    verification_audit_record: &VerificationAuditRecord,
    public_info: HashMap<String, cbor::value::Value>,
) -> Result<TransactionHash, CreateAnchorError> {
    let verification_audit_anchor = verification_audit_record.to_anchor(public_info);
    let cbor = cbor::cbor_encode(&verification_audit_anchor)?;
    let register_data = cbor.try_into()?;

    let tx = send::register_data(
        &anchor_transaction_metadata.signer,
        anchor_transaction_metadata.sender,
        anchor_transaction_metadata.account_sequence_number,
        anchor_transaction_metadata.expiry,
        register_data,
    );
    let item = BlockItem::AccountTransaction(tx);

    // Submit the transaction to the chain.
    let transaction_hash = client.send_block_item(&item).await?;

    Ok(transaction_hash)
}
