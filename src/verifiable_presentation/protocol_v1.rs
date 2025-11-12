//! Types and functions used in Concordium verifiable presentation protocol version 1.
use crate::v2::{self, RPCError};
use concordium_base::{
    base::Nonce,
    common::{
        cbor::{self, CborSerializationError},
        types::TransactionTime,
    },
    contracts_common::AccountAddress,
    hashes::TransactionHash,
    transactions::{send, BlockItem, ExactSizeTransactionSigner, TooLargeError},
    web3id::{
        did::Network,
        sdk::protocol::{VerificationAuditRecord, VerificationRequest, VerificationRequestData},
    },
};
use std::collections::HashMap;

#[derive(thiserror::Error, Debug)]
pub enum CreateAnchorError {
    #[error("Node query error: {0}")]
    Query(#[from] v2::QueryError),
    #[error("Data register transaction data is too large: {0}")]
    TooLarge(#[from] TooLargeError),
    #[error("Cbor serialization error: {0}")]
    CborSerialization(#[from] CborSerializationError),
}

impl From<RPCError> for CreateAnchorError {
    fn from(err: RPCError) -> Self {
        CreateAnchorError::Query(err.into())
    }
}

/// Metadata for transaction submission.
pub struct AnchorTransactionMetadata<'a, S: ExactSizeTransactionSigner> {
    /// The signer object used to sign the on-chain anchor transaction. This must correspond to the `sender` account below.
    pub signer: &'a S,
    /// The sender account of the anchor transaction.
    pub sender: AccountAddress,
    /// The sequence number for the sender account to use.
    pub account_sequence_number: Nonce,
    /// The transaction expiry time.
    pub expiry: TransactionTime,
}

/// Function that creates and anchors the verification request on-chain.
pub async fn create_and_anchor_verification_request<S: ExactSizeTransactionSigner>(
    mut client: v2::Client,
    anchor_transaction_metadata: AnchorTransactionMetadata<'_, S>,
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
    let item = BlockItem::AccountTransaction(tx);

    // Submit the transaction to the chain.
    let transaction_hash = client.send_block_item(&item).await?;

    Ok(VerificationRequest {
        request: verification_request_data,
        anchor_transaction_hash: transaction_hash,
    })
}

/// The verification audit data to be stored in an off-chain database for regulatory purposes.
/// The type links the private `VerificationAuditRecord` type which its publicly
/// anchored on-chain version via the transaction hash.
/// The type includes the result of the proof verification.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", rename = "ConcordiumVerificationAuditDataV1")]
pub struct VerificationAuditData {
    /// The verification audit record that was anchored on chain.
    #[serde(flatten)]
    pub record: VerificationAuditRecord,
    /// Blockchain transaction hash that anchors the audit.
    pub transaction_ref: TransactionHash,
    /// Boolean specifying if the cryptographic proof verification passed
    /// and the metadata/context/validity of the credential was verified successfully.
    pub verification_result: bool,
}

/// Function that creates and anchors the audit record on-chain.
/// TODO: The function will report additionally if the cryptographic proof and
/// metadata/context/validity of the credential checks have passed successfully.
pub async fn verify_and_anchor_audit_record<S: ExactSizeTransactionSigner>(
    client: v2::Client,
    _network: Network, // needed for the `verify` function.
    anchor_transaction_metadata: AnchorTransactionMetadata<'_, S>,
    verification_audit_record: VerificationAuditRecord,
    public_info: HashMap<String, cbor::value::Value>,
) -> Result<VerificationAuditData, CreateAnchorError> {
    // TODO: call the `verify` function from `RUN-51`.
    // Even if above verification fails, we anchor the audit record on-chain.
    let verification_result = false;

    let transaction_hash = create_and_anchor_audit_record(
        client,
        anchor_transaction_metadata,
        &verification_audit_record,
        public_info,
    )
    .await?;

    Ok(VerificationAuditData {
        record: verification_audit_record,
        transaction_ref: transaction_hash,
        verification_result,
    })
}

/// Function that creates and anchors the audit record on-chain.
pub async fn create_and_anchor_audit_record<S: ExactSizeTransactionSigner>(
    mut client: v2::Client,
    anchor_transaction_metadata: AnchorTransactionMetadata<'_, S>,
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
