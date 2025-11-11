use crate::v2;
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
    #[error("Node RPC error: {0}")]
    RPC(#[from] v2::RPCError),
    #[error("Node query error: {0}")]
    Query(#[from] v2::QueryError),
    #[error("Data register transaction data is too large: {0}")]
    TooLarge(#[from] TooLargeError),
    #[error("Cbor serialization error: {0}")]
    CborSerialization(#[from] CborSerializationError),
}

pub async fn create_and_anchor_verification_request(
    mut client: v2::Client,
    signer: &impl ExactSizeTransactionSigner,
    sender: AccountAddress,
    account_sequence_number: Nonce,
    expiry: TransactionTime,
    verification_request_data: VerificationRequestData,
    public_info: HashMap<String, cbor::value::Value>,
) -> Result<VerificationRequest, CreateAnchorError> {
    let verification_request_anchor = verification_request_data.to_anchor(public_info);
    let cbor = cbor::cbor_encode(&verification_request_anchor)?;
    let register_data = cbor.try_into()?;

    let tx = send::register_data(
        &signer,
        sender,
        account_sequence_number,
        expiry,
        register_data,
    );
    let item = BlockItem::AccountTransaction(tx);

    // Submit the transaction to the chain
    let transaction_hash = client.send_block_item(&item).await?;

    Ok(VerificationRequest {
        request: verification_request_data,
        anchor_transaction_hash: transaction_hash,
    })
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", rename = "ConcordiumVerificationAuditDataV1")]
pub struct VerificationAuditData {
    /// The verification audit record that was anchored on chain.
    #[serde(flatten)]
    pub record: VerificationAuditRecord,
    /// Blockchain transaction hash that anchors the audit.
    pub transaction_ref: TransactionHash,
    /// Boolean specifying if the verification of the verifiable presentation passed.
    pub verification_result: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn verify_and_anchor_audit_record(
    client: v2::Client,
    _network: Network, // needed for the `verify` function.
    signer: &impl ExactSizeTransactionSigner,
    sender: AccountAddress,
    account_sequence_number: Nonce,
    expiry: TransactionTime,
    verification_audit_record: VerificationAuditRecord,
    public_info: HashMap<String, cbor::value::Value>,
) -> Result<VerificationAuditData, CreateAnchorError> {
    // TODO: call the `verify` function from `RUN-51`.
    // Even if above verification fails, we anchor the audit record on-chain.
    let verification_result = false;

    let transaction_hash = create_and_anchor_audit_record(
        client,
        signer,
        sender,
        account_sequence_number,
        expiry,
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

pub async fn create_and_anchor_audit_record(
    mut client: v2::Client,
    signer: &impl ExactSizeTransactionSigner,
    sender: AccountAddress,
    account_sequence_number: Nonce,
    expiry: TransactionTime,
    verification_audit_record: &VerificationAuditRecord,
    public_info: HashMap<String, cbor::value::Value>,
) -> Result<TransactionHash, CreateAnchorError> {
    let verification_audit_anchor = verification_audit_record.to_anchor(public_info);
    let cbor = cbor::cbor_encode(&verification_audit_anchor)?;
    let register_data = cbor.try_into()?;

    let tx = send::register_data(
        &signer,
        sender,
        account_sequence_number,
        expiry,
        register_data,
    );
    let item = BlockItem::AccountTransaction(tx);

    // Submit the transaction to the chain
    let transaction_hash = client.send_block_item(&item).await?;

    Ok(transaction_hash)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_serde_verification_audit_data() {
        // TODO
    }
}
