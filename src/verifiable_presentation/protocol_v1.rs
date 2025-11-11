use crate::{
    v2,
    verifiable_presentation::web3id::sdk::protocol::{Context, CredentialStatementRequest},
};
use concordium_base::transactions::TooLargeError;
use concordium_base::{
    base::Nonce,
    common::{cbor, types::TransactionTime},
    contracts_common::AccountAddress,
    hashes::TransactionHash,
    transactions::{send, BlockItem, ExactSizeTransactionSigner},
    web3id::sdk::protocol::VerificationRequestData,
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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
// #[serde(tag = "type", rename = "ConcordiumContextInformationV1")] // TODO: check if we need to tag
pub struct VerificationRequestV1 {
    /// TODO
    pub context: Context,
    /// TODO
    pub credential_statements: Vec<CredentialStatementRequest>,
    /// TODO
    pub transaction_ref: TransactionHash,
}

impl VerificationRequestV1 {
    pub async fn create_and_anchor(
        mut client: v2::Client,
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        account_sequence_number: Nonce,
        expiry: TransactionTime,
        verification_request_data: VerificationRequestData,
        public_info: HashMap<String, cbor::value::Value>,
    ) -> Result<VerificationRequestV1, CreateAnchorError> {
        let verification_request_anchor = verification_request_data.to_anchor(public_info);
        let cbor = cbor::cbor_encode(&verification_request_anchor).unwrap(); // TODO: remove the unwrap
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
        client.wait_until_finalized(&transaction_hash).await?;

        Ok(VerificationRequestV1 {
            context: verification_request_data.context,
            credential_statements: verification_request_data.subject_claims,
            transaction_ref: transaction_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_serde_verification_request() {
        // TODO
    }
}
