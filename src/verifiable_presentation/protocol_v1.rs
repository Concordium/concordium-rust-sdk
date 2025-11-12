//! Types and functions used in Concordium verifiable presentation protocol version 1.
use crate::{
    types::{AccountTransactionEffects, BlockItemSummaryDetails},
    v2::{self, RPCError},
};
use concordium_base::{
    base::Nonce,
    common::{
        cbor::{self, CborSerializationError},
        types::TransactionTime,
        upward::UnknownDataError,
    },
    contracts_common::AccountAddress,
    hashes::TransactionHash,
    id::constants::{ArCurve, IpPairing},
    transactions::{send, BlockItem, ExactSizeTransactionSigner, TooLargeError},
    web3id::{
        sdk::protocol::{
            VerificationAuditRecord, VerificationRequest, VerificationRequestAnchor,
            VerificationRequestData,
        },
        v1::PresentationV1,
        Web3IdAttribute,
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

#[derive(thiserror::Error, Debug)]
pub enum VerifyAnchorError {
    #[error(
        "On-chain anchor was invalid and could not be retrieved from anchor transaction hash."
    )]
    InvalidOnChainAnchor,
    #[error("Unknown data error: {0}")]
    UnknownDataError(#[from] UnknownDataError),
    #[error("Cbor serialization error: {0}")]
    CborSerialization(#[from] CborSerializationError),
    #[error("Node query error: {0}")]
    Query(#[from] v2::QueryError),
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

/// The anchored verification audit record to be stored in an off-chain database for regulatory purposes.
/// The type links the private `VerificationAuditRecord` type which its publicly
/// anchored on-chain version via the transaction hash.
/// The type includes the result of the proof verification.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", rename = "ConcordiumAnchoredVerificationAuditRecordV1")]
pub struct AnchoredVerificationAuditRecord {
    /// The verification audit record that was anchored on chain.
    #[serde(flatten)]
    pub record: VerificationAuditRecord,
    /// Blockchain transaction hash that anchors the audit.
    pub transaction_ref: TransactionHash,
    /// Boolean specifying if the cryptographic proof verification passed
    /// and the metadata/context/validity of the credential was verified successfully.
    pub verification_result: bool,
}

/// Function that verifies if the on-chain hash matches the computed hash given the context/statements.
pub async fn verify_verification_request_anchor_hash(
    client: &mut v2::Client,
    verification_request: VerificationRequest,
) -> Result<(), VerifyAnchorError> {
    let VerificationRequest { request, .. } = verification_request;

    // Build verification data
    let mut verification_data = VerificationRequestData::new(request.context);
    for claim in request.subject_claims {
        verification_data = verification_data.add_statement_request(claim);
    }

    let computed_hash = verification_data.hash();

    // Fetch the finalized transaction
    let (_, _, summary) = client
        .get_finalized_block_item(verification_request.anchor_transaction_hash)
        .await?;

    // Extract account transaction
    let BlockItemSummaryDetails::AccountTransaction(anchor_tx) = summary.details.known_or_err()?
    else {
        return Err(VerifyAnchorError::InvalidOnChainAnchor);
    };

    // Extract data registered payload
    let AccountTransactionEffects::DataRegistered { data } = anchor_tx.effects.known_or_err()?
    else {
        return Err(VerifyAnchorError::InvalidOnChainAnchor);
    };

    // Decode anchor hash
    let anchor: VerificationRequestAnchor = cbor::cbor_decode(data.as_ref())?;

    if computed_hash != anchor.hash {
        return Err(VerifyAnchorError::InvalidOnChainAnchor);
    }

    Ok(())
}

/// This function performs several validation steps:
/// * 1. The verification request anchor on-chain corresponds to the given verification request.
pub async fn verify(
    client: &mut v2::Client,
    verification_request: VerificationRequest,
    _presentation: &PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
) -> Result<bool, CreateAnchorError> {
    let verified = verify_verification_request_anchor_hash(client, verification_request)
        .await
        .is_ok();

    // TODO: call the `verify` function/functions from `RUN-51`.
    // See also https://github.com/Concordium/concordium-node-sdk-js/pull/591

    // 1. Check the context in verifiable presentation matches the context in the request.
    // compareContexts(request, presentation);

    // 2. Verify cryptographic integrity of presentation and metadata
    // https://linear.app/concordium/issue/RUN-22/add-support-to-the-rust-sdk-for-cryptographic-verification-of-a#comment-1de4df29

    // 3. Check that none of the credentials have expired
    // determine_credential_validity_status() function in open PR for `RUN-51`.

    // 4. Check the claims in verifiable presentation matches the statements in the request.
    // verifyPresentationRequest(client, verification_request, _presentation.request);

    Ok(verified)
}

/// Function that creates and anchors the audit record on-chain.
/// TODO: The function will report additionally if the cryptographic proof and
/// metadata/context/validity of the credential checks have passed successfully.
pub async fn verify_and_anchor_audit_record<S: ExactSizeTransactionSigner>(
    client: &mut v2::Client,
    anchor_transaction_metadata: AnchorTransactionMetadata<'_, S>,
    verification_request: VerificationRequest,
    presentation: PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
    id: String,
    public_info: HashMap<String, cbor::value::Value>,
) -> Result<AnchoredVerificationAuditRecord, CreateAnchorError> {
    let verification_result = verify(client, verification_request.clone(), &presentation).await?;

    let verification_audit_record =
        VerificationAuditRecord::new(verification_request, id, presentation);
    let transaction_hash = create_and_anchor_audit_record(
        client,
        anchor_transaction_metadata,
        &verification_audit_record,
        public_info,
    )
    .await?;

    Ok(AnchoredVerificationAuditRecord {
        record: verification_audit_record,
        transaction_ref: transaction_hash,
        verification_result,
    })
}

/// Function that creates and anchors the audit record on-chain.
pub async fn create_and_anchor_audit_record<S: ExactSizeTransactionSigner>(
    client: &mut v2::Client,
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
