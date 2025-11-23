//! Functionality for requesting and verifying V1 Concordium verifiable presentations.
//!
//! A verification flow consists of multiple stages:
//!
//! 1. Create a [`VerificationRequest`]: A verification flow is started by constructing [`VerificationRequestData`]
//! and creating the [`VerificationRequest`] with [`create_verification_request_and_submit_anchor`] which also
//! submits the corresponding [`VerificationRequestAnchor`] (VRA) on chain.
//!
//! 2. Generate and prove [`VerifiablePresentationV1`]: The claims in the [`VerificationRequest`] are
//! proved by a credential holder in the context specified in the request and
//! embedded in a [`VerifiablePresentationV1`] together with the context and proofs.
//! The prover is implemented in [`VerifiablePresentationRequestV1::prove`](anchor::VerifiablePresentationRequestV1::prove).
//!
//! 3. Verify a [`VerifiablePresentationV1`]: The presentation can be verified together with
//! the verification request with [`verify_presentation_and_submit_audit_anchor`], which submits
//! and [`VerificationAuditRecord`] (VAA) on chain and returns the [`VerificationAuditRecord`] to
//! be stored locally by the verifier.
//!
//! 4. Verify an [`VerificationAuditRecord`]: The stored audit record can be re-verified with
//! [`verify_audit_record`] if/when needed.
//!
//! The example `web3id_v1_verification_flow` demonstrates the verification flow.

use crate::types::{AccountTransactionEffects, BlockItemSummaryDetails};
use crate::v2;

use crate::endpoints::RPCError;
use crate::smart_contracts::common::AccountAddress;
use crate::v2::{AccountIdentifier, BlockIdentifier, IntoBlockIdentifier, QueryError};
use concordium_base::base::{CredentialRegistrationID, Nonce};
use concordium_base::common::cbor;
use concordium_base::common::cbor::CborSerializationError;
use concordium_base::common::upward::UnknownDataError;
use concordium_base::hashes::TransactionHash;
use concordium_base::id::types;
use concordium_base::id::types::{AccountCredentialWithoutProofs, ArInfos, IpIdentity};
use concordium_base::transactions::{
    send, BlockItem, ExactSizeTransactionSigner, RegisteredData, TooLargeError,
};
use concordium_base::web3id::v1::anchor::{
    self as anchor, CredentialValidityType, PresentationVerificationResult,
    VerifiablePresentationV1, VerificationAuditRecord, VerificationContext, VerificationMaterial,
    VerificationMaterialWithValidity, VerificationRequest, VerificationRequestAnchor,
    VerificationRequestAnchorAndBlockHash, VerificationRequestData,
};
use concordium_base::web3id::v1::{
    AccountCredentialVerificationMaterial, CredentialMetadataTypeV1, CredentialMetadataV1,
    IdentityCredentialVerificationMaterial,
};
use concordium_base::{hashes, web3id};

use concordium_base::common::types::TransactionTime;
use futures::StreamExt;
use futures::{future, TryStreamExt};
use std::collections::{BTreeMap, HashMap};

/// Data returned from verifying a presentation against the corresponding verification request.
/// Contains the verification result, the audit record and the transaction hash
/// for the transaction registering the verification audit anchor (VAA) on-chain in case
/// the verification was successful.
/// The audit record should be stored in an off-chain database for regulatory purposes
/// and should generally be kept private.
#[derive(Debug, Clone, PartialEq)]
pub struct PresentationVerificationData {
    // Whether the verification was successful. If `false`, the verifiable presentation is not
    // valid and the credentials and claims in it are not verified to be true.
    pub verification_result: PresentationVerificationResult,
    /// The verification audit record. A corresponding [`VerificationRequestAnchor`] (VAA) is submitted
    /// on chain, if the verification is successful. Notice that the existence of the audit record,
    /// does not mean that verification was successful, that is specified
    /// by [`Self::verification_result`]. The audit record should be stored in an off-chain database for regulatory purposes
    // /// and should generally be kept private.
    pub audit_record: VerificationAuditRecord,
    /// Blockchain transaction hash for the transaction that registers
    /// the verification audit anchor (VAA) on-chain. Notice that
    /// this transaction may not have been finalized yet. The anchor is
    /// only submitted if the verification is successful.
    pub anchor_transaction_hash: Option<hashes::TransactionHash>,
}

#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("on-chain request anchor transaction is of invalid type")]
    InvalidRequestAnchor,
    #[error("on-chain request anchor transaction not finalized yet")]
    RequestAnchorNotFinalized,
    #[error("unknown data error: {0}")]
    UnknownDataError(#[from] UnknownDataError),
    #[error("node query error: {0}")]
    Query(#[from] v2::QueryError),
    #[error("create anchor: {0}")]
    Anchor(#[from] CreateAnchorError),
    #[error("CBOR serialization error: {0}")]
    CborSerialization(#[from] CborSerializationError),
    #[error("unknown identity provider: {0}")]
    UnknownIdentityProvider(IpIdentity),
    #[error("credential {cred_id} no longer present or of unknown type on account: {account}")]
    CredentialNotPresent {
        cred_id: CredentialRegistrationID,
        account: AccountAddress,
    },
    #[error("initial credential {cred_id} cannot be used.")]
    InitialCredential { cred_id: CredentialRegistrationID },
}

/// Metadata for transaction submission.
pub struct AuditRecordArgument<S: ExactSizeTransactionSigner> {
    /// Id of the audit record to create. Is fully determined by the verifier/caller.
    pub audit_record_id: String,
    /// Public information to be included in the audit record anchor (VAA) on-chain.
    pub public_info: Option<HashMap<String, cbor::value::Value>>,
    /// Metadata for the anchor transaction that submits the audit record anchor (VAA) on-chain.
    pub audit_record_anchor_transaction_metadata: AnchorTransactionMetadata<S>,
}

// todo ar doc
pub async fn verify_audit_record(
    client: &mut v2::Client,
    network: web3id::did::Network,
    block_identifier: impl IntoBlockIdentifier,
    verification_audit_record: &VerificationAuditRecord,
) -> Result<PresentationVerificationResult, VerifyError> {
    let block_identifier = block_identifier.into_block_identifier();
    let global_context = client
        .get_cryptographic_parameters(block_identifier)
        .await?
        .response;

    let block_info = client.get_block_info(block_identifier).await?.response;

    let request_anchor = lookup_request_anchor(client, &verification_audit_record.request).await?;

    let verification_material = lookup_verification_materials_and_validity(
        client,
        block_identifier,
        &verification_audit_record.presentation,
    )
    .await?;

    let context = VerificationContext {
        network,
        validity_time: block_info.block_slot_time,
    };

    Ok(anchor::verify_presentation_with_request_anchor(
        &global_context,
        &context,
        &verification_audit_record.request,
        &verification_audit_record.presentation,
        &request_anchor,
        &verification_material,
    ))
}

// todo ar doc
pub async fn verify_presentation_and_submit_audit_anchor(
    client: &mut v2::Client,
    network: web3id::did::Network,
    block_identifier: impl IntoBlockIdentifier,
    verification_request: VerificationRequest,
    verifiable_presentation: VerifiablePresentationV1,
    audit_record_arg: AuditRecordArgument<impl ExactSizeTransactionSigner>,
) -> Result<PresentationVerificationData, VerifyError> {
    let block_identifier = block_identifier.into_block_identifier();
    let global_context = client
        .get_cryptographic_parameters(block_identifier)
        .await?
        .response;

    let block_info = client.get_block_info(block_identifier).await?.response;

    let request_anchor = lookup_request_anchor(client, &verification_request).await?;

    let verification_material = lookup_verification_materials_and_validity(
        client,
        block_identifier,
        &verifiable_presentation,
    )
    .await?;

    let context = VerificationContext {
        network,
        validity_time: block_info.block_slot_time,
    };

    let verification_result = anchor::verify_presentation_with_request_anchor(
        &global_context,
        &context,
        &verification_request,
        &verifiable_presentation,
        &request_anchor,
        &verification_material,
    );

    let audit_record = VerificationAuditRecord::new(
        audit_record_arg.audit_record_id,
        verification_request,
        verifiable_presentation,
    );

    let anchor_transaction_hash = if verification_result.is_success() {
        let txn_hash = submit_verification_audit_record_anchor(
            client,
            audit_record_arg.audit_record_anchor_transaction_metadata,
            &audit_record,
            audit_record_arg.public_info,
        )
        .await?;
        Some(txn_hash)
    } else {
        None
    };

    Ok(PresentationVerificationData {
        verification_result,
        audit_record,
        anchor_transaction_hash,
    })
}

/// Looks up the verifiable request anchor (VRA) from the verification
/// request.
pub async fn lookup_request_anchor(
    client: &mut v2::Client,
    verification_request: &VerificationRequest,
) -> Result<VerificationRequestAnchorAndBlockHash, VerifyError> {
    // Fetch the transaction
    let item_status = client
        .get_block_item_status(&verification_request.anchor_transaction_hash)
        .await?;

    let (block_hash, summary) = item_status
        .is_finalized()
        .ok_or(VerifyError::RequestAnchorNotFinalized)?;

    // Extract account transaction
    let BlockItemSummaryDetails::AccountTransaction(anchor_tx) =
        summary.details.as_ref().known_or_err()?
    else {
        return Err(VerifyError::InvalidRequestAnchor);
    };

    // Extract data registered payload
    let AccountTransactionEffects::DataRegistered { data } =
        anchor_tx.effects.as_ref().known_or_err()?
    else {
        return Err(VerifyError::InvalidRequestAnchor);
    };

    // Decode anchor hash
    let verification_request_anchor: VerificationRequestAnchor = cbor::cbor_decode(data.as_ref())?;

    Ok(VerificationRequestAnchorAndBlockHash {
        verification_request_anchor,
        block_hash: *block_hash,
    })
}

/// Lookup verification material for presentation
async fn lookup_verification_materials_and_validity(
    client: &mut v2::Client,
    block_identifier: BlockIdentifier,
    presentation: &VerifiablePresentationV1,
) -> Result<Vec<VerificationMaterialWithValidity>, VerifyError> {
    let verification_material =
        future::try_join_all(presentation.metadata().map(|cred_metadata| {
            let mut client = client.clone();
            async move {
                lookup_verification_material_and_validity(
                    &mut client,
                    block_identifier,
                    &cred_metadata,
                )
                .await
            }
        }))
        .await?;
    Ok(verification_material)
}

/// Lookup verification material for presentation
async fn lookup_verification_material_and_validity(
    client: &mut v2::Client,
    block_identifier: BlockIdentifier,
    cred_metadata: &CredentialMetadataV1,
) -> Result<VerificationMaterialWithValidity, VerifyError> {
    Ok(match &cred_metadata.cred_metadata {
        CredentialMetadataTypeV1::Account(metadata) => {
            let account_info = client
                .get_account_info(
                    &AccountIdentifier::CredId(metadata.cred_id),
                    block_identifier,
                )
                .await?;

            let Some(account_cred) =
                account_info
                    .response
                    .account_credentials
                    .values()
                    .find_map(|cred| {
                        cred.value
                            .as_ref()
                            .known()
                            .and_then(|c| (c.cred_id() == metadata.cred_id.as_ref()).then_some(c))
                    })
            else {
                return Err(VerifyError::CredentialNotPresent {
                    cred_id: metadata.cred_id,
                    account: account_info.response.account_address,
                });
            };

            match account_cred {
                AccountCredentialWithoutProofs::Initial { .. } => {
                    return Err(VerifyError::InitialCredential {
                        cred_id: metadata.cred_id,
                    })
                }
                AccountCredentialWithoutProofs::Normal { cdv, commitments } => {
                    let credential_validity = types::CredentialValidity {
                        created_at: account_cred.policy().created_at,
                        valid_to: cdv.policy.valid_to,
                    };

                    VerificationMaterialWithValidity {
                        verification_material: VerificationMaterial::Account(
                            AccountCredentialVerificationMaterial {
                                issuer: cdv.ip_identity,
                                attribute_commitments: commitments.cmm_attributes.clone(),
                            },
                        ),
                        validity: CredentialValidityType::ValidityPeriod(credential_validity),
                    }
                }
            }
        }
        CredentialMetadataTypeV1::Identity(metadata) => {
            let ip_info = client
                .get_identity_providers(block_identifier)
                .await?
                .response
                .try_filter(|ip| future::ready(ip.ip_identity == metadata.issuer))
                .next()
                .await
                .ok_or(VerifyError::UnknownIdentityProvider(metadata.issuer))?
                .map_err(|status| QueryError::RPCError(RPCError::CallError(status)))?;

            let ars_infos: BTreeMap<_, _> = client
                .get_anonymity_revokers(block_identifier)
                .await?
                .response
                .map_ok(|ar_info| (ar_info.ar_identity, ar_info))
                .try_collect()
                .await
                .map_err(|status| QueryError::RPCError(RPCError::CallError(status)))?;

            VerificationMaterialWithValidity {
                verification_material: VerificationMaterial::Identity(
                    IdentityCredentialVerificationMaterial {
                        ip_info,
                        ars_infos: ArInfos {
                            anonymity_revokers: ars_infos,
                        },
                    },
                ),
                validity: CredentialValidityType::ValidityPeriod(metadata.validity.clone()),
            }
        }
    })
}

/// Error creating and registering anchor.
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

/// Metadata for anchor transaction submission.
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
///
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
    public_info: Option<HashMap<String, cbor::value::Value>>,
) -> Result<VerificationRequest, CreateAnchorError> {
    let verification_request_anchor = verification_request_data.to_anchor(public_info);
    let cbor = cbor::cbor_encode(&verification_request_anchor)?;
    let register_data = RegisteredData::try_from(cbor)?;

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
///
/// Notice that the VAA will only be submitted, it is not included on-chain yet when
/// the function returns. The transaction must
/// be tracked until finalization for the audit record to be registered successfully.
pub async fn submit_verification_audit_record_anchor<S: ExactSizeTransactionSigner>(
    client: &mut v2::Client,
    anchor_transaction_metadata: AnchorTransactionMetadata<S>,
    verification_audit_record: &VerificationAuditRecord,
    public_info: Option<HashMap<String, cbor::value::Value>>,
) -> Result<TransactionHash, CreateAnchorError> {
    let verification_audit_anchor = verification_audit_record.to_anchor(public_info);
    let cbor = cbor::cbor_encode(&verification_audit_anchor)?;
    let register_data = RegisteredData::try_from(cbor)?;

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
