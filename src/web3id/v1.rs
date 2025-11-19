//! Functionality for requesting and verifying V1 Web3Id credentials.
//!
//! A verification flow is started by constructing [`VerificationRequestData`]
//! and submitting the corresponding [`VerificationRequestAnchor`] (VRA) on chain with
//! [`create_verification_request_and_submit_anchor`]. The returned [`VerificationRequest`] is handed over
//! to a credential holder to create a [`VerifiablePresentationV1`]. The presentation is then verified together with
//! the verification request with [`verify_presentation_and_submit_audit_anchor`], which submits
//! and [`VerificationAuditRecord`] (VAA) on chain and returns the [`VerificationAuditRecord`] to
//! be stored locally by the verifier.

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
use concordium_base::web3id;
use concordium_base::web3id::v1::anchor::{
    self as base_anchor, CredentialValidityType, VerifiablePresentationV1, VerificationAuditRecord,
    VerificationContext, VerificationMaterial, VerificationMaterialWithValidity,
    VerificationRequest, VerificationRequestAnchor, VerificationRequestAnchorAndBlockHash,
    VerificationRequestData,
};
use concordium_base::web3id::v1::{
    AccountCredentialVerificationMaterial, CredentialMetadataTypeV1, CredentialMetadataV1,
    IdentityCredentialVerificationMaterial,
};

use concordium_base::common::types::TransactionTime;
use futures::StreamExt;
use futures::{future, TryStreamExt};
use std::collections::{BTreeMap, HashMap};

/// The verification audit record and the transaction hash
/// for the transaction registering the verification audit anchor (VAA) on-chain.
/// The audit record should be stored in an off-chain database for regulatory purposes
/// and should generally be kept private.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", rename = "ConcordiumVerificationDataV1")]
pub struct VerificationData {
    /// The verification audit record that was anchored on chain.
    pub record: VerificationAuditRecord,
    /// Blockchain transaction hash for the transaction that registers
    /// the verification audit anchor (VAA) on-chain. Notice that
    /// this transaction may not have been finalized yet.
    pub transaction_ref: TransactionHash,
    // Whether the verification was successful. If `false`, the verifiable presentation is not
    // valid and the claims in it are not verified to be true.
    pub verification_result: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error(
        "on-chain request anchor was invalid and could not be retrieved from anchor transaction hash"
    )]
    InvalidRequestAnchor,
    #[error("unknown data error: {0}")]
    UnknownDataError(#[from] UnknownDataError),
    #[error("CBOR serialization error: {0}")]
    CborSerialization(#[from] CborSerializationError),
    #[error("node query error: {0}")]
    Query(#[from] v2::QueryError),
    #[error("create anchor: {0}")]
    Anchor(#[from] CreateAnchorError),
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

pub async fn verify_presentation_and_submit_audit_anchor(
    client: &mut v2::Client,
    network: web3id::did::Network,
    block_identifier: impl IntoBlockIdentifier,
    verification_request: VerificationRequest,
    verifiable_presentation: VerifiablePresentationV1,
    audit_record_arg: AuditRecordArgument<impl ExactSizeTransactionSigner>,
) -> Result<VerificationData, VerifyError> {
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

    let verification_result = base_anchor::verify_presentation_with_request_anchor(
        &global_context,
        &context,
        &verification_request,
        &verifiable_presentation,
        &request_anchor,
        &verification_material,
    )
    .is_ok();

    let verification_audit_record = VerificationAuditRecord::new(
        audit_record_arg.audit_record_id,
        verification_request,
        verifiable_presentation,
    );
    let transaction_hash = submit_verification_audit_record_anchor(
        client,
        audit_record_arg.audit_record_anchor_transaction_metadata,
        &verification_audit_record,
        audit_record_arg.public_info,
    )
    .await?;

    Ok(VerificationData {
        record: verification_audit_record,
        transaction_ref: transaction_hash,
        verification_result,
    })
}

/// Looks up the verifiable request anchor (VRA) from the verification
/// request.
pub async fn lookup_request_anchor(
    client: &mut v2::Client,
    verification_request: &VerificationRequest,
) -> Result<VerificationRequestAnchorAndBlockHash, VerifyError> {
    // Fetch the finalized transaction
    let (_, block_hash, summary) = client
        .get_finalized_block_item(verification_request.anchor_transaction_hash)
        .await?;

    // Extract account transaction
    let BlockItemSummaryDetails::AccountTransaction(anchor_tx) = summary.details.known_or_err()?
    else {
        return Err(VerifyError::InvalidRequestAnchor);
    };

    // Extract data registered payload
    let AccountTransactionEffects::DataRegistered { data } = anchor_tx.effects.known_or_err()?
    else {
        return Err(VerifyError::InvalidRequestAnchor);
    };

    // Decode anchor hash
    let verification_request_anchor: VerificationRequestAnchor = cbor::cbor_decode(data.as_ref())?;

    Ok(VerificationRequestAnchorAndBlockHash {
        verification_request_anchor,
        block_hash,
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
