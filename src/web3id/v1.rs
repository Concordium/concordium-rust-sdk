use crate::types::{AccountTransactionEffects, BlockItemSummaryDetails};
use crate::v2;

use crate::endpoints::RPCError;
use crate::smart_contracts::common::AccountAddress;
use crate::v2::{AccountIdentifier, BlockIdentifier, IntoBlockIdentifier, QueryError};
use crate::web3id::v1::anchor::{AnchorTransactionMetadata, CreateAnchorError};
use concordium_base::base::CredentialRegistrationID;
use concordium_base::common::cbor;
use concordium_base::common::cbor::CborSerializationError;
use concordium_base::common::upward::UnknownDataError;
use concordium_base::hashes::{BlockHash, TransactionHash};
use concordium_base::id::constants::{ArCurve, IpPairing};
use concordium_base::id::types::{ArInfos, GlobalContext, IpIdentity};
use concordium_base::transactions::ExactSizeTransactionSigner;
use concordium_base::web3id;
use concordium_base::web3id::v1::anchor::{
    VerificationAuditRecord, VerificationRequest, VerificationRequestAnchor,
    VerificationRequestData,
};
use concordium_base::web3id::v1::{
    AccountCredentialVerificationMaterial, CredentialMetadataTypeV1, CredentialMetadataV1,
    IdentityCredentialVerificationMaterial,
};
use concordium_base::web3id::{v1, Web3IdAttribute};
use futures::StreamExt;
use futures::{future, TryStreamExt};
use std::collections::{BTreeMap, HashMap};

pub type PresentationV1 = v1::PresentationV1<IpPairing, ArCurve, Web3IdAttribute>;
pub type RequestV1 = v1::RequestV1<ArCurve, Web3IdAttribute>;
pub type CredentialVerificationMaterial = v1::CredentialVerificationMaterial<IpPairing, ArCurve>;

/// Functionality to create the verification request anchor (VRA) and verification audit anchor (VAA).
pub mod anchor;

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
    // todo ar
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

#[derive(Debug)]
pub enum VerifyFailureReason {
    Verify,
}

/// Metadata for transaction submission.
pub struct AuditRecordArgument<S: ExactSizeTransactionSigner> {
    /// Id of the audit record to create. Is fully determined by the verifier/caller.
    pub audit_record_id: String,
    /// Public information to be included in the audit record anchor (VAA) on-chain.
    pub public_info: HashMap<String, cbor::value::Value>,
    /// Metadata for the anchor transaction that submits the audit record anchor (VAA) on-chain.
    pub audit_record_anchor_transaction_metadata: AnchorTransactionMetadata<S>,
}

pub async fn verify_presentation_and_submit_audit_anchor(
    client: &mut v2::Client,
    network: web3id::did::Network,
    block_identifier: impl IntoBlockIdentifier,
    verification_request: VerificationRequest,
    verifiable_presentation: PresentationV1,
    audit_record_arg: AuditRecordArgument<impl ExactSizeTransactionSigner>,
) -> Result<VerificationData, VerifyError> {
    let block_identifier = block_identifier.into_block_identifier();
    let global_context = client
        .get_cryptographic_parameters(block_identifier)
        .await?
        .response;

    let block_info = client.get_block_info(block_identifier).await?.response;

    let (request_anchor_block_hash, request_anchor) =
        lookup_request_anchor(client, verification_request.anchor_transaction_hash).await?;

    let verification_material =
        lookup_verification_materials(client, block_identifier, &verifiable_presentation).await?;

    let verification_result = verify_request_and_presentation(
        &global_context,
        &verification_request,
        &verifiable_presentation,
        verification_material.iter(),
        request_anchor_block_hash,
        &request_anchor,
    )
    .is_ok();

    let verification_audit_record = VerificationAuditRecord::new(
        verification_request,
        audit_record_arg.audit_record_id,
        verifiable_presentation,
    );
    let transaction_hash = anchor::submit_verification_audit_record_anchor(
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

/// Looks up the request anchor on the chain and returns it
async fn lookup_request_anchor(
    client: &mut v2::Client,
    anchor_transaction_hash: TransactionHash,
) -> Result<(BlockHash, VerificationRequestAnchor), VerifyError> {
    // Fetch the finalized transaction
    let (_, block_hash, summary) = client
        .get_finalized_block_item(anchor_transaction_hash)
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
    let anchor: VerificationRequestAnchor = cbor::cbor_decode(data.as_ref())?;

    Ok((block_hash, anchor))
}

/// Lookup verification material for presentation
async fn lookup_verification_materials(
    client: &mut v2::Client,
    block_identifier: BlockIdentifier,
    presentation: &PresentationV1,
) -> Result<Vec<CredentialVerificationMaterial>, VerifyError> {
    let verification_material = future::try_join_all(presentation.metadata().map(|metadata| {
        let mut client = client.clone();
        async move {
            lookup_verification_material(&mut client, block_identifier, &metadata.cred_metadata)
                .await
        }
    }))
    .await?;
    Ok(verification_material)
}

/// Lookup verification material for presentation
async fn lookup_verification_material(
    client: &mut v2::Client,
    block_identifier: BlockIdentifier,
    credential_metadata: &CredentialMetadataTypeV1,
) -> Result<CredentialVerificationMaterial, VerifyError> {
    Ok(match credential_metadata {
        CredentialMetadataTypeV1::Account(metadata) => {
            let account_info = client
                .get_account_info(
                    &AccountIdentifier::CredId(metadata.cred_id),
                    block_identifier,
                )
                .await?;
            let Some(cred) = account_info
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

            // if c.issuer() != issuer {
            //     return Err(CredentialLookupError::InconsistentIssuer {
            //         stated: issuer,
            //         actual: c.issuer(),
            //     });
            // }

            // let credential_validity = CredentialValidity {
            //     created_at: cdv.policy.created_at,
            //     valid_to: cdv.policy.valid_to,
            // };
            // let status =
            //     determine_credential_validity_status(&credential_validity, &block_info)?;

            match cred {
                concordium_base::id::types::AccountCredentialWithoutProofs::Initial { .. } => {
                    return Err(VerifyError::InitialCredential {
                        cred_id: metadata.cred_id,
                    })
                }
                concordium_base::id::types::AccountCredentialWithoutProofs::Normal {
                    cdv,
                    commitments,
                } => {
                    CredentialVerificationMaterial::Account(AccountCredentialVerificationMaterial {
                        attribute_commitments: commitments.cmm_attributes.clone(),
                    })
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

            CredentialVerificationMaterial::Identity(IdentityCredentialVerificationMaterial {
                ip_info,
                ars_infos: ArInfos {
                    anonymity_revokers: ars_infos,
                },
            })
        }
    })
}

/// This function performs several validation steps:
/// * 1. The verification request anchor on-chain corresponds to the given verification request.
fn verify_request_and_presentation<'a>(
    global_context: &'a GlobalContext<ArCurve>,
    request: &VerificationRequest,
    presentation: &PresentationV1,
    verification_material: impl ExactSizeIterator<Item = &'a CredentialVerificationMaterial>,
    request_anchor_block_hash: BlockHash,
    request_anchor: &VerificationRequestAnchor,
) -> Result<(), VerifyFailureReason> {
    // Verify the request matches the request anchor
    verify_request_anchor(request, request_anchor)?;

    // Verify anchor block hash matches presentation context
    verify_anchor_block_hash(request_anchor_block_hash, presentation)?;

    // Cryptographically verify the presentation
    let request_from_presentation =
        verify_presentation(global_context, presentation, verification_material)?;

    // Verify the request matches the presentation
    verify_request(&request_from_presentation, request)?;

    Ok(())
}

fn verify_presentation<'a>(
    global_context: &'a GlobalContext<ArCurve>,
    presentation: &PresentationV1,
    verification_material: impl ExactSizeIterator<Item = &'a CredentialVerificationMaterial>,
) -> Result<RequestV1, VerifyFailureReason> {
    presentation
        .verify(global_context, verification_material)
        .map_err(|_| VerifyFailureReason::Verify)
}

fn verify_anchor_block_hash(
    request_anchor_block_hash: BlockHash,
    presentation: &PresentationV1,
) -> Result<(), VerifyFailureReason> {
    // todo verify request anchor block hash matches presentation context

    Ok(())
}

/// Verify that request anchor matches the verification request.
fn verify_request_anchor(
    verification_request: &VerificationRequest,
    request_anchor: &VerificationRequestAnchor,
) -> Result<(), VerifyFailureReason> {
    let verification_request_data = VerificationRequestData {
        context: verification_request.context.clone(),
        subject_claims: verification_request.subject_claims.clone(),
    };

    if verification_request_data.hash() != request_anchor.hash {
        return Err(VerifyFailureReason::Verify);
    }

    Ok(())
}

/// Verify that verifiable presentation matches the verification request.
fn verify_request(
    request_from_presentation: &RequestV1,
    verification_request: &VerificationRequest,
) -> Result<(), VerifyFailureReason> {
    // todo verify subject claims in presentation matches request
    //      this incudes both statements and the identity provider and the credential type
    // todo verify context in presentation matches request context

    Ok(())
}

// /// determine the credential validity based on the valid from and valid to date information.
// /// The block info supplied has the slot time we will use as the current time, to check validity against
// fn determine_credential_validity_status(
//     validity: CredentialValidity,
//     block_info: BlockInfo,
// ) -> Result<CredentialStatus, CredentialLookupError> {
//     let valid_from = validity
//         .created_at
//         .lower()
//         .ok_or(CredentialLookupError::InvalidResponse(
//             "Credential valid from date is not valid.".into(),
//         ))?;
//
//     let valid_to = validity
//         .valid_to
//         .upper()
//         .ok_or(CredentialLookupError::InvalidResponse(
//             "Credential valid to date is not valid.".into(),
//         ))?;
//
//     let now = block_info.block_slot_time;
//
//     if valid_from > now {
//         Ok(CredentialStatus::NotActivated)
//     } else if valid_to >= now {
//         Ok(CredentialStatus::Active)
//     } else {
//         Ok(CredentialStatus::Expired)
//     }
// }
