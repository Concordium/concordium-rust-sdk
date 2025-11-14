use crate::types::{AccountTransactionEffects, BlockItemSummaryDetails};
use crate::v2;

use crate::web3id::v1::anchor::{AnchorTransactionMetadata, CreateAnchorError};
use concordium_base::common::cbor;
use concordium_base::common::cbor::CborSerializationError;
use concordium_base::common::upward::UnknownDataError;
use concordium_base::hashes;
use concordium_base::hashes::{BlockHash, TransactionHash};
use concordium_base::id::constants::{ArCurve, IpPairing};
use concordium_base::transactions::ExactSizeTransactionSigner;
use concordium_base::web3id::v1::anchor::{
    UnfilledContextInformation, VerificationAuditRecord, VerificationRequest,
    VerificationRequestAnchor, VerificationRequestData,
};
use concordium_base::web3id::v1::{ContextInformation, ContextProperty, PresentationV1};
use concordium_base::web3id::Web3IdAttribute;
use std::collections::HashMap;

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

#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("error")]
    Verify,
}

/// Function that creates and anchors the audit record on-chain.
/// TODO: The function will report additionally if the cryptographic proof and
/// metadata/context/validity of the credential checks have passed successfully.
pub async fn verify_and_anchor_audit_record<S: ExactSizeTransactionSigner>(
    client: &mut v2::Client,
    anchor_transaction_metadata: AnchorTransactionMetadata<'_, S>,
    verification_request: VerificationRequest,
    verifiable_presentation: PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
    audit_record_id: String,
    public_info: HashMap<String, cbor::value::Value>,
) -> Result<VerificationData, VerifyAnchorError> {
    let (request_anchor_block_hash, request_anchor) =
        lookup_request_anchor(client, verification_request.anchor_transaction_hash).await?;

    let verification_result = verify_request_and_presentation(
        &verification_request,
        &verifiable_presentation,
        request_anchor_block_hash,
        request_anchor,
    )
    .is_ok();

    let verification_audit_record = VerificationAuditRecord::new(
        verification_request,
        audit_record_id,
        verifiable_presentation,
        verification_result,
    );
    let transaction_hash = anchor::submit_verification_audit_record_anchor(
        client,
        anchor_transaction_metadata,
        &verification_audit_record,
        public_info,
    )
    .await?;

    Ok(VerificationData {
        record: verification_audit_record,
        transaction_ref: transaction_hash,
    })
}

/// Looks up request anchor on chain and returns it
async fn lookup_request_anchor(
    client: &mut v2::Client,
    anchor_transaction_hash: TransactionHash,
) -> Result<(BlockHash, VerificationRequestAnchor), VerifyAnchorError> {
    // Fetch the finalized transaction
    let (_, block_hash, summary) = client
        .get_finalized_block_item(anchor_transaction_hash)
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

    Ok((block_hash, anchor))
}

/// This function performs several validation steps:
/// * 1. The verification request anchor on-chain corresponds to the given verification request.
fn verify_request_and_presentation(
    request: &VerificationRequest,
    presentation: &PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
    request_anchor_block_hash: BlockHash,
    request_anchor: &VerificationRequestAnchor,
) -> Result<(), VerifyError> {
    // Verify the request matches the request anchor
    verify_request_anchor(request, request_anchor)?;

    // Verify the request matches the presentation
    verify_request(request, presentation)?;

    // Verify anchor block hash matches presentation context
    verify_anchor_block_hash(request_anchor_block_hash, presentation)?;

    // 2. Verify cryptographic integrity of presentation and metadata
    // https://linear.app/concordium/issue/RUN-22/add-support-to-the-rust-sdk-for-cryptographic-verification-of-a#comment-1de4df29

    // 3. Check that none of the credentials have expired
    // determine_credential_validity_status() function in open PR for `RUN-51`.

    Ok(())
}

fn verify_anchor_block_hash(
    request_anchor_block_hash: BlockHash,
    presentation: &PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
) -> Result<(), VerifyError> {
    // todo verify request anchor block hash matches presentation context

    Ok(())
}


/// Verify that request anchor matches the verification request.
fn verify_request_anchor(
    verification_request: &VerificationRequest,
    request_anchor: &VerificationRequestAnchor,
) -> Result<(), VerifyError> {
    let verification_request_data = VerificationRequestData {
        context: verification_request.context.clone(),
        subject_claims: verification_request.subject_claims.clone(),
    };

    if verification_request_data.hash() != request_anchor.hash {
        return Err(VerifyError::Verify);
    }

    Ok(())
}

/// Verify that verifiable presentation matches the verification request.
fn verify_request(
    verification_request: &VerificationRequest,
    verifiable_presentation: &PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
) -> Result<(), VerifyError> {
    // todo verify subject claims in presentation matches request
    //      this incudes both statements and the identity provider and the credential type
    // todo verify context in presentation matches request context

    Ok(())
}

// check the list of identity providers to find the matching one for the issuer u32 provided
fn determine_ip_info(
    issuer: u32,
    ip_info_list: Vec<IpInfo<IpPairing>>,
) -> Result<IpInfo<IpPairing>, CredentialLookupError> {
    for ip_info in ip_info_list {
        if ip_info.ip_identity.0 == issuer {
            Ok(ip_info);
        }
    }
    Err(CredentialLookupError::InvalidResponse(
        "TODO - placeholder error for now".to_string(),
    ))
}

/// determine the credential validity based on the valid from and valid to date information.
/// The block info supplied has the slot time we will use as the current time, to check validity against
fn determine_credential_validity_status(
    validity: CredentialValidity,
    block_info: BlockInfo,
) -> Result<CredentialStatus, CredentialLookupError> {
    let valid_from = validity
        .created_at
        .lower()
        .ok_or(CredentialLookupError::InvalidResponse(
            "Credential valid from date is not valid.".into(),
        ))?;

    let valid_to = validity
        .valid_to
        .upper()
        .ok_or(CredentialLookupError::InvalidResponse(
            "Credential valid to date is not valid.".into(),
        ))?;

    let now = block_info.block_slot_time;

    if valid_from > now {
        Ok(CredentialStatus::NotActivated)
    } else if valid_to >= now {
        Ok(CredentialStatus::Active)
    } else {
        Ok(CredentialStatus::Expired)
    }
}

/// verify a presentation for the v1 proofs protocol
pub async fn verify_presentation(
    client: v2::Client,
    network: web3id::did::Network,
    presentation: web3id::v1::PresentationV1<IpPairing, ArCurve, web3id::Web3IdAttribute>,
    bi: impl IntoBlockIdentifier,
    request: RequestV1<ArCurve, web3id::Web3IdAttribute>,
    identity_providers: Vec<IpInfo<IpPairing>>,
    anonymity_revokers: Vec<ArInfo<ArCurve>>,
) -> Result<AnchoredVerificationAuditRecord, _> {
    // get the global context
    let global_context = get_global_context(client, bi).await?;

    let block_info = client
        .get_block_info(bi)
        .map_err(|e| {
            CredentialLookupError::InvalidResponse("Issue occured gettting block info".to_string())
        })
        .await?
        .response;

    // build verification material by extracting the metadata for the credentials
    let verification_material = get_public_data_v1(
        presentation,
        identity_providers,
        anonymity_revokers,
        block_info,
    )
    .await?;

    // verification of the presentation
    let request_v1 = presentation.verify(&global_context, verification_material.iter());

    // TODO - audit anchor call goes here, and return AnchoredVerificationAuditRecord
    AnchoredVerificationAuditRecord {}
}

/// get the global context using the client to query the node for the cryptographic parameters
pub async fn get_global_context(
    client: v2::Client,
    bi: impl IntoBlockIdentifier,
) -> Result<GlobalContext<ArCurve>, CredentialLookupError> {
    let r = client
        .get_cryptographic_parameters(bi)
        .map_err(|e| {
            CredentialLookupError::InvalidResponse(
                "could not get global context for block provided".to_string(),
            )
        })
        .await?
        .response;

    Ok(r)
}

/// Retrieve the public data for the presentation.
/// Will call the cryptographic verification for each metadata of the presentation provided and also check the credential validity
pub async fn get_public_data_v1(
    presentation: PresentationV1<IpPairing, ArCurve, web3id::Web3IdAttribute>,
    identity_providers: Vec<IpInfo<IpPairing>>,
    anonymity_revokers: Vec<ArInfo<ArCurve>>,
    block_info: BlockInfo,
) -> Result<Vec<CredentialVerificationMaterial<IpPairing, ArCurve>>, CredentialLookupError> {
    let credential_verification_materials = presentation
        .metadata()
        .map(|metadata| async move {
            verify_credential_metadata_v1(
                &metadata,
                &identity_providers,
                &anonymity_revokers,
                block_info,
            )
            .await
        })
        .collect::<futures::stream::FuturesOrdered<_>>();
    credential_verification_materials.try_collect().await
}

/// Verify metadata provided and return the CredentialVerificationMaterial
pub async fn verify_credential_metadata_v1(
    metadata: &CredentialMetadataV1,
    identity_providers: &Vec<IpInfo<IpPairing>>,
    anonymity_revokers: &Vec<ArInfo<ArCurve>>,
    block_info: BlockInfo,
) -> Result<CredentialVerificationMaterial<IpPairing, ArCurve>, CredentialLookupError> {
    match metadata.cred_metadata {
        CredentialMetadataTypeV1::Identity(identity_credential_metadata) => {
            let credential_ip_identity = identity_credential_metadata.issuer;
            let matching_ip_info =
                find_matching_ip_info(credential_ip_identity, identity_providers)?;

            let ar_infos = get_ars_infos(anonymity_revokers);

            // credentials validity status
            let status = determine_credential_validity_status(
                identity_credential_metadata.validity,
                block_info,
            );

            // build and return the verification material for the identity
            Ok(CredentialVerificationMaterial::Identity(
                IdentityCredentialVerificationMaterial {
                    ip_info: matching_ip_info,
                    ars_infos: ar_infos,
                },
            ));
        }
        _ => Err(CredentialLookupError::InvalidResponse(
            "Not supported right now".to_string(),
        )),
    }
}

fn find_matching_ip_info(
    ip_identity: IpIdentity,
    identity_providers: Vec<IpInfo<IpPairing>>,
) -> Result<IpInfo<IpPairing>, CredentialLookupError> {
    for ip_info in identity_providers {
        if ip_info.ip_identity == ip_identity {
            Ok(ip_info);
        }
    }
    Err(CredentialLookupError::InvalidResponse(
        "No identity provider found matching this identity".to_string(),
    ))
}

fn get_ars_infos(anonymity_revokers: Vec<ArInfo<ArCurve>>) -> ArInfos<ArCurve> {
    let mut ars_infos_btree = BTreeMap::new();
    for ar in anonymity_revokers {
        ars_infos_btree.insert(ar.ar_identity, ar);
    }

    ArInfos {
        anonymity_revokers: ars_infos_btree,
    }
}
