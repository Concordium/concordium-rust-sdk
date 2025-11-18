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
use concordium_base::hashes::TransactionHash;
use concordium_base::id::constants::{ArCurve, IpPairing};
use concordium_base::id::types;
use concordium_base::id::types::{AccountCredentialWithoutProofs, ArInfos, IpIdentity};
use concordium_base::transactions::ExactSizeTransactionSigner;
use concordium_base::web3id;
use concordium_base::web3id::v1::anchor::{
    self as base_anchor, CredentialValidity, VerificationAuditRecord, VerificationContext,
    VerificationRequest, VerificationRequestAnchor, VerificationRequestAndBlockHash,
};
use concordium_base::web3id::v1::{
    AccountCredentialVerificationMaterial, IdentityCredentialVerificationMaterial,
};
use concordium_base::web3id::{v1, Web3IdAttribute};
use futures::StreamExt;
use futures::{future, TryStreamExt};
use std::collections::{BTreeMap, HashMap};

pub type PresentationV1 = v1::PresentationV1<IpPairing, ArCurve, Web3IdAttribute>;
pub type CredentialV1 = v1::CredentialV1<IpPairing, ArCurve, Web3IdAttribute>;
pub type RequestV1 = v1::RequestV1<ArCurve, Web3IdAttribute>;
pub type CredentialVerificationMaterial = v1::CredentialVerificationMaterial<IpPairing, ArCurve>;

/// Functionality to create and verify the verification request anchor (VRA) and verification audit anchor (VAA).
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

// todo ar where to create audit record?

pub async fn verify_presentation_and_create_audit_anchor(
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

    let request_anchor =
        lookup_request_anchor(client, verification_request.anchor_transaction_hash).await?;

    let (verification_material, credential_validities): (Vec<_>, Vec<_>) =
        lookup_verification_materials_and_validity(
            client,
            block_identifier,
            &verifiable_presentation,
        )
        .await?
        .into_iter()
        .unzip();

    let context = VerificationContext {
        network,
        now: block_info.block_slot_time,
    };

    let verification_result = base_anchor::verify_presentation_with_request_anchor(
        &global_context,
        &context,
        &verification_request,
        &verifiable_presentation,
        &request_anchor,
        verification_material.iter(),
        credential_validities.iter(),
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
) -> Result<VerificationRequestAndBlockHash, VerifyError> {
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
    let verification_request_anchor: VerificationRequestAnchor = cbor::cbor_decode(data.as_ref())?;

    Ok(VerificationRequestAndBlockHash {
        verification_request_anchor,
        block_hash,
    })
}

/// Lookup verification material for presentation
async fn lookup_verification_materials_and_validity(
    client: &mut v2::Client,
    block_identifier: BlockIdentifier,
    presentation: &PresentationV1,
) -> Result<Vec<(CredentialVerificationMaterial, CredentialValidity)>, VerifyError> {
    let verification_material =
        future::try_join_all(presentation.verifiable_credentials.iter().map(|cred| {
            let mut client = client.clone();
            async move {
                lookup_verification_material_and_validity(&mut client, block_identifier, cred).await
            }
        }))
        .await?;
    Ok(verification_material)
}

/// Lookup verification material for presentation
async fn lookup_verification_material_and_validity(
    client: &mut v2::Client,
    block_identifier: BlockIdentifier,
    credential: &CredentialV1,
) -> Result<(CredentialVerificationMaterial, CredentialValidity), VerifyError> {
    Ok(match credential {
        CredentialV1::Account(cred) => {
            let metadata = cred.metadata();

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

                    (
                        CredentialVerificationMaterial::Account(
                            AccountCredentialVerificationMaterial {
                                issuer: cdv.ip_identity,
                                attribute_commitments: commitments.cmm_attributes.clone(),
                            },
                        ),
                        CredentialValidity::ValidityPeriod(credential_validity),
                    )
                }
            }
        }
        CredentialV1::Identity(cred) => {
            let metadata = cred.metadata();

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

            (
                CredentialVerificationMaterial::Identity(IdentityCredentialVerificationMaterial {
                    ip_info,
                    ars_infos: ArInfos {
                        anonymity_revokers: ars_infos,
                    },
                }),
                CredentialValidity::ValidityPeriod(cred.validity.clone()),
            )
        }
    })
}
