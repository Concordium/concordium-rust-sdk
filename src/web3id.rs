//! Functionality for retrieving, verifying, and registering web3id credentials.

use crate::{
    cis4::{Cis4Contract, Cis4QueryError},
    types::queries::BlockInfo,
    v2::{self, BlockIdentifier, IntoBlockIdentifier},
};
use anyhow::Ok;
pub use concordium_base::web3id::*;
use concordium_base::{
    base::CredentialRegistrationID,
    cis4_types::CredentialStatus,
    contracts_common::AccountAddress,
    id::{
        constants::{ArCurve, IpPairing},
        types::{ArInfos, CredentialValidity, IpIdentity, IpInfo},
    },
    web3id::{
        self,
        v1::{
            CredentialMetadataTypeV1, CredentialMetadataV1, CredentialVerificationMaterial,
            IdentityCredentialVerificationMaterial, RequestV1,
        },
    },
};
use futures::{TryFutureExt, TryStreamExt};

#[derive(thiserror::Error, Debug)]
pub enum CredentialLookupError {
    #[error("Credential network not supported.")]
    IncorrectNetwork,
    #[error("Credential issuer not as stated: {stated} != {actual}.")]
    InconsistentIssuer {
        stated: IpIdentity,
        actual: IpIdentity,
    },
    #[error("Unable to look up account: {0}")]
    QueryError(#[from] v2::QueryError),
    #[error("Unable to query CIS4 contract: {0}")]
    Cis4QueryError(#[from] Cis4QueryError),
    #[error("Credential {cred_id} no longer present or of unknown type on account: {account}")]
    CredentialNotPresentOrUnknown {
        cred_id: CredentialRegistrationID,
        account: AccountAddress,
    },
    #[error("Initial credential {cred_id} cannot be used.")]
    InitialCredential { cred_id: CredentialRegistrationID },
    #[error("Unexpected response from the node: {0}")]
    InvalidResponse(String),
    #[error("Unknown stored credential for {cred_id}. Updating the rust-sdk to a version compatible with the node will resolve this issue.")]
    UnknownCredential { cred_id: CredentialRegistrationID },
}

/// The public cryptographic data of a credential together with its current
/// status.
pub struct CredentialWithMetadata {
    /// The status of the credential at a point in time.
    pub status: CredentialStatus,
    /// The extra public inputs needed for verification.
    pub inputs: CredentialsInputs<ArCurve>,
}

/// TODO - please review, I created this on the basis that we need something similar to the above
/// where we have a credential status returned, and also the RequestV1 that was verified. Not sure if these are both needed
pub struct VerifiablePresentationReqeuestWithMetadata {
    /// The status of the credential at a point in time.
    pub status: CredentialStatus,
    /// the verified request
    pub request: RequestV1<ArCurve, web3id::Web3IdAttribute>,
}

/// Retrieve and validate credential metadata in a particular block.
///
/// This does not validate the cryptographic proofs, only the metadata. In
/// particular it checks.
///
/// - credential exists
/// - the credential's network is as supplied to this function
/// - in case of account credentials, the credential issuer is as stated in the
///   proof
/// - credential commitments can be correctly parsed
/// - credential is active and not expired at the timestamp of the supplied
///   block
/// - in case of an account credential, the credential is a normal credential,
///   and not initial.
///
/// For web3id credentials the issuer contract is the source of truth, and this
/// function does not perform additional validity checks apart from querying the
/// contract.
pub async fn verify_credential_metadata(
    mut client: v2::Client,
    network: web3id::did::Network,
    metadata: &ProofMetadata,
    bi: impl IntoBlockIdentifier,
) -> Result<CredentialWithMetadata, CredentialLookupError> {
    if metadata.network != network {
        return Err(CredentialLookupError::IncorrectNetwork);
    }
    let bi = bi.into_block_identifier();
    match metadata.cred_metadata {
        CredentialMetadata::Account { issuer, cred_id } => {
            let ai = client
                .get_account_info(&cred_id.into(), BlockIdentifier::LastFinal)
                .await?;
            let Some(cred) = ai.response.account_credentials.values().find(|cred| {
                cred.value
                    .as_ref()
                    .is_known_and(|c| c.cred_id() == cred_id.as_ref())
            }) else {
                return Err(CredentialLookupError::CredentialNotPresentOrUnknown {
                    cred_id,
                    account: ai.response.account_address,
                });
            };
            let c = cred
                .value
                .as_ref()
                .known_or(CredentialLookupError::UnknownCredential { cred_id })?;
            if c.issuer() != issuer {
                return Err(CredentialLookupError::InconsistentIssuer {
                    stated: issuer,
                    actual: c.issuer(),
                });
            }
            match &c {
                concordium_base::id::types::AccountCredentialWithoutProofs::Initial { .. } => {
                    Err(CredentialLookupError::InitialCredential { cred_id })
                }
                concordium_base::id::types::AccountCredentialWithoutProofs::Normal {
                    cdv,
                    commitments,
                } => {
                    let now = client.get_block_info(bi).await?.response.block_slot_time;
                    let valid_from = cdv.policy.created_at.lower().ok_or_else(|| {
                        CredentialLookupError::InvalidResponse(
                            "Credential creation date is not valid.".into(),
                        )
                    })?;
                    let valid_until = cdv.policy.valid_to.upper().ok_or_else(|| {
                        CredentialLookupError::InvalidResponse(
                            "Credential creation date is not valid.".into(),
                        )
                    })?;
                    let status = if valid_from > now {
                        CredentialStatus::NotActivated
                    } else if valid_until < now {
                        CredentialStatus::Expired
                    } else {
                        CredentialStatus::Active
                    };
                    let inputs = CredentialsInputs::Account {
                        commitments: commitments.cmm_attributes.clone(),
                    };

                    Ok(CredentialWithMetadata { status, inputs })
                }
            }
        }
        CredentialMetadata::Web3Id { contract, holder } => {
            let mut contract_client = Cis4Contract::create(client, contract).await?;
            let issuer_pk = contract_client.issuer(bi).await?;

            let inputs = CredentialsInputs::Web3 { issuer_pk };

            let status = contract_client.credential_status(holder, bi).await?;

            Ok(CredentialWithMetadata { status, inputs })
        }
    }
}

/// Verify credential metadata for Presentation V1 which includes Identity based credential verification
pub async fn verify_credential_metadata_v1(
    mut client: v2::Client,
    network: web3id::did::Network, // TODO - check if we really need it
    metadata: CredentialMetadataV1,
    bi: impl IntoBlockIdentifier,
    presentation_v1: &web3id::v1::PresentationV1<IpPairing, ArCurve, web3id::Web3IdAttribute>,
    request_v1: RequestV1<ArCurve, web3id::Web3IdAttribute>,
    ip_info: IpInfo<IpPairing>,
    ars_infos: ArInfos<ArCurve>,
) -> Result<VerifiablePresentationReqeuestWithMetadata, CredentialLookupError> {
    match metadata.cred_metadata {
        // For verifying account credentials v1
        CredentialMetadataTypeV1::Account(account_credential_metadata) => {
            // call the other verify function
            let proof = ProofMetadata {
                created: metadata.created,
                network,
                cred_metadata: CredentialMetadata::Account {
                    issuer: account_credential_metadata.issuer,
                    cred_id: account_credential_metadata.cred_id,
                },
            };

            let credential_with_metadata =
                verify_credential_metadata(client, network, &proof, bi).await?;

            // TODO:  Error for now - probably need to confirm return type for this one
            Err(CredentialLookupError::InvalidResponse(
                "not supported right now".to_string(),
            ))
        }
        CredentialMetadataTypeV1::Identity(identity_credential_metadata) => {
            let bi = bi.into_block_identifier();
            let issuer = identity_credential_metadata.issuer;
            let credential_validity = identity_credential_metadata.validity;

            // Global context will be looked up on chain - through grpc client
            let global_context = client
                .get_cryptographic_parameters(bi)
                .map_err(|_e| {
                    CredentialLookupError::InvalidResponse("global context lookup fail".to_string())
                })
                .await?
                .response;

            // determine credential validity here
            let block_info = client.get_block_info(bi).await?.response;
            let status = determine_credential_validity_status(credential_validity, block_info)?;

            /// TODO - anchor validation should be done somewhere here in a follow up ticket
            /// anchor validation will be done, by looking up the transaction hash on chain
            /// and verifying it matches in an expected block
            let verification_material = vec![CredentialVerificationMaterial::Identity(
                IdentityCredentialVerificationMaterial { ip_info, ars_infos },
            )];

            // cryptographic verification, which returns the verified request
            let request = presentation_v1
                .verify(&global_context, verification_material.into_iter())
                .map_err(|_e| {
                    CredentialLookupError::InvalidResponse("Some error for now".to_string())
                })?;

            Ok(VerifiablePresentationReqeuestWithMetadata { request, status })
        }
    }
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

/// Retrieve the public data of credentials validating any metadata that is
/// part of the credentials.
///
/// If any credentials from the presentation are from a network different than
/// the one supplied an error is returned.
///
/// See [`verify_credential_metadata`] for the checks performed on each of the
/// credentials.
pub async fn get_public_data(
    client: &mut v2::Client,
    network: web3id::did::Network,
    presentation: &web3id::Presentation<ArCurve, web3id::Web3IdAttribute>,
    bi: impl IntoBlockIdentifier,
) -> Result<Vec<CredentialWithMetadata>, CredentialLookupError> {
    let block = bi.into_block_identifier();
    let stream = presentation
        .metadata()
        .map(|meta| {
            let mainnet_client = client.clone();
            async move { verify_credential_metadata(mainnet_client, network, &meta, block).await }
        })
        .collect::<futures::stream::FuturesOrdered<_>>();
    stream.try_collect().await
}

/// get public data for presentation v1, which supports Identity credentials verification
pub async fn get_public_data_v1(
    client: &mut v2::Client,
    network: web3id::did::Network,
    presentation: &web3id::v1::PresentationV1<IpPairing, ArCurve, web3id::Web3IdAttribute>,
    bi: impl IntoBlockIdentifier,
    request: RequestV1<ArCurve, web3id::Web3IdAttribute>,
    ip_info: IpInfo<IpPairing>,
    ars_infos: ArInfos<ArCurve>,
) -> Result<Vec<VerifiablePresentationReqeuestWithMetadata>, CredentialLookupError> {
    let block = bi.into_block_identifier();
    let stream = presentation
        .metadata()
        .map(|meta| {
            let client = client.clone();
            async move {
                verify_credential_metadata_v1(
                    client,
                    network,
                    meta,
                    block,
                    presentation,
                    request,
                    ip_info,
                    ars_infos,
                )
                .await
            }
        })
        .collect::<futures::stream::FuturesOrdered<_>>();
    stream.try_collect().await
}
