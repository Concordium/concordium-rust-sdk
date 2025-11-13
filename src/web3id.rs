//! Functionality for retrieving, verifying, and registering web3id credentials.

use std::collections::BTreeMap;

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
        types::{ArInfo, ArInfos, CredentialValidity, GlobalContext, IpIdentity, IpInfo},
    },
    web3id::{
        self,
        v1::{
            CredentialMetadataTypeV1, CredentialMetadataV1, CredentialVerificationMaterial, IdentityCredentialVerificationMaterial, PresentationV1, RequestV1
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
                    let block_info = client.get_block_info(bi).await?.response;

                    let credential_validity = CredentialValidity { created_at: cdv.policy.created_at, valid_to: cdv.policy.valid_to };
                    let status = determine_credential_validity_status(credential_validity, block_info);

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

// check the list of identity providers to find the matching one for the issuer u32 provided
fn determine_ip_info(issuer: u32, ip_info_list: Vec<IpInfo<IpPairing>>) -> Result<IpInfo<IpPairing>, CredentialLookupError>{
    for ip_info in ip_info_list {
        if ip_info.ip_identity.0 == issuer {
            Ok(ip_info);
        }
    }
    Err(CredentialLookupError::InvalidResponse("TODO - placeholder error for now".to_string()))
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


/// TODO - placeholder until merged anchor changes
struct AnchoredVerificationAuditRecord {

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

    let block_info = client.get_block_info(bi)
        .map_err(|e| CredentialLookupError::InvalidResponse("Issue occured gettting block info".to_string()))
        .await?
        .response;

    // build verification material by extracting the metadata for the credentials
    let verification_material = get_public_data_v1(presentation, identity_providers, anonymity_revokers, block_info).await?;

    // verification of the presentation
    let request_v1 = presentation.verify(&global_context, verification_material.iter());

    // TODO - audit anchor call goes here, and return AnchoredVerificationAuditRecord
    AnchoredVerificationAuditRecord {

    }
}

/// get the global context using the client to query the node for the cryptographic parameters
pub async fn get_global_context(
    client: v2::Client,
    bi: impl IntoBlockIdentifier,
) -> Result<GlobalContext<ArCurve>, CredentialLookupError> {
    let r = client.get_cryptographic_parameters(bi)
        .map_err(|e| CredentialLookupError::InvalidResponse("could not get global context for block provided".to_string()))
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
    block_info: BlockInfo
) -> Result<Vec<CredentialVerificationMaterial<IpPairing, ArCurve>>, CredentialLookupError>{
    let credential_verification_materials = presentation.metadata()
        .map(|metadata| {
            async move { verify_credential_metadata_v1(&metadata, &identity_providers, &anonymity_revokers, block_info).await }
        })
        .collect::<futures::stream::FuturesOrdered<_>>();
    credential_verification_materials.try_collect().await
}

/// Verify metadata provided and return the CredentialVerificationMaterial
pub async fn verify_credential_metadata_v1(
    metadata: &CredentialMetadataV1,
    identity_providers: &Vec<IpInfo<IpPairing>>,
    anonymity_revokers: &Vec<ArInfo<ArCurve>>,
    block_info: BlockInfo
) -> Result<CredentialVerificationMaterial<IpPairing, ArCurve>, CredentialLookupError>{
    match metadata.cred_metadata {
        CredentialMetadataTypeV1::Identity(identity_credential_metadata) => {
            let credential_ip_identity = identity_credential_metadata.issuer;
            let matching_ip_info = find_matching_ip_info(credential_ip_identity, identity_providers)?;

            let ar_infos = get_ars_infos(anonymity_revokers);

            // credentials validity status
            let status = determine_credential_validity_status(identity_credential_metadata.validity, block_info);

            // build and return the verification material for the identity
            Ok(CredentialVerificationMaterial::Identity(
                IdentityCredentialVerificationMaterial { ip_info: matching_ip_info, ars_infos: ar_infos }
            ));
        }
        _ => Err(CredentialLookupError::InvalidResponse("Not supported right now".to_string()))
    }
}

fn find_matching_ip_info(ip_identity: IpIdentity, identity_providers: Vec<IpInfo<IpPairing>>) -> Result<IpInfo<IpPairing>, CredentialLookupError>{
    for ip_info in identity_providers {
        if ip_info.ip_identity == ip_identity {
            Ok(ip_info);
        }
    }
    Err(CredentialLookupError::InvalidResponse("No identity provider found matching this identity".to_string()))
}

fn get_ars_infos(
    anonymity_revokers: Vec<ArInfo<ArCurve>>,
) -> ArInfos<ArCurve> {
    let mut ars_infos_btree = BTreeMap::new();
    for ar in anonymity_revokers {
        ars_infos_btree.insert(ar.ar_identity, ar);
    }

    ArInfos {
        anonymity_revokers: ars_infos_btree
    }
}