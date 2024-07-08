//! Functionality for retrieving, verifying, and registering web3id credentials.

use crate::{
    cis4::{Cis4Contract, Cis4QueryError},
    v2::{self, BlockIdentifier, IntoBlockIdentifier},
};
pub use concordium_base::web3id::*;
use concordium_base::{
    base::CredentialRegistrationID,
    cis4_types::CredentialStatus,
    contracts_common::AccountAddress,
    id::{constants::ArCurve, types::IpIdentity},
    web3id,
};
use futures::TryStreamExt;

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
    #[error("Credential {cred_id} no longer present on account: {account}")]
    CredentialNotPresent {
        cred_id: CredentialRegistrationID,
        account: AccountAddress,
    },
    #[error("Initial credential {cred_id} cannot be used.")]
    InitialCredential { cred_id: CredentialRegistrationID },
    #[error("Unexpected response from the node: {0}")]
    InvalidResponse(String),
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
            let Some(cred) = ai.response.account_credentials.values().find(|cred| cred.value.cred_id() == cred_id.as_ref()) else {
                return Err(CredentialLookupError::CredentialNotPresent{ cred_id, account: ai.response.account_address });
            };
            if cred.value.issuer() != issuer {
                return Err(CredentialLookupError::InconsistentIssuer {
                    stated: issuer,
                    actual: cred.value.issuer(),
                });
            }
            match &cred.value {
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
