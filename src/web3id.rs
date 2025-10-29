//! Functionality for retrieving, verifying, and registering web3id credentials.

use std::collections::BTreeMap;

use crate::{
    cis4::{Cis4Contract, Cis4QueryError},
    types::queries::BlockInfo,
    v2::{self, BlockIdentifier, IntoBlockIdentifier},
};
pub use concordium_base::web3id::*;
use concordium_base::{
    base::CredentialRegistrationID,
    cis4_types::CredentialStatus,
    contracts_common::AccountAddress,
    id::{
        constants::{ArCurve, IpPairing},
        types::{ArInfo, ArInfos, CredentialValidity, IpIdentity, IpInfo},
    },
    web3id,
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
    pub inputs: CredentialsInputs<IpPairing, ArCurve>,
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

                    // create the credential validity reference
                    let validity = CredentialValidity {
                        created_at: cdv.policy.created_at,
                        valid_to: cdv.policy.valid_to,
                    };

                    // determine credential validity status
                    let status = determine_credential_validity_status(validity, block_info)?;

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

        CredentialMetadata::Identity { issuer, validity } => {
            // get all the identity providers at current block
            let identity_providers = client
                .get_identity_providers(bi)
                .await?
                .response
                .try_collect::<Vec<_>>()
                .map_err(|_e| {
                    CredentialLookupError::InvalidResponse(
                        "Error getting identity providers".into(),
                    )
                })
                .await?;

            // get anonymity revokers
            let anonymity_revokers = client
                .get_anonymity_revokers(bi)
                .await?
                .response
                .try_collect::<Vec<_>>()
                .map_err(|_e| {
                    CredentialLookupError::InvalidResponse(
                        "Error while getting annonymity revokers.".into(),
                    )
                })
                .await?;

            let block_info = client.get_block_info(bi).await?.response;

            // call verify now for the data gathered
            verify_identity_credential_metadata(
                block_info,
                issuer,
                identity_providers,
                anonymity_revokers,
                validity,
            )
        }
    }
}

/// verify metadata for an identity
fn verify_identity_credential_metadata(
    block_info: BlockInfo,
    issuer: IpIdentity,
    identity_providers: Vec<IpInfo<IpPairing>>,
    anonymity_revokers: Vec<ArInfo<ArCurve>>,
    validity: CredentialValidity,
) -> Result<CredentialWithMetadata, CredentialLookupError> {
    // get the matching identity provider
    let matching_idp = identity_providers
        .iter()
        .find(|idp| idp.ip_identity.0 == issuer.0)
        .ok_or(CredentialLookupError::InvalidResponse(
            "Error occurred while getting matching identity provider".into(),
        ))?;

    // create a new BTreeMap to hold the Anonymity revoker identity -> the anonymity revoker info
    let mut anonymity_revoker_infos = BTreeMap::new();

    for ar in anonymity_revokers {
        anonymity_revoker_infos.insert(ar.ar_identity, ar);
    }

    // build inputs
    let inputs = CredentialsInputs::Identity {
        ip_info: matching_idp.clone(),
        ars_infos: ArInfos {
            anonymity_revokers: anonymity_revoker_infos,
        },
    };

    // determine the credential validity status
    let status = determine_credential_validity_status(validity, block_info)?;

    Ok(CredentialWithMetadata { inputs, status })
}

/// Checks the credentials validity for the block info provided and returns a Credential Status
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
    presentation: &web3id::Presentation<IpPairing, ArCurve, web3id::Web3IdAttribute>,
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

#[cfg(test)]
mod tests {
    use crate::types::queries::ProtocolVersionInt;

    use super::*;
    use chrono::{DateTime, Utc};
    use concordium_base::{
        base::{AbsoluteBlockHeight, BlockHeight, Energy, GenesisIndex, ProtocolVersion},
        constants::SHA256,
        hashes::HashBytes,
        id::types::YearMonth,
    };

    #[test]
    fn test_determine_credential_validity_status_as_active() {
        let now = YearMonth::now();
        let now_time = now.lower().expect("expected now time");
        // create an 'active' credential validity, created last year, expires next year
        let validity = CredentialValidity {
            created_at: YearMonth {
                month: now.month,
                year: now.year - 1,
            },
            valid_to: YearMonth {
                month: now.month,
                year: now.year + 1,
            },
        };

        // stub the current block information
        let block_info = get_dummy_block_info(now_time);

        let credential_status_result = determine_credential_validity_status(validity, block_info)
            .expect("expected credential status here");

        assert_eq!(CredentialStatus::Active, credential_status_result);
    }

    #[test]
    fn test_determine_credential_validity_status_as_expired() {
        let now = YearMonth::now();
        let now_time = now.lower().expect("expected now time");

        // create an 'expired' credential validity, created last year, expires 2 month ago
        let validity = CredentialValidity {
            created_at: YearMonth {
                month: now.month,
                year: now.year - 1,
            },
            valid_to: YearMonth {
                month: now.month - 2,
                year: now.year,
            },
        };

        // stub the current block information
        let block_info = get_dummy_block_info(now_time);

        let credential_status_result = determine_credential_validity_status(validity, block_info)
            .expect("expected credential status here");

        assert_eq!(CredentialStatus::Expired, credential_status_result);
    }

    #[test]
    fn test_determine_credential_validity_status_as_not_active() {
        let now = YearMonth::now();
        let now_time = now.lower().expect("expected now time");

        // create a 'not active' credential validity, created 1 month in future, expires 1 year in future
        let validity = CredentialValidity {
            created_at: YearMonth {
                month: now.month + 1,
                year: now.year,
            },
            valid_to: YearMonth {
                month: now.month,
                year: now.year + 1,
            },
        };

        // stub the current block information
        let block_info = get_dummy_block_info(now_time);

        let credential_status_result = determine_credential_validity_status(validity, block_info)
            .expect("expected credential status here");

        assert_eq!(CredentialStatus::NotActivated, credential_status_result);
    }

    // helper util to just get a dummy block based on a block slot time provided for credential validity testing
    fn get_dummy_block_info(block_slot_time: DateTime<Utc>) -> BlockInfo {
        BlockInfo {
            transactions_size: 0u64,
            block_parent: HashBytes::new([1u8; SHA256]),
            block_hash: HashBytes::new([1u8; SHA256]),
            finalized: true,
            block_state_hash: HashBytes::new([1u8; SHA256]),
            block_arrive_time: block_slot_time,
            block_receive_time: block_slot_time,
            transaction_count: 0,
            transaction_energy_cost: Energy::default(),
            block_slot: None,
            block_last_finalized: HashBytes::new([1u8; SHA256]),
            block_slot_time: block_slot_time,
            block_height: AbsoluteBlockHeight { height: 1u64 },
            era_block_height: BlockHeight { height: 1u64 },
            genesis_index: GenesisIndex { height: 0u32 },
            block_baker: None,
            protocol_version: ProtocolVersionInt::from_enum(ProtocolVersion::P9),
            round: None,
            epoch: None,
        }
    }
}
