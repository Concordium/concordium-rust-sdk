//! Functionality for retrieving, verifying, and registering web3id credentials.

use std::collections::BTreeMap;

use crate::{
    cis4::{Cis4Contract, Cis4QueryError},
    v2::{self, BlockIdentifier, IntoBlockIdentifier},
};
use chrono::{DateTime, Utc};
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

                    let status = determine_credential_status_valid_from_valid_to(now, valid_from, valid_until);

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
            let identity_providers = client.get_identity_providers(bi).await?
                .response
                .try_collect::<Vec<_>>()
                .map_err(|_e| CredentialLookupError::InvalidResponse("Error getting identity providers".into()))
                .await?;

            // get anonymity revokers
            let anonymity_revokers = client.get_anonymity_revokers(bi).await?.response
                .try_collect::<Vec<_>>()
                .map_err(|_e|
                    CredentialLookupError::InvalidResponse("Error while getting annonymity revokers.".into(),
                ))
                .await?;
            
            let now = client.get_block_info(bi).await?.response.block_slot_time;

            // call verify now for the data gathered
            verify_identity_credential_metadata(now, issuer, identity_providers, anonymity_revokers, validity)
        }
    }
}

/// verify metadata for an identity
fn verify_identity_credential_metadata(
    utc_time:DateTime<Utc>, 
    issuer: IpIdentity, 
    identity_providers: Vec<IpInfo<IpPairing>>, 
    anonymity_revokers: Vec<ArInfo<ArCurve>>, 
    validity: CredentialValidity
) -> Result<CredentialWithMetadata, CredentialLookupError> {
    // get the matching identity provider
    let matching_idp = identity_providers.iter()
        .find(|idp| {
            idp.ip_identity.0 == issuer.0
        })
        .ok_or( CredentialLookupError::InvalidResponse("Error occurred while getting matching identity provider".into()))?;

    // create a new BTreeMap to hold the Anonymity revoker identity -> the anonymity revoker info
    let mut anonymity_revoker_infos = BTreeMap::new();

    for ar in anonymity_revokers {
        anonymity_revoker_infos.insert(ar.ar_identity, ar);
    }

    // build inputs
    let inputs = CredentialsInputs::Identity { ip_info: matching_idp.clone(), ars_infos: ArInfos { anonymity_revokers: anonymity_revoker_infos } };

    // Credential Status handling
    let valid_to = validity.valid_to.upper()
        .ok_or(CredentialLookupError::InvalidResponse("Error while getting the valid to date for the credentials validity.".into()))?;

    let credential_status = determine_credential_status_valid_to(utc_time, valid_to);

    Ok(CredentialWithMetadata { inputs: inputs, status: credential_status})
}

/// determine the credential status where both the valid from and valid to is provided
fn determine_credential_status_valid_from_valid_to(
    time_to_compare_to: DateTime<Utc>,
    valid_from: DateTime<Utc>,
    valid_to: DateTime<Utc>,
) -> CredentialStatus {
    if valid_from > time_to_compare_to {
        CredentialStatus::NotActivated
    } else {
        determine_credential_status_valid_to(time_to_compare_to, valid_to)
    }
}

/// determine the credential status where you only have a `valid to` field and no valid from (such as identity)
fn determine_credential_status_valid_to(
    time_to_compare_to: DateTime<Utc>,
    valid_to: DateTime<Utc>,
) -> CredentialStatus {
    if valid_to < time_to_compare_to {
        CredentialStatus::Expired
    } else {
        CredentialStatus::Active
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
    use super::*;
    use chrono::{Datelike, Days};
    use concordium_base::{contracts_common::PublicKeyEd25519, id::types::{ArIdentity, Description, YearMonth}, ps_sig::PublicKey};

    /// valid from is before now, valid to is in the future, therefore credential status should be `active`
    #[test]
    fn test_determine_credential_status_as_active_for_account() {
        let now = Utc::now();
        let valid_from = now
            .checked_sub_days(Days::new(20))
            .expect("expected valid date time");
        let valid_to = now
            .checked_add_days(Days::new(30))
            .expect("expected valid date time");

        let status = determine_credential_status_valid_from_valid_to(now, valid_from, valid_to);
        assert_eq!(CredentialStatus::Active, status);
    }

    /// valid from is after now, valid to is in the future, therefore credential status should be `not activated`
    #[test]
    fn test_determine_credential_status_as_not_activated_valid_from_after_today() {
        let now = Utc::now();
        let valid_from = now
            .checked_add_days(Days::new(2))
            .expect("expected valid date time");
        let valid_to = now
            .checked_add_days(Days::new(30))
            .expect("expected valid date time");

        let status = determine_credential_status_valid_from_valid_to(now, valid_from, valid_to);
        assert_eq!(CredentialStatus::NotActivated, status);
    }

    /// valid from is before now, valid to is in the past, therefore credential status should be `expired`
    #[test]
    fn test_determine_credential_status_as_expired_from_and_to_in_past() {
        let now = Utc::now();
        let valid_from = now
            .checked_sub_days(Days::new(100))
            .expect("expected valid date time");
        let valid_to = now
            .checked_sub_days(Days::new(30))
            .expect("expected valid date time");

        let status = determine_credential_status_valid_from_valid_to(now, valid_from, valid_to);
        assert_eq!(CredentialStatus::Expired, status);
    }

    // identity credential status check, returns as active for valid to date in the future
    #[test]
    fn test_determine_credential_status_as_active_for_identity() {
        let now = Utc::now();
        let valid_to = now
            .checked_add_days(Days::new(20))
            .expect("expected valid date time");

        let status = determine_credential_status_valid_to(now, valid_to);
        assert_eq!(CredentialStatus::Active, status);
    }

    // identity credential status check, returns as expired for valid to date in the past
    #[test]
    fn test_determine_credential_status_as_expired_for_identity() {
        let now = Utc::now();
        let valid_to = now
            .checked_sub_days(Days::new(2))
            .expect("expected valid date time");

        let status = determine_credential_status_valid_to(now, valid_to);
        assert_eq!(CredentialStatus::Expired, status);
    }

    // test the verification of an identity credential
    #[test]
    fn test_verify_identity_credential_metadata_success() {
        
        // mock data
        let now = Utc::now();
        let issuer = IpIdentity(1u32);

        // Identity provider
        let ip_description = Description {description: "dummy description".to_string(), name: "dummy name".to_string(), url: "http://dummy.com".to_string()};
        let ip_verify_key = None; // TODO ROB - not sure how i build this
        let ip_cdi_key = None; // TODO ROB - not sure how i build this
        let ip_info_stubbed = IpInfo { ip_identity: issuer, ip_description: ip_description, ip_verify_key: ip_verify_key, ip_cdi_verify_key: ip_cdi_key};
        let identity_providers = vec![ip_info_stubbed];

        // the anonymity revokers for testing
        let ar_identity = ArIdentity(1u32);
        let ar_public_key = PublicKey { .. }; // TODO ROB - not sure how i build this
        let ar_description = Description {description: "ar description".to_string(), name: "ar dummy name".to_string(), url: "http://dummy.com".to_string()};
        let anonymity_revoker = ArInfo {ar_identity: ar_identity, ar_description: ar_description, ar_public_key:  ar_public_key };
        let anonymity_revokers = vec![anonymity_revoker];

        // credential validity
        let created_at = YearMonth { month: now.month() as u8 , year: (now.year() - 1)};
        let valid_to = YearMonth { month: (now.month() + 1) as u8, year: (now.year() as u16)};
        let credential_validity = CredentialValidity {created_at: created_at, valid_to: valid_to};

        // invocation
        let result = verify_identity_credential_metadata(
            now, issuer, identity_providers, anonymity_revokers, validity)?;
        
        // Expected anonymity revoker information returned in result
        let expected_ar_info_btree = BTreeMap::new();
        expected_ar_info_btree.insert(ar_identity, anonymity_revoker);
        let expected_ar_infos = ArInfos {anonymity_revokers: expected_ar_info_btree};

        // Assertions
        assert_eq!(result.status, CredentialStatus::Active);

        // Assertions for the Credential Iputs returned on the result
        match result.inputs {
            CredentialsInputs::Identity { ip_info, ars_infos } => {
                assert_eq!(ip_info, ip_info_stubbed);
                assert_eq!(ars_infos, expected_ar_infos);
            },
            _ => panic!("we should not reach here, we should have handled inputs realted to identity credentials for this test")
        }

    }
}
