//! Functionality for retrieving, verifying, and registering web3id credentials.

use crate::{
    cis4::{Cis4Contract, Cis4QueryError},
    v2::{self, BlockIdentifier, IntoBlockIdentifier},
};
pub use concordium_base::web3id::*;
use concordium_base::{
    base::CredentialRegistrationID,
    cis4_types::CredentialStatus,
    contracts_common::{AccountAddress, ContractAddress},
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
    #[error(
        "Cannot parse the commitment returned from contract: {contract} for credential {cred_id}."
    )]
    CommitmentParseError {
        contract: ContractAddress,
        cred_id:  CredentialHolderId,
    },
    #[error("Unexpected response from the node: {0}")]
    InvalidResponse(String),
}

/// The public cryptographic data of a credential together with its current
/// status.
pub struct CredentialWithMetadata {
    /// The status of the credential at a point in time.
    pub status:      CredentialStatus,
    /// The commitments of the credential.
    pub commitments: CredentialsInputs<ArCurve>,
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
                    let commitments = CredentialsInputs::Account {
                        commitments: commitments.cmm_attributes.clone(),
                    };

                    Ok(CredentialWithMetadata {
                        status,
                        commitments,
                    })
                }
            }
        }
        CredentialMetadata::Web3Id { contract, owner } => {
            let mut contract_client = Cis4Contract::create(client, contract).await?;
            let entry = contract_client.credential_entry(owner, bi).await?;
            let commitment = concordium_base::common::from_bytes(&mut std::io::Cursor::new(
                &entry.credential_info.commitment,
            ))
            .map_err(|_| CredentialLookupError::CommitmentParseError {
                contract,
                cred_id: owner,
            })?;

            let commitments = CredentialsInputs::Web3 { commitment };

            let status = contract_client.credential_status(owner, bi).await?;

            Ok(CredentialWithMetadata {
                status,
                commitments,
            })
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

/// Functionality related to storage of credential secrets in smart contracts.
pub mod storage {
    use crate::{
        base as concordium_base,
        base::common,
        contract_client::ViewError,
        id::{constants::ArCurve, pedersen_commitment::Randomness},
        smart_contracts::common::{self as concordium_std, Timestamp},
        types::ContractAddress,
        v2::IntoBlockIdentifier,
        web3id::{CredentialHolderId, Web3IdAttribute, Web3IdSigner},
    };
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm,
    };
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Copy)]
    pub enum Web3IdStorageRole {}

    pub type CredentialStorageContract = crate::contract_client::ContractClient<Web3IdStorageRole>;

    impl CredentialStorageContract {
        /// Get the credential stored in the contract. Returns `Ok(None)` if the
        /// credential does not exist in the contract.
        pub async fn get_credential_secrets(
            &mut self,
            cred_id: &CredentialHolderId,
            bi: impl IntoBlockIdentifier,
        ) -> Result<Option<VersionedEncryptedCredential>, ViewError> {
            self.view("view", &cred_id, bi).await
        }
    }

    #[derive(concordium_std::Serial, concordium_std::Deserial, PartialEq)]
    /// The credential stored in the credential storage contract.
    pub struct VersionedEncryptedCredential {
        /// Metadata associated with the credential.
        version:              u16,
        /// The encrypted credential.
        encrypted_credential: Vec<u8>,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum DecryptError {
        #[error("Unsupported version: {0}")]
        UnsupportedVersion(u16),
        #[error("Unable to parse response: {0}")]
        Parse(#[from] concordium_std::ParseError),
        #[error("Unable to decrypt: {0}")]
        DecryptFailure(#[from] aes_gcm::Error),
        #[error("Unable decode decrypted credential secrets.")]
        DecodeFailure,
    }

    impl VersionedEncryptedCredential {
        /// Decrypt the [`ViewResponse`] with the provided AES256 secret key.
        /// The public key `pk` is used to check authenticity.
        pub fn decrypt(
            &self,
            pk: CredentialHolderId,
            key: [u8; 32],
        ) -> Result<CredentialSecrets, DecryptError> {
            if self.version != 0 {
                return Err(DecryptError::UnsupportedVersion(self.version));
            }
            let encrypted = concordium_std::from_bytes::<EncryptedCredentialSecrets>(
                &self.encrypted_credential,
            )?;
            let cipher = Aes256Gcm::new(&key.into());
            let payload = aes_gcm::aead::Payload {
                msg: &encrypted.ciphertext,
                aad: pk.public_key.as_bytes(),
            };
            let decrypted = cipher.decrypt(&encrypted.nonce.into(), payload)?;
            let Ok(cs) = common::from_bytes(&mut std::io::Cursor::new(decrypted)) else {
            return Err(DecryptError::DecodeFailure);
        };
            Ok(cs)
        }
    }

    /// The parameter type for the contract function `store`.
    #[derive(concordium_std::Serialize, serde::Serialize, serde::Deserialize, Debug, Clone)]
    pub struct StoreParam {
        /// Public key that created the above signature.
        pub public_key: CredentialHolderId,
        /// Signature from the holder.
        #[serde(with = "crate::internal::byte_array_hex")]
        pub signature:  [u8; ed25519_dalek::SIGNATURE_LENGTH],
        // The signed data.
        pub data:       DataToSign,
    }

    /// The parameter type for the contract function `serializationHelper`.
    #[derive(concordium_std::Serialize, serde::Serialize, serde::Deserialize, Clone, Debug)]
    pub struct DataToSign {
        /// A timestamp to make signatures expire.
        pub timestamp:            Timestamp,
        /// The contract_address that the signature is intended for.
        pub contract_address:     ContractAddress,
        /// Metadata associated with the credential.
        pub version:              u16,
        /// The serialized encrypted_credential.
        #[concordium(size_length = 2)]
        #[serde(with = "crate::internal::byte_array_hex")]
        pub encrypted_credential: Vec<u8>,
    }

    impl DataToSign {
        pub fn sign(self, signer: &impl Web3IdSigner) -> StoreParam {
            let mut data_to_sign = b"WEB3ID:STORE".to_vec();
            use concordium_std::Serial;
            self.serial(&mut data_to_sign)
                .expect("Serialization to vector does not fail.");
            let signature = signer.sign(&data_to_sign);

            StoreParam {
                public_key: signer.id().into(),
                signature:  signature.to_bytes(),
                data:       self,
            }
        }
    }

    #[derive(common::Serial, common::Deserial, Debug, serde::Serialize, serde::Deserialize)]
    /// Secret data of a credential that is to be stored.
    pub struct CredentialSecrets {
        pub issuer:     ContractAddress,
        /// The randomness from the commitment.
        pub randomness: Randomness<ArCurve>,
        /// The values that are committed to.
        pub values:     BTreeMap<u8, Web3IdAttribute>,
    }
    #[derive(concordium_std::Serial, concordium_std::Deserial)]
    /// The credential secrets that were encrypted, combined with public data
    /// needed for decryption.
    pub struct EncryptedCredentialSecrets {
        nonce:      [u8; 12],
        #[concordium(size_length = 2)]
        ciphertext: Vec<u8>,
    }

    impl CredentialSecrets {
        /// Encrypt the credential secrets using aes-gcm.
        ///
        /// - `pk` is the public key of the credential holder. This is used as
        ///   the authentication header.
        /// - `key` is the **secret** key for AES encryption.
        /// - `nonce` is the initialization vector for encryption. It should be
        ///   sampled randomly for each encryption.
        pub fn encrypt(
            &self,
            pk: CredentialHolderId,
            key: [u8; 32],
            nonce: [u8; 12],
        ) -> Result<EncryptedCredentialSecrets, aes_gcm::Error> {
            let cipher = Aes256Gcm::new(&key.into());
            let payload = aes_gcm::aead::Payload {
                msg: &common::to_bytes(self),
                aad: pk.public_key.as_bytes(),
            };
            let ciphertext = cipher.encrypt(&nonce.into(), payload)?;
            Ok(EncryptedCredentialSecrets { nonce, ciphertext })
        }
    }
}
