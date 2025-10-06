//! Functionality for generating, and verifying account signatures.
use crate::v2::{self, AccountIdentifier, BlockIdentifier, QueryError};
use concordium_base::{
    common::{
        types::{CredentialIndex, KeyIndex, KeyPair, Signature},
        Versioned,
    },
    contracts_common::{AccountAddress, SignatureThreshold},
    curve_arithmetic::Curve,
    id::types::{
        AccountCredentialWithoutProofs, AccountKeys, Attribute, InitialAccountData,
        PublicCredentialData, VerifyKey,
    },
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Digest;
use std::collections::BTreeMap;
/// Errors that can occur during generating or verifying account signatures.
#[derive(thiserror::Error, Debug)]
pub enum SignatureError {
    #[error("Network error: {0}")]
    QueryError(#[from] QueryError),
    #[error(
        "Indices do not exist on chain for credential index `{credential_index}` and key index \
         `{key_index}`"
    )]
    MissingIndicesOnChain { credential_index: u8, key_index: u8 },
    #[error("The indices in the maps do not match")]
    MismatchMapIndices,
    #[error(
        "The public key and the private key in the `account_keys` map do not match for credential \
         index `{credential_index}` and key index `{key_index}`"
    )]
    MismatchPublicPrivateKeys { credential_index: u8, key_index: u8 },
    #[error(
        "The public key on chain `{expected_public_key:?}` and the public key \
         `{actual_public_key:?}` in the signature map do not match for credential index \
         `{credential_index}` and key index `{key_index}`"
    )]
    MismatchPublicKeyOnChain {
        credential_index: u8,
        key_index: u8,
        expected_public_key: Box<VerifyingKey>,
        actual_public_key: Box<VerifyingKey>,
    },
}
/// Account signatures are constructed similarly to transaction signatures. The
/// only difference is that account signatures use as account nonce the value 0
/// when signing. This is to ensure that the user does not accidentally sign a
/// valid transaction. As such account signatures can be used to sign messages
/// in wallets that can then be verified in a smart contract or by a backend.
///
/// Account signatures should be thought of as a nested map, indexed on the
/// outer layer by credential indices, and the inner map maps key indices to
/// [`Signature`]s.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Deserialize, serde::Serialize)
)]
#[repr(transparent)]
pub struct AccountSignatures {
    pub sigs: BTreeMap<u8, CredentialSignatures>,
}
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Deserialize, serde::Serialize)
)]
#[repr(transparent)]
pub struct CredentialSignatures {
    pub sigs: BTreeMap<u8, Signature>,
}
impl AccountSignatures {
    /// Create the account signature type from a single signature at credential
    /// and key indices 0. This is a helper function to create the type when
    /// dealing with a single-signer account (in contrast to a multi-sig
    /// account). The naming `singleton` is used in Concordium's code base
    /// to indicate that there is only one element in the maps.
    pub fn singleton(signature: Signature) -> Self {
        let credential_map = CredentialSignatures {
            sigs: [(0, signature)].into(),
        };
        AccountSignatures {
            sigs: [(0, credential_map)].into(),
        }
    }
}
/// Account signatures verification data includes the [`Signature`]s and
/// associated [`VerifyKey`]s for some credentials and key indices.
///
/// Account signatures verification data should be thought of as a nested map,
/// indexed on the outer layer by credential indices, and the inner map maps key
/// indices to [`Signature`]s and [`VerifyKey`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Deserialize, serde::Serialize)
)]
#[repr(transparent)]
pub struct AccountSignaturesVerificationData {
    pub data: BTreeMap<u8, CredentialSignaturesVerificationData>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Deserialize, serde::Serialize)
)]
#[repr(transparent)]
pub struct CredentialSignaturesVerificationData {
    pub data: BTreeMap<u8, AccountSignaturesVerificationEntry>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct AccountSignaturesVerificationEntry {
    pub signature: Signature,
    pub public_key: VerifyKey,
}
impl AccountSignaturesVerificationData {
    /// Create the account signatures verification data type from a single
    /// signature and public key at credential and key indices 0. This is a
    /// helper function to create the type when dealing with a single-signer
    /// account (in contrast to a multi-sig account). The naming `singleton`
    /// is used in Concordium's code base to indicate that there is only one
    /// element in the maps.
    pub fn singleton(signature: Signature, public_key: VerifyKey) -> Self {
        let credential_map = CredentialSignaturesVerificationData {
            data: [(
                0,
                AccountSignaturesVerificationEntry {
                    signature,
                    public_key,
                },
            )]
            .into(),
        };
        AccountSignaturesVerificationData {
            data: [(0, credential_map)].into(),
        }
    }
    /// Zip an [`AccountSignatures`] and an [`AccountKeys`] into
    /// an [`AccountSignaturesVerificationData`] type. The function returns an
    /// error if the indices in the maps do not match.
    pub fn zip_signatures_and_keys(
        account_signatures: AccountSignatures,
        account_keys: AccountKeys,
    ) -> Result<Self, SignatureError> {
        let mut outer_map = BTreeMap::new();
        if account_signatures.sigs.len() != account_keys.keys.len() {
            return Err(SignatureError::MismatchMapIndices);
        }
        for (outer_key, credential_sigs) in account_signatures.sigs {
            let Some(account_key_pair) =
                account_keys.keys.get(&CredentialIndex { index: outer_key })
            else {
                return Err(SignatureError::MismatchMapIndices);
            };
            let public_keys = account_key_pair.get_public_keys();
            if credential_sigs.sigs.len() != public_keys.len() {
                return Err(SignatureError::MismatchMapIndices);
            }
            let inner_map: Result<
                BTreeMap<u8, AccountSignaturesVerificationEntry>,
                SignatureError,
            > = credential_sigs
                .sigs
                .into_iter()
                .zip(public_keys.into_iter())
                .map(|((inner_key, signature), (key_index, public_key))| {
                    if inner_key != key_index.0 {
                        return Err(SignatureError::MismatchMapIndices);
                    }
                    Ok((
                        inner_key,
                        AccountSignaturesVerificationEntry {
                            signature,
                            public_key,
                        },
                    ))
                })
                .collect();
            outer_map.insert(
                outer_key,
                CredentialSignaturesVerificationData { data: inner_map? },
            );
        }
        Ok(AccountSignaturesVerificationData { data: outer_map })
    }
}
/// Calculate the message hash that is signed in Concordium wallets.
pub fn calculate_message_hash(message: impl AsRef<[u8]>, signer: AccountAddress) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(signer);
    hasher.update([0u8; 8]);
    hasher.update(message);
    hasher.finalize().into()
}
/// Check that all key indices in the signatures map exist on chain but not vice
/// versa.
fn check_signature_map_key_indices_on_chain<C: Curve, AttributeType: Attribute<C::Scalar>>(
    signatures: &AccountSignatures,
    on_chain_credentials: &BTreeMap<
        CredentialIndex,
        Versioned<AccountCredentialWithoutProofs<C, AttributeType>>,
    >,
) -> Result<(), SignatureError> {
    for (outer_key, inner_map) in &signatures.sigs {
        let on_chain_cred = on_chain_credentials
            .get(&CredentialIndex { index: *outer_key })
            .ok_or(SignatureError::MissingIndicesOnChain {
                credential_index: *outer_key,
                key_index: 0u8,
            })?;
        for inner_key in inner_map.sigs.keys() {
            let map = match &on_chain_cred.value {
                AccountCredentialWithoutProofs::Initial { icdv } => &icdv.cred_account.keys,
                AccountCredentialWithoutProofs::Normal { cdv, .. } => &cdv.cred_key_info.keys,
            };
            if !map.contains_key(&KeyIndex(*inner_key)) {
                return Err(SignatureError::MissingIndicesOnChain {
                    credential_index: *outer_key,
                    key_index: *inner_key,
                });
            }
        }
    }
    Ok(())
}
/// Verify a given message was signed by the given account.
/// Concretely this means:
/// - enough credential holders signed the message.
/// - each of the credential signatures has the required number of signatures.
/// - all of the signatures are valid, that is, it is not sufficient that a
///   threshold number are valid, and some extra signatures included are
///   invalid.
pub async fn verify_account_signature(
    mut client: v2::Client,
    signer: AccountAddress,
    signatures: &AccountSignatures,
    message: impl AsRef<[u8]>,
    bi: BlockIdentifier,
) -> Result<bool, SignatureError> {
    let message_hash = calculate_message_hash(message, signer);
    let signer_account_info = client
        .get_account_info(&AccountIdentifier::Address(signer), bi)
        .await?;
    let signer_account_credentials = signer_account_info.response.account_credentials;
    let credential_signatures_threshold = signer_account_info.response.account_threshold;
    check_signature_map_key_indices_on_chain(signatures, &signer_account_credentials)?;
    let mut valid_credential_signatures_count = 0u8;
    for (credential_index, credential) in signer_account_credentials {
        let (keys, signatures_threshold) = match credential.value {
            AccountCredentialWithoutProofs::Initial { icdv } => {
                (icdv.cred_account.keys, icdv.cred_account.threshold)
            }
            AccountCredentialWithoutProofs::Normal { cdv, .. } => {
                (cdv.cred_key_info.keys, cdv.cred_key_info.threshold)
            }
        };
        let mut valid_signatures_count = 0u8;
        for (key_index, public_key) in keys {
            let Some(cred_sigs) = signatures.sigs.get(&credential_index.index) else {
                continue;
            };
            let Some(signature) = cred_sigs.sigs.get(&key_index.0) else {
                continue;
            };
            if public_key.verify(message_hash, signature) {
                valid_signatures_count += 1;
            } else {
                return Ok(false);
            }
        }
        if valid_signatures_count >= signatures_threshold.into() {
            valid_credential_signatures_count += 1;
        }
    }
    Ok(valid_credential_signatures_count >= credential_signatures_threshold.into())
}
/// Wrapper around the [`verify_account_signature`] function to simplify the
/// verification for single-signer accounts.
pub async fn verify_single_account_signature(
    client: v2::Client,
    signer: AccountAddress,
    signature: Signature,
    message: impl AsRef<[u8]>,
    bi: BlockIdentifier,
) -> Result<bool, SignatureError> {
    verify_account_signature(
        client,
        signer,
        &AccountSignatures::singleton(signature),
        message,
        bi,
    )
    .await
}
/// Verifies account signatures similarly to the [`verify_account_signature`]
/// function but does not perform any checks against the on-chain data such as:
/// - if the signer account exists on chain.
/// - if the credential or key indices from the `signature_data` map exist on
///   chain.
/// - if the thresholds on chain are followed.
/// - if the public keys in the `signature_data` map match the public keys on
///   chain.
pub fn verify_account_signature_unchecked(
    signer: AccountAddress,
    signature_data: AccountSignaturesVerificationData,
    message: impl AsRef<[u8]>,
) -> Result<bool, SignatureError> {
    let message_hash = calculate_message_hash(message, signer);
    for credential in signature_data.data.values() {
        for AccountSignaturesVerificationEntry {
            signature,
            public_key,
        } in credential.data.values()
        {
            if !public_key.verify(message_hash, signature) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
/// Wrapper around the [`verify_account_signature_unchecked`] function to
/// simplify the verification for single-signer accounts.
pub fn verify_single_account_signature_unchecked(
    signer: AccountAddress,
    signature: Signature,
    public_key: VerifyKey,
    message: impl AsRef<[u8]>,
) -> Result<bool, SignatureError> {
    verify_account_signature_unchecked(
        signer,
        AccountSignaturesVerificationData::singleton(signature, public_key),
        message,
    )
}
/// Generate [`AccountSignatures`] for a signer account with the given
/// `account_keys`. The function does perform checks against the on-chain data
/// such as:
/// - if the signer account exists on chain.
/// - if the credential or key indices from the `account_keys` map exist on
///   chain.
/// - if the public keys in the `account_keys` map match the public keys on
///   chain.
/// - if the public keys in the `account_keys` map match the private keys in the
///   `account_keys` map.
pub async fn sign_as_account(
    mut client: v2::Client,
    signer: AccountAddress,
    account_keys: AccountKeys,
    message: impl AsRef<[u8]>,
    bi: BlockIdentifier,
) -> Result<AccountSignatures, SignatureError> {
    let message_hash = calculate_message_hash(message, signer);
    let mut account_signatures = AccountSignatures {
        sigs: BTreeMap::new(),
    };
    let signer_account_info = client
        .get_account_info(&AccountIdentifier::Address(signer), bi)
        .await?;
    let signer_account_credentials = signer_account_info.response.account_credentials;
    for (credential_index, credential) in account_keys.keys {
        for (key_index, signing_key) in credential.keys {
            let on_chain_credential = &signer_account_credentials
                .get(&credential_index)
                .ok_or(SignatureError::MissingIndicesOnChain {
                    credential_index: credential_index.index,
                    key_index: key_index.0,
                })?
                .value;
            let on_chain_keys = match on_chain_credential {
                AccountCredentialWithoutProofs::Initial { icdv } => &icdv.cred_account.keys,
                AccountCredentialWithoutProofs::Normal { cdv, .. } => &cdv.cred_key_info.keys,
            };
            let on_chain_public_key =
                on_chain_keys
                    .get(&key_index)
                    .ok_or(SignatureError::MissingIndicesOnChain {
                        credential_index: credential_index.index,
                        key_index: key_index.0,
                    })?;
            let VerifyKey::Ed25519VerifyKey(public_key) = *on_chain_public_key;
            if signing_key.public() != public_key {
                return Err(SignatureError::MismatchPublicKeyOnChain {
                    credential_index: credential_index.index,
                    key_index: key_index.0,
                    expected_public_key: Box::new(public_key),
                    actual_public_key: Box::new(signing_key.public()),
                });
            }
            let signature = signing_key.sign(&message_hash);
            if !VerifyKey::from(public_key).verify(message_hash, &Signature::from(signature)) {
                return Err(SignatureError::MismatchPublicPrivateKeys {
                    credential_index: credential_index.index,
                    key_index: key_index.0,
                });
            }
            account_signatures
                .sigs
                .entry(credential_index.index)
                .or_insert_with(|| CredentialSignatures {
                    sigs: BTreeMap::new(),
                })
                .sigs
                .insert(key_index.0, signature.into());
        }
    }
    Ok(account_signatures)
}
/// Wrapper around the [`sign_as_account`] function to simplify the signature
/// generation for single-signer accounts.
pub async fn sign_as_single_signer_account(
    client: v2::Client,
    signer: AccountAddress,
    signing_key: SigningKey,
    message: impl AsRef<[u8]>,
    bi: BlockIdentifier,
) -> Result<Signature, SignatureError> {
    let keypair: KeyPair = KeyPair::from(signing_key);
    let keypairs = AccountKeys::from(InitialAccountData {
        keys: [(KeyIndex(0), keypair)].into(),
        threshold: SignatureThreshold::ONE,
    });
    let mut signature = sign_as_account(client, signer, keypairs, message, bi).await?;
    Ok(signature.sigs.get_mut(&0).unwrap().sigs.remove(&0).unwrap())
}
/// Generates account signatures similarly to the [`sign_as_account`] function
/// but does not perform any checks against the on-chain data such as:
/// - if the signer account exists on chain.
/// - if the credential or key indices from the `account_keys` map exist on
///   chain.
/// - if the public keys in the `account_keys` map match the public keys on
///   chain.
/// - if the public keys in the `account_keys` map match the private keys in the
///   `account_keys` map.
pub fn sign_as_account_unchecked(
    signer: AccountAddress,
    account_keys: &AccountKeys,
    message: impl AsRef<[u8]>,
) -> AccountSignatures {
    let message_hash = calculate_message_hash(message, signer);
    let mut account_signatures = AccountSignatures {
        sigs: BTreeMap::new(),
    };
    for (credential_index, credential) in &account_keys.keys {
        for (key_index, signing_keys) in &credential.keys {
            let signature = signing_keys.sign(&message_hash);
            account_signatures
                .sigs
                .entry(credential_index.index)
                .or_insert_with(|| CredentialSignatures {
                    sigs: BTreeMap::new(),
                })
                .sigs
                .insert(key_index.0, signature.into());
        }
    }
    account_signatures
}
/// Wrapper around the [`sign_as_account_unchecked`] function to simplify the
/// signature generation for single-signer accounts.
pub fn sign_as_single_signer_account_unchecked(
    signer: AccountAddress,
    signing_key: SigningKey,
    message: impl AsRef<[u8]>,
) -> Result<Signature, SignatureError> {
    let keypair: KeyPair = KeyPair::from(signing_key);
    let keypairs = AccountKeys::from(InitialAccountData {
        keys: [(KeyIndex(0), keypair)].into(),
        threshold: SignatureThreshold::ONE,
    });
    let signature = sign_as_account_unchecked(signer, &keypairs, message);
    Ok(signature.sigs[&0].sigs[&0].clone())
}
#[cfg(test)]
mod tests {
    use super::*;
    use concordium_base::{base::AccountThreshold, id::types::CredentialData};
    use std::str::FromStr;
    const NODE_URL: &str = "http://node.testnet.concordium.com:20000";
    #[test]
    #[cfg(feature = "serde_deprecated")]
    fn test_serde_account_signatures_verification_data() {
        let rng = &mut rand::thread_rng();
        let keypairs = AccountKeys::singleton(rng);
        let credential_keys = &keypairs.keys[&CredentialIndex { index: 0 }];
        let key_pair = &credential_keys.keys[&KeyIndex(0)];
        let public_key = key_pair.public().into();
        let signature = Signature::from(ed25519_dalek::Signature::from_bytes(&[0u8; 64]));
        let account_signatures_verification_data =
            AccountSignaturesVerificationData::singleton(signature, public_key);
        let serialized = serde_json::to_string(&account_signatures_verification_data)
            .expect("Failed to serialize account_signatures_verification_data");
        let deserialized: AccountSignaturesVerificationData = serde_json::from_str(&serialized)
            .expect("Failed to deserialize account_signatures_verification_data");
        assert_eq!(account_signatures_verification_data, deserialized);
    }
    #[test]
    #[cfg(feature = "serde_deprecated")]
    fn test_serde_account_signatures() {
        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&[0u8; 64]);
        let account_signatures = AccountSignatures::singleton(Signature::from(ed25519_signature));
        let serialized = serde_json::to_string(&account_signatures)
            .expect("Failed to serialize account_signatures");
        let deserialized: AccountSignatures =
            serde_json::from_str(&serialized).expect("Failed to deserialize account_signatures");
        assert_eq!(account_signatures, deserialized);
    }
    #[test]
    fn test_sign_and_verify_text_message_unchecked() {
        let message: &str = "test";
        let text_message = message.as_bytes();
        let rng = &mut rand::thread_rng();
        let keypairs = AccountKeys::singleton(rng);
        let account_address = AccountAddress([0u8; 32]);
        let account_signature = sign_as_account_unchecked(account_address, &keypairs, text_message);
        assert_eq!(account_signature.sigs.len(), 1);
        let account_signatures_verification_data =
            AccountSignaturesVerificationData::zip_signatures_and_keys(account_signature, keypairs)
                .expect("Expect zipping of maps to succeed");
        assert_eq!(account_signatures_verification_data.data.len(), 1);
        let is_valid = verify_account_signature_unchecked(
            account_address,
            account_signatures_verification_data,
            text_message,
        )
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[test]
    fn test_sign_and_verify_text_message_unchecked_single() {
        let message: &str = "test";
        let text_message = message.as_bytes();
        let rng = &mut rand::thread_rng();
        let keypairs = AccountKeys::singleton(rng);
        let single_key = keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)].clone();
        let credential_keys = &keypairs.keys[&CredentialIndex { index: 0 }];
        let key_pair = &credential_keys.keys[&KeyIndex(0)];
        let public_key = key_pair.public();
        let account_address = AccountAddress([0u8; 32]);
        let single_account_signature = sign_as_single_signer_account_unchecked(
            account_address,
            single_key.into(),
            text_message,
        )
        .expect("Expect signing to succeed");
        let is_valid = verify_single_account_signature_unchecked(
            account_address,
            single_account_signature,
            public_key.into(),
            text_message,
        )
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[tokio::test]
    async fn test_sign_and_verify_text_message_checked() {
        let message: &str = "test";
        let text_message = message.as_bytes();
        let private_key = "f74e3188e4766841600f6fd0095a0ac1c30e4c2e97b9797d7e05a28a48f5c37c";
        let bytes = hex::decode(private_key).expect("Invalid hex string for private key.");
        let signing_key = SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("Invalid private key size"),
        );
        let keypair: KeyPair = KeyPair::from(signing_key);
        let keypairs = AccountKeys::from(InitialAccountData {
            keys: [(KeyIndex(0), keypair)].into(),
            threshold: SignatureThreshold::ONE,
        });
        let account_address =
            AccountAddress::from_str("47b6Qe2XtZANHetanWKP1PbApLKtS3AyiCtcXaqLMbypKjCaRw")
                .expect("Expect generating account address successfully");
        let client = v2::Client::new(
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");
        let account_signature = sign_as_account(
            client.clone(),
            account_address,
            keypairs,
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");
        assert_eq!(account_signature.sigs.len(), 1);
        let is_valid = verify_account_signature(
            client.clone(),
            account_address,
            &account_signature,
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[tokio::test]
    async fn test_sign_and_verify_text_message_checked_single() {
        let message: &str = "test";
        let text_message = message.as_bytes();
        let private_key = "f74e3188e4766841600f6fd0095a0ac1c30e4c2e97b9797d7e05a28a48f5c37c";
        let bytes = hex::decode(private_key).expect("Invalid hex string for private key.");
        let signing_key = SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("Invalid private key size"),
        );
        let keypair: KeyPair = KeyPair::from(signing_key);
        let keypairs = AccountKeys::from(InitialAccountData {
            keys: [(KeyIndex(0), keypair)].into(),
            threshold: SignatureThreshold::ONE,
        });
        let single_key = keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)].clone();
        let account_address =
            AccountAddress::from_str("47b6Qe2XtZANHetanWKP1PbApLKtS3AyiCtcXaqLMbypKjCaRw")
                .expect("Expect generating account address successfully");
        let client = v2::Client::new(
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");
        let single_account_signature = sign_as_single_signer_account(
            client.clone(),
            account_address,
            single_key.into(),
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");
        let is_valid = verify_single_account_signature(
            client,
            account_address,
            single_account_signature,
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[test]
    fn test_sign_and_verify_binary_message_unchecked() {
        let binary_message: &[u8] = b"test";
        let rng = &mut rand::thread_rng();
        let keypairs = AccountKeys::singleton(rng);
        let account_address = AccountAddress([0u8; 32]);
        let account_signature =
            sign_as_account_unchecked(account_address, &keypairs, binary_message);
        assert_eq!(account_signature.sigs.len(), 1);
        let account_signatures_verification_data =
            AccountSignaturesVerificationData::zip_signatures_and_keys(account_signature, keypairs)
                .expect("Expect zipping of maps to succeed");
        assert_eq!(account_signatures_verification_data.data.len(), 1);
        let is_valid = verify_account_signature_unchecked(
            account_address,
            account_signatures_verification_data,
            binary_message,
        )
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[test]
    fn test_sign_and_verify_binary_message_unchecked_single() {
        let binary_message: &[u8] = b"test";
        let rng = &mut rand::thread_rng();
        let keypairs = AccountKeys::singleton(rng);
        let single_key = keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)].clone();
        let account_address = AccountAddress([0u8; 32]);
        let single_account_signature = sign_as_single_signer_account_unchecked(
            account_address,
            single_key.clone().into(),
            binary_message,
        )
        .expect("Expect signing to succeed");
        let is_valid = verify_single_account_signature_unchecked(
            account_address,
            single_account_signature,
            single_key.public().into(),
            binary_message,
        )
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[tokio::test]
    async fn test_sign_and_verify_binary_message_checked() {
        let binary_message: &[u8] = b"test";
        let private_key = "f74e3188e4766841600f6fd0095a0ac1c30e4c2e97b9797d7e05a28a48f5c37c";
        let bytes = hex::decode(private_key).expect("Invalid hex string for private key.");
        let signing_key = SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("Invalid private key size"),
        );
        let keypair: KeyPair = KeyPair::from(signing_key);
        let keypairs = AccountKeys::from(InitialAccountData {
            keys: [(KeyIndex(0), keypair)].into(),
            threshold: SignatureThreshold::ONE,
        });
        let account_address =
            AccountAddress::from_str("47b6Qe2XtZANHetanWKP1PbApLKtS3AyiCtcXaqLMbypKjCaRw")
                .expect("Expect generating account address successfully");
        let client = v2::Client::new(
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");
        let account_signature = sign_as_account(
            client.clone(),
            account_address,
            keypairs,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");
        assert_eq!(account_signature.sigs.len(), 1);
        let is_valid = verify_account_signature(
            client,
            account_address,
            &account_signature,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[tokio::test]
    async fn test_sign_and_verify_binary_message_checked_single() {
        let binary_message: &[u8] = b"test";
        let private_key = "f74e3188e4766841600f6fd0095a0ac1c30e4c2e97b9797d7e05a28a48f5c37c";
        let bytes = hex::decode(private_key).expect("Invalid hex string for private key.");
        let signing_key = SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("Invalid private key size"),
        );
        let keypair: KeyPair = KeyPair::from(signing_key);
        let keypairs = AccountKeys::from(InitialAccountData {
            keys: [(KeyIndex(0), keypair)].into(),
            threshold: SignatureThreshold::ONE,
        });
        let single_key = keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)].clone();
        let account_address =
            AccountAddress::from_str("47b6Qe2XtZANHetanWKP1PbApLKtS3AyiCtcXaqLMbypKjCaRw")
                .expect("Expect generating account address successfully");
        let client = v2::Client::new(
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");
        let single_account_signature = sign_as_single_signer_account(
            client.clone(),
            account_address,
            single_key.clone().into(),
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");
        let is_valid = verify_single_account_signature(
            client,
            account_address,
            single_account_signature,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[test]
    fn test_sign_and_verify_text_message_unchecked_multi_sig_account() {
        let message: &str = "test";
        let text_message = message.as_bytes();
        let rng = &mut rand::thread_rng();
        let single_keypairs = AccountKeys::singleton(rng);
        let credential_map = [
            (
                CredentialIndex { index: 0 },
                CredentialData {
                    keys: [
                        (
                            KeyIndex(0u8),
                            single_keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)]
                                .clone(),
                        ),
                        (
                            KeyIndex(1u8),
                            single_keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)]
                                .clone(),
                        ),
                    ]
                    .into(),
                    threshold: SignatureThreshold::TWO,
                },
            ),
            (
                CredentialIndex { index: 1 },
                CredentialData {
                    keys: [
                        (
                            KeyIndex(0u8),
                            single_keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)]
                                .clone(),
                        ),
                        (
                            KeyIndex(1u8),
                            single_keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)]
                                .clone(),
                        ),
                    ]
                    .into(),
                    threshold: SignatureThreshold::TWO,
                },
            ),
        ]
        .into();
        let keypairs_multi_sig_account = AccountKeys {
            keys: credential_map,
            threshold: AccountThreshold::TWO,
        };
        let account_address = AccountAddress([0u8; 32]);
        let account_signatures =
            sign_as_account_unchecked(account_address, &keypairs_multi_sig_account, text_message);
        assert_eq!(account_signatures.sigs.len(), 2);
        assert_eq!(account_signatures.sigs[&0].sigs.len(), 2);
        assert_eq!(account_signatures.sigs[&1].sigs.len(), 2);
        let account_signatures_verification_data =
            AccountSignaturesVerificationData::zip_signatures_and_keys(
                account_signatures,
                keypairs_multi_sig_account,
            )
            .expect("Expect zipping of maps to succeed");
        assert_eq!(account_signatures_verification_data.data.len(), 2);
        assert_eq!(account_signatures_verification_data.data[&0].data.len(), 2);
        assert_eq!(account_signatures_verification_data.data[&1].data.len(), 2);
        let is_valid = verify_account_signature_unchecked(
            account_address,
            account_signatures_verification_data,
            text_message,
        )
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
    #[tokio::test]
    async fn test_sign_and_verify_binary_message_multi_sig_account() {
        let binary_message: &[u8] = b"test";
        let private_key = "bbabcd59e5ca2edb2073e1936f4df84fbe352fb03c4e55061957f5099b94f562";
        let bytes = hex::decode(private_key).expect("Invalid hex string for private key.");
        let signing_key = SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("Invalid private key size"),
        );
        let keypair1: KeyPair = KeyPair::from(signing_key);
        let private_key = "751c9c11a7e9f4729779d8795c21aa02973bb2e7276700444ead643c255a38ae";
        let bytes = hex::decode(private_key).expect("Invalid hex string for private key.");
        let signing_key = SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("Invalid private key size"),
        );
        let keypair2: KeyPair = KeyPair::from(signing_key);
        let keypairs = AccountKeys::from(InitialAccountData {
            keys: [
                (KeyIndex(0), keypair1.clone()),
                (KeyIndex(1), keypair2.clone()),
            ]
            .into(),
            threshold: SignatureThreshold::TWO,
        });
        let account_address =
            AccountAddress::from_str("4jxvYasaPncfmCFCLZCvuL5cZuvR5HAQezCHZH7ZA7AGsRYpix")
                .expect("Expect generating account address successfully");
        let client = v2::Client::new(
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");
        let account_signatures = sign_as_account(
            client.clone(),
            account_address,
            keypairs,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");
        assert_eq!(account_signatures.sigs.len(), 1);
        assert_eq!(account_signatures.sigs[&0].sigs.len(), 2);
        let is_valid = verify_account_signature(
            client,
            account_address,
            &account_signatures,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert!(is_valid);
    }
}
