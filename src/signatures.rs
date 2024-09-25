//! Functionality for generating, and verifying account signatures.

// TODO: test for binary and string signing with external repo.
// TODO: test for binary and string signing checked with external repo.
// TODO: check account with several keys.
// TODO: better zip and check that the maps and indexes correspond to each
// other.
// TODO: correct the error name `MissingSignature`
use crate::v2::{self, AccountIdentifier, IntoBlockIdentifier, QueryError};
use concordium_base::{
    common::{
        types::{CredentialIndex, KeyIndex, KeyPair, Signature},
        Versioned,
    },
    contracts_common::{to_bytes, AccountAddress, SignatureThreshold},
    curve_arithmetic::Curve,
    id::types::{
        AccountCredentialWithoutProofs, AccountKeys, Attribute, InitialAccountData, VerifyKey,
    },
};
use ed25519_dalek::SigningKey;
use sha2::Digest;
use std::collections::BTreeMap;

#[derive(thiserror::Error, Debug)]
/// An error that can be used as the error for the
/// [`view`](ContractClient::view) family of functions.
pub enum SignatureError {
    #[error("Network error: {0}")]
    QueryError(#[from] QueryError),
    #[error("Missing signature at credential index {credential_index} and key index {key_index}")]
    MissingSignature {
        credential_index: u8,
        key_index:        u8,
    },
    #[error("The indexes in the maps do not match")]
    MismatchMapIndexes,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Message<'a> {
    BinaryMessage(&'a [u8]),
    TextMessage(&'a str),
}

/// Account signatures. This is an analogue of transaction signatures that are
/// part of transactions that get sent to the chain.
///
/// It should be thought of as a nested map, indexed on the outer layer by
/// credential indexes, and the inner map maps key indices to [`Signature`]s.
#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct AccountPublicKeys {
    pub keys: BTreeMap<u8, CredentialPublicKeys>,
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct CredentialPublicKeys {
    pub keys: BTreeMap<u8, VerifyKey>,
}

impl AccountPublicKeys {
    pub fn singleton(public_key: VerifyKey) -> Self {
        let credential_map = CredentialPublicKeys {
            keys: [(0, public_key)].into_iter().collect(),
        };

        AccountPublicKeys {
            keys: [(0, credential_map)].into_iter().collect(),
        }
    }
}

/// Account signatures. This is an analogue of transaction signatures that are
/// part of transactions that get sent to the chain.
///
/// It should be thought of as a nested map, indexed on the outer layer by
/// credential indexes, and the inner map maps key indices to [`Signature`]s.
#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct AccountSignatures {
    pub sigs: BTreeMap<u8, CredentialSignatures>,
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct CredentialSignatures {
    pub sigs: BTreeMap<u8, Signature>,
}

impl AccountSignatures {
    pub fn singleton(signature: Signature) -> Self {
        let credential_map = CredentialSignatures {
            sigs: [(0, signature)].into_iter().collect(),
        };

        AccountSignatures {
            sigs: [(0, credential_map)].into_iter().collect(),
        }
    }
}

pub fn calculate_message_hash(
    message: &Message<'_>,
    signer: AccountAddress,
) -> Result<[u8; 32], SignatureError> {
    let message_bytes;
    let message_signed_in_wallet: &[u8] = match message {
        Message::BinaryMessage(message) => message,
        Message::TextMessage(message) => {
            message_bytes = to_bytes(&message);
            &message_bytes
        }
    };

    // A message signed in a Concordium wallet is prepended with the
    // `account` address (signer) and 8 zero bytes. Accounts in a Concordium
    // wallet can either sign a regular transaction (in that case the
    // prepend is `account` address and the nonce of the account which is by
    // design >= 1) or sign a message (in that case the prepend is `account`
    // address and 8 zero bytes). Hence, the 8 zero bytes ensure that the user
    // does not accidentally sign a transaction. The account nonce is of type
    // u64 (8 bytes).
    Ok(sha2::Sha256::digest(
        [
            &signer.as_ref() as &[u8],
            &[0u8; 8],
            message_signed_in_wallet,
        ]
        .concat(),
    )
    .into())
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
///
/// Check that all key indexes in the signatures map exist on chain but not vice
/// versa.
fn exist_signature_map_keys_on_chain<C: Curve, AttributeType: Attribute<C::Scalar>>(
    signatures: &AccountSignatures,
    on_chain_credentials: &BTreeMap<
        CredentialIndex,
        Versioned<AccountCredentialWithoutProofs<C, AttributeType>>,
    >,
) -> bool {
    // Ensure all top-level keys in signatures exist in on_chain_credentials
    signatures.sigs.keys().all(|outer_key| {
        // Check if the outer key exists in the on_chain_credentials map
        on_chain_credentials
            .get(&CredentialIndex { index: *outer_key })
            .map_or(false, |on_chain_cred| {
                // Ensure that second-level keys in signatures exist in on_chain_credentials
                signatures.sigs[outer_key].sigs.keys().all(|inner_key| {
                    let map = match &on_chain_cred.value {
                        AccountCredentialWithoutProofs::Initial { icdv } => &icdv.cred_account.keys,
                        AccountCredentialWithoutProofs::Normal { cdv, .. } => {
                            &cdv.cred_key_info.keys
                        }
                    };
                    map.contains_key(&KeyIndex(*inner_key))
                })
            })
    })
}

/// Verify a given message was signed by the given account.
/// Concretely this means
///
/// - enough credential holders signed the message
/// - each of the credential signatures has the required number of signatures.
/// - all of the signatures are valid, that is, it is not sufficient that a
///   threshold number are valid, and some extra signarues included are invalid.
pub async fn verify_account_signature(
    mut client: v2::Client,
    signer: AccountAddress,
    signatures: AccountSignatures,
    message: &Message<'_>,
    bi: impl IntoBlockIdentifier,
) -> Result<bool, SignatureError> {
    let message_hash = calculate_message_hash(message, signer)?;

    let signer_account_info = client
        .get_account_info(&AccountIdentifier::Address(signer), bi)
        .await?;

    let signer_account_credentials = signer_account_info.response.account_credentials;
    let credential_signatures_threshold = signer_account_info.response.account_threshold;

    if !exist_signature_map_keys_on_chain(&signatures, &signer_account_credentials) {
        return Err(SignatureError::MismatchMapIndexes);
    }

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
            // If a signature exists for the given credential and key index, verify it and
            // increase the `valid_signatures_count`.
            if let Some(cred_sigs) = signatures.sigs.get(&credential_index.index) {
                if let Some(signature) = cred_sigs.sigs.get(&key_index.0) {
                    if public_key.verify(message_hash, signature) {
                        // If the signature is valid, increase the `valid_signatures_count`.
                        valid_signatures_count += 1;
                    } else {
                        // If any signature is invalid, return `false`.
                        return Ok(false);
                    }
                }
            }
        }

        // Check if the number of valid signatures meets the required threshold
        // so that this credential counts has having a valid credential signature.
        if valid_signatures_count >= signatures_threshold.into() {
            valid_credential_signatures_count += 1;
        }
    }

    // Check if the total number of valid credential signatures meets the required
    // threshold.
    Ok(valid_credential_signatures_count >= credential_signatures_threshold.into())
}

pub async fn verify_single_account_signature(
    client: v2::Client,
    signer: AccountAddress,
    signature: Signature,
    message: &Message<'_>,
    bi: impl IntoBlockIdentifier,
) -> Result<bool, SignatureError> {
    verify_account_signature(
        client,
        signer,
        AccountSignatures::singleton(signature),
        message,
        bi,
    )
    .await
}

fn have_maps_equal_keys(signatures: &AccountSignatures, public_keys: &AccountPublicKeys) -> bool {
    // Check the top-level keys and second-level keys are equal in the maps
    signatures.sigs.keys().all(|outer_key| {
        public_keys
            .keys
            .get(outer_key)
            .map_or(false, |pub_key_map| {
                signatures.sigs[outer_key]
                    .sigs
                    .keys()
                    .eq(pub_key_map.keys.keys())
            })
    })
}

// No check is done if that account exists on chain or if the thresholds on
// chain are followed.
pub fn verify_account_signature_unchecked(
    signer: AccountAddress,
    signatures: AccountSignatures,
    public_keys: AccountPublicKeys,
    message: &Message<'_>,
) -> Result<bool, SignatureError> {
    let message_hash = calculate_message_hash(message, signer)?;

    if !have_maps_equal_keys(&signatures, &public_keys) {
        return Err(SignatureError::MismatchMapIndexes);
    }

    for (credential_index, credential) in public_keys.keys {
        for (key_index, public_key) in credential.keys {
            let signature = signatures
                .sigs
                .get(&credential_index)
                .ok_or(SignatureError::MissingSignature {
                    credential_index,
                    key_index,
                })?
                .sigs
                .get(&key_index)
                .ok_or(SignatureError::MissingSignature {
                    credential_index,
                    key_index,
                })?;

            if !public_key.verify(message_hash, signature) {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

pub fn verify_single_account_signature_unchecked(
    signer: AccountAddress,
    signature: Signature,
    public_keys: AccountPublicKeys,
    message: &Message<'_>,
) -> Result<bool, SignatureError> {
    verify_account_signature_unchecked(
        signer,
        AccountSignatures::singleton(signature),
        public_keys,
        message,
    )
}

pub async fn sign_as_account(
    mut client: v2::Client,
    signer: AccountAddress,
    account_keys: AccountKeys,
    message: &Message<'_>,
    bi: impl IntoBlockIdentifier,
) -> Result<AccountSignatures, SignatureError> {
    let message_hash = calculate_message_hash(message, signer)?;

    let mut account_signatures = AccountSignatures {
        sigs: BTreeMap::new(),
    };

    let signer_account_info = client
        .get_account_info(&AccountIdentifier::Address(signer), bi)
        .await?;

    let signer_account_credentials = signer_account_info.response.account_credentials;

    for (credential_index, credential) in signer_account_credentials {
        let keys = match credential.value {
            AccountCredentialWithoutProofs::Initial { icdv } => icdv.cred_account.keys,
            AccountCredentialWithoutProofs::Normal { cdv, .. } => cdv.cred_key_info.keys,
        };
        for (key_index, public_key) in keys {
            let signing_keys = account_keys
                .keys
                .get(&credential_index)
                .ok_or(SignatureError::MissingSignature {
                    credential_index: credential_index.index,
                    key_index:        key_index.0,
                })?
                .keys
                .get(&key_index)
                .ok_or(SignatureError::MissingSignature {
                    credential_index: credential_index.index,
                    key_index:        key_index.0,
                })?;

            let VerifyKey::Ed25519VerifyKey(verifying_key) = public_key;

            if signing_keys.public() != verifying_key {
                return Err(SignatureError::MissingSignature {
                    credential_index: credential_index.index,
                    key_index:        key_index.0,
                });
            };

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

    Ok(account_signatures)
}

pub async fn sign_as_single_signer_account(
    client: v2::Client,
    signer: AccountAddress,
    signing_key: SigningKey,
    message: &Message<'_>,
    bi: impl IntoBlockIdentifier,
) -> Result<Signature, SignatureError> {
    let keypair: KeyPair = KeyPair::from(signing_key);
    // Generate account keys that have one keypair at index 0 in both maps.
    let keypairs = AccountKeys::from(InitialAccountData {
        keys:      [(KeyIndex(0), keypair)].into_iter().collect(),
        threshold: SignatureThreshold::ONE,
    });
    let signature = sign_as_account(client, signer, keypairs, message, bi).await?;
    // Accessing the maps at index 0 is safe because we generated an
    // AccountSignature with a keypair at index 0 at both maps.
    Ok(signature.sigs[&0].sigs[&0].clone())
}

pub fn sign_as_account_unchecked(
    signer: AccountAddress,
    account_keys: AccountKeys,
    message: &Message<'_>,
) -> Result<AccountSignatures, SignatureError> {
    let message_hash = calculate_message_hash(message, signer)?;

    let mut account_signatures = AccountSignatures {
        sigs: BTreeMap::new(),
    };

    for (credential_index, credential) in account_keys.keys {
        for (key_index, signing_keys) in credential.keys {
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

    Ok(account_signatures)
}

pub fn sign_as_single_signer_account_unchecked(
    signer: AccountAddress,
    signing_key: SigningKey,
    message: &Message<'_>,
) -> Result<Signature, SignatureError> {
    let keypair: KeyPair = KeyPair::from(signing_key);
    // Generate account keys that have one keypair at index 0 in both maps.
    let keypairs = AccountKeys::from(InitialAccountData {
        keys:      [(KeyIndex(0), keypair)].into_iter().collect(),
        threshold: SignatureThreshold::ONE,
    });
    let signature = sign_as_account_unchecked(signer, keypairs, message)?;
    // Accessing the maps at index 0 is safe because we generated an
    // AccountSignature with a keypair at index 0 at both maps.
    Ok(signature.sigs[&0].sigs[&0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use concordium_base::common::types::CredentialIndex;
    use std::str::FromStr;
    use v2::BlockIdentifier;

    #[test]
    fn test_serde_account_public_keys() {
        let rng = &mut rand::thread_rng();

        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::singleton(rng);

        // Get public key from map.
        let credential_keys = &keypairs.keys[&CredentialIndex { index: 0 }];
        let key_pair = &credential_keys.keys[&KeyIndex(0)];
        let public_key = key_pair.public();

        // Create AccountPublicKeys type with the public key.
        let account_public_keys = AccountPublicKeys::singleton(public_key.into());

        // Check that the serialization and deserialization works.
        let serialized = serde_json::to_string(&account_public_keys)
            .expect("Failed to serialize account_public_keys");
        let deserialized: AccountPublicKeys =
            serde_json::from_str(&serialized).expect("Failed to deserialize account_public_keys");
        assert_eq!(account_public_keys, deserialized);
    }

    #[test]
    fn test_serde_account_signatures() {
        // Generate account signature.
        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&[0u8; 64]);
        let account_signatures = AccountSignatures::singleton(Signature::from(ed25519_signature));

        // Check that the serialization and deserialization works.
        let serialized = serde_json::to_string(&account_signatures)
            .expect("Failed to serialize account_signatures");
        let deserialized: AccountSignatures =
            serde_json::from_str(&serialized).expect("Failed to deserialize account_signatures");
        assert_eq!(account_signatures, deserialized);
    }

    #[test]
    fn test_sign_and_verify_text_message_unchecked() {
        // Create a message to sign.
        let message: &str = "test";
        let text_message = &Message::TextMessage(message);

        let rng = &mut rand::thread_rng();

        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::singleton(rng);
        let single_key = keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)].clone();

        // Get public key from map.
        let credential_keys = &keypairs.keys[&CredentialIndex { index: 0 }];
        let key_pair = &credential_keys.keys[&KeyIndex(0)];
        let public_key = key_pair.public();

        // Create an account address.
        let account_address = AccountAddress([0u8; 32]);

        // Generate signature.
        let account_signature = sign_as_account_unchecked(account_address, keypairs, text_message)
            .expect("Expect signing to succeed");
        let single_account_signature = sign_as_single_signer_account_unchecked(
            account_address,
            single_key.into(),
            text_message,
        )
        .expect("Expect signing to succeed");

        // Check that the signature is valid.
        let is_valid = verify_account_signature_unchecked(
            account_address,
            account_signature,
            AccountPublicKeys::singleton(public_key.into()),
            text_message,
        )
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
        let is_valid = verify_single_account_signature_unchecked(
            account_address,
            single_account_signature,
            AccountPublicKeys::singleton(public_key.into()),
            text_message,
        )
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    #[tokio::test]
    async fn test_sign_and_verify_text_message_checked() {
        // Create a message to sign.
        let message: &str = "test";
        let text_message = &Message::TextMessage(message);

        // Create a keypair from a private key.
        let private_key = "f74e3188e4766841600f6fd0095a0ac1c30e4c2e97b9797d7e05a28a48f5c37c";
        let bytes = hex::decode(private_key).expect("Invalid hex string for private key.");

        let signing_key = SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("Invalid private key size"),
        );
        let keypair: KeyPair = KeyPair::from(signing_key);
        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::from(InitialAccountData {
            keys:      [(KeyIndex(0), keypair)].into_iter().collect(),
            threshold: SignatureThreshold::ONE,
        });
        let single_key = keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)].clone();

        // Add the corresponding account address from testnet associated with above
        // private key.
        let account_address =
            AccountAddress::from_str("47b6Qe2XtZANHetanWKP1PbApLKtS3AyiCtcXaqLMbypKjCaRw")
                .expect("Expect generating account address successfully");

        // Establish a connection to the node client.
        let client = v2::Client::new(
            v2::Endpoint::new("http://node.testnet.concordium.com:20000")
                .expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");

        // Generate signature.
        let account_signature = sign_as_account(
            client.clone(),
            account_address,
            keypairs,
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");
        let single_account_signature = sign_as_single_signer_account(
            client.clone(),
            account_address,
            single_key.into(),
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");

        // Check that the signature is valid.
        let is_valid = verify_account_signature(
            client.clone(),
            account_address,
            account_signature,
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
        // Check that the signature is valid.
        let is_valid = verify_single_account_signature(
            client,
            account_address,
            single_account_signature,
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    #[test]
    fn test_sign_and_verify_binary_message_unchecked() {
        // Create a message to sign.
        let message: &[u8] = b"test";
        let binary_message = &Message::BinaryMessage(message);

        let rng = &mut rand::thread_rng();

        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::singleton(rng);

        // Get public key from map.
        let credential_keys = &keypairs.keys[&CredentialIndex { index: 0 }];
        let key_pair = &credential_keys.keys[&KeyIndex(0)];
        let public_key = key_pair.public();

        // Create an account address.
        let account_address = AccountAddress([0u8; 32]);

        // Generate signature.
        let account_signature =
            sign_as_account_unchecked(account_address, keypairs, binary_message)
                .expect("Expect signing to succeed");

        // Check that the signature is valid.
        let is_valid = verify_account_signature_unchecked(
            account_address,
            account_signature,
            AccountPublicKeys::singleton(public_key.into()),
            binary_message,
        )
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    #[tokio::test]
    async fn test_sign_and_verify_binary_message_checked() {
        // Create a message to sign.
        let message: &[u8] = b"test";
        let binary_message = &Message::BinaryMessage(message);

        // Create a keypair from a private key.
        let private_key = "f74e3188e4766841600f6fd0095a0ac1c30e4c2e97b9797d7e05a28a48f5c37c";
        let bytes = hex::decode(private_key).expect("Invalid hex string for private key.");

        let signing_key = SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .expect("Invalid private key size"),
        );
        let keypair: KeyPair = KeyPair::from(signing_key);
        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::from(InitialAccountData {
            keys:      [(KeyIndex(0), keypair)].into_iter().collect(),
            threshold: SignatureThreshold::ONE,
        });

        // Add the corresponding account address from testnet associated with above
        // private key.
        let account_address =
            AccountAddress::from_str("47b6Qe2XtZANHetanWKP1PbApLKtS3AyiCtcXaqLMbypKjCaRw")
                .expect("Expect generating account address successfully");

        // Establish a connection to the node client.
        let client = v2::Client::new(
            v2::Endpoint::new("http://node.testnet.concordium.com:20000")
                .expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");

        // Generate signature.
        let account_signature = sign_as_account(
            client.clone(),
            account_address,
            keypairs,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");

        // Check that the signature is valid.
        let is_valid = verify_account_signature(
            client,
            account_address,
            account_signature,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }
}
