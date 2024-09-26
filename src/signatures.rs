//! Functionality for generating, and verifying account signatures.
// TODO: test for binary and string signing with external repo.
// TODO: test for binary and string signing checked with external repo.
// TODO: check account with several keys.
use crate::v2::{self, AccountIdentifier, BlockIdentifier, IntoBlockIdentifier, QueryError};
use concordium_base::{
    common::{
        types::{CredentialIndex, KeyIndex, KeyPair, Signature},
        Versioned,
    },
    contracts_common::{to_bytes, AccountAddress, SignatureThreshold},
    curve_arithmetic::Curve,
    id::types::{
        AccountCredentialWithoutProofs, AccountKeys, Attribute, InitialAccountData,
        PublicCredentialData, VerifyKey,
    },
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Digest;
use std::collections::BTreeMap;

#[derive(thiserror::Error, Debug)]
/// An error that can be used as the error for the
/// [`view`](ContractClient::view) family of functions.
pub enum SignatureError {
    #[error("Network error: {0}")]
    QueryError(#[from] QueryError),
    #[error(
        "Key indexes do not exist on chain (credential index: `{credential_index}`, key index: \
         `{key_index}`)"
    )]
    MissingKeyIndexesOnChain {
        credential_index: u8,
        key_index:        u8,
    },
    #[error("The indexes in the maps do not match")]
    MismatchMapIndexes,
    #[error("The public key and private key do not match")]
    MismatchPublicPrivateKeys,
    #[error(
        "The public key on chain `{expected_public_key:?}` and the public key \
         `{actual_public_key:?}` in the signature map do not match for credential index \
         `{credential_index}` and key index `{key_index}`"
    )]
    MismatchPublicKeyOnChain {
        credential_index:    u8,
        key_index:           u8,
        expected_public_key: Box<VerifyingKey>,
        actual_public_key:   Box<VerifyingKey>,
    },
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

/// Account signatures. This is an analogue of transaction signatures that are
/// part of transactions that get sent to the chain.
///
/// It should be thought of as a nested map, indexed on the outer layer by
/// credential indexes, and the inner map maps key indices to [`Signature`]s.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct AccountSignaturesVerificationData {
    pub data: BTreeMap<u8, CredentialSignaturesVerificationData>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
pub struct CredentialSignaturesVerificationData {
    pub data: BTreeMap<u8, AccountSignaturesVerificationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AccountSignaturesVerificationEntry {
    pub signature:  Signature,
    pub public_key: VerifyKey,
}

impl AccountSignaturesVerificationData {
    pub fn singleton(signature: Signature, public_key: VerifyKey) -> Self {
        let credential_map = CredentialSignaturesVerificationData {
            data: [(0, AccountSignaturesVerificationEntry {
                signature,
                public_key,
            })]
            .into_iter()
            .collect(),
        };

        AccountSignaturesVerificationData {
            data: [(0, credential_map)].into_iter().collect(),
        }
    }

    pub fn zip_signatures_and_keys(
        account_signatures: &AccountSignatures,
        account_keys: &AccountKeys,
    ) -> Result<Self, SignatureError> {
        let mut outer_map = BTreeMap::new();

        for (&outer_key, credential_sigs) in &account_signatures.sigs {
            // Check if corresponding account key exists
            if let Some(account_key_pair) =
                account_keys.keys.get(&CredentialIndex { index: outer_key })
            {
                let public_keys = account_key_pair.get_public_keys();

                // Create the inner map
                let inner_map: Result<
                    BTreeMap<u8, AccountSignaturesVerificationEntry>,
                    SignatureError,
                > = credential_sigs
                    .sigs
                    .iter()
                    .zip(public_keys.iter())
                    .map(|((&inner_key, signature), (key_index, public_key))| {
                        // Ensure that inner_key and key_index match
                        if inner_key != key_index.0 {
                            return Err(SignatureError::MismatchMapIndexes);
                        }
                        Ok((inner_key, AccountSignaturesVerificationEntry {
                            signature:  signature.clone(),
                            public_key: public_key.clone(),
                        }))
                    })
                    .collect();

                outer_map.insert(outer_key, CredentialSignaturesVerificationData {
                    data: inner_map?,
                });
            } else {
                return Err(SignatureError::MismatchMapIndexes);
            }
        }

        Ok(AccountSignaturesVerificationData { data: outer_map })
    }
}

pub fn calculate_message_hash(message: &Message<'_>, signer: AccountAddress) -> [u8; 32] {
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
    sha2::Sha256::digest(
        [
            &signer.as_ref() as &[u8],
            &[0u8; 8],
            message_signed_in_wallet,
        ]
        .concat(),
    )
    .into()
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
    // Ensure all top-level keys in signatures exist in the on_chain_credentials map
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
    signatures: &AccountSignatures,
    message: &Message<'_>,
    bi: impl IntoBlockIdentifier,
) -> Result<bool, SignatureError> {
    let message_hash = calculate_message_hash(message, signer);

    let signer_account_info = client
        .get_account_info(&AccountIdentifier::Address(signer), bi)
        .await?;

    let signer_account_credentials = signer_account_info.response.account_credentials;
    let credential_signatures_threshold = signer_account_info.response.account_threshold;

    if !exist_signature_map_keys_on_chain(signatures, &signer_account_credentials) {
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
        &AccountSignatures::singleton(signature),
        message,
        bi,
    )
    .await
}

// No check is done if that account exists on chain or if the thresholds on
// chain are followed.
pub fn verify_account_signature_unchecked(
    signer: AccountAddress,
    signature_data: AccountSignaturesVerificationData,
    message: &Message<'_>,
) -> Result<bool, SignatureError> {
    let message_hash = calculate_message_hash(message, signer);

    for (_, credential) in signature_data.data {
        for (
            _,
            AccountSignaturesVerificationEntry {
                signature,
                public_key,
            },
        ) in credential.data
        {
            if !public_key.verify(message_hash, &signature) {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

pub fn verify_single_account_signature_unchecked(
    signer: AccountAddress,
    signature: Signature,
    public_key: VerifyKey,
    message: &Message<'_>,
) -> Result<bool, SignatureError> {
    verify_account_signature_unchecked(
        signer,
        AccountSignaturesVerificationData::singleton(signature, public_key),
        message,
    )
}

pub async fn sign_as_account(
    mut client: v2::Client,
    signer: AccountAddress,
    account_keys: AccountKeys,
    message: &Message<'_>,
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
                .ok_or(SignatureError::MissingKeyIndexesOnChain {
                    credential_index: credential_index.index,
                    key_index:        key_index.0,
                })?
                .value;

            let on_chain_keys = match on_chain_credential {
                AccountCredentialWithoutProofs::Initial { icdv } => &icdv.cred_account.keys,
                AccountCredentialWithoutProofs::Normal { cdv, .. } => &cdv.cred_key_info.keys,
            };

            let on_chain_public_key =
                on_chain_keys
                    .get(&key_index)
                    .ok_or(SignatureError::MissingKeyIndexesOnChain {
                        credential_index: credential_index.index,
                        key_index:        key_index.0,
                    })?;

            let VerifyKey::Ed25519VerifyKey(verifying_key) = *on_chain_public_key;

            if signing_key.public() != verifying_key {
                return Err(SignatureError::MismatchPublicKeyOnChain {
                    credential_index:    credential_index.index,
                    key_index:           key_index.0,
                    expected_public_key: Box::new(verifying_key),
                    actual_public_key:   Box::new(signing_key.public()),
                });
            };

            let signature = signing_key.sign(&message_hash);

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

    // Check that the signatures are valid to ensure
    // that public and private keys in the `account_keys` map match.
    let is_valid = verify_account_signature(client, signer, &account_signatures, message, bi)
        .await
        .map_err(|_| SignatureError::MismatchPublicPrivateKeys)?;

    if is_valid {
        Ok(account_signatures)
    } else {
        Err(SignatureError::MismatchPublicPrivateKeys)
    }
}

pub async fn sign_as_single_signer_account(
    client: v2::Client,
    signer: AccountAddress,
    signing_key: SigningKey,
    message: &Message<'_>,
    bi: BlockIdentifier,
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
    account_keys: &AccountKeys,
    message: &Message<'_>,
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
    let signature = sign_as_account_unchecked(signer, &keypairs, message);
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

    const NODE_URL: &str = "http://node.testnet.concordium.com:20000";

    #[test]
    fn test_serde_account_signatures_verification_data() {
        let rng = &mut rand::thread_rng();

        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::singleton(rng);
        // Get public key from map.
        let credential_keys = &keypairs.keys[&CredentialIndex { index: 0 }];
        let key_pair = &credential_keys.keys[&KeyIndex(0)];
        let public_key = key_pair.public().into();

        // Generate a signature.
        let signature = Signature::from(ed25519_dalek::Signature::from_bytes(&[0u8; 64]));

        // Create AccountSignaturesVerificationData type.
        let account_signatures_verification_data =
            AccountSignaturesVerificationData::singleton(signature, public_key);

        // Check that the serialization and deserialization works.
        let serialized = serde_json::to_string(&account_signatures_verification_data)
            .expect("Failed to serialize account_signatures_verification_data");
        let deserialized: AccountSignaturesVerificationData = serde_json::from_str(&serialized)
            .expect("Failed to deserialize account_signatures_verification_data");
        assert_eq!(account_signatures_verification_data, deserialized);
    }

    #[test]
    fn test_serde_account_signatures() {
        // Create AccountSignatures type.
        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&[0u8; 64]);
        let account_signatures = AccountSignatures::singleton(Signature::from(ed25519_signature));

        // Check that the serialization and deserialization works.
        let serialized = serde_json::to_string(&account_signatures)
            .expect("Failed to serialize account_signatures");
        let deserialized: AccountSignatures =
            serde_json::from_str(&serialized).expect("Failed to deserialize account_signatures");
        assert_eq!(account_signatures, deserialized);
    }

    // We test signing and verifying of a text messages here. We use the `unchecked`
    // version of the functions.
    #[test]
    fn test_sign_and_verify_text_message_unchecked() {
        // Create a message to sign.
        let message: &str = "test";
        let text_message = &Message::TextMessage(message);

        let rng = &mut rand::thread_rng();

        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::singleton(rng);

        // Create an account address.
        let account_address = AccountAddress([0u8; 32]);

        // Generate signature.
        let account_signature = sign_as_account_unchecked(account_address, &keypairs, text_message);

        let account_signatures_verification_data =
            AccountSignaturesVerificationData::zip_signatures_and_keys(
                &account_signature,
                &keypairs,
            )
            .expect("Expect zipping of maps to succeed");

        // Check that the signature is valid.
        let is_valid = verify_account_signature_unchecked(
            account_address,
            account_signatures_verification_data,
            text_message,
        )
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    // We test signing and verifying of a text messages here. We use the `unchecked`
    // and `single` version of the functions.
    #[test]
    fn test_sign_and_verify_text_message_unchecked_single() {
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
        let single_account_signature = sign_as_single_signer_account_unchecked(
            account_address,
            single_key.into(),
            text_message,
        )
        .expect("Expect signing to succeed");

        // Check that the signature is valid.
        let is_valid = verify_single_account_signature_unchecked(
            account_address,
            single_account_signature,
            public_key.into(),
            text_message,
        )
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    // We test signing and verifying of a text messages here. We use the `checked`
    // version of the functions.
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

        // Add the corresponding account address from testnet associated with above
        // private key.
        let account_address =
            AccountAddress::from_str("47b6Qe2XtZANHetanWKP1PbApLKtS3AyiCtcXaqLMbypKjCaRw")
                .expect("Expect generating account address successfully");

        // Establish a connection to the node client.
        let client = v2::Client::new(
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
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

        // Check that the signature is valid.
        let is_valid = verify_account_signature(
            client.clone(),
            account_address,
            &account_signature,
            text_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    // We test signing and verifying of a text messages here. We use the `checked`
    // and `single` version of the functions.
    #[tokio::test]
    async fn test_sign_and_verify_text_message_checked_single() {
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
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");

        // Generate signature.
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

    // We test signing and verifying of a binary messages here. We use the
    // `unchecked` version of the functions.
    #[test]
    fn test_sign_and_verify_binary_message_unchecked() {
        // Create a message to sign.
        let message: &[u8] = b"test";
        let binary_message = &Message::BinaryMessage(message);

        let rng = &mut rand::thread_rng();

        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::singleton(rng);

        // Create an account address.
        let account_address = AccountAddress([0u8; 32]);

        // Generate signature.
        let account_signature =
            sign_as_account_unchecked(account_address, &keypairs, binary_message);

        let account_signatures_verification_data =
            AccountSignaturesVerificationData::zip_signatures_and_keys(
                &account_signature,
                &keypairs,
            )
            .expect("Expect zipping of maps to succeed");

        // Check that the signature is valid.
        let is_valid = verify_account_signature_unchecked(
            account_address,
            account_signatures_verification_data,
            binary_message,
        )
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    // We test signing and verifying of a binary messages here. We use the
    // `unchecked` and `single` version of the functions.
    #[test]
    fn test_sign_and_verify_binary_message_unchecked_single() {
        // Create a message to sign.
        let message: &[u8] = b"test";
        let binary_message = &Message::BinaryMessage(message);

        let rng = &mut rand::thread_rng();

        // Generate account keys that have one keypair at index 0 in both maps.
        let keypairs = AccountKeys::singleton(rng);
        let single_key = keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)].clone();

        // Create an account address.
        let account_address = AccountAddress([0u8; 32]);

        // Generate signature.
        let single_account_signature = sign_as_single_signer_account_unchecked(
            account_address,
            single_key.clone().into(),
            binary_message,
        )
        .expect("Expect signing to succeed");

        // Check that the signature is valid.
        let is_valid = verify_single_account_signature_unchecked(
            account_address,
            single_account_signature,
            single_key.public().into(),
            binary_message,
        )
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    // We test signing and verifying of a binary messages here. We use the `checked`
    // version of the functions.
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
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
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
            &account_signature,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }

    // We test signing and verifying of a binary messages here. We use the `checked`
    // and `single` version of the functions.
    #[tokio::test]
    async fn test_sign_and_verify_binary_message_checked_single() {
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
        let single_key = keypairs.keys[&CredentialIndex { index: 0 }].keys[&KeyIndex(0)].clone();

        // Add the corresponding account address from testnet associated with above
        // private key.
        let account_address =
            AccountAddress::from_str("47b6Qe2XtZANHetanWKP1PbApLKtS3AyiCtcXaqLMbypKjCaRw")
                .expect("Expect generating account address successfully");

        // Establish a connection to the node client.
        let client = v2::Client::new(
            v2::Endpoint::new(NODE_URL).expect("Expect generating endpoint successfully"),
        )
        .await
        .expect("Expect generating node client successfully");

        // Generate signature.
        let single_account_signature = sign_as_single_signer_account(
            client.clone(),
            account_address,
            single_key.clone().into(),
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect signing to succeed");

        // Check that the signature is valid.
        let is_valid = verify_single_account_signature(
            client,
            account_address,
            single_account_signature,
            binary_message,
            BlockIdentifier::Best,
        )
        .await
        .expect("Expect verification to succeed");
        assert_eq!(is_valid, true);
    }
}
