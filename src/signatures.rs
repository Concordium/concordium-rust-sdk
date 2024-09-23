//! Functionality for generating, and verifying account signatures.

// TODO: add function that only signs some of the keys.
// TODO: add function that signs as a singleton.
// TODO: test for binary and string signing.
use std::collections::BTreeMap;

use concordium_base::{
    common::types::Signature as Signature2,
    contracts_common::{
        to_bytes, AccountAddress, AccountSignatures, CredentialSignatures, Signature,
        SignatureEd25519,
    },
    id::types::{AccountCredentialWithoutProofs, AccountKeys, VerifyKey},
};
use sha2::Digest;

use crate::v2::{self, AccountIdentifier, IntoBlockIdentifier, QueryError};

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
}

pub enum Message<'a> {
    BinaryMessage(&'a [u8]),
    TextMessage(String),
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
pub async fn verify_account_signature(
    mut client: v2::Client,
    signer: AccountAddress,
    signatures: AccountSignatures,
    message: Message<'_>,
    bi: impl IntoBlockIdentifier,
) -> Result<bool, SignatureError> {
    let message_bytes;
    let message_signed_in_wallet = match message {
        Message::BinaryMessage(message) => message,
        Message::TextMessage(message) => {
            message_bytes = to_bytes(&message);
            &message_bytes
        }
    };

    // A message signed in the Concordium wallet is prepended with the
    // `account` address (signer) and 8 zero bytes. Accounts in the Concordium
    // wallet can either sign a regular transaction (in that case the
    // prepend is `account` address and the nonce of the account which is by
    // design >= 1) or sign a message (in that case the prepend is `account`
    // address and 8 zero bytes). Hence, the 8 zero bytes ensure that the user
    // does not accidentally sign a transaction. The account nonce is of type
    // u64 (8 bytes).
    // Add the prepend to the message and calculate the final message hash.

    let message_hash = sha2::Sha256::digest(
        [
            &signer.as_ref() as &[u8],
            &[0u8; 8],
            message_signed_in_wallet,
        ]
        .concat(),
    );

    let signer_account_info = client
        .get_account_info(&AccountIdentifier::Address(signer), bi)
        .await?;

    let signer_account_credentials = signer_account_info.response.account_credentials;

    for (credential_index, credential) in signer_account_credentials {
        match credential.value {
            AccountCredentialWithoutProofs::Initial { icdv } => {
                for (key_index, public_key) in icdv.cred_account.keys {
                    let signature = signatures
                        .sigs
                        .get(&credential_index.index)
                        .ok_or(SignatureError::MissingSignature {
                            credential_index: credential_index.index,
                            key_index:        key_index.0,
                        })?
                        .sigs
                        .get(&key_index.0)
                        .ok_or(SignatureError::MissingSignature {
                            credential_index: credential_index.index,
                            key_index:        key_index.0,
                        })?;

                    match signature {
                        Signature::Ed25519(signature) => {
                            if !public_key.verify(message_hash, &Signature2 {
                                sig: signature.0.to_vec(),
                            }) {
                                return Ok(false);
                            }
                        }
                        _ => return Ok(false),
                    }
                }
            }
            AccountCredentialWithoutProofs::Normal { cdv, .. } => {
                for (key_index, public_key) in cdv.cred_key_info.keys {
                    let signature = signatures
                        .sigs
                        .get(&credential_index.index)
                        .ok_or(SignatureError::MissingSignature {
                            credential_index: credential_index.index,
                            key_index:        key_index.0,
                        })?
                        .sigs
                        .get(&key_index.0)
                        .ok_or(SignatureError::MissingSignature {
                            credential_index: credential_index.index,
                            key_index:        key_index.0,
                        })?;

                    match signature {
                        Signature::Ed25519(signature) => {
                            if !public_key.verify(message_hash, &Signature2 {
                                sig: signature.0.to_vec(),
                            }) {
                                return Ok(false);
                            }
                        }
                        _ => return Ok(false),
                    }
                }
            }
        };
    }

    Ok(true)
}

/// Account signatures. This is an analogue of transaction signatures that are
/// part of transactions that get sent to the chain.
///
/// It should be thought of as a nested map, indexed on the outer layer by
/// credential indexes, and the inner map maps key indices to [`Signature`]s.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive-serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(transparent)]
pub struct AccountPublicKeys {
    pub keys: BTreeMap<u8, CredentialPublicKeys>,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive-serde", derive(serde::Deserialize, serde::Serialize))]
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

pub fn verify_account_signature_unchecked(
    signer: AccountAddress,
    signatures: AccountSignatures,
    public_keys: AccountPublicKeys,
    message: Message<'_>,
) -> Result<bool, SignatureError> {
    let message_bytes;
    let message_signed_in_wallet = match message {
        Message::BinaryMessage(message) => message,
        Message::TextMessage(message) => {
            message_bytes = to_bytes(&message);
            &message_bytes
        }
    };

    // A message signed in the Concordium wallet is prepended with the
    // `account` address (signer) and 8 zero bytes. Accounts in the Concordium
    // wallet can either sign a regular transaction (in that case the
    // prepend is `account` address and the nonce of the account which is by
    // design >= 1) or sign a message (in that case the prepend is `account`
    // address and 8 zero bytes). Hence, the 8 zero bytes ensure that the user
    // does not accidentally sign a transaction. The account nonce is of type
    // u64 (8 bytes).
    // Add the prepend to the message and calculate the final message hash.

    let message_hash = sha2::Sha256::digest(
        [
            &signer.as_ref() as &[u8],
            &[0u8; 8],
            message_signed_in_wallet,
        ]
        .concat(),
    );

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

            match signature {
                Signature::Ed25519(signature) => {
                    if !public_key.verify(message_hash, &Signature2 {
                        sig: signature.0.to_vec(),
                    }) {
                        return Ok(false);
                    }
                }
                _ => return Ok(false),
            }
        }
    }

    Ok(true)
}

pub fn sign_as_account_unchecked(
    signer: AccountAddress,
    account_keys: AccountKeys,
    message: Message<'_>,
) -> Result<AccountSignatures, SignatureError> {
    let message_bytes;
    let message_signed_in_wallet = match message {
        Message::BinaryMessage(message) => message,
        Message::TextMessage(message) => {
            message_bytes = to_bytes(&message);
            &message_bytes
        }
    };

    // A message signed in the Concordium wallet is prepended with the
    // `account` address (signer) and 8 zero bytes. Accounts in the Concordium
    // wallet can either sign a regular transaction (in that case the
    // prepend is `account` address and the nonce of the account which is by
    // design >= 1) or sign a message (in that case the prepend is `account`
    // address and 8 zero bytes). Hence, the 8 zero bytes ensure that the user
    // does not accidentally sign a transaction. The account nonce is of type
    // u64 (8 bytes).
    // Add the prepend to the message and calculate the final message hash.

    let message_hash = sha2::Sha256::digest(
        [
            &signer.as_ref() as &[u8],
            &[0u8; 8],
            message_signed_in_wallet,
        ]
        .concat(),
    );
    let mut account_signatures = AccountSignatures {
        sigs: BTreeMap::new(),
    };

    for (credential_index, credential) in account_keys.keys {
        for (key_index, public_key) in credential.keys {
            let signature = public_key.sign(&message_hash);

            account_signatures
                .sigs
                .entry(credential_index.index)
                .or_insert_with(|| CredentialSignatures {
                    sigs: BTreeMap::new(),
                })
                .sigs
                .insert(
                    key_index.0,
                    Signature::Ed25519(SignatureEd25519(signature.into())),
                );
        }
    }

    Ok(account_signatures)
}
