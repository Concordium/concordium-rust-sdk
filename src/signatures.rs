//! Functionality for generating, and verifying account signatures.

use concordium_base::{
    common::types::Signature,
    contracts_common::{to_bytes, AccountAddress},
    id::types::AccountCredentialWithoutProofs,
};
use sha2::Digest;

use crate::v2::{self, AccountIdentifier, IntoBlockIdentifier, QueryError};

#[derive(thiserror::Error, Debug)]
/// An error that can be used as the error for the
/// [`view`](ContractClient::view) family of functions.
pub enum SignatureError {
    #[error("Network error: {0}")]
    QueryError(#[from] QueryError),
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
    // TODO: add signature map 'AccountTransactionSignature'
    signature: Signature,
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
        .await
        .map_err(SignatureError::QueryError)?;

    let signer_account_credentials = signer_account_info.response.account_credentials;

    for (.., credential) in signer_account_credentials {
        match credential.value {
            AccountCredentialWithoutProofs::Initial { icdv } => {
                for (.., public_key) in icdv.cred_account.keys {
                    if !public_key.verify(message_hash, &signature) {
                        return Ok(false);
                    }
                }
            }
            AccountCredentialWithoutProofs::Normal { cdv, .. } => {
                for (_, public_key) in cdv.cred_key_info.keys {
                    if !public_key.verify(message_hash, &signature) {
                        return Ok(false);
                    }
                }
            }
        };
    }

    Ok(true)
}
