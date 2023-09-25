//! This module contains types and functions for interacting with smart
//! contracts following the [CIS-4](https://proposals.concordium.software/CIS/cis-4.html) specification.
//!
//! The type [`Cis4Contract`](crate::cis4::Cis4Contract) acts as a wrapper
//! around the [Client](crate::v2::Client) and a contract address providing
//! functions for querying and making transactions to smart contract.

use crate::{
    contract_client::*,
    types::{transactions, RejectReason},
    v2::IntoBlockIdentifier,
};
pub use concordium_base::{cis2_types::MetadataUrl, cis4_types::*};
use concordium_base::{
    constants::MAX_PARAMETER_LEN,
    contracts_common,
    hashes::TransactionHash,
    smart_contracts::{ExceedsParameterSize, OwnedParameter},
    transactions::{AccountTransaction, EncodedPayload},
    web3id::{CredentialHolderId, Web3IdSigner, REVOKE_DOMAIN_STRING},
};

#[derive(thiserror::Error, Debug)]
/// An error that can occur when executing CIS4 queries.
pub enum Cis4QueryError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] contracts_common::NewReceiveNameError),

    /// A general RPC error occurred.
    #[error("RPC error: {0}")]
    RPCError(#[from] super::v2::QueryError),

    /// The data returned from q query could not be parsed.
    #[error("Failed parsing the response.")]
    ResponseParseError(#[from] contracts_common::ParseError),

    /// The node rejected the invocation.
    #[error("Rejected by the node: {0:?}.")]
    NodeRejected(crate::types::RejectReason),
}

impl From<RejectReason> for Cis4QueryError {
    fn from(value: RejectReason) -> Self { Self::NodeRejected(value) }
}

impl Cis4QueryError {
    /// Check if the error variant is a logic error, i.e., the query
    /// was received by the node which attempted to execute it, and it failed.
    /// If so, extract the reason for execution failure.
    pub fn is_contract_error(&self) -> Option<&crate::types::RejectReason> {
        if let Self::NodeRejected(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

#[derive(thiserror::Error, Debug)]
/// An error that can occur when sending CIS4 update transactions.
pub enum Cis4TransactionError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] contracts_common::NewReceiveNameError),

    /// The parameter is too large.
    #[error("Parameter is too large: {0}")]
    InvalidParams(#[from] ExceedsParameterSize),

    /// A general RPC error occurred.
    #[error("RPC error: {0}")]
    RPCError(#[from] super::v2::RPCError),

    /// The node rejected the invocation.
    #[error("Rejected by the node: {0:?}.")]
    NodeRejected(crate::types::RejectReason),
}

/// Transaction metadata for CIS-4 update transactions.
pub type Cis4TransactionMetadata = ContractTransactionMetadata;

#[derive(Debug, Clone, Copy)]
/// A marker type to indicate that a [`ContractClient`] is a client for a `CIS4`
/// contract.
pub enum Cis4Type {}

/// A wrapper around the client representing a CIS4 credential registry smart
/// contract.
///
/// Note that cloning is cheap and is, therefore, the intended way of sharing
/// this type between multiple tasks.
///
/// See also [`ContractClient`] for generic methods available for any contract.
pub type Cis4Contract = ContractClient<Cis4Type>;

impl Cis4Contract {
    /// Look up an entry in the registry by its id.
    pub async fn credential_entry(
        &mut self,
        cred_id: CredentialHolderId,
        bi: impl IntoBlockIdentifier,
    ) -> Result<CredentialEntry, Cis4QueryError> {
        let parameter =
            OwnedParameter::from_serial(&cred_id).expect("Credential ID is a valid parameter.");

        self.view_raw("credentialEntry", parameter, bi).await
    }

    /// Look up the status of a credential by its id.
    pub async fn credential_status(
        &mut self,
        cred_id: CredentialHolderId,
        bi: impl IntoBlockIdentifier,
    ) -> Result<CredentialStatus, Cis4QueryError> {
        let parameter =
            OwnedParameter::from_serial(&cred_id).expect("Credential ID is a valid parameter.");

        self.view_raw("credentialStatus", parameter, bi).await
    }

    /// Get the list of all the revocation keys together with their nonces.
    pub async fn revocation_keys(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> Result<Vec<RevocationKeyWithNonce>, Cis4QueryError> {
        let parameter = OwnedParameter::empty();

        self.view_raw("revocationKeys", parameter, bi).await
    }

    /// Look up the credential registry's metadata.
    pub async fn registry_metadata(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> Result<RegistryMetadata, Cis4QueryError> {
        let parameter = OwnedParameter::empty();
        self.view_raw("registryMetadata", parameter, bi).await
    }

    /// Look up the issuer's public key.
    pub async fn issuer(
        &mut self,
        bi: impl IntoBlockIdentifier,
    ) -> Result<IssuerKey, Cis4QueryError> {
        let parameter = OwnedParameter::empty();

        self.view_raw("issuer", parameter, bi).await
    }

    /// Construct a transaction for registering a new credential.
    /// Note that this **does not** send the transaction.c
    pub fn make_register_credential(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        cred_info: &CredentialInfo,
        additional_data: &[u8],
    ) -> Result<AccountTransaction<EncodedPayload>, Cis4TransactionError> {
        use contracts_common::Serial;
        let mut payload = contracts_common::to_bytes(cred_info);
        let actual = payload.len() + additional_data.len() + 2;
        if payload.len() + additional_data.len() + 2 > MAX_PARAMETER_LEN {
            return Err(Cis4TransactionError::InvalidParams(ExceedsParameterSize {
                actual,
                max: MAX_PARAMETER_LEN,
            }));
        }
        (additional_data.len() as u16)
            .serial(&mut payload)
            .expect("We checked lengths above, so this must succeed.");
        payload.extend_from_slice(additional_data);
        let parameter = OwnedParameter::try_from(payload)?;
        self.make_update_raw(signer, metadata, "registerCredential", parameter)
    }

    /// Register a new credential.
    pub async fn register_credential(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        cred_info: &CredentialInfo,
        additional_data: &[u8],
    ) -> Result<TransactionHash, Cis4TransactionError> {
        let tx = self.make_register_credential(signer, metadata, cred_info, additional_data)?;
        let hash = self.client.send_account_transaction(tx).await?;
        Ok(hash)
    }

    /// Construct a transaction to revoke a credential as an issuer.
    pub fn make_revoke_credential_as_issuer(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        cred_id: CredentialHolderId,
        reason: Option<Reason>,
    ) -> Result<AccountTransaction<EncodedPayload>, Cis4TransactionError> {
        let parameter = OwnedParameter::from_serial(&(cred_id, reason))?;

        self.make_update_raw(signer, metadata, "revokeCredentialIssuer", parameter)
    }

    /// Revoke a credential as an issuer.
    pub async fn revoke_credential_as_issuer(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        cred_id: CredentialHolderId,
        reason: Option<Reason>,
    ) -> Result<TransactionHash, Cis4TransactionError> {
        let tx = self.make_revoke_credential_as_issuer(signer, metadata, cred_id, reason)?;
        let hash = self.client.send_account_transaction(tx).await?;
        Ok(hash)
    }

    /// Revoke a credential as the holder.
    ///
    /// The extra nonce that must be provided is the holder's nonce inside the
    /// contract. The signature on this revocation message is set to expire at
    /// the same time as the transaction.
    pub async fn revoke_credential_as_holder(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        web3signer: impl Web3IdSigner, // the holder
        nonce: u64,
        reason: Option<Reason>,
    ) -> Result<TransactionHash, Cis4TransactionError> {
        let tx =
            self.make_revoke_credential_as_holder(signer, metadata, web3signer, nonce, reason)?;
        let hash = self.client.send_account_transaction(tx).await?;
        Ok(hash)
    }

    /// Revoke a credential as the holder.
    ///
    /// The extra nonce that must be provided is the holder's nonce inside the
    /// contract. The signature on this revocation message is set to expire at
    /// the same time as the transaction.
    pub fn make_revoke_credential_as_holder(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        web3signer: impl Web3IdSigner, // the holder
        nonce: u64,
        reason: Option<Reason>,
    ) -> Result<AccountTransaction<EncodedPayload>, Cis4TransactionError> {
        use contracts_common::Serial;
        let mut to_sign = REVOKE_DOMAIN_STRING.to_vec();
        let cred_id: CredentialHolderId = web3signer.id().into();
        cred_id
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        self.address
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        nonce
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        metadata
            .expiry
            .seconds
            .checked_mul(1000)
            .unwrap_or(u64::MAX)
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        reason
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        let sig = web3signer.sign(&to_sign);
        let mut parameter_vec = sig.to_bytes().to_vec();
        parameter_vec.extend_from_slice(&to_sign[REVOKE_DOMAIN_STRING.len()..]);
        let parameter = OwnedParameter::try_from(parameter_vec)?;

        self.make_update_raw(signer, metadata, "revokeCredentialHolder", parameter)
    }

    /// Revoke a credential as another party, distinct from issuer or holder.
    ///
    /// The extra nonce that must be provided is the nonce associated with the
    /// key that signs the revocation message.
    /// The signature on this revocation message is set to expire at
    /// the same time as the transaction.
    pub async fn revoke_credential_other(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        revoker: impl Web3IdSigner, // the revoker.
        nonce: u64,
        cred_id: CredentialHolderId,
        reason: Option<&Reason>,
    ) -> Result<TransactionHash, Cis4TransactionError> {
        let tx =
            self.make_revoke_credential_other(signer, metadata, revoker, nonce, cred_id, reason)?;
        let hash = self.client.send_account_transaction(tx).await?;
        Ok(hash)
    }

    /// Construct a transaction to revoke a credential as another party,
    /// distinct from issuer or holder.
    ///
    /// The extra nonce that must be provided is the nonce associated with the
    /// key that signs the revocation message.
    /// The signature on this revocation message is set to expire at
    /// the same time as the transaction.
    pub fn make_revoke_credential_other(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        revoker: impl Web3IdSigner, // the revoker.
        nonce: u64,
        cred_id: CredentialHolderId,
        reason: Option<&Reason>,
    ) -> Result<AccountTransaction<EncodedPayload>, Cis4TransactionError> {
        use contracts_common::Serial;
        let mut to_sign = REVOKE_DOMAIN_STRING.to_vec();
        cred_id
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        self.address
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        nonce
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        metadata
            .expiry
            .seconds
            .checked_mul(1000)
            .unwrap_or(u64::MAX)
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        RevocationKey::from(revoker.id())
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        reason
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        let sig = revoker.sign(&to_sign);
        let mut parameter_vec = sig.to_bytes().to_vec();
        parameter_vec.extend_from_slice(&to_sign[REVOKE_DOMAIN_STRING.len()..]);
        let parameter = OwnedParameter::try_from(parameter_vec)?;

        self.make_update_raw(signer, metadata, "revokeCredentialOther", parameter)
    }
}
