use crate::{
    types::{
        smart_contracts::{self, ContractContext},
        transactions,
    },
    v2::{BlockIdentifier, Client},
};
use concordium_base::{
    base::Nonce,
    common::types,
    contracts_common::{self, AccountAddress, Amount, ContractAddress},
    hashes::TransactionHash,
    smart_contracts::{ExceedsParameterSize, OwnedParameter, OwnedReceiveName},
    transactions::UpdateContractPayload,
    web3id::Web3IdSigner,
};
pub use concordium_base::{cis2_types::MetadataUrl, cis4_types::*};
use std::sync::Arc;

pub struct Cis4Contract {
    client:        Client,
    address:       ContractAddress,
    contract_name: Arc<contracts_common::OwnedContractName>,
}

#[derive(thiserror::Error, Debug)]
pub enum Cis4QueryError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] contracts_common::NewReceiveNameError),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] super::v2::QueryError),

    /// The data returned from q query could not be parsed.
    #[error("Failed parsing the response.")]
    ResponseParseError(#[from] contracts_common::ParseError),

    /// The node rejected the invocation.
    #[error("Rejected by the node: {0:?}.")]
    NodeRejected(crate::types::RejectReason),
}

#[derive(thiserror::Error, Debug)]
pub enum Cis4TransactionError {
    /// The smart contract receive name is invalid.
    #[error("Invalid receive name: {0}")]
    InvalidReceiveName(#[from] contracts_common::NewReceiveNameError),

    /// The parameter is too large.
    #[error("Parameter is too large: {0}")]
    InvalidParams(#[from] ExceedsParameterSize),

    /// A general RPC error occured.
    #[error("RPC error: {0}")]
    RPCError(#[from] super::v2::RPCError),

    /// The node rejected the invocation.
    #[error("Rejected by the node: {0:?}.")]
    NodeRejected(crate::types::RejectReason),
}

/// Transaction metadata for CIS-4
#[derive(Debug, Clone, Copy)]
pub struct Cis4TransactionMetadata {
    /// The account address sending the transaction.
    pub sender_address: AccountAddress,
    /// The nonce to use for the transaction.
    pub nonce:          Nonce,
    /// Expiry date of the transaction.
    pub expiry:         types::TransactionTime,
    /// The limit on energy to use for the transaction.
    pub energy:         transactions::send::GivenEnergy,
    /// The amount of CCD to include in the transaction.
    pub amount:         types::Amount,
}

impl Cis4Contract {
    /// Construct a Cis4Contract.
    ///
    /// # Arguments
    ///
    /// * `client` - The RPC client for the concordium node. Note that cloning
    ///   [`Client`] is cheap and is therefore the intended way of sharing.
    /// * `address` - The contract address of the CIS4 registry smart contract.
    /// * `contract_name` - The name of the contract.
    pub fn new(
        client: Client,
        address: ContractAddress,
        contract_name: contracts_common::OwnedContractName,
    ) -> Cis4Contract {
        Cis4Contract {
            client,
            address,
            contract_name: Arc::new(contract_name),
        }
    }

    /// Look up an entry in the registry by id.
    pub async fn credential_entry(
        &mut self,
        cred_id: CredentialId,
    ) -> Result<CredentialQueryResponse, Cis4QueryError> {
        let parameter =
            OwnedParameter::from_serial(&cred_id).expect("Credential ID is a valid parameter.");

        self.make_query("credentialEntry", parameter).await
    }

    /// Look up the status of a credential by its id.
    pub async fn credential_status(
        &mut self,
        cred_id: CredentialId,
    ) -> Result<CredentialStatus, Cis4QueryError> {
        let parameter =
            OwnedParameter::from_serial(&cred_id).expect("Credential ID is a valid parameter.");

        self.make_query("credentialStatus", parameter).await
    }

    /// Get the list of all the revocation keys together with their nonces.
    pub async fn revocation_keys(&mut self) -> Result<Vec<RevocationKeyWithNonce>, Cis4QueryError> {
        let parameter = OwnedParameter::empty();

        self.make_query("revocationKeys", parameter).await
    }

    /// Look up all the issuer keys.
    pub async fn issuer_keys(&mut self) -> Result<Vec<IssuerKey>, Cis4QueryError> {
        let parameter = OwnedParameter::empty();

        self.make_query("issuerKeys", parameter).await
    }

    /// Look up the issuer's metadata URL.
    pub async fn issuer_metadata(&mut self) -> Result<MetadataUrl, Cis4QueryError> {
        let parameter = OwnedParameter::empty();
        self.make_query("issuerMetadata", parameter).await
    }

    /// Look up the issuer's account address.
    pub async fn issuer_address(&mut self) -> Result<AccountAddress, Cis4QueryError> {
        let parameter = OwnedParameter::empty();

        self.make_query("issuer", parameter).await
    }

    /// Register a new credential.
    pub async fn register_credential(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        cred_id: CredentialId,
        cred_info: &CredentialInfo,
    ) -> Result<TransactionHash, Cis4TransactionError> {
        let parameter = OwnedParameter::from_serial(&(cred_id, cred_info))?;

        self.make_call(signer, metadata, "registerCredential", parameter)
            .await
    }

    /// Revoke a credential as an issuer.
    pub async fn revoke_credential_as_issuer(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        cred_id: CredentialId,
        reason: Option<Reason>,
    ) -> Result<TransactionHash, Cis4TransactionError> {
        let parameter = OwnedParameter::from_serial(&(cred_id, reason))?;

        self.make_call(signer, metadata, "revokeCredentialIssuer", parameter)
            .await
    }

    /// Revoke a credential as an issuer.
    ///
    /// The extra nonce that must be provided is the owner's nonce inside the
    /// contract. The signature on this revocation message is set to expire at
    /// the same time as the transaction.
    pub async fn revoke_credential_as_holder(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        web3signer: impl Web3IdSigner,
        nonce: u64,
        cred_id: CredentialId,
        reason: Option<Reason>,
    ) -> Result<TransactionHash, Cis4TransactionError> {
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
        reason
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        let sig = web3signer.sign(&to_sign);
        let mut parameter_vec = sig.to_bytes().to_vec();
        parameter_vec.extend_from_slice(&to_sign[REVOKE_DOMAIN_STRING.len()..]);
        let parameter = OwnedParameter::try_from(parameter_vec)?;

        self.make_call(signer, metadata, "revokeCredentialHolder", parameter)
            .await
    }

    /// Revoke a credential as a revoker.
    ///
    /// The extra nonce that must be provided is the owner's nonce inside the
    /// contract. The signature on this revocation message is set to expire at
    /// the same time as the transaction.
    pub async fn revoke_credential_as_revoker(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        web3signer: impl Web3IdSigner, // the revoker.
        nonce: u64,
        key: RevocationKey,
        cred_id: CredentialId,
        reason: Option<Reason>,
    ) -> Result<TransactionHash, Cis4TransactionError> {
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
        key.serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        reason
            .serial(&mut to_sign)
            .expect("Serialization to vector does not fail.");
        let sig = web3signer.sign(&to_sign);
        let mut parameter_vec = sig.to_bytes().to_vec();
        parameter_vec.extend_from_slice(&to_sign[REVOKE_DOMAIN_STRING.len()..]);
        let parameter = OwnedParameter::try_from(parameter_vec)?;

        self.make_call(signer, metadata, "revokeCredentialHolder", parameter)
            .await
    }

    async fn make_query<A: contracts_common::Deserial>(
        &mut self,
        entrypoint: &str,
        parameter: OwnedParameter,
    ) -> Result<A, Cis4QueryError> {
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let method = OwnedReceiveName::try_from(format!("{contract_name}.{entrypoint}"))?;

        let context = ContractContext {
            invoker: None,
            contract: self.address,
            amount: Amount::zero(),
            method,
            parameter,
            energy: 1_000_000.into(),
        };

        let invoke_result = self
            .client
            .invoke_instance(BlockIdentifier::LastFinal, &context)
            .await?
            .response;
        process_response(invoke_result)
    }

    async fn make_call(
        &mut self,
        signer: &impl transactions::ExactSizeTransactionSigner,
        metadata: &Cis4TransactionMetadata,
        entrypoint: &str,
        message: OwnedParameter,
    ) -> Result<TransactionHash, Cis4TransactionError> {
        let contract_name = self.contract_name.as_contract_name().contract_name();
        let receive_name = OwnedReceiveName::try_from(format!("{contract_name}.{entrypoint}"))?;

        let payload = UpdateContractPayload {
            amount: Amount::zero(),
            address: self.address,
            receive_name,
            message,
        };

        let tx = transactions::send::make_and_sign_transaction(
            signer,
            metadata.sender_address,
            metadata.nonce,
            metadata.expiry,
            metadata.energy,
            transactions::Payload::Update { payload },
        );

        let hash = self.client.send_account_transaction(tx).await?;
        Ok(hash)
    }
}

fn process_response<A: contracts_common::Deserial>(
    response: smart_contracts::InvokeContractResult,
) -> Result<A, Cis4QueryError> {
    match response {
        smart_contracts::InvokeContractResult::Success { return_value, .. } => {
            let bytes: smart_contracts::ReturnValue = return_value.ok_or(
                Cis4QueryError::ResponseParseError(contracts_common::ParseError {}),
            )?;
            let response: A = contracts_common::from_bytes(&bytes.value)?;
            Ok(response)
        }
        smart_contracts::InvokeContractResult::Failure { reason, .. } => {
            Err(Cis4QueryError::NodeRejected(reason))
        }
    }
}
