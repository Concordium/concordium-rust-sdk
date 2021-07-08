use super::{
    hashes, smart_contracts, AccountThreshold, AggregateSigPairing, BakerAggregationVerifyKey,
    BakerElectionVerifyKey, BakerSignVerifyKey, ContractAddress, CredentialIndex,
    CredentialRegistrationID, Energy, Nonce, RegisteredData,
};
use crate::constants::*;
use crypto_common::{
    derive::{Serial, Serialize},
    serde_impls::KeyPairDef,
    types::{Amount, KeyIndex, Timestamp, TransactionSignature, TransactionTime},
    Buffer, Deserial, Get, ParseResult, Put, ReadBytesExt, SerdeDeserialize, SerdeSerialize,
    Serial,
};
use derive_more::*;
use encrypted_transfers::types::{EncryptedAmountTransferData, SecToPubAmountTransferData};
use id::types::{
    AccountAddress, AccountCredential, CredentialDeploymentInfo, CredentialPublicKeys,
};
use sha2::Digest;
use std::collections::BTreeMap;

#[derive(
    Debug, Copy, Clone, Serial, SerdeSerialize, SerdeDeserialize, Into, Display, Eq, PartialEq,
)]
#[serde(transparent)]
/// Type safe wrapper to record the size of the transaction payload.
pub struct PayloadSize {
    size: u32,
}

impl Deserial for PayloadSize {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let size: u32 = source.get()?;
        anyhow::ensure!(
            size <= MAX_PAYLOAD_SIZE,
            "Size of the payload exceeds maximum allowed."
        );
        Ok(PayloadSize { size })
    }
}

#[derive(Debug, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Header of an account transaction that contains basic data to check whether
/// the sender and the transaction is valid.
pub struct TransactionHeader {
    /// Sender account of the transaction.
    pub sender:        AccountAddress,
    /// Sequence number of the transaction.
    pub nonce:         Nonce,
    /// Maximum amount of energy the transaction can take to execute.
    pub energy_amount: Energy,
    /// Size of the transaction payload. This is used to deserialize the
    /// payload.
    pub payload_size:  PayloadSize,
    /// Latest time the transaction can be included in a block.
    pub expiry:        TransactionTime,
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
/// An account transaction payload that has not yet been deserialized.
/// This is a simple wrapper around Vec<u8> with bespoke serialization.
pub struct EncodedPayload {
    #[serde(with = "crate::internal::byte_array_hex")]
    pub(crate) payload: Vec<u8>,
}

/// This serial instance does not have an inverse. It needs a context with the
/// length.
impl Serial for EncodedPayload {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self.payload)
            .expect("Writing to buffer should succeed.");
    }
}

/// Parse an encoded payload of specified length.
pub fn get_encoded_payload<R: ReadBytesExt>(
    source: &mut R,
    len: PayloadSize,
) -> ParseResult<EncodedPayload> {
    // The use of deserial_bytes is safe here (no execessive allocations) because
    // payload_size is limited
    let payload = crypto_common::deserial_bytes(source, u32::from(len) as usize)?;
    Ok(EncodedPayload { payload })
}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// An account transaction signed and paid for by a sender account.
/// The payload type is a generic parameter to support two kinds of payloads,
/// a fully deserialized [Payload] type, and an [EncodedPayload]. The latter is
/// useful since deserialization of some types of payloads is expensive. It is
/// thus useful to delay deserialization until after we have checked signatures
/// and the sender account information.
pub struct AccountTransaction<PayloadType> {
    pub signature: TransactionSignature,
    pub header:    TransactionHeader,
    pub payload:   PayloadType,
}

impl Serial for AccountTransaction<EncodedPayload> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.signature);
        out.put(&self.header);
        out.put(&self.payload);
    }
}

impl Serial for AccountTransaction<Payload> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.signature);
        out.put(&self.header);
        self.payload.encode_to_buffer(out)
    }
}

impl Deserial for AccountTransaction<EncodedPayload> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let signature = source.get()?;
        let header: TransactionHeader = source.get()?;
        let payload = get_encoded_payload(source, header.payload_size)?;
        Ok(AccountTransaction {
            signature,
            header,
            payload,
        })
    }
}

impl Deserial for AccountTransaction<Payload> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let signature = source.get()?;
        let header: TransactionHeader = source.get()?;
        let payload_len = u64::from(u32::from(header.payload_size));
        let mut limited = <&mut R as std::io::Read>::take(source, payload_len);
        let payload = limited.get()?;
        // ensure the payload length matches the stated size.
        if limited.limit() == 0 {
            Ok(AccountTransaction {
                signature,
                header,
                payload,
            })
        } else {
            anyhow::bail!("Payload length information is inaccurate: bytes of input remaining.")
        }
    }
}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Payload of an account transaction.
pub enum Payload {
    /// Deploy a Wasm module with the given source.
    DeployModule {
        #[serde(rename = "mod")]
        module: smart_contracts::WasmModule,
    },
    /// Initialize a new smart contract instance.
    InitContract {
        /// Deposit this amount of GTU.
        amount:    Amount,
        /// Reference to the module from which to initialize the instance.
        mod_ref:   smart_contracts::ModuleRef,
        /// Name of the contract in the module.
        init_name: smart_contracts::InitName,
        /// Message to invoke the initialization method with.
        param:     smart_contracts::Parameter,
    },
    /// Update a smart contract instance by invoking a specific function.
    Update {
        /// Send the given amount of GTU together with the message to the
        /// contract instance.
        amount:       Amount,
        /// Address of the contract instance to invoke.
        address:      ContractAddress,
        /// Name of the method to invoke on the contract.
        receive_name: smart_contracts::ReceiveName,
        /// Message to send to the contract instance.
        message:      smart_contracts::Parameter,
    },
    /// Transfer GTU to an account.
    Transfer {
        /// Address to send to.
        to_address: AccountAddress,
        /// Amount to send.
        amount:     Amount,
    },
    /// Register the sender account as a baker.
    AddBaker {
        /// Public key for participating in the election lottery.
        election_verify_key:    BakerElectionVerifyKey,
        /// Public key for verifying this baker's signatures.
        signature_verify_key:   BakerSignVerifyKey,
        /// Public key for verifying this baker's signature on finalization
        /// records.
        aggregation_verify_key: BakerAggregationVerifyKey,
        /// Proof of knowledge of the secret key corresponding to the signature
        /// verification key.
        proof_sig:              eddsa_ed25519::Ed25519DlogProof,
        /// Proof of knowledge of the election secret key.
        proof_election:         eddsa_ed25519::Ed25519DlogProof,
        /// Proof of knowledge of the secret key for signing finalization
        /// records.
        proof_aggregation:      aggregate_sig::Proof<AggregateSigPairing>,
        /// Initial baking stake.
        baking_stake:           Amount,
        /// Whether to add earnings to the stake automatically or not.
        restake_earnings:       bool,
    },
    /// Deregister the account as a baker.
    RemoveBaker,
    /// Update baker's stake.
    UpdateBakerStake {
        /// The new stake.
        stake: Amount,
    },
    /// Modify whether to add earnings to the baker stake automatically or not.
    UpdateBakerRestakeEarnings {
        /// New value of the flag.
        restake_earnings: bool,
    },
    /// Update the baker's keys.
    UpdateBakerKeys {
        /// New public key for participating in the election lottery.
        election_verify_key:    BakerElectionVerifyKey,
        /// New public key for verifying this baker's signatures.
        signature_verify_key:   BakerSignVerifyKey,
        /// New public key for verifying this baker's signature on finalization
        /// records.
        aggregation_verify_key: BakerAggregationVerifyKey,
        /// Proof of knowledge of the secret key corresponding to the signature
        /// verification key.
        proof_sig:              eddsa_ed25519::Ed25519DlogProof,
        /// Proof of knowledge of the election secret key.
        proof_election:         eddsa_ed25519::Ed25519DlogProof,
        /// Proof of knowledge of the secret key for signing finalization
        /// records.
        proof_aggregation:      aggregate_sig::Proof<AggregateSigPairing>,
    },
    /// Update signing keys of a specific credential.
    UpdateCredentialKeys {
        /// Id of the credential whose keys are to be updated.
        cred_id: CredentialRegistrationID,
        /// The new public keys.
        keys:    CredentialPublicKeys,
    },
    /// Transfer an encrypted amount.
    EncryptedAmountTransfer {
        /// The recepient's address.
        to:   AccountAddress,
        /// The (encrypted) amount to transfer and proof of correctness of
        /// accounting.
        data: Box<EncryptedAmountTransferData<id::constants::ArCurve>>,
    },
    /// Transfer from public to encrypted balance of the sender account.
    TransferToEncrypted {
        /// The amount to transfer.
        amount: Amount,
    },
    /// Transfer an amount from encrypted to the public balance of the account.
    TransferToPublic {
        /// The amount to transfer and proof of correctness of accounting.
        data: SecToPubAmountTransferData<id::constants::ArCurve>,
    },
    /// Transfer an amount with schedule.
    TransferWithSchedule {
        /// The recepient.
        to:       AccountAddress,
        /// The release schedule. This can be at most 255 elements.
        schedule: Vec<(Timestamp, Amount)>,
    },
    /// Update the account's credentials.
    UpdateCredentials {
        /// New credentials to add.
        new_cred_infos: BTreeMap<
            CredentialIndex,
            CredentialDeploymentInfo<
                id::constants::IpPairing,
                id::constants::ArCurve,
                id::ffi::AttributeKind,
            >,
        >,
        /// Ids of credentials to remove.
        remove_cred_ids: Vec<CredentialRegistrationID>,
        /// The new account threshold.
        new_threshold:   AccountThreshold,
    },
    /// Register the given data on the chain.
    RegisterData {
        /// The data to register.
        data: RegisteredData,
    },
}

impl Serial for Payload {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match &self {
            Payload::DeployModule { module } => {
                out.put(&0u8);
                out.put(module);
            }
            Payload::InitContract {
                amount,
                mod_ref,
                init_name,
                param,
            } => {
                out.put(&1u8);
                out.put(amount);
                out.put(mod_ref);
                out.put(init_name);
                out.put(param);
            }
            Payload::Update {
                amount,
                address,
                receive_name,
                message,
            } => {
                out.put(&2u8);
                out.put(amount);
                out.put(address);
                out.put(receive_name);
                out.put(message);
            }
            Payload::Transfer { to_address, amount } => {
                out.put(&3u8);
                out.put(to_address);
                out.put(amount);
            }
            Payload::AddBaker {
                election_verify_key,
                signature_verify_key,
                aggregation_verify_key,
                proof_sig,
                proof_election,
                proof_aggregation,
                baking_stake,
                restake_earnings,
            } => {
                out.put(&4u8);
                out.put(election_verify_key);
                out.put(signature_verify_key);
                out.put(aggregation_verify_key);
                out.put(proof_sig);
                out.put(proof_election);
                out.put(proof_aggregation);
                out.put(baking_stake);
                out.put(restake_earnings);
            }
            Payload::RemoveBaker => {
                out.put(&5u8);
            }
            Payload::UpdateBakerStake { stake } => {
                out.put(&6u8);
                out.put(stake);
            }
            Payload::UpdateBakerRestakeEarnings { restake_earnings } => {
                out.put(&7u8);
                out.put(restake_earnings);
            }
            Payload::UpdateBakerKeys {
                election_verify_key,
                signature_verify_key,
                aggregation_verify_key,
                proof_sig,
                proof_election,
                proof_aggregation,
            } => {
                out.put(&8u8);
                out.put(election_verify_key);
                out.put(signature_verify_key);
                out.put(aggregation_verify_key);
                out.put(proof_sig);
                out.put(proof_election);
                out.put(proof_aggregation);
            }
            Payload::UpdateCredentialKeys { cred_id, keys } => {
                out.put(&13u8);
                out.put(cred_id);
                out.put(keys);
            }
            Payload::EncryptedAmountTransfer { to, data } => {
                out.put(&16u8);
                out.put(to);
                out.put(data);
            }
            Payload::TransferToEncrypted { amount } => {
                out.put(&17u8);
                out.put(amount);
            }
            Payload::TransferToPublic { data } => {
                out.put(&18);
                out.put(data);
            }
            Payload::TransferWithSchedule { to, schedule } => {
                out.put(&19u8);
                out.put(to);
                out.put(&(schedule.len() as u8));
                for (ts, release) in schedule {
                    out.put(ts);
                    out.put(release);
                }
            }
            Payload::UpdateCredentials {
                new_cred_infos,
                remove_cred_ids,
                new_threshold,
            } => {
                out.put(&20u8);
                out.put(&(new_cred_infos.len() as u8));
                crypto_common::serial_map_no_length(new_cred_infos, out);
                out.put(&(remove_cred_ids.len() as u8));
                crypto_common::serial_vector_no_length(remove_cred_ids, out);
                out.put(new_threshold);
            }
            Payload::RegisterData { data } => {
                out.put(&21u8);
                out.put(data);
            }
        }
    }
}

impl Deserial for Payload {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        match tag {
            0 => {
                let module = source.get()?;
                Ok(Payload::DeployModule { module })
            }
            1 => {
                let amount = source.get()?;
                let mod_ref = source.get()?;
                let init_name = source.get()?;
                let param = source.get()?;
                Ok(Payload::InitContract {
                    amount,
                    mod_ref,
                    init_name,
                    param,
                })
            }
            2 => {
                let amount = source.get()?;
                let address = source.get()?;
                let receive_name = source.get()?;
                let message = source.get()?;
                Ok(Payload::Update {
                    amount,
                    address,
                    receive_name,
                    message,
                })
            }
            3 => {
                let to_address = source.get()?;
                let amount = source.get()?;
                Ok(Payload::Transfer { to_address, amount })
            }
            4 => {
                let election_verify_key = source.get()?;
                let signature_verify_key = source.get()?;
                let aggregation_verify_key = source.get()?;
                let proof_sig = source.get()?;
                let proof_election = source.get()?;
                let proof_aggregation = source.get()?;
                let baking_stake = source.get()?;
                let restake_earnings = source.get()?;
                Ok(Payload::AddBaker {
                    election_verify_key,
                    signature_verify_key,
                    aggregation_verify_key,
                    proof_sig,
                    proof_election,
                    proof_aggregation,
                    baking_stake,
                    restake_earnings,
                })
            }
            5 => Ok(Payload::RemoveBaker),
            6 => {
                let stake = source.get()?;
                Ok(Payload::UpdateBakerStake { stake })
            }
            7 => {
                let restake_earnings = source.get()?;
                Ok(Payload::UpdateBakerRestakeEarnings { restake_earnings })
            }
            8 => {
                let election_verify_key = source.get()?;
                let signature_verify_key = source.get()?;
                let aggregation_verify_key = source.get()?;
                let proof_sig = source.get()?;
                let proof_election = source.get()?;
                let proof_aggregation = source.get()?;
                Ok(Payload::UpdateBakerKeys {
                    election_verify_key,
                    signature_verify_key,
                    aggregation_verify_key,
                    proof_sig,
                    proof_election,
                    proof_aggregation,
                })
            }
            13 => {
                let cred_id = source.get()?;
                let keys = source.get()?;
                Ok(Payload::UpdateCredentialKeys { cred_id, keys })
            }
            16 => {
                let to = source.get()?;
                let data = source.get()?;
                Ok(Payload::EncryptedAmountTransfer { to, data })
            }
            17 => {
                let amount = source.get()?;
                Ok(Payload::TransferToEncrypted { amount })
            }
            18 => {
                let data = source.get()?;
                Ok(Payload::TransferToPublic { data })
            }
            19 => {
                let to = source.get()?;
                let len: u8 = source.get()?;
                let schedule = crypto_common::deserial_vector_no_length(source, len.into())?;
                Ok(Payload::TransferWithSchedule { to, schedule })
            }
            20 => {
                let cred_infos_len: u8 = source.get()?;
                let new_cred_infos =
                    crypto_common::deserial_map_no_length(source, cred_infos_len.into())?;
                let remove_cred_ids_len: u8 = source.get()?;
                let remove_cred_ids =
                    crypto_common::deserial_vector_no_length(source, remove_cred_ids_len.into())?;
                let new_threshold = source.get()?;
                Ok(Payload::UpdateCredentials {
                    new_cred_infos,
                    remove_cred_ids,
                    new_threshold,
                })
            }
            21 => {
                let data = source.get()?;
                Ok(Payload::RegisterData { data })
            }
            _ => {
                anyhow::bail!("Unsupported transaction payload tag {}", tag)
            }
        }
    }
}

impl Payload {
    /// Encode the transaction payload by serializing.
    pub fn encode(&self) -> EncodedPayload {
        let payload = crypto_common::to_bytes(&self);
        EncodedPayload { payload }
    }

    /// Encode the payload directly to a buffer. This will in general be more
    /// efficient than `encode`. However this will only matter if serialization
    /// was to be done in a tight loop.
    pub fn encode_to_buffer<B: Buffer>(&self, out: &mut B) { out.put(&self) }
}

impl EncodedPayload {
    pub fn size(&self) -> PayloadSize {
        let size = self.payload.len() as u32;
        PayloadSize { size }
    }
}

/// Compute the transaction sign hash from the header and payload.
/// This is semantically equivalent, but a bit more efficient, than first
/// serializing the [Payload] to [EncodedPayload] and then using
/// [compute_transaction_sign_hash_encoded]
pub fn compute_transaction_sign_hash(
    header: &TransactionHeader,
    payload: &Payload,
) -> hashes::TransactionSignHash {
    let mut hasher = sha2::Sha256::new();
    hasher.put(header);
    payload.encode_to_buffer(&mut hasher);
    hashes::HashBytes::new(hasher.result())
}

/// Compute the transaction sign hash from an encoded payload and header.
pub fn compute_transaction_sign_hash_encoded(
    header: &TransactionHeader,
    payload: &EncodedPayload,
) -> hashes::TransactionSignHash {
    let mut hasher = sha2::Sha256::new();
    hasher.put(header);
    hasher.put(payload);
    hashes::HashBytes::new(hasher.result())
}

/// Sign the given transaction with provided keys.
pub fn sign_transaction<'a, I, J: 'a>(
    keys: I,
    header: TransactionHeader,
    payload: Payload,
) -> AccountTransaction<Payload>
where
    I: IntoIterator<Item = (&'a CredentialIndex, J)>,
    J: IntoIterator<Item = (&'a KeyIndex, &'a KeyPairDef)>, {
    let hash_to_sign = compute_transaction_sign_hash(&header, &payload);
    let signature = sign_transaction_hash(keys, &hash_to_sign);
    AccountTransaction {
        signature,
        header,
        payload,
    }
}

/// Sign the transaction whose payload has already been serialized.
pub fn sign_transaction_encoded<'a, I, J>(
    keys: I,
    header: TransactionHeader,
    payload: EncodedPayload,
) -> AccountTransaction<EncodedPayload>
where
    I: IntoIterator<Item = (&'a CredentialIndex, J)>,
    J: IntoIterator<Item = (&'a KeyIndex, &'a KeyPairDef)>, {
    let hash_to_sign = compute_transaction_sign_hash_encoded(&header, &payload);
    let signature = sign_transaction_hash(keys, &hash_to_sign);
    AccountTransaction {
        signature,
        header,
        payload,
    }
}

/// A convenience wrapper around sign_transaction that construct the transaction
/// and signs it.
pub fn make_and_sign_transaction<'a, I, J>(
    keys: I,
    sender: AccountAddress,
    nonce: Nonce,
    energy_amount: Energy,
    expiry: TransactionTime,
    payload: &Payload,
) -> AccountTransaction<EncodedPayload>
where
    I: IntoIterator<Item = (&'a CredentialIndex, J)>,
    J: IntoIterator<Item = (&'a KeyIndex, &'a KeyPairDef)>, {
    let encoded = payload.encode();
    let payload_size = encoded.size();
    let header = TransactionHeader {
        sender,
        nonce,
        energy_amount,
        payload_size,
        expiry,
    };
    sign_transaction_encoded(keys, header, encoded)
}

/// Sign the pre-hashed transaction.
pub fn sign_transaction_hash<'a, I, J>(
    keys: I,
    hash_to_sign: &hashes::TransactionSignHash,
) -> TransactionSignature
where
    I: IntoIterator<Item = (&'a CredentialIndex, J)>,
    J: IntoIterator<Item = (&'a KeyIndex, &'a KeyPairDef)>, {
    let mut signatures = BTreeMap::<CredentialIndex, BTreeMap<KeyIndex, _>>::new();
    for (ci, cred_keys) in keys.into_iter() {
        let cred_sigs = cred_keys
            .into_iter()
            .map(|(ki, kp)| (*ki, kp.sign(hash_to_sign.as_ref())))
            .collect::<BTreeMap<_, _>>();
        signatures.insert(*ci, cred_sigs);
    }
    TransactionSignature { signatures }
}

#[derive(Debug, Clone)]
/// A block item are data items that are transmitted on the network either as
/// separate messages, or as part of blocks. They are the only user-generated
/// (as opposed to protocol-generated) message.
pub enum BlockItem<PayloadType> {
    /// Account transactions are messages which are signed and paid for by an
    /// account.
    AccountTransaction(AccountTransaction<PayloadType>),
    /// Credential deployments create new accounts. They are not paid for
    /// directly by the sender. Instead, bakers are rewarded by the protocol for
    /// including them.
    CredentialDeployment(
        Box<
            AccountCredential<
                id::constants::IpPairing,
                id::constants::ArCurve,
                id::ffi::AttributeKind,
            >,
        >,
    ),
    // FIXME: Add update instructions
}

impl<PayloadType> BlockItem<PayloadType> {
    /// Compute the hash of the block item that identifies the block item on the
    /// chain.
    pub fn hash(&self) -> hashes::TransactionHash
    where
        BlockItem<PayloadType>: Serial, {
        let mut hasher = sha2::Sha256::new();
        hasher.put(&self);
        hashes::HashBytes::new(hasher.result())
    }
}

impl Serial for BlockItem<EncodedPayload> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match &self {
            BlockItem::AccountTransaction(at) => {
                out.put(&0u8);
                out.put(at)
            }
            BlockItem::CredentialDeployment(acdi) => {
                out.put(&1u8);
                out.put(acdi);
            }
        }
    }
}

impl Deserial for BlockItem<EncodedPayload> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        match tag {
            0 => {
                let at = source.get()?;
                Ok(BlockItem::AccountTransaction(at))
            }
            1 => {
                let acdi = source.get()?;
                Ok(BlockItem::CredentialDeployment(acdi))
            }
            2 => todo!("Update instruction"),
            _ => anyhow::bail!("Unsupported block item type: {}.", tag),
        }
    }
}
