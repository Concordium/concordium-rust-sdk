//! Module exposing certificates for blocks.
//! The types are only relevant for nodes running at least protocol version
//! 6.

use concordium_base::{
    base::{BakerId, Epoch, Round},
    hashes,
    hashes::BlockHash,
};
use std::collections::BTreeSet;

/// An aggregate signature on a [`QuorumCertificate`] created
/// by members of the finalization committee.
#[derive(concordium_base::common::Serialize, Clone, Copy, Debug, PartialEq)]
pub struct QuorumSignature(
    pub concordium_base::aggregate_sig::Signature<concordium_base::base::AggregateSigPairing>,
);

/// A quorum certificate on a block.
#[derive(Debug)]
pub struct QuorumCertificate {
    /// [`BlockHash`] of the block that this [`QuorumCertificate`]
    /// certifies.
    pub block_hash: BlockHash,
    /// [`Round`] of the block that this [`QuorumCertificate`]
    /// certifies.
    pub round: Round,
    /// [`Epoch`] of the block that this [`QuorumCertificate`]
    /// certifies.
    pub epoch: Epoch,
    /// The aggregate signature on the block identified by the
    /// `block_hash` which serves as a proof that the block
    /// was accepted on the chain by a quorum of the finalization
    /// committee.
    pub aggregate_signature: QuorumSignature,
    /// The baker ids of the finalizers that formed
    /// the `aggregate_signature`.
    /// Note that the signatories are sorted in ascending order of [`BakerId`].
    pub signatories: BTreeSet<BakerId>,
}

/// A map from a [`Round`] to the set of finalizers
/// (identified by their [`BakerId`]) which signed off
/// in the round.
#[derive(Debug)]
pub struct FinalizerRound {
    /// The round which was signed off.
    pub round: Round,
    /// The set of finalizers who signed off.
    /// (identified by their [`BakerId`])
    /// Note that the baker ids are sorted in ascending order and are
    /// distinct.
    pub finalizers: Vec<BakerId>,
}

/// An aggregate signature on a [`TimeoutCertificate`] created
/// by members of the finalization committee.
#[derive(concordium_base::common::Serialize, Clone, Copy, Debug, PartialEq)]
pub struct TimeoutSignature(
    pub concordium_base::aggregate_sig::Signature<concordium_base::base::AggregateSigPairing>,
);

/// The timeout certificate serves as a proof that no block
/// was created and/or distributed to the network in time.
/// The [`TimeoutCertificate`] makes it possible for the consensus protocol
/// to advance to the following round, thus giving (possibly) another baker
/// the chance to bake a block.
#[derive(Debug)]
pub struct TimeoutCertificate {
    /// The round that timed out.
    pub round: Round,
    /// The minimum epoch of which signatures are included in
    /// the signature for the certificate.
    pub min_epoch: Epoch,
    /// The rounds of which finalizers have their best quorum
    /// certificates in the [`Epoch`] `min_epoch`.
    pub qc_rounds_first_epoch: Vec<FinalizerRound>,
    /// The rounds of which finalizers have their best quorum
    /// certificates in the [`Epoch`] `min_epoch` + 1.
    pub qc_rounds_second_epoch: Vec<FinalizerRound>,
    /// The aggregate signature by the finalization committee which
    /// serves as a proof that the [`Round`] timed out, hence
    /// no block was added to the chain.
    pub aggregate_signature: TimeoutSignature,
}

/// The epoch finalization entry serves as a proof that
/// a quorum of the finalization committee has progressed
/// to a new [`Epoch`].
#[derive(Debug)]
pub struct EpochFinalizationEntry {
    /// The [`QuorumCertificate`] of the finalized block.
    pub finalized_qc: QuorumCertificate,
    /// The [`QuorumCertificate`] of the immediate successor
    /// of the block indicated by `finalized_qc`.
    pub successor_qc: QuorumCertificate,
    /// The witness that proves that the block of the `successor_qc`
    /// is an immediate decendant of the block of the `finalized_qc`.
    pub successor_proof: hashes::SuccessorProof,
}

#[derive(Debug)]
pub struct BlockCertificates {
    /// The [`QuorumCertificate`] of a block.
    /// Note that this will be [`None`] in the case
    /// where the block is a genesis block.
    pub quorum_certificate: Option<QuorumCertificate>,
    /// The [`TimeoutCertificate`] is present if and only if
    /// the previous round of the block timed out.
    pub timeout_certificate: Option<TimeoutCertificate>,
    /// The [`EpochFinalizationEntry`] is present if and only if
    /// the block is the first block of a new [`Epoch`].
    pub epoch_finalization_entry: Option<EpochFinalizationEntry>,
}

pub mod raw {
    //! This module contains the "raw" version of block certificates, where the
    //! finalizers are referenced by their finalization index, rather than
    //! `BakerId`.

    use concordium_base::{
        base::{Epoch, Round},
        hashes::BlockHash,
    };

    use super::{QuorumSignature, TimeoutSignature};

    /// The index of a finalizer in a particular finalization committee.
    #[derive(concordium_base::common::Serialize, Clone, Copy, Debug, PartialEq)]
    pub struct FinalizerIndex {
        pub index: u32,
    }

    impl From<FinalizerIndex> for usize {
        fn from(value: FinalizerIndex) -> Self {
            value.index as usize
        }
    }

    /// The message that is multicast by a finalizer when validating and signing
    /// a block.
    #[derive(Clone, Copy, Debug)]
    pub struct QuorumMessage {
        /// Signature on the relevant quorum signature message.
        pub signature: QuorumSignature,
        /// Hash of the block that is signed.
        pub block: BlockHash,
        /// Index of the finalizer signing the message.
        pub finalizer: FinalizerIndex,
        /// Round of the block.
        pub round: Round,
        /// Epoch of the block.
        pub epoch: Epoch,
    }

    /// A quorum certificate on a block. This certifies that 2/3 of the
    /// finalization committee signed the block.
    #[derive(Clone, Debug)]
    pub struct QuorumCertificate {
        /// The hash of the block that is certified.
        pub block_hash: BlockHash,
        /// The round of the block that is certified.
        pub round: Round,
        /// The epoch of the block that is certified.
        pub epoch: Epoch,
        /// The aggregated signature of the finalization committee
        /// on the block that is certified.
        pub aggregate_signature: QuorumSignature,
        /// A vector of the finalizers that formed the quorum certificate
        /// i.e., the ones who have contributed to the aggregate signature.
        /// The finalizers are identified by their finalizer index, which refers
        /// to the finalization committee for the epoch.
        pub signatories: Vec<FinalizerIndex>,
    }

    /// A (non-aggregate) signature of a validator. This is used for the
    /// validator's signature on blocks it produces, as well as for some
    /// finalization messages.
    #[derive(concordium_base::common::Serialize, Clone, Copy, Debug, Eq, PartialEq)]
    pub struct BlockSignature(pub ed25519_dalek::Signature);

    /// A timeout message including the sender's signature.
    #[derive(Clone, Debug)]
    pub struct TimeoutMessage {
        /// Index of the finalizer signing the message.
        pub finalizer: FinalizerIndex,
        /// Index of the round that timed out.
        pub round: Round,
        /// Current epoch number of the finalizer sending the timeout message.
        /// This can be different from the epoch of the quorum certificate.
        pub epoch: Epoch,
        /// Highest quorum certificate known to the finalizer at the time of
        /// timeout.
        pub quorum_certificate: QuorumCertificate,
        /// Signature on the appropriate timeout signature message.
        pub signature: TimeoutSignature,
        /// Signature of the finalizer on the timeout message as a whole.
        pub message_signature: BlockSignature,
    }

    /// The set of finalizers that signed in a particular round.
    #[derive(Clone, Debug)]
    pub struct FinalizerRound {
        /// The round for which the finalizers signed.
        pub round: Round,
        /// The finalizers that signed for the round.
        pub finalizers: Vec<FinalizerIndex>,
    }

    /// The timeout certificate serves as a proof that no block
    /// was created and/or distributed to the network in time.
    /// The [`TimeoutCertificate`] makes it possible for the consensus protocol
    /// to advance to the following round, thus giving (possibly) another baker
    /// the chance to bake a block.
    #[derive(Clone, Debug)]
    pub struct TimeoutCertificate {
        /// The round that timed out.
        pub round: Round,
        /// The minimum epoch of which signatures are included in
        /// the signature for the certificate.
        pub min_epoch: Epoch,
        /// The rounds of which finalizers have their best quorum
        /// certificates in the [`Epoch`] `min_epoch`.
        pub qc_rounds_first_epoch: Vec<FinalizerRound>,
        /// The rounds of which finalizers have their best quorum
        /// certificates in the [`Epoch`] `min_epoch` + 1.
        pub qc_rounds_second_epoch: Vec<FinalizerRound>,
        /// The aggregate signature by the finalization committee which
        /// serves as a proof that the [`Round`] timed out, hence
        /// no block was added to the chain.
        pub aggregate_signature: TimeoutSignature,
    }

    /// A finalization entry that proves that a block is finalized.
    #[derive(Clone, Debug)]
    pub struct FinalizationEntry {
        /// The quorum certificate of the finalized block.
        pub finalized_qc: QuorumCertificate,
        /// The quorum certificate of the immediate successor of the block
        /// indicated by `finalized_qc`. This block must be in the same epoch
        /// and the next round as that of `finalized_qc`.
        pub successor_qc: QuorumCertificate,
        /// The witness that proves that the block of the `successor_qc`
        /// is an immediate decendant of the block of the `finalized_qc`.
        pub successor_proof: super::hashes::SuccessorProof,
    }

    /// Collected timeout messages for a single round.
    #[derive(Clone, Debug)]
    pub struct TimeoutMessages {
        /// The first epoch for which timeout messsages are present.
        pub first_epoch: Epoch,
        /// The timeout messages for the first epoch.
        /// There should always be at least one.
        pub first_epoch_timeouts: Vec<TimeoutMessage>,
        /// The timeout messages for the second epoch.
        pub second_epoch_timeouts: Vec<TimeoutMessage>,
    }
}
