//! Module exposing certificates for blocks.
//! The types are only relevant for nodes running at least protocol version
//! 6.

use concordium_base::{
    base::{BakerId, Epoch, Round},
    common::Serial,
    hashes::BlockHash,
};

/// An aggregate signature on a [`QuorumCertificate`] created
/// by members of the finalization committee.
#[derive(concordium_base::common::Serialize, Clone, Debug, PartialEq)]
pub struct QuorumSignature(
    pub concordium_base::aggregate_sig::Signature<concordium_base::base::AggregateSigPairing>,
);

/// A quorum certificate on a block.
#[derive(Debug)]
pub struct QuorumCertificate {
    /// [`BlockHash`] of the block that this [`QuorumCertificate`]
    /// certifies.
    pub block_hash:          BlockHash,
    /// [`Round`] of the block that this [`QuorumCertificate`]
    /// certifies.
    pub round:               Round,
    /// [`Epoch`] of the block that this [`QuorumCertificate`]
    /// certifies.
    pub epoch:               Epoch,
    /// The aggregate signature on the block identified by the
    /// `block_hash` which serves as a proof that the block
    /// was accepted on the chain by a quorum of the finalization
    /// committee.
    pub aggregate_signature: QuorumSignature,
    /// The baker ids of the finalizers that formed
    /// the `aggregate_signature`.
    /// Note that the baker ids are sorted in ascending order and are
    /// distinct.
    pub signatories:         Vec<BakerId>,
}

/// A map from a [`Round`] to the set of finalizers
/// (identified by their [`BakerId`]) which signed off
/// in the round.
#[derive(Debug)]
pub struct FinalizerRound {
    /// The round which was signed off.
    pub round:      Round,
    /// The set of finalizers who signed off.
    /// (identified by their [`BakerId`])
    /// Note that the baker ids are sorted in ascending order and are
    /// distinct.
    pub finalizers: Vec<BakerId>,
}

/// An aggregate signature on a [`TimeoutCertificate`] created
/// by members of the finalization committee.
#[derive(concordium_base::common::Serialize, Clone, Debug, PartialEq)]
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
    pub round:                  Round,
    /// The minimum epoch of which signatures are included in
    /// the signature for the certificate.
    pub min_epoch:              Epoch,
    /// The rounds of which finalizers have their best quorum
    /// certificates in the [`Epoch`] `min_epoch`.
    pub qc_rounds_first_epoch:  Vec<FinalizerRound>,
    /// The rounds of which finalizers have their best quorum
    /// certificates in the [`Epoch`] `min_epoch` + 1.
    pub qc_rounds_second_epoch: Vec<FinalizerRound>,
    /// The aggregate signature by the finalization committee which
    /// serves as a proof that the [`Round`] timed out, hence
    /// no block was added to the chain.
    pub aggregate_signature:    TimeoutSignature,
}

/// A proof that establishes that a block of a
/// [`EpochFinalizationEntry`] is an
/// immediate successor of the finalized block.
#[derive(Debug)]
pub struct SuccessorProof(pub [u8; 32]);

/// The epoch finalization entry serves as a proof that
/// a quorum of the finalization committee has progressed
/// to a new [`Epoch`].
#[derive(Debug)]
pub struct EpochFinalizationEntry {
    /// The [`QuorumCertificate`] of the finalized block.
    pub finalized_qc:    QuorumCertificate,
    /// The [`QuorumCertificate`] of the immediate successor
    /// of the block indicated by `finalized_qc`.
    pub successor_qc:    QuorumCertificate,
    /// The witness that proves that the block of the `successor_qc`
    /// is an immediate decendant of the block of the `finalized_qc`.
    pub successor_proof: SuccessorProof,
}

#[derive(Debug)]
pub struct BlockCertificates {
    /// The [`QuorumCertificate`] of a block.
    /// Note that this will be [`None`] in the case
    /// where the block is a genesis block.
    pub quorum_certificate:       Option<QuorumCertificate>,
    /// The [`TimeoutCertificate`] is present if and only if
    /// the previous round of the block timed out.
    pub timeout_certificate:      Option<TimeoutCertificate>,
    /// The [`EpochFinalizationEntry`] is present if and only if
    /// the block is the first block of a new [`Epoch`].
    pub epoch_finalization_entry: Option<EpochFinalizationEntry>,
}
