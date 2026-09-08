use alloy_primitives::B256;
use bitvec::prelude::*;
use n42_h2_primitives::{
    BlsSecretKey,
    bls::{
        AggregateSignature, BlsPublicKey, BlsSignature, batch_verify_h2_v4_with_fallback,
        batch_verify_with_fallback,
    },
    consensus::{
        H2V4ChainIdentity, QuorumCertificate, TimeoutCertificate, ViewNumber,
        h2_v4_commit_signing_message, h2_v4_new_view_signing_message,
        h2_v4_proposal_signing_message, h2_v4_timeout_signing_message, h2_v4_vote_signing_message,
    },
};
use std::collections::{HashMap, HashSet};

use crate::error::{ConsensusError, ConsensusResult};
use crate::validator::ValidatorSet;

/// Selects the BLS ciphersuite and signed bytes used by the consensus engine.
/// Native remains the default; H2-v4 is enabled only by an explicit participant
/// configuration and binds every signature to the chain identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConsensusSigningProfile {
    #[default]
    Native,
    H2V4(H2V4ChainIdentity),
}

impl ConsensusSigningProfile {
    pub fn proposal_message(
        self,
        view: ViewNumber,
        block_hash: B256,
        validator_changes: &Option<Vec<n42_h2_primitives::consensus::ValidatorChange>>,
    ) -> Vec<u8> {
        match self {
            Self::Native => proposal_signing_message(view, &block_hash, validator_changes).to_vec(),
            // gov5's v4 profile hardcodes a zero validator-change hash and
            // does not support reconfiguration (interop_v4.go). Deriving a
            // real hash here would be invisible until a committee change
            // actually lands, and then the two clients would sign different
            // preimages for the same proposal and reject each other at
            // exactly that view. Zero until the dynamic-changes revision
            // defines one hash both clients derive identically; the brief is
            // explicit that no v4 chain may configure epoch changes before
            // then. The startup log already states this invariant.
            Self::H2V4(identity) => {
                let _ = validator_changes;
                h2_v4_proposal_signing_message(identity, view, block_hash, B256::ZERO).to_vec()
            }
        }
    }

    pub fn vote_message(self, view: ViewNumber, block_hash: B256) -> Vec<u8> {
        match self {
            Self::Native => signing_message(view, &block_hash).to_vec(),
            Self::H2V4(identity) => h2_v4_vote_signing_message(identity, view, block_hash).to_vec(),
        }
    }

    /// The message a *progress vote* signs: a follower that imported a block
    /// after its view had passed tells that view's leader so, in a `Vote`
    /// whose signature is over this message and not the vote's. It can never
    /// count towards a QC (no verifier accepts it as a vote) and is only read
    /// by the leader's `voters_seen` ledger; see the stragglers' grace.
    pub fn progress_vote_message(self, view: ViewNumber, block_hash: B256) -> Vec<u8> {
        let mut message = self.vote_message(view, block_hash);
        message.extend_from_slice(b"/n42/imported-late");
        message
    }

    pub fn commit_message(self, view: ViewNumber, block_hash: B256, changes_hash: B256) -> Vec<u8> {
        match self {
            Self::Native => commit_signing_message(view, &block_hash, &changes_hash).to_vec(),
            // Zero for the same reason as `proposal_message`.
            Self::H2V4(identity) => {
                let _ = changes_hash;
                h2_v4_commit_signing_message(identity, view, block_hash, B256::ZERO).to_vec()
            }
        }
    }

    pub fn timeout_message(self, view: ViewNumber) -> Vec<u8> {
        match self {
            Self::Native => timeout_signing_message(view).to_vec(),
            Self::H2V4(identity) => h2_v4_timeout_signing_message(identity, view).to_vec(),
        }
    }

    pub fn new_view_message(self, view: ViewNumber) -> Vec<u8> {
        match self {
            Self::Native => newview_signing_message(view).to_vec(),
            Self::H2V4(identity) => h2_v4_new_view_signing_message(identity, view).to_vec(),
        }
    }

    pub fn sign(self, secret_key: &BlsSecretKey, message: &[u8]) -> BlsSignature {
        match self {
            Self::Native => secret_key.sign(message),
            Self::H2V4(_) => secret_key.sign_h2_v4(message),
        }
    }

    pub fn verify_single(
        self,
        public_key: &BlsPublicKey,
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        match self {
            Self::Native => public_key.verify_prevalidated(message, signature),
            Self::H2V4(_) => public_key.verify_h2_v4_prevalidated(message, signature),
        }
        .is_ok()
    }

    /// Batch-verifies distinct (message, signature, key) tuples, returning the
    /// positions that failed. Both ciphersuites use the multi-pairing path with
    /// random scalars; only the domain and the localizing fallback differ.
    pub fn batch_verify(
        self,
        messages: &[&[u8]],
        signatures: &[&BlsSignature],
        public_keys: &[&BlsPublicKey],
    ) -> Result<(), Vec<usize>> {
        match self {
            Self::Native => batch_verify_with_fallback(messages, signatures, public_keys),
            Self::H2V4(_) => batch_verify_h2_v4_with_fallback(messages, signatures, public_keys),
        }
    }

    fn verify_aggregate(
        self,
        message: &[u8],
        signature: &BlsSignature,
        public_keys: &[&BlsPublicKey],
    ) -> bool {
        match self {
            Self::Native => AggregateSignature::verify_aggregate(message, signature, public_keys),
            Self::H2V4(_) => {
                AggregateSignature::verify_h2_v4_aggregate(message, signature, public_keys)
            }
        }
        .is_ok()
    }
}

/// Collects votes for a specific view and produces a QuorumCertificate
/// once n-f votes from the active validator set are received.
#[derive(Debug)]
pub struct VoteCollector {
    view: ViewNumber,
    block_hash: B256,
    /// Collected signatures indexed by validator index.
    votes: HashMap<u32, BlsSignature>,
    set_size: u32,
    /// Validators whose signatures were already verified by the caller.
    /// Skipped during `build_qc_with_message` to avoid redundant BLS pairings.
    verified: HashSet<u32>,
}

impl VoteCollector {
    pub fn new(view: ViewNumber, block_hash: B256, set_size: u32) -> Self {
        let capacity = set_size as usize;
        Self {
            view,
            block_hash,
            votes: HashMap::with_capacity(capacity),
            set_size,
            verified: HashSet::with_capacity(capacity),
        }
    }

    /// Adds a vote. Returns `Err` if the validator has already voted.
    pub fn add_vote(
        &mut self,
        validator_index: u32,
        signature: BlsSignature,
    ) -> ConsensusResult<()> {
        if self.votes.contains_key(&validator_index) {
            return Err(ConsensusError::DuplicateVote {
                view: self.view,
                validator_index,
            });
        }
        self.votes.insert(validator_index, signature);
        Ok(())
    }

    /// Adds a vote that has already been signature-verified by the caller.
    /// Marks the validator in `verified` to skip re-verification in `build_qc_with_message`.
    pub fn add_verified_vote(
        &mut self,
        validator_index: u32,
        signature: BlsSignature,
    ) -> ConsensusResult<()> {
        self.add_vote(validator_index, signature)?;
        self.verified.insert(validator_index);
        Ok(())
    }

    pub fn block_hash(&self) -> B256 {
        self.block_hash
    }

    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    pub fn has_quorum(&self, quorum_size: usize) -> bool {
        self.votes.len() >= quorum_size
    }

    /// Builds a QuorumCertificate using the standard vote signing message.
    pub fn build_qc(&self, validator_set: &ValidatorSet) -> ConsensusResult<QuorumCertificate> {
        let message = signing_message(self.view, &self.block_hash);
        self.build_qc_with_message(validator_set, &message)
    }

    /// Builds a QuorumCertificate using a custom signing message.
    ///
    /// Used for CommitVote (Round 2) which uses `commit_signing_message` instead of the
    /// standard `signing_message`. Votes with invalid signatures are skipped (defense-in-depth);
    /// the QC fails only if fewer than `quorum_size` valid votes remain.
    pub fn build_qc_with_message(
        &self,
        validator_set: &ValidatorSet,
        message: &[u8],
    ) -> ConsensusResult<QuorumCertificate> {
        self.build_qc_with_profile_message(validator_set, message, ConsensusSigningProfile::Native)
    }

    pub fn build_qc_with_profile_message(
        &self,
        validator_set: &ValidatorSet,
        message: &[u8],
        signing_profile: ConsensusSigningProfile,
    ) -> ConsensusResult<QuorumCertificate> {
        // Guard: the validator_set passed here must match the set_size this collector
        // was created with. A mismatch (e.g. during epoch transitions) would cause
        // bitvec index out-of-bounds panics in release builds or UB in debug builds.
        if validator_set.len() != self.set_size {
            return Err(ConsensusError::InvalidQC {
                view: self.view,
                reason: format!(
                    "validator_set size mismatch: collector set_size={}, validator_set.len()={}",
                    self.set_size,
                    validator_set.len()
                ),
            });
        }

        let quorum_size = validator_set.quorum_size();
        if self.votes.len() < quorum_size {
            return Err(ConsensusError::InsufficientVotes {
                view: self.view,
                have: self.votes.len(),
                need: quorum_size,
            });
        }

        let mut valid_sigs: Vec<&BlsSignature> = Vec::with_capacity(self.votes.len());
        let mut signers = bitvec![u8, Msb0; 0; self.set_size as usize];
        let mut unverified = Vec::with_capacity(self.votes.len());

        for (&idx, sig) in &self.votes {
            if idx >= self.set_size {
                tracing::warn!(target: "n42::cl::quorum", view = self.view, idx, "skipping out-of-range validator in QC build");
                continue;
            }

            if self.verified.contains(&idx) {
                valid_sigs.push(sig);
                signers.set(idx as usize, true);
                continue;
            }

            let pk = match validator_set.get_public_key(idx) {
                Ok(pk) => pk,
                Err(_) => {
                    tracing::warn!(target: "n42::cl::quorum", view = self.view, idx, "skipping unknown validator in QC build");
                    continue;
                }
            };
            unverified.push((idx, sig, pk));
        }

        // Verify the untrusted tail in one randomized multi-pairing. The
        // primitive falls back to individual verification only when the batch
        // fails, preserving the old ability to exclude exactly the bad votes.
        // Random coefficients are generated inside n42-primitives, so a
        // malicious signer cannot construct cancelling invalid signatures.
        if !unverified.is_empty() {
            let messages = vec![message; unverified.len()];
            let signatures = unverified
                .iter()
                .map(|(_, sig, _)| *sig)
                .collect::<Vec<_>>();
            let public_keys = unverified.iter().map(|(_, _, pk)| *pk).collect::<Vec<_>>();
            let bad = signing_profile
                .batch_verify(&messages, &signatures, &public_keys)
                .err()
                .unwrap_or_default()
                .into_iter()
                .collect::<HashSet<_>>();

            for (position, (idx, sig, _)) in unverified.into_iter().enumerate() {
                if bad.contains(&position) {
                    tracing::warn!(target: "n42::cl::quorum", view = self.view, idx, "skipping invalid signature in QC build");
                    continue;
                }
                valid_sigs.push(sig);
                signers.set(idx as usize, true);
            }
        }

        if valid_sigs.len() < quorum_size {
            return Err(ConsensusError::InsufficientVotes {
                view: self.view,
                have: valid_sigs.len(),
                need: quorum_size,
            });
        }

        let aggregate_signature = AggregateSignature::aggregate(&valid_sigs)?;
        Ok(QuorumCertificate {
            view: self.view,
            block_hash: self.block_hash,
            aggregate_signature,
            signers,
        })
    }
}

/// Collects timeout messages for a specific view and produces a TimeoutCertificate.
#[derive(Debug)]
pub struct TimeoutCollector {
    view: ViewNumber,
    timeouts: HashMap<u32, (BlsSignature, QuorumCertificate)>,
    set_size: u32,
    verified: HashSet<u32>,
}

impl TimeoutCollector {
    pub fn new(view: ViewNumber, set_size: u32) -> Self {
        let capacity = set_size as usize;
        Self {
            view,
            timeouts: HashMap::with_capacity(capacity),
            set_size,
            verified: HashSet::with_capacity(capacity),
        }
    }

    pub fn view(&self) -> ViewNumber {
        self.view
    }

    /// Adds a timeout message. Returns `Err` if the validator has already submitted one.
    pub fn add_timeout(
        &mut self,
        validator_index: u32,
        signature: BlsSignature,
        high_qc: QuorumCertificate,
    ) -> ConsensusResult<()> {
        if self.timeouts.contains_key(&validator_index) {
            return Err(ConsensusError::DuplicateVote {
                view: self.view,
                validator_index,
            });
        }
        self.timeouts.insert(validator_index, (signature, high_qc));
        Ok(())
    }

    /// Adds a timeout message that has already been signature-verified by the caller.
    pub fn add_verified_timeout(
        &mut self,
        validator_index: u32,
        signature: BlsSignature,
        high_qc: QuorumCertificate,
    ) -> ConsensusResult<()> {
        self.add_timeout(validator_index, signature, high_qc)?;
        self.verified.insert(validator_index);
        Ok(())
    }

    pub fn timeout_count(&self) -> usize {
        self.timeouts.len()
    }

    pub fn has_quorum(&self, quorum_size: usize) -> bool {
        self.timeouts.len() >= quorum_size
    }

    /// Builds a TimeoutCertificate from collected timeout signatures.
    ///
    /// Timeout messages with invalid signatures are skipped (defense-in-depth).
    /// The TC fails only if fewer than `quorum_size` valid timeouts remain.
    pub fn build_tc(&self, validator_set: &ValidatorSet) -> ConsensusResult<TimeoutCertificate> {
        self.build_tc_with_profile(validator_set, ConsensusSigningProfile::Native)
    }

    pub fn build_tc_with_profile(
        &self,
        validator_set: &ValidatorSet,
        signing_profile: ConsensusSigningProfile,
    ) -> ConsensusResult<TimeoutCertificate> {
        if validator_set.len() != self.set_size {
            return Err(ConsensusError::InvalidTC {
                view: self.view,
                reason: format!(
                    "validator_set size mismatch: collector set_size={}, validator_set.len()={}",
                    self.set_size,
                    validator_set.len()
                ),
            });
        }

        let quorum_size = validator_set.quorum_size();
        if self.timeouts.len() < quorum_size {
            return Err(ConsensusError::InsufficientVotes {
                view: self.view,
                have: self.timeouts.len(),
                need: quorum_size,
            });
        }

        let message = signing_profile.timeout_message(self.view);
        let mut highest_qc: Option<&QuorumCertificate> = None;
        let mut valid_sigs: Vec<&BlsSignature> = Vec::with_capacity(self.timeouts.len());
        let mut signers = bitvec![u8, Msb0; 0; self.set_size as usize];
        let mut unverified = Vec::with_capacity(self.timeouts.len());

        for (&idx, (sig, high_qc)) in &self.timeouts {
            if idx >= self.set_size {
                tracing::warn!(target: "n42::cl::quorum", view = self.view, idx, "skipping out-of-range validator in TC build");
                continue;
            }

            if self.verified.contains(&idx) {
                valid_sigs.push(sig);
                signers.set(idx as usize, true);
                if highest_qc.as_ref().is_none_or(|hq| high_qc.view > hq.view) {
                    highest_qc = Some(high_qc);
                }
                continue;
            }

            let pk = match validator_set.get_public_key(idx) {
                Ok(pk) => pk,
                Err(_) => {
                    tracing::warn!(target: "n42::cl::quorum", view = self.view, idx, "skipping unknown validator in TC build");
                    continue;
                }
            };
            unverified.push((idx, sig, pk, high_qc));
        }

        if !unverified.is_empty() {
            let messages = vec![message.as_slice(); unverified.len()];
            let signatures = unverified
                .iter()
                .map(|(_, sig, _, _)| *sig)
                .collect::<Vec<_>>();
            let public_keys = unverified
                .iter()
                .map(|(_, _, pk, _)| *pk)
                .collect::<Vec<_>>();
            let bad = signing_profile
                .batch_verify(&messages, &signatures, &public_keys)
                .err()
                .unwrap_or_default()
                .into_iter()
                .collect::<HashSet<_>>();

            for (position, (idx, sig, _, high_qc)) in unverified.into_iter().enumerate() {
                if bad.contains(&position) {
                    tracing::warn!(target: "n42::cl::quorum", view = self.view, idx, "skipping invalid timeout signature in TC build");
                    continue;
                }
                valid_sigs.push(sig);
                signers.set(idx as usize, true);
                if highest_qc.as_ref().is_none_or(|hq| high_qc.view > hq.view) {
                    highest_qc = Some(high_qc);
                }
            }
        }

        if valid_sigs.len() < quorum_size {
            return Err(ConsensusError::InsufficientVotes {
                view: self.view,
                have: valid_sigs.len(),
                need: quorum_size,
            });
        }

        let aggregate_signature = AggregateSignature::aggregate(&valid_sigs)?;
        let high_qc = highest_qc
            .cloned()
            .ok_or_else(|| ConsensusError::InvalidTC {
                view: self.view,
                reason: "no high_qc found in timeout messages".to_string(),
            })?;

        Ok(TimeoutCertificate {
            view: self.view,
            aggregate_signature,
            signers,
            high_qc,
        })
    }
}

/// Distinguishes QC vs TC for error reporting in shared validation logic.
#[derive(Debug, Clone, Copy)]
enum CertKind {
    QC,
    TC,
}

impl CertKind {
    fn invalid_error(self, view: ViewNumber, reason: String) -> ConsensusError {
        match self {
            CertKind::QC => ConsensusError::InvalidQC { view, reason },
            CertKind::TC => ConsensusError::InvalidTC { view, reason },
        }
    }
}

/// Collects and validates signer public keys from a signers bitmap.
///
/// Validates bitmap length against the validator set (prevents short bitmaps from
/// bypassing quorum checks), then collects the public keys of all set bits.
fn collect_signer_keys<'a>(
    signers: &BitVec<u8, Msb0>,
    validator_set: &'a ValidatorSet,
    quorum_size: usize,
    view: ViewNumber,
    cert_kind: CertKind,
) -> ConsensusResult<Vec<&'a BlsPublicKey>> {
    let expected_len = validator_set.len() as usize;
    if signers.len() != expected_len {
        let reason = format!(
            "signers bitmap length mismatch: got {}, expected {}",
            signers.len(),
            expected_len,
        );
        return Err(cert_kind.invalid_error(view, reason));
    }

    let signer_count = signers.iter().filter(|b| **b).count();
    if signer_count < quorum_size {
        let reason = format!("insufficient signers: have {signer_count}, need {quorum_size}");
        return Err(cert_kind.invalid_error(view, reason));
    }

    signers
        .iter()
        .enumerate()
        .filter(|(_, bit)| **bit)
        .map(|(idx, _)| validator_set.get_public_key(idx as u32))
        .collect::<ConsensusResult<Vec<_>>>()
}

/// Verifies a QuorumCertificate (Round 1) against the validator set.
pub fn verify_qc(qc: &QuorumCertificate, validator_set: &ValidatorSet) -> ConsensusResult<()> {
    verify_qc_with_profile(qc, validator_set, ConsensusSigningProfile::Native)
}

pub fn verify_qc_with_profile(
    qc: &QuorumCertificate,
    validator_set: &ValidatorSet,
    signing_profile: ConsensusSigningProfile,
) -> ConsensusResult<()> {
    let quorum_size = validator_set.quorum_size();
    let signer_pks = collect_signer_keys(
        &qc.signers,
        validator_set,
        quorum_size,
        qc.view,
        CertKind::QC,
    )?;
    let message = signing_profile.vote_message(qc.view, qc.block_hash);
    signing_profile
        .verify_aggregate(&message, &qc.aggregate_signature, &signer_pks)
        .then_some(())
        .ok_or_else(|| ConsensusError::InvalidQC {
            view: qc.view,
            reason: "aggregated signature verification failed".to_string(),
        })
}

/// Verifies a CommitQC (Round 2) against the validator set.
///
/// Caller must pass the `changes_hash` from the proposal that produced this
/// view's PrepareQC (i.e. `Decide.validator_changes_hash` for the same view),
/// or `B256::ZERO` when no validator changes were carried. The hash is part
/// of the signed bytes, so a Byzantine leader cannot swap it after the fact.
pub fn verify_commit_qc(
    qc: &QuorumCertificate,
    validator_set: &ValidatorSet,
    changes_hash: &B256,
) -> ConsensusResult<()> {
    verify_commit_qc_with_profile(
        qc,
        validator_set,
        changes_hash,
        ConsensusSigningProfile::Native,
    )
}

pub fn verify_commit_qc_with_profile(
    qc: &QuorumCertificate,
    validator_set: &ValidatorSet,
    changes_hash: &B256,
    signing_profile: ConsensusSigningProfile,
) -> ConsensusResult<()> {
    let quorum_size = validator_set.quorum_size();
    let signer_pks = collect_signer_keys(
        &qc.signers,
        validator_set,
        quorum_size,
        qc.view,
        CertKind::QC,
    )?;
    let message = signing_profile.commit_message(qc.view, qc.block_hash, *changes_hash);
    signing_profile
        .verify_aggregate(&message, &qc.aggregate_signature, &signer_pks)
        .then_some(())
        .ok_or_else(|| ConsensusError::InvalidQC {
            view: qc.view,
            reason: "commit QC aggregated signature verification failed".to_string(),
        })
}

/// Verifies a QC that may be either a PrepareQC (Round 1) or CommitQC (Round 2).
///
/// Used when a QC is embedded as `high_qc` in a timeout message or `justify_qc`
/// in a proposal — we don't always know whether the producer signed it under
/// the prepare or the commit domain. The function tries the prepare format
/// first (most common) and falls back to the commit format with the supplied
/// `changes_hash` (or zero, when the caller doesn't have it cached).
pub fn verify_qc_any_domain(
    qc: &QuorumCertificate,
    validator_set: &ValidatorSet,
    changes_hash: &B256,
) -> ConsensusResult<()> {
    verify_qc_any_domain_with_profile(
        qc,
        validator_set,
        changes_hash,
        ConsensusSigningProfile::Native,
    )
}

pub fn verify_qc_any_domain_with_profile(
    qc: &QuorumCertificate,
    validator_set: &ValidatorSet,
    changes_hash: &B256,
    signing_profile: ConsensusSigningProfile,
) -> ConsensusResult<()> {
    let quorum_size = validator_set.quorum_size();
    let signer_pks = collect_signer_keys(
        &qc.signers,
        validator_set,
        quorum_size,
        qc.view,
        CertKind::QC,
    )?;

    // Try prepare (Round 1) message format first (most common path).
    let prepare_msg = signing_profile.vote_message(qc.view, qc.block_hash);
    if signing_profile.verify_aggregate(&prepare_msg, &qc.aggregate_signature, &signer_pks) {
        return Ok(());
    }

    // Fall back to commit (Round 2) message format.
    let commit_msg = signing_profile.commit_message(qc.view, qc.block_hash, *changes_hash);
    signing_profile
        .verify_aggregate(&commit_msg, &qc.aggregate_signature, &signer_pks)
        .then_some(())
        .ok_or_else(|| ConsensusError::InvalidQC {
            view: qc.view,
            reason:
                "aggregated signature verification failed (tried both prepare and commit domains)"
                    .to_string(),
        })
}

/// Verifies a TimeoutCertificate against the validator set.
pub fn verify_tc(tc: &TimeoutCertificate, validator_set: &ValidatorSet) -> ConsensusResult<()> {
    verify_tc_with_profile(tc, validator_set, ConsensusSigningProfile::Native)
}

pub fn verify_tc_with_profile(
    tc: &TimeoutCertificate,
    validator_set: &ValidatorSet,
    signing_profile: ConsensusSigningProfile,
) -> ConsensusResult<()> {
    let quorum_size = validator_set.quorum_size();
    let signer_pks = collect_signer_keys(
        &tc.signers,
        validator_set,
        quorum_size,
        tc.view,
        CertKind::TC,
    )?;
    let message = signing_profile.timeout_message(tc.view);
    signing_profile
        .verify_aggregate(&message, &tc.aggregate_signature, &signer_pks)
        .then_some(())
        .ok_or_else(|| ConsensusError::InvalidTC {
            view: tc.view,
            reason: "aggregated signature verification failed".to_string(),
        })
}

/// Computes the `changes_hash` for a set of validator changes.
///
/// Returns `B256::ZERO` when there are no changes; otherwise returns
/// `blake3(bincode::serialize(changes))`.  This is the value that must be
/// passed to [`verify_commit_qc`] and [`commit_signing_message`].
pub fn validator_changes_hash(
    validator_changes: &Option<Vec<n42_h2_primitives::consensus::ValidatorChange>>,
) -> B256 {
    match validator_changes {
        Some(changes) if !changes.is_empty() => {
            let encoded =
                bincode::serialize(changes).expect("ValidatorChange serialization cannot fail");
            B256::from(*blake3::hash(&encoded).as_bytes())
        }
        _ => B256::ZERO,
    }
}

/// Signing message for Round 1 votes: view (8 bytes LE) || block_hash (32 bytes).
pub fn signing_message(view: ViewNumber, block_hash: &B256) -> [u8; 40] {
    let mut msg = [0u8; 40];
    msg[..8].copy_from_slice(&view.to_le_bytes());
    msg[8..].copy_from_slice(block_hash.as_slice());
    msg
}

/// Signing message for Proposals: view || block_hash || changes_hash.
///
/// Extends [`signing_message`] with a 32-byte Blake3 hash of the serialized
/// `validator_changes` (or zeros if no changes).  This binds the proposer's
/// BLS signature to the exact set of validator changes, preventing a Byzantine
/// leader or relay from sending different change-lists under the same signature.
pub fn proposal_signing_message(
    view: ViewNumber,
    block_hash: &B256,
    validator_changes: &Option<Vec<n42_h2_primitives::consensus::ValidatorChange>>,
) -> [u8; 72] {
    let mut msg = [0u8; 72];
    msg[..8].copy_from_slice(&view.to_le_bytes());
    msg[8..40].copy_from_slice(block_hash.as_slice());
    let changes_hash = match validator_changes {
        Some(changes) if !changes.is_empty() => {
            let encoded =
                bincode::serialize(changes).expect("ValidatorChange serialization cannot fail");
            *blake3::hash(&encoded).as_bytes()
        }
        _ => [0u8; 32],
    };
    msg[40..72].copy_from_slice(&changes_hash);
    msg
}

/// Signing message for Round 2 commit votes:
///   `"commit" (6) || view (8 LE) || block_hash (32) || changes_hash (32)` = 78 bytes.
///
/// `changes_hash` is `EpochManager::hash_changes(validator_changes)` from the
/// proposal that produced this view's PrepareQC, or `B256::ZERO` when no
/// validator changes were proposed. Including it in the signed message binds
/// every commit vote (and therefore the aggregated CommitQC) to the exact
/// validator change set carried by the Decide, so a Byzantine leader cannot
/// substitute a different `validator_changes_hash` after collecting commit
/// votes (Finding 8 in the HotStuff-2 audit). Wire-format breaking — bumps
/// `CONSENSUS_PROTOCOL_VERSION`.
pub fn commit_signing_message(
    view: ViewNumber,
    block_hash: &B256,
    changes_hash: &B256,
) -> [u8; 78] {
    let mut msg = [0u8; 78];
    msg[..6].copy_from_slice(b"commit");
    msg[6..14].copy_from_slice(&view.to_le_bytes());
    msg[14..46].copy_from_slice(block_hash.as_slice());
    msg[46..78].copy_from_slice(changes_hash.as_slice());
    msg
}

/// Signing message for timeout messages: "timeout" || view (8 bytes LE).
pub fn timeout_signing_message(view: ViewNumber) -> [u8; 15] {
    let mut msg = [0u8; 15];
    msg[..7].copy_from_slice(b"timeout");
    msg[7..].copy_from_slice(&view.to_le_bytes());
    msg
}

/// Signing message for NewView messages: "newview" || view (8 bytes LE).
/// Distinct from `timeout_signing_message` to prevent cross-domain replay.
pub fn newview_signing_message(view: ViewNumber) -> [u8; 15] {
    let mut msg = [0u8; 15];
    msg[..7].copy_from_slice(b"newview");
    msg[7..].copy_from_slice(&view.to_le_bytes());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use crate::ValidatorInfo;
    use n42_h2_primitives::BlsSecretKey;

    fn test_key(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).expect("deterministic test key should be valid")
    }

    fn test_validator_set(n: usize) -> (Vec<BlsSecretKey>, ValidatorSet) {
        let sks: Vec<_> = (0..n).map(|i| test_key(0x20 + i as u8)).collect();
        let infos: Vec<_> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| ValidatorInfo {
                address: Address::with_last_byte(i as u8),
                bls_public_key: sk.public_key(),
                p2p_peer_id: None,
            })
            .collect();
        let f = ((n as u32).saturating_sub(1)) / 3;
        let vs = ValidatorSet::new(&infos, f);
        (sks, vs)
    }

    #[test]
    fn test_vote_collector_basic() {
        let (sks, vs) = test_validator_set(4);
        let view = 1u64;
        let block_hash = B256::repeat_byte(0xBB);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());

        assert_eq!(collector.vote_count(), 0);
        assert!(!collector.has_quorum(vs.quorum_size()));

        let msg = signing_message(view, &block_hash);
        for i in 0..3u32 {
            let sig = sks[i as usize].sign(&msg);
            collector
                .add_vote(i, sig)
                .expect("adding vote should succeed");
        }

        assert_eq!(collector.vote_count(), 3);
        assert!(collector.has_quorum(vs.quorum_size()));
    }

    #[test]
    fn test_five_validator_three_votes_cannot_form_qc() {
        let (sks, vs) = test_validator_set(5);
        let view = 2u64;
        let block_hash = B256::repeat_byte(0xB5);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());
        let msg = signing_message(view, &block_hash);

        for i in 0..3u32 {
            collector.add_vote(i, sks[i as usize].sign(&msg)).unwrap();
        }

        assert_eq!(vs.quorum_size(), 4);
        assert!(!collector.has_quorum(vs.quorum_size()));
        assert!(matches!(
            collector.build_qc(&vs),
            Err(ConsensusError::InsufficientVotes {
                have: 3,
                need: 4,
                ..
            })
        ));
    }

    #[test]
    fn test_vote_collector_duplicate() {
        let (sks, vs) = test_validator_set(4);
        let view = 1u64;
        let block_hash = B256::repeat_byte(0xCC);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());

        let msg = signing_message(view, &block_hash);
        let sig = sks[0].sign(&msg);

        collector
            .add_vote(0, sig.clone())
            .expect("first vote should succeed");

        let result = collector.add_vote(0, sks[0].sign(&msg));
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::DuplicateVote {
                view: v,
                validator_index: idx,
            } => {
                assert_eq!(v, view);
                assert_eq!(idx, 0);
            }
            other => panic!("expected DuplicateVote, got: {:?}", other),
        }
    }

    #[test]
    fn test_build_qc_and_verify() {
        let (sks, vs) = test_validator_set(4);
        let view = 5u64;
        let block_hash = B256::repeat_byte(0xDD);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());

        let msg = signing_message(view, &block_hash);
        for i in 0..3u32 {
            let sig = sks[i as usize].sign(&msg);
            collector.add_vote(i, sig).unwrap();
        }

        let qc = collector.build_qc(&vs).expect("build_qc should succeed");
        assert_eq!(qc.view, view);
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.signer_count(), 3);
        assert!(qc.signers[0]);
        assert!(qc.signers[1]);
        assert!(qc.signers[2]);
        assert!(!qc.signers[3]);

        verify_qc(&qc, &vs).expect("verify_qc should succeed");
    }

    #[test]
    fn test_verify_qc_insufficient_signers() {
        let (sks, vs) = test_validator_set(4);
        let view = 10u64;
        let block_hash = B256::repeat_byte(0xEE);

        let msg = signing_message(view, &block_hash);
        let sig = sks[0].sign(&msg);
        let agg_sig = n42_h2_primitives::bls::AggregateSignature::aggregate(&[&sig]).unwrap();

        let qc = QuorumCertificate {
            view,
            block_hash,
            aggregate_signature: agg_sig,
            signers: {
                let mut bv = bitvec![u8, Msb0; 0; 4];
                bv.set(0, true);
                bv
            },
        };

        let result = verify_qc(&qc, &vs);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::InvalidQC { view: v, reason } => {
                assert_eq!(v, view);
                assert!(reason.contains("insufficient signers"), "got: {reason}");
            }
            other => panic!("expected InvalidQC, got: {:?}", other),
        }
    }

    #[test]
    fn test_signing_message() {
        let view: ViewNumber = 42;
        let block_hash = B256::repeat_byte(0xFF);
        let msg = signing_message(view, &block_hash);

        assert_eq!(msg.len(), 40);
        assert_eq!(&msg[..8], &42u64.to_le_bytes());
        assert_eq!(&msg[8..], block_hash.as_slice());
    }

    #[test]
    fn test_timeout_signing_message() {
        let view: ViewNumber = 99;
        let msg = timeout_signing_message(view);

        assert_eq!(msg.len(), 15);
        assert_eq!(&msg[..7], b"timeout");
        assert_eq!(&msg[7..], &99u64.to_le_bytes());
    }

    #[test]
    fn test_commit_signing_message_format() {
        let view: ViewNumber = 7;
        let block_hash = B256::repeat_byte(0x11);
        let changes_hash = B256::repeat_byte(0x22);
        let msg = commit_signing_message(view, &block_hash, &changes_hash);

        assert_eq!(msg.len(), 78);
        assert_eq!(&msg[..6], b"commit");
        assert_eq!(&msg[6..14], &7u64.to_le_bytes());
        assert_eq!(&msg[14..46], block_hash.as_slice());
        assert_eq!(&msg[46..78], changes_hash.as_slice());
    }

    #[test]
    fn test_commit_signing_message_includes_changes_hash() {
        let view: ViewNumber = 5;
        let block = B256::repeat_byte(0xAB);
        let m_zero = commit_signing_message(view, &block, &B256::ZERO);
        let m_set = commit_signing_message(view, &block, &B256::repeat_byte(0xFF));
        // Different changes_hash values must produce different signed bytes,
        // otherwise a Byzantine leader could swap changes_hash post-aggregation.
        assert_ne!(m_zero, m_set);
    }

    #[test]
    fn test_build_qc_insufficient_votes() {
        let (sks, vs) = test_validator_set(4);
        let view = 1u64;
        let block_hash = B256::repeat_byte(0xAA);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());

        let msg = signing_message(view, &block_hash);
        collector.add_vote(0, sks[0].sign(&msg)).unwrap();

        let result = collector.build_qc(&vs);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::InsufficientVotes { have, need, .. } => {
                assert_eq!(have, 1);
                assert_eq!(need, 3);
            }
            other => panic!("expected InsufficientVotes, got: {:?}", other),
        }
    }

    #[test]
    fn test_build_qc_skips_invalid_signature() {
        let (sks, vs) = test_validator_set(4);
        let view = 3u64;
        let block_hash = B256::repeat_byte(0xF1);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());

        let msg = signing_message(view, &block_hash);
        for i in 0..3u32 {
            let sig = sks[i as usize].sign(&msg);
            collector.add_vote(i, sig).unwrap();
        }

        // Invalid vote: signed with wrong block hash
        let wrong_msg = signing_message(view, &B256::repeat_byte(0xFF));
        collector.add_vote(3, sks[3].sign(&wrong_msg)).unwrap();

        let qc = collector
            .build_qc(&vs)
            .expect("QC should form from valid votes");
        assert_eq!(qc.signer_count(), 3);
        assert!(qc.signers[0]);
        assert!(qc.signers[1]);
        assert!(qc.signers[2]);
        assert!(!qc.signers[3]);
        verify_qc(&qc, &vs).expect("QC should verify");
    }

    #[test]
    fn test_build_qc_fails_with_too_many_invalid() {
        let (sks, vs) = test_validator_set(4);
        let view = 4u64;
        let block_hash = B256::repeat_byte(0xF2);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());

        let msg = signing_message(view, &block_hash);
        for i in 0..2u32 {
            collector.add_vote(i, sks[i as usize].sign(&msg)).unwrap();
        }

        let wrong_msg = signing_message(99, &block_hash);
        for i in 2..4u32 {
            collector
                .add_vote(i, sks[i as usize].sign(&wrong_msg))
                .unwrap();
        }

        let result = collector.build_qc(&vs);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::InsufficientVotes { have, need, .. } => {
                assert_eq!(have, 2);
                assert_eq!(need, 3);
            }
            other => panic!("expected InsufficientVotes, got: {:?}", other),
        }
    }

    #[test]
    fn test_build_tc_skips_invalid_signature() {
        let (sks, vs) = test_validator_set(4);
        let view = 5u64;
        let genesis_qc = QuorumCertificate::genesis();
        let mut collector = TimeoutCollector::new(view, vs.len());
        let msg = timeout_signing_message(view);

        for i in 0..3u32 {
            collector
                .add_timeout(i, sks[i as usize].sign(&msg), genesis_qc.clone())
                .unwrap();
        }

        // Invalid timeout: wrong view
        let wrong_msg = timeout_signing_message(999);
        collector
            .add_timeout(3, sks[3].sign(&wrong_msg), genesis_qc.clone())
            .unwrap();

        let tc = collector
            .build_tc(&vs)
            .expect("TC should form from valid timeouts");
        assert_eq!(tc.signers.iter().filter(|b| **b).count(), 3);
        assert!(tc.signers[0]);
        assert!(tc.signers[1]);
        assert!(tc.signers[2]);
        assert!(!tc.signers[3]);
    }

    #[test]
    fn test_build_tc_fails_with_too_many_invalid() {
        let (sks, vs) = test_validator_set(4);
        let view = 6u64;
        let genesis_qc = QuorumCertificate::genesis();
        let mut collector = TimeoutCollector::new(view, vs.len());
        let msg = timeout_signing_message(view);

        for i in 0..2u32 {
            collector
                .add_timeout(i, sks[i as usize].sign(&msg), genesis_qc.clone())
                .unwrap();
        }

        let wrong_msg = timeout_signing_message(999);
        for i in 2..4u32 {
            collector
                .add_timeout(i, sks[i as usize].sign(&wrong_msg), genesis_qc.clone())
                .unwrap();
        }

        let result = collector.build_tc(&vs);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::InsufficientVotes { have, need, .. } => {
                assert_eq!(have, 2);
                assert_eq!(need, 3);
            }
            other => panic!("expected InsufficientVotes, got: {:?}", other),
        }
    }

    #[test]
    fn test_build_tc_highest_qc_from_valid_only() {
        let (sks, vs) = test_validator_set(4);
        let view = 7u64;
        let genesis_qc = QuorumCertificate::genesis();

        // Higher QC that will be attached to the invalid timeout
        let higher_qc = QuorumCertificate {
            view: 5,
            block_hash: B256::repeat_byte(0xAB),
            aggregate_signature: genesis_qc.aggregate_signature.clone(),
            signers: genesis_qc.signers.clone(),
        };

        let mut collector = TimeoutCollector::new(view, vs.len());
        let msg = timeout_signing_message(view);

        for i in 0..3u32 {
            collector
                .add_timeout(i, sks[i as usize].sign(&msg), genesis_qc.clone())
                .unwrap();
        }

        let wrong_msg = timeout_signing_message(999);
        collector
            .add_timeout(3, sks[3].sign(&wrong_msg), higher_qc)
            .unwrap();

        let tc = collector.build_tc(&vs).expect("TC should form");
        // high_qc should be genesis (view 0), not the invalid timeout's view 5
        assert_eq!(tc.high_qc.view, 0);
    }

    #[test]
    fn test_verify_commit_qc_valid() {
        let (sks, vs) = test_validator_set(4);
        let view = 10u64;
        let block_hash = B256::repeat_byte(0xC1);

        let mut collector = VoteCollector::new(view, block_hash, vs.len());
        let msg = commit_signing_message(view, &block_hash, &alloy_primitives::B256::ZERO);
        for i in 0..3u32 {
            collector.add_vote(i, sks[i as usize].sign(&msg)).unwrap();
        }
        let commit_qc = collector.build_qc_with_message(&vs, &msg).unwrap();

        verify_commit_qc(&commit_qc, &vs, &alloy_primitives::B256::ZERO)
            .expect("verify_commit_qc should succeed");
    }

    #[test]
    fn test_verify_commit_qc_insufficient_signers() {
        let (sks, vs) = test_validator_set(4);
        let view = 11u64;
        let block_hash = B256::repeat_byte(0xC2);

        let msg = commit_signing_message(view, &block_hash, &alloy_primitives::B256::ZERO);
        let sig = sks[0].sign(&msg);
        let agg_sig = AggregateSignature::aggregate(&[&sig]).unwrap();

        let qc = QuorumCertificate {
            view,
            block_hash,
            aggregate_signature: agg_sig,
            signers: {
                let mut bv = bitvec![u8, Msb0; 0; 4];
                bv.set(0, true);
                bv
            },
        };

        let result = verify_commit_qc(&qc, &vs, &alloy_primitives::B256::ZERO);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::InvalidQC { view: v, reason } => {
                assert_eq!(v, view);
                assert!(reason.contains("insufficient signers"), "got: {reason}");
            }
            other => panic!("expected InvalidQC, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_qc_rejects_commit_qc() {
        let (sks, vs) = test_validator_set(4);
        let view = 12u64;
        let block_hash = B256::repeat_byte(0xC3);

        let mut collector = VoteCollector::new(view, block_hash, vs.len());
        let msg = commit_signing_message(view, &block_hash, &alloy_primitives::B256::ZERO);
        for i in 0..3u32 {
            collector.add_vote(i, sks[i as usize].sign(&msg)).unwrap();
        }
        let commit_qc = collector.build_qc_with_message(&vs, &msg).unwrap();

        let result = verify_qc(&commit_qc, &vs);
        assert!(result.is_err(), "verify_qc should reject a CommitQC");
    }

    #[test]
    fn test_verify_commit_qc_rejects_prepare_qc() {
        let (sks, vs) = test_validator_set(4);
        let view = 13u64;
        let block_hash = B256::repeat_byte(0xC4);

        let mut collector = VoteCollector::new(view, block_hash, vs.len());
        let msg = signing_message(view, &block_hash);
        for i in 0..3u32 {
            collector.add_vote(i, sks[i as usize].sign(&msg)).unwrap();
        }
        let prepare_qc = collector.build_qc(&vs).unwrap();

        let result = verify_commit_qc(&prepare_qc, &vs, &alloy_primitives::B256::ZERO);
        assert!(
            result.is_err(),
            "verify_commit_qc should reject a PrepareQC"
        );
    }

    #[test]
    fn test_timeout_collector_duplicate_rejected() {
        let (sks, _vs) = test_validator_set(4);
        let view = 10u64;
        let genesis_qc = QuorumCertificate::genesis();
        let mut collector = TimeoutCollector::new(view, 4);
        let msg = timeout_signing_message(view);
        let sig = sks[0].sign(&msg);

        collector
            .add_timeout(0, sig.clone(), genesis_qc.clone())
            .expect("first timeout should succeed");

        let result = collector.add_timeout(0, sks[0].sign(&msg), genesis_qc);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::DuplicateVote {
                view: v,
                validator_index,
            } => {
                assert_eq!(v, view);
                assert_eq!(validator_index, 0);
            }
            other => panic!("expected DuplicateVote, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_tc_checks_quorum_bitmap_and_aggregate_signature() {
        let (sks, vs) = test_validator_set(4);
        let view = 14u64;
        let mut collector = TimeoutCollector::new(view, vs.len());
        let msg = timeout_signing_message(view);
        for i in 0..3u32 {
            collector
                .add_timeout(i, sks[i as usize].sign(&msg), QuorumCertificate::genesis())
                .unwrap();
        }

        let mut tc = collector.build_tc(&vs).expect("quorum TC should form");
        verify_tc(&tc, &vs).expect("valid TC aggregate should verify");

        let wrong_msg = timeout_signing_message(view + 1);
        let wrong_sigs: Vec<_> = (0..3u32)
            .map(|i| sks[i as usize].sign(&wrong_msg))
            .collect();
        let wrong_refs: Vec<_> = wrong_sigs.iter().collect();
        tc.aggregate_signature = AggregateSignature::aggregate(&wrong_refs).unwrap();
        assert!(
            verify_tc(&tc, &vs).is_err(),
            "a signer bitmap cannot authenticate an aggregate over another view"
        );

        tc.signers.set(2, false);
        assert!(
            verify_tc(&tc, &vs).is_err(),
            "a TC bitmap below quorum must be rejected before pairing verification"
        );
    }

    #[test]
    fn test_build_tc_rejects_validator_set_size_mismatch() {
        let (sks, vs) = test_validator_set(4);
        let (_, smaller_vs) = test_validator_set(3);
        let view = 15u64;
        let msg = timeout_signing_message(view);
        let mut collector = TimeoutCollector::new(view, vs.len());
        for i in 0..3u32 {
            collector
                .add_timeout(i, sks[i as usize].sign(&msg), QuorumCertificate::genesis())
                .unwrap();
        }

        assert!(matches!(
            collector.build_tc(&smaller_vs),
            Err(ConsensusError::InvalidTC { .. })
        ));
    }

    #[test]
    fn test_timeout_collector_view_getter() {
        let collector = TimeoutCollector::new(42, 4);
        assert_eq!(collector.view(), 42);

        let collector2 = TimeoutCollector::new(0, 7);
        assert_eq!(collector2.view(), 0);
    }

    #[test]
    fn test_proposal_signing_message_differs_from_vote() {
        let view = 42u64;
        let hash = B256::repeat_byte(0xAA);
        let vote_msg = signing_message(view, &hash);
        let prop_msg = proposal_signing_message(view, &hash, &None);
        // First 40 bytes match
        assert_eq!(&vote_msg[..], &prop_msg[..40]);
        // Proposal has 32 extra zero bytes for no-changes hash
        assert_eq!(&prop_msg[40..], &[0u8; 32]);
    }

    #[test]
    fn test_proposal_signing_message_changes_hash() {
        let view = 1u64;
        let hash = B256::repeat_byte(0xBB);
        let msg_none = proposal_signing_message(view, &hash, &None);
        let msg_empty = proposal_signing_message(view, &hash, &Some(vec![]));
        // None and empty vec both produce zero hash
        assert_eq!(msg_none, msg_empty);

        let changes = Some(vec![n42_h2_primitives::consensus::ValidatorChange::Remove {
            address: alloy_primitives::Address::repeat_byte(0x01),
        }]);
        let msg_with = proposal_signing_message(view, &hash, &changes);
        // With changes, the hash portion differs
        assert_ne!(&msg_with[40..], &[0u8; 32]);
        assert_ne!(msg_with, msg_none);
    }

    #[test]
    fn test_proposal_signing_deterministic() {
        let changes = Some(vec![n42_h2_primitives::consensus::ValidatorChange::Remove {
            address: alloy_primitives::Address::repeat_byte(0x42),
        }]);
        let m1 = proposal_signing_message(1, &B256::ZERO, &changes);
        let m2 = proposal_signing_message(1, &B256::ZERO, &changes);
        assert_eq!(m1, m2);
    }

    #[test]
    fn h2_v4_profile_forms_and_verifies_qc_only_in_pop_domain() {
        let (sks, vs) = test_validator_set(4);
        let identity = H2V4ChainIdentity {
            chain_id: 42,
            genesis_hash: B256::repeat_byte(0xA4),
        };
        let profile = ConsensusSigningProfile::H2V4(identity);
        let view = 17;
        let block_hash = B256::repeat_byte(0xB4);
        let message = profile.vote_message(view, block_hash);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());
        for index in 0..3 {
            collector
                .add_vote(index, profile.sign(&sks[index as usize], &message))
                .unwrap();
        }

        let qc = collector
            .build_qc_with_profile_message(&vs, &message, profile)
            .unwrap();
        verify_qc_with_profile(&qc, &vs, profile).unwrap();
        assert!(verify_qc(&qc, &vs).is_err());
    }

    #[test]
    fn h2_v4_profile_forms_and_verifies_commit_qc_only_in_pop_domain() {
        let (sks, vs) = test_validator_set(4);
        let profile = ConsensusSigningProfile::H2V4(H2V4ChainIdentity {
            chain_id: 42,
            genesis_hash: B256::repeat_byte(0xA5),
        });
        let view = 18;
        let block_hash = B256::repeat_byte(0xB5);
        let changes_hash = B256::ZERO;
        let message = profile.commit_message(view, block_hash, changes_hash);
        let mut collector = VoteCollector::new(view, block_hash, vs.len());
        for index in 0..3 {
            collector
                .add_vote(index, profile.sign(&sks[index as usize], &message))
                .unwrap();
        }

        let qc = collector
            .build_qc_with_profile_message(&vs, &message, profile)
            .unwrap();
        verify_commit_qc_with_profile(&qc, &vs, &changes_hash, profile).unwrap();
        assert!(verify_commit_qc(&qc, &vs, &changes_hash).is_err());
    }

    #[test]
    fn h2_v4_profile_forms_and_verifies_timeout_certificate() {
        let (sks, vs) = test_validator_set(4);
        let profile = ConsensusSigningProfile::H2V4(H2V4ChainIdentity {
            chain_id: 42,
            genesis_hash: B256::repeat_byte(0xC4),
        });
        let view = 19;
        let message = profile.timeout_message(view);
        let mut collector = TimeoutCollector::new(view, vs.len());
        for index in 0..3 {
            collector
                .add_timeout(
                    index,
                    profile.sign(&sks[index as usize], &message),
                    QuorumCertificate::genesis(),
                )
                .unwrap();
        }

        let tc = collector.build_tc_with_profile(&vs, profile).unwrap();
        verify_tc_with_profile(&tc, &vs, profile).unwrap();
        assert!(verify_tc(&tc, &vs).is_err());
    }

    /// TC construction batches the same way QC construction does, so it needs
    /// the same guarantee: a bad signature is localized and dropped rather than
    /// failing the whole batch, and its signer bit stays clear.
    #[test]
    fn h2_v4_timeout_certificate_drops_only_the_bad_signature() {
        let (sks, vs) = test_validator_set(4);
        let profile = ConsensusSigningProfile::H2V4(H2V4ChainIdentity {
            chain_id: 42,
            genesis_hash: B256::repeat_byte(0xC5),
        });
        let view = 23;
        let message = profile.timeout_message(view);
        let mut collector = TimeoutCollector::new(view, vs.len());
        for index in 0..4u32 {
            // Validator 2 signs the wrong view, which is exactly what the batch
            // must catch without discarding the other three.
            let signature = if index == 2 {
                profile.sign(&sks[2], &profile.timeout_message(view + 1))
            } else {
                profile.sign(&sks[index as usize], &message)
            };
            collector
                .add_timeout(index, signature, QuorumCertificate::genesis())
                .unwrap();
        }

        let tc = collector.build_tc_with_profile(&vs, profile).unwrap();
        verify_tc_with_profile(&tc, &vs, profile).unwrap();
        assert!(
            !tc.signers[2],
            "the wrong-view signer must not appear in the TC bitmap"
        );
        assert_eq!(
            tc.signers.count_ones(),
            3,
            "the other three timeouts must survive"
        );
    }

    /// gov5's v4 profile signs a zero validator-change hash unconditionally
    /// (`interop_v4.go` passes `types.Hash{}`), and its first revision does not
    /// support reconfiguration at all. If this side derived a real hash from
    /// the changes, nothing would look wrong until a committee change actually
    /// landed — at that view the two clients would sign different preimages
    /// for the same proposal, each reject the other's signature, and the
    /// chain would stall precisely when it was reconfiguring.
    ///
    /// Native signing keeps binding the real hash; only the v4 profile is
    /// pinned, and only until both sides specify one derivation they share.
    #[test]
    fn h2_v4_signing_ignores_validator_changes() {
        use n42_h2_primitives::consensus::{H2V4ChainIdentity, ValidatorChange};

        let identity = H2V4ChainIdentity {
            chain_id: 94,
            genesis_hash: B256::repeat_byte(0x11),
        };
        let profile = ConsensusSigningProfile::H2V4(identity);
        let view = 7;
        let block_hash = B256::repeat_byte(0xAB);
        let changes = Some(vec![ValidatorChange::Remove {
            address: alloy_primitives::Address::with_last_byte(3),
        }]);

        // Sanity: these changes really do hash to something non-zero, so the
        // assertions below are not vacuous.
        assert_ne!(validator_changes_hash(&changes), B256::ZERO);

        assert_eq!(
            profile.proposal_message(view, block_hash, &changes),
            profile.proposal_message(view, block_hash, &None),
            "v4 proposal signing must not depend on validator changes"
        );
        assert_eq!(
            profile.commit_message(view, block_hash, validator_changes_hash(&changes)),
            profile.commit_message(view, block_hash, B256::ZERO),
            "v4 commit signing must not depend on validator changes"
        );

        // Native is unchanged: it still binds the changes.
        let native = ConsensusSigningProfile::Native;
        assert_ne!(
            native.proposal_message(view, block_hash, &changes),
            native.proposal_message(view, block_hash, &None),
            "native signing must keep binding validator changes"
        );
    }
}
