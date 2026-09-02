use alloy_primitives::B256;
use n42_h2_primitives::consensus::{ConsensusMessage, PrepareQC, Proposal, ViewNumber};

use super::round::Phase;
use super::state_machine::{ConsensusEngine, EngineOutput};
use crate::error::{ConsensusError, ConsensusResult};

const MAX_IMPORTED_BLOCKS: usize = 64;

impl ConsensusEngine {
    /// Recovers validator changes from a late Proposal whose block has already
    /// been committed by a Decide. GossipSub does not guarantee ordering, so a
    /// follower can observe Decide first and Proposal second for the same view.
    /// Without this recovery path, the follower misses the leader's committed
    /// validator changes and diverges at the next epoch boundary.
    pub(super) fn recover_late_committed_proposal(
        &mut self,
        proposal: &Proposal,
    ) -> ConsensusResult<bool> {
        let Some(changes) = proposal.validator_changes.as_ref() else {
            return Ok(false);
        };
        if changes.is_empty() {
            // `None` and `Some([])` have the same signed changes hash. Treat
            // both as no reconfiguration so unsigned representation details
            // cannot change consensus state.
            return Ok(false);
        }

        let current_view = self.round_state.current_view();
        if proposal.view >= current_view {
            return Ok(false);
        }

        let last_committed = self.round_state.last_committed_qc();
        if last_committed.view != proposal.view || last_committed.block_hash != proposal.block_hash
        {
            return Ok(false);
        }

        let expected_hash = self.cached_changes_hash(&proposal.block_hash);
        if expected_hash == B256::ZERO {
            return Ok(false);
        }

        let actual_hash = crate::EpochManager::hash_changes(changes);
        if actual_hash != expected_hash {
            tracing::warn!(
                target: "n42::cl::proposal",
                view = proposal.view,
                block_hash = %proposal.block_hash,
                expected_hash = %expected_hash,
                actual_hash = %actual_hash,
                "ignoring late committed proposal with mismatched validator_changes hash"
            );
            return Ok(false);
        }

        let proposal_epoch = self.epoch_manager.epoch_for_view(proposal.view);
        if self.epoch_manager.current_epoch() != proposal_epoch
            || self.epoch_manager.has_staged_next()
        {
            return Ok(false);
        }

        let view_set = self.validator_set_for_view(proposal.view);
        let expected_leader = self.leader_index_for_view(proposal.view);
        if proposal.proposer != expected_leader {
            tracing::warn!(
                target: "n42::cl::proposal",
                view = proposal.view,
                expected = expected_leader,
                actual = proposal.proposer,
                "ignoring late committed proposal from unexpected proposer"
            );
            return Ok(false);
        }

        let pk = match view_set.get_public_key(proposal.proposer) {
            Ok(pk) => pk,
            Err(error) => {
                tracing::warn!(
                    target: "n42::cl::proposal",
                    view = proposal.view,
                    proposer = proposal.proposer,
                    error = %error,
                    "ignoring late committed proposal with unknown proposer"
                );
                return Ok(false);
            }
        };
        let prop_msg = self.signing_profile.proposal_message(
            proposal.view,
            proposal.block_hash,
            &proposal.validator_changes,
        );
        if !self
            .signing_profile
            .verify_single(pk, &prop_msg, &proposal.signature)
        {
            tracing::warn!(
                target: "n42::cl::proposal",
                view = proposal.view,
                proposer = proposal.proposer,
                "ignoring late committed proposal with invalid signature"
            );
            return Ok(false);
        }

        self.epoch_manager.replace_pending_from_proposal(changes);
        self.epoch_manager.commit_pending_changes()?;
        self.emit(EngineOutput::CommittedBlockValidatorChangesRecovered {
            view: proposal.view,
            block_hash: proposal.block_hash,
            validator_changes: changes.clone(),
        })?;
        tracing::warn!(
            target: "n42::cl::proposal",
            view = proposal.view,
            block_hash = %proposal.block_hash,
            changes = ?changes,
            "recovered validator changes from late committed proposal"
        );
        Ok(true)
    }

    /// Called when this node (as leader) has a block ready to propose.
    pub(super) fn on_block_ready(
        &mut self,
        block_hash: B256,
        tx_root_hash: Option<B256>,
    ) -> ConsensusResult<()> {
        let view = self.round_state.current_view();

        if !self.is_current_leader() {
            tracing::debug!(target: "n42::cl::proposal", view, "not leader, ignoring block ready");
            return Ok(());
        }

        if self.round_state.phase() != Phase::WaitingForProposal {
            tracing::debug!(target: "n42::cl::proposal", view, phase = ?self.round_state.phase(), "not in proposal phase");
            return Ok(());
        }

        let justify_qc = self.round_state.locked_qc().clone();
        let piggybacked_qc = self.previous_prepare_qc.take();
        let chained = piggybacked_qc.is_some();

        // Include any pending validator changes so all nodes apply the same
        // changes at CommitQC time (consensus-safe commit-then-activate).
        let validator_changes = self.epoch_manager.pending_changes_for_proposal();
        if matches!(
            self.signing_profile,
            super::quorum::ConsensusSigningProfile::H2V4(_)
        ) && validator_changes
            .as_ref()
            .is_some_and(|changes| !changes.is_empty())
        {
            return Err(ConsensusError::H2V4ValidatorChangesUnsupported);
        }
        let changes_hash = match validator_changes.as_ref() {
            Some(changes) => crate::EpochManager::hash_changes(changes),
            None => B256::ZERO,
        };
        // Cache for the leader's R2 commit-vote signing path. The
        // BoundedFifoMap caps the entries and evicts in real insertion order.
        self.pending_changes_hashes.insert(block_hash, changes_hash);

        // Signature covers changes_hash to prevent Byzantine relay from swapping changes.
        let prop_msg = self
            .signing_profile
            .proposal_message(view, block_hash, &validator_changes);
        let signature = self.signing_profile.sign(&self.secret_key, &prop_msg);
        let vote_msg = self.signing_profile.vote_message(view, block_hash);

        // Use the epoch-aware index for the proposer field.  In the epoch-drift zone
        // (staging committed but epoch boundary not yet fired), validator_set_for_view
        // already returns the staged next_set for the current view, so followers compute
        // expected_leader and look up the proposer's public key using that set.
        // self.my_index is only updated at the epoch boundary; using it here would send
        // the OLD index, causing an InvalidProposer rejection whenever the new validator's
        // address sorts before this node's, shifting this node's position in the set.
        let proposer = self
            .local_validator_index_for_view(view)
            .unwrap_or(self.my_index);

        let proposal = Proposal {
            view,
            block_hash,
            justify_qc,
            proposer,
            signature,
            prepare_qc: piggybacked_qc,
            tx_root_hash,
            validator_changes,
        };

        if proposal.validator_changes.is_some() {
            tracing::info!(target: "n42::cl::proposal",
                view, %block_hash,
                changes = ?proposal.validator_changes,
                "proposing block with validator changes"
            );
        }

        tracing::debug!(target: "n42::cl::proposal",
            view, %block_hash,
            chained,
            "proposing block"
        );

        let view_set_len = self.validator_set_for_view(view).len();
        self.vote_collector = Some(crate::protocol::quorum::VoteCollector::new(
            view,
            block_hash,
            view_set_len,
        ));
        self.commit_collector = Some(crate::protocol::quorum::VoteCollector::new(
            view,
            block_hash,
            view_set_len,
        ));
        self.round_state.enter_voting();

        // Leader self-vote: GossipSub does not deliver messages back to the sender,
        // so the leader must add its own vote directly to the collector. Record the
        // vote in last_voted_view *before* signing — same crash-safety invariant as
        // send_vote(): we err on the side of not voting rather than double-voting.
        if !self.round_state.may_vote_in(view) {
            tracing::warn!(
                target: "n42::cl::proposal",
                view,
                last_voted = self.round_state.last_voted_view(),
                "leader already voted in this view; aborting proposal"
            );
            return Ok(());
        }
        self.round_state.record_vote(view);
        // Persist the leader self-vote with the same crash-safety contract as
        // send_vote(); a fsync failure aborts the proposal.
        self.vote_log.record_vote(view)?;
        // Reuse the vote_msg computed above (same view + block_hash).
        let leader_vote_sig = self.signing_profile.sign(&self.secret_key, &vote_msg);
        if let Some(ref mut collector) = self.vote_collector {
            collector.add_verified_vote(self.my_index, leader_vote_sig)?;
        }

        self.view_timing.proposal_sent = Some(std::time::Instant::now());
        self.emit(EngineOutput::BroadcastMessage(ConsensusMessage::Proposal(
            proposal,
        )))?;

        // Check if quorum already reached (single-validator scenario).
        self.try_form_prepare_qc()
    }

    /// Processes a proposal from the leader.
    pub(super) fn process_proposal(&mut self, proposal: Proposal) -> ConsensusResult<()> {
        let view = self.round_state.current_view();

        if proposal.view != view {
            return Err(ConsensusError::ViewMismatch {
                current: view,
                received: proposal.view,
            });
        }

        let view_set = self.validator_set_for_view(view);
        let expected_leader = self.leader_index_for_view(view);
        if proposal.proposer != expected_leader {
            return Err(ConsensusError::InvalidProposer {
                view,
                expected: expected_leader,
                actual: proposal.proposer,
            });
        }

        let pk = view_set.get_public_key(proposal.proposer)?;
        if matches!(
            self.signing_profile,
            super::quorum::ConsensusSigningProfile::H2V4(_)
        ) && proposal
            .validator_changes
            .as_ref()
            .is_some_and(|changes| !changes.is_empty())
        {
            return Err(ConsensusError::H2V4ValidatorChangesUnsupported);
        }
        // Verify proposal signature covers (view, block_hash, changes_hash).
        let prop_msg = self.signing_profile.proposal_message(
            view,
            proposal.block_hash,
            &proposal.validator_changes,
        );
        if !self
            .signing_profile
            .verify_single(pk, &prop_msg, &proposal.signature)
        {
            return Err(ConsensusError::InvalidSignature {
                view,
                validator_index: proposal.proposer,
            });
        }

        // Track the exact signed message rather than only block_hash: validator
        // changes are part of the signature domain and two different change
        // sets for the same block are also equivocation. Record only after BLS
        // verification so a forged first message cannot poison the tracker.
        let proposal_commitment = B256::from(*blake3::hash(&prop_msg).as_bytes());
        // edition-2021: N42-26 writes this as a let-chain; filtering the
        // Option keeps the guard and the body identical.
        if let Some((previous_commitment, previous_block_hash)) = self
            .proposal_equivocation_tracker
            .get(&proposal.proposer)
            .copied()
            .filter(|&(previous_commitment, _)| previous_commitment != proposal_commitment)
        {
            // Preserve the existing block-hash evidence shape for ordinary
            // double proposals. If only the signed changes differ, emit the
            // two distinct signed-message commitments instead.
            let (hash1, hash2) = if previous_block_hash != proposal.block_hash {
                (previous_block_hash, proposal.block_hash)
            } else {
                (previous_commitment, proposal_commitment)
            };
            tracing::warn!(target: "n42::cl::proposal", view,
                proposer = proposal.proposer, %hash1, %hash2,
                "proposal equivocation detected");
            self.emit(EngineOutput::EquivocationDetected {
                view,
                validator: proposal.proposer,
                hash1,
                hash2,
            })?;
            return Ok(());
        }
        self.proposal_equivocation_tracker
            .entry(proposal.proposer)
            .or_insert((proposal_commitment, proposal.block_hash));

        // Verify the justify_qc's aggregate BLS signature to prevent a Byzantine leader
        // from injecting a forged QC that manipulates honest nodes' locked_qc.
        // Genesis QC (view 0) is exempt — it has no real aggregate signatures.
        // Uses verify_qc_any_domain_or_known because justify_qc may be either a
        // prepare QC or commit QC. Exact locally persisted QCs remain usable after
        // restart even when their validator-changes signing-domain cache is empty.
        if proposal.justify_qc.view > 0 {
            self.verify_qc_any_domain_or_known(&proposal.justify_qc)
                .map_err(|e| {
                    tracing::warn!(target: "n42::cl::proposal",
                        view, proposer = proposal.proposer, qc_view = proposal.justify_qc.view,
                        "rejecting proposal with invalid justify_qc: {e}"
                    );
                    e
                })?;
        }

        if !self.round_state.is_safe_to_vote(&proposal.justify_qc) {
            return Err(ConsensusError::SafetyViolation {
                qc_view: proposal.justify_qc.view,
                locked_view: self.round_state.locked_qc().view,
            });
        }

        self.round_state.update_locked_qc(&proposal.justify_qc);

        // Chained mode: process piggybacked PrepareQC if present.
        if let Some(ref piggybacked_qc) = proposal.prepare_qc {
            let verification = self
                .resolve_qc_validator_set(piggybacked_qc)
                .and_then(|set| {
                    super::quorum::verify_qc_with_profile(piggybacked_qc, set, self.signing_profile)
                });
            match verification {
                Ok(()) => {
                    tracing::debug!(target: "n42::cl::proposal",
                        view,
                        qc_view = piggybacked_qc.view,
                        "accepted piggybacked PrepareQC from proposal"
                    );
                    self.round_state.update_locked_qc(piggybacked_qc);
                }
                Err(e) => {
                    // Invalid piggybacked QC is not fatal — the proposal itself is valid.
                    tracing::warn!(target: "n42::cl::proposal", view, error = %e, "rejected invalid piggybacked PrepareQC, ignoring");
                }
            }
        }

        // Apply validator changes from the leader's Proposal.
        // `Some(changes)` → leader has changes, replace local pending.
        // `None` → leader has no changes. Do NOT clear local pending —
        // this node may have pending changes from RPC that haven't been
        // included in a Proposal yet (the node wasn't leader). They will
        // be included when this node next becomes leader.
        const MAX_CHANGES_PER_PROPOSAL: usize = 4;
        // edition-2021: N42-26 writes this as a let-chain. This one has an
        // `else`, so the filter must stay inside the same `if let` expression.
        let changes_hash = if let Some(changes) = proposal
            .validator_changes
            .as_ref()
            .filter(|changes| !changes.is_empty())
        {
            if changes.len() > MAX_CHANGES_PER_PROPOSAL {
                return Err(ConsensusError::TooManyValidatorChanges {
                    count: changes.len(),
                    max: MAX_CHANGES_PER_PROPOSAL,
                });
            }
            let hash = crate::EpochManager::hash_changes(changes);
            self.epoch_manager.replace_pending_from_proposal(changes);
            hash
        } else {
            B256::ZERO
        };
        // Cache the proposal's changes_hash so the R2 commit-vote signing
        // path can include it.
        self.pending_changes_hashes
            .insert(proposal.block_hash, changes_hash);

        // Store pending tx_root_hash for future DA verification if present.
        if let Some(tx_root) = proposal.tx_root_hash {
            self.pending_tx_roots.insert(proposal.block_hash, tx_root);
        }

        self.round_state.enter_voting();
        self.view_timing.proposal_received = Some(std::time::Instant::now());

        // Trigger eager import in background (needed for finalization).
        self.emit(EngineOutput::ExecuteBlock(proposal.block_hash))?;

        // Gov5's H2 profile is import-gated: an R1 vote attests that this node
        // has executed and validated the proposed payload, not merely seen its
        // hash. Keep the native profile's established optimistic path intact.
        if matches!(
            self.signing_profile,
            super::quorum::ConsensusSigningProfile::H2V4(_)
        ) {
            self.pending_proposal = Some(super::state_machine::PendingProposal {
                view,
                block_hash: proposal.block_hash,
                justify_block: proposal.justify_qc.block_hash,
            });
            if self.imported_blocks.contains(&proposal.block_hash) {
                if !self.extends_justify(proposal.block_hash) {
                    return Ok(());
                }
                tracing::info!(target: "n42::interop::h2v4", view, block_hash = %proposal.block_hash, "import-gated vote: block already execution-validated");
                self.send_vote(view, proposal.block_hash)?;
            } else {
                tracing::info!(target: "n42::interop::h2v4", view, block_hash = %proposal.block_hash, "import-gated vote: waiting for execution validation");
            }
            return Ok(());
        }

        // Optimistic Voting: vote immediately after Proposal validation.
        //
        // R1 vote signs (view, block_hash) — it does NOT commit to block validity.
        // The Proposal has already been fully verified: leader identity, BLS signature,
        // justify_qc aggregate signature, and HotStuff-2 safety rules.
        //
        // Block validity (EVM execution) is verified during finalization:
        //   - new_payload validates the block in reth's engine tree
        //   - FCU commits it to the canonical chain
        //   - If invalid: FCU fails → view change recovers
        //
        // This eliminates the ~300-500ms vote_delay caused by waiting for BlockData
        // arrival and new_payload completion before voting.
        tracing::info!(target: "n42::cl::proposal", view, block_hash = %proposal.block_hash, "optimistic vote: voting immediately after proposal validation");
        self.send_vote(view, proposal.block_hash)?;

        Ok(())
    }

    /// Processes a PrepareQC from the leader: validates the QC and sends a CommitVote.
    pub(super) fn process_prepare_qc(&mut self, pqc: PrepareQC) -> ConsensusResult<()> {
        let view = self.round_state.current_view();

        if pqc.view != view {
            return Err(ConsensusError::ViewMismatch {
                current: view,
                received: pqc.view,
            });
        }

        if pqc.qc.view != pqc.view {
            return Err(ConsensusError::ViewMismatch {
                current: pqc.view,
                received: pqc.qc.view,
            });
        }

        if pqc.qc.block_hash != pqc.block_hash {
            return Err(ConsensusError::BlockHashMismatch {
                expected: pqc.block_hash,
                got: pqc.qc.block_hash,
            });
        }

        let qc_set = self.resolve_qc_validator_set(&pqc.qc)?;
        super::quorum::verify_qc_with_profile(&pqc.qc, qc_set, self.signing_profile)?;
        self.round_state.update_locked_qc(&pqc.qc);
        self.round_state.enter_pre_commit();

        if !self.is_local_validator_active_for_view(view) {
            tracing::debug!(
                target: "n42::cl::proposal",
                view,
                my_index = self.my_index,
                "observer (or stale my_index): skipping commit vote"
            );
            return Ok(());
        }

        tracing::debug!(target: "n42::cl::proposal", view, block_hash = %pqc.block_hash, "received valid PrepareQC, sending commit vote");

        if !self.round_state.may_commit_vote_in(view) {
            tracing::warn!(target: "n42::cl::proposal", view,
                last_commit_voted = self.round_state.last_commit_voted_view(),
                "suppressed duplicate commit vote (already commit-voted in this view)");
            return Ok(());
        }
        // Persist before signing for the same crash-safety reason as R1.
        self.round_state.record_commit_vote(view);
        self.vote_log.record_commit_vote(view)?;

        // Bind this R2 commit-vote signature to the same changes_hash the
        // leader's proposal carried.
        let changes_hash = self.cached_changes_hash(&pqc.block_hash);
        let commit_msg = self
            .signing_profile
            .commit_message(view, pqc.block_hash, changes_hash);
        let commit_sig = self.signing_profile.sign(&self.secret_key, &commit_msg);
        let leader = self.leader_index_for_view(view);

        let commit_vote = n42_h2_primitives::consensus::CommitVote {
            view,
            block_hash: pqc.block_hash,
            voter: self.my_index,
            signature: commit_sig,
        };

        self.view_timing.commit_vote_sent = Some(std::time::Instant::now());
        self.emit(EngineOutput::SendToValidator(
            leader,
            ConsensusMessage::CommitVote(commit_vote),
        ))
    }

    /// Sends a Round 1 vote for the given view and block hash.
    ///
    /// Checks `last_voted_view` to prevent double-voting after crash recovery
    /// (fundamental BFT safety invariant).
    pub(super) fn send_vote(&mut self, view: ViewNumber, block_hash: B256) -> ConsensusResult<()> {
        if !self.is_local_validator_active_for_view(view) {
            tracing::debug!(
                target: "n42::cl::proposal",
                view,
                my_index = self.my_index,
                "observer (or stale my_index): skipping vote"
            );
            return Ok(());
        }
        if !self.round_state.may_vote_in(view) {
            tracing::warn!(
                target: "n42::cl::proposal",
                view,
                last_voted = self.round_state.last_voted_view(),
                "suppressed duplicate vote (already voted in this view)"
            );
            return Ok(());
        }
        // Record BEFORE signing/sending so a crash between record and send is safe
        // (we err on the side of not voting rather than double-voting). The
        // vote_log fsync MUST succeed before we sign — otherwise a crash after
        // signing but before record could let the recovered node re-vote.
        self.round_state.record_vote(view);
        self.vote_log.record_vote(view)?;

        let leader = self.leader_index_for_view(view);
        let vote_msg = self.signing_profile.vote_message(view, block_hash);
        let vote_sig = self.signing_profile.sign(&self.secret_key, &vote_msg);

        let vote = n42_h2_primitives::consensus::Vote {
            view,
            block_hash,
            voter: self.my_index,
            signature: vote_sig,
        };

        tracing::info!(target: "n42::cl::proposal", view, %block_hash, voter = self.my_index, target_leader = leader, "sending vote to leader");
        self.view_timing.vote_sent = Some(std::time::Instant::now());
        self.emit(EngineOutput::SendToValidator(
            leader,
            ConsensusMessage::Vote(vote),
        ))
    }

    /// Handles the BlockImported event from the orchestrator.
    ///
    /// Native optimistic voting uses this as execution diagnostics. Gov5 H2
    /// participant mode also releases the matching deferred R1 vote here.
    pub(super) fn on_block_imported(&mut self, block_hash: B256) -> ConsensusResult<()> {
        if self.imported_blocks.insert(block_hash) {
            if self.imported_block_fifo.len() >= MAX_IMPORTED_BLOCKS {
                self.evict_oldest_imported_block();
            }
            self.imported_block_fifo.push_back(block_hash);
        }

        // edition-2021: N42-26 writes this as a let-chain. Resolving the
        // pending view first also ends the borrow of `self` before `send_vote`.
        let pending_vote_view = self
            .pending_proposal
            .as_ref()
            .filter(|pending| {
                pending.view == self.round_state.current_view()
                    && pending.block_hash == block_hash
                    && self.round_state.may_vote_in(pending.view)
            })
            .map(|pending| pending.view);
        let profile_is_h2_v4 = matches!(
            self.signing_profile,
            super::quorum::ConsensusSigningProfile::H2V4(_)
        );
        if let Some(view) = pending_vote_view.filter(|_| profile_is_h2_v4) {
            if !self.extends_justify(block_hash) {
                return Ok(());
            }
            tracing::info!(target: "n42::interop::h2v4", view, %block_hash, "import-gated vote: execution validated, sending vote");
            self.send_vote(view, block_hash)?;
        }
        Ok(())
    }

    /// The extends rule: a proposal's block has to be a child of the block its
    /// justify QC certifies. `is_safe_to_vote` compares views only, so without
    /// this a leader that never imported the certified block can propose a
    /// sibling of it from a stale head — and a quorum that votes on views
    /// alone commits that sibling next to a block it already committed. gov5
    /// refuses exactly this (`extendsJustify`); it wedges instead when a
    /// Rust quorum does not.
    ///
    /// A genesis justify (no block) and an unknown parent pass, as they do in
    /// gov5: the rule refuses what it can see, and never a vote it cannot judge.
    fn extends_justify(&self, block_hash: B256) -> bool {
        let Some(pending) = self.pending_proposal.as_ref() else {
            return true;
        };
        if pending.justify_block == B256::ZERO {
            return true;
        }
        let Some(parent) = self.imported_parents.get(&block_hash).copied() else {
            return true;
        };
        // A zero parent is no parent: gov5 reads it as unknown, and so do
        // the harness's mock blocks.
        if parent == B256::ZERO {
            return true;
        }
        if parent != pending.justify_block {
            tracing::warn!(target: "n42::interop::h2v4",
                view = pending.view, %block_hash, %parent, justify_block = %pending.justify_block,
                "import-gated vote REFUSED: proposal does not extend its justify QC's block"
            );
            return false;
        }
        true
    }

    /// Drops the oldest import evidence, skipping the hash a deferred H2 vote is
    /// still waiting on.
    ///
    /// The block whose import releases the pending vote is not necessarily the
    /// most recent one imported: catching up delivers a burst of blocks, and 64
    /// of them are enough to push the awaited hash out. Losing that entry is
    /// terminal for the view rather than merely wasteful — the orchestrator
    /// deduplicates both block data and eager imports, so no second
    /// `BlockImported` ever arrives for a hash reth already executed, and the
    /// vote is never released. Rotating the live hash to the back keeps the
    /// cache bounded (by at most one extra entry) without stranding it.
    fn evict_oldest_imported_block(&mut self) {
        let live = self
            .pending_proposal
            .as_ref()
            .map(|pending| pending.block_hash);
        for _ in 0..self.imported_block_fifo.len() {
            let Some(oldest) = self.imported_block_fifo.pop_front() else {
                return;
            };
            if Some(oldest) == live {
                self.imported_block_fifo.push_back(oldest);
                continue;
            }
            self.imported_blocks.remove(&oldest);
            self.imported_parents.remove(&oldest);
            return;
        }
    }
}
