use alloy_primitives::B256;
use n42_h2_primitives::consensus::{CommitVote, ConsensusMessage, PrepareQC, Vote};
use std::collections::HashMap;

use super::state_machine::{ConsensusEngine, EngineOutput};
use crate::error::{ConsensusError, ConsensusResult};

/// Checks an equivocation tracker for a validator voting for two different blocks.
/// Returns `Some((hash1, hash2))` if equivocation detected, `None` otherwise.
pub(super) fn check_equivocation(
    tracker: &mut HashMap<u32, B256>,
    voter: u32,
    block_hash: B256,
) -> Option<(B256, B256)> {
    if let Some(&prev) = tracker.get(&voter) {
        if prev != block_hash {
            return Some((prev, block_hash));
        }
    } else {
        tracker.insert(voter, block_hash);
    }
    None
}

impl ConsensusEngine {
    /// A vote for a view this node led recently and has left: no longer part
    /// of the protocol, but a leader wants to know that the voter is keeping
    /// up (see `voters_seen`). A real vote that was merely slow or a progress
    /// vote (`progress_vote_message`) both say the voter has imported the
    /// block; verified before it is noted, so a peer cannot vouch for
    /// another's progress. Anything else is ignored.
    pub(super) fn note_late_vote(&mut self, vote: &Vote) {
        let view = self.round_state.current_view();
        if !(vote.view < view
            && view - vote.view <= super::state_machine::VOTERS_SEEN_WINDOW as u64
            && self.is_leader_for_view(vote.view))
        {
            return;
        }
        let view_set = self.validator_set_for_view(vote.view);
        let Ok(pk) = view_set.get_public_key(vote.voter) else { return };
        let late = self.signing_profile.vote_message(vote.view, vote.block_hash);
        let progress = self.signing_profile.progress_vote_message(vote.view, vote.block_hash);
        if self.signing_profile.verify_single(pk, &progress, &vote.signature)
            || self.signing_profile.verify_single(pk, &late, &vote.signature)
        {
            self.note_voter(vote.view, vote.voter);
        }
    }

    /// Processes a Round 1 (Prepare) vote from a validator.
    pub(super) fn process_vote(&mut self, vote: Vote) -> ConsensusResult<()> {
        self.process_vote_inner(vote, false)
    }

    /// Processes a vote whose exact message was authenticated by the engine's
    /// randomized batch verifier.
    pub(super) fn process_verified_vote(&mut self, vote: Vote) -> ConsensusResult<()> {
        self.process_vote_inner(vote, true)
    }

    fn process_vote_inner(&mut self, vote: Vote, signature_verified: bool) -> ConsensusResult<()> {
        let view = self.round_state.current_view();

        if vote.view != view {
            self.note_late_vote(&vote);
            return Err(ConsensusError::ViewMismatch {
                current: view,
                received: vote.view,
            });
        }

        // Votes are addressed to the leader (SendToValidator). Followers that receive
        // multi-path duplicates (or anything a Byzantine peer relays directly) drop
        // here, mirroring the R2 design. Aside from saving work, this prevents an
        // unauthenticated peer from poisoning equivocation_tracker with forged
        // (voter, hash) pairs and starving the real voter's later vote.
        if !self.is_current_leader() {
            return Ok(());
        }

        if !signature_verified {
            let view_set = self.validator_set_for_view(view);
            let pk = view_set.get_public_key(vote.voter)?;
            let msg = self.signing_profile.vote_message(view, vote.block_hash);
            if !self
                .signing_profile
                .verify_single(pk, &msg, &vote.signature)
            {
                return Err(ConsensusError::InvalidSignature {
                    view,
                    validator_index: vote.voter,
                });
            }
        }

        // Equivocation check is gated on a verified signature so that an unauthenticated
        // peer cannot poison the tracker against a real voter.
        if let Some((h1, h2)) =
            check_equivocation(&mut self.equivocation_tracker, vote.voter, vote.block_hash)
        {
            tracing::warn!(target: "n42::cl::voting", view, validator = vote.voter,
                hash1 = %h1, hash2 = %h2, "vote equivocation detected");
            self.emit(EngineOutput::EquivocationDetected {
                view,
                validator: vote.voter,
                hash1: h1,
                hash2: h2,
            })?;
            return Ok(());
        }

        // Compare with the collector only after signature verification and
        // equivocation tracking. Otherwise a Byzantine validator's vote for a
        // sibling hash is discarded before it can become evidence, making
        // detection depend on which vote arrived first.
        let expected_hash = match self.vote_collector.as_ref() {
            Some(c) => c.block_hash(),
            None => return Ok(()),
        };
        if vote.block_hash != expected_hash {
            tracing::debug!(target: "n42::cl::voting", view, voter = vote.voter,
                "ignoring verified vote for non-proposed block after equivocation tracking");
            return Ok(());
        }
        self.note_voter(view, vote.voter);

        let collector = match self.vote_collector.as_mut() {
            Some(c) => c,
            None => {
                tracing::warn!(target: "n42::cl::voting", view, "vote_collector not initialized, ignoring vote");
                return Ok(());
            }
        };
        match collector.add_verified_vote(vote.voter, vote.signature) {
            Ok(()) => {}
            Err(ConsensusError::DuplicateVote { .. }) => {
                tracing::debug!(
                    target: "n42::cl::voting",
                    view,
                    voter = vote.voter,
                    "ignoring duplicate vote (dual-path delivery)"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        tracing::debug!(target: "n42::cl::voting",
            view,
            voter = vote.voter,
            count = collector.vote_count(),
            "received vote"
        );

        self.try_form_prepare_qc()
    }

    /// Attempts to form a PrepareQC from collected Round 1 votes.
    ///
    /// When quorum is reached, broadcasts the QC, transitions to PreCommit,
    /// and self-votes for CommitVote (Round 2).
    pub(super) fn try_form_prepare_qc(&mut self) -> ConsensusResult<()> {
        let view = self.round_state.current_view();
        let view_set = self.validator_set_for_view(view);

        let has_quorum = self
            .vote_collector
            .as_ref()
            .is_some_and(|c| c.has_quorum(view_set.quorum_size()));

        if !has_quorum || self.prepare_qc.is_some() {
            return Ok(());
        }

        let collector = match self.vote_collector.as_ref() {
            Some(c) => c,
            None => {
                tracing::warn!(target: "n42::cl::voting", view, "vote_collector not initialized in try_form_prepare_qc");
                return Ok(());
            }
        };
        let vote_message = self
            .signing_profile
            .vote_message(view, collector.block_hash());
        let qc = collector.build_qc_with_profile_message(
            view_set,
            &vote_message,
            self.signing_profile,
        )?;

        tracing::debug!(target: "n42::cl::voting", view, signers = qc.signer_count(), "QC formed, entering pre-commit");

        self.view_timing.prepare_qc_formed = Some(std::time::Instant::now());
        self.view_timing.prepare_vote_count = collector.vote_count() as u32;
        self.prepare_qc = Some(qc.clone());
        self.round_state.enter_pre_commit();
        self.round_state.update_locked_qc(&qc);

        let block_hash = qc.block_hash;
        let prepare_qc_msg = PrepareQC {
            view,
            block_hash,
            qc,
        };
        self.emit(EngineOutput::BroadcastMessage(ConsensusMessage::PrepareQC(
            prepare_qc_msg,
        )))?;

        // Leader self-vote for CommitVote (Round 2). Bind to the same
        // changes_hash on_block_ready cached so this self-vote signs the
        // same domain as every follower's commit vote.
        if !self.round_state.may_commit_vote_in(view) {
            tracing::warn!(target: "n42::cl::voting", view,
                last_commit_voted = self.round_state.last_commit_voted_view(),
                "leader already cast a commit vote in this view; suppressing R2 self-vote");
            return Ok(());
        }
        self.round_state.record_commit_vote(view);
        self.vote_log.record_commit_vote(view)?;
        let changes_hash = self.cached_changes_hash(&block_hash);
        let commit_msg = self
            .signing_profile
            .commit_message(view, block_hash, changes_hash);
        let commit_sig = self.signing_profile.sign(&self.secret_key, &commit_msg);
        if let Some(ref mut collector) = self.commit_collector {
            collector.add_verified_vote(self.my_index, commit_sig)?;
        }

        self.try_form_commit_qc()
    }

    /// Processes a Round 2 (Commit) vote from a validator.
    pub(super) fn process_commit_vote(&mut self, cv: CommitVote) -> ConsensusResult<()> {
        self.process_commit_vote_inner(cv, false)
    }

    /// Processes a commit vote whose exact message was authenticated by the
    /// engine's randomized batch verifier.
    pub(super) fn process_verified_commit_vote(&mut self, cv: CommitVote) -> ConsensusResult<()> {
        self.process_commit_vote_inner(cv, true)
    }

    fn process_commit_vote_inner(
        &mut self,
        cv: CommitVote,
        signature_verified: bool,
    ) -> ConsensusResult<()> {
        let view = self.round_state.current_view();

        if cv.view != view {
            return Err(ConsensusError::ViewMismatch {
                current: view,
                received: cv.view,
            });
        }

        if !self.is_current_leader() {
            return Ok(());
        }

        if !signature_verified {
            let view_set = self.validator_set_for_view(view);
            let pk = view_set.get_public_key(cv.voter)?;
            let changes_hash = self.cached_changes_hash(&cv.block_hash);
            let msg = self
                .signing_profile
                .commit_message(view, cv.block_hash, changes_hash);
            if !self.signing_profile.verify_single(pk, &msg, &cv.signature) {
                return Err(ConsensusError::InvalidSignature {
                    view,
                    validator_index: cv.voter,
                });
            }
        }

        // R2 equivocation check — gated on verified signature, leader-only by design
        // (CommitVotes are sent directly to the leader, not broadcast).
        if let Some((h1, h2)) = check_equivocation(
            &mut self.commit_equivocation_tracker,
            cv.voter,
            cv.block_hash,
        ) {
            tracing::warn!(target: "n42::cl::voting", view, validator = cv.voter,
                hash1 = %h1, hash2 = %h2, "commit-vote equivocation detected");
            self.emit(EngineOutput::EquivocationDetected {
                view,
                validator: cv.voter,
                hash1: h1,
                hash2: h2,
            })?;
            return Ok(());
        }

        let expected_hash = match self.commit_collector.as_ref() {
            Some(c) => c.block_hash(),
            None => return Ok(()),
        };
        if cv.block_hash != expected_hash {
            tracing::debug!(target: "n42::cl::voting", view, voter = cv.voter,
                "ignoring verified commit vote for non-proposed block after equivocation tracking");
            return Ok(());
        }

        let collector = match self.commit_collector.as_mut() {
            Some(c) => c,
            None => {
                tracing::warn!(target: "n42::cl::voting", view, "commit_collector not initialized, ignoring commit vote");
                return Ok(());
            }
        };
        match collector.add_verified_vote(cv.voter, cv.signature) {
            Ok(()) => {}
            Err(ConsensusError::DuplicateVote { .. }) => {
                tracing::debug!(
                    target: "n42::cl::voting",
                    view,
                    voter = cv.voter,
                    "ignoring duplicate commit vote (dual-path delivery)"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        tracing::debug!(target: "n42::cl::voting",
            view,
            voter = cv.voter,
            count = collector.vote_count(),
            "received commit vote"
        );

        self.try_form_commit_qc()
    }

    /// Attempts to form a Commit QC from collected Round 2 votes.
    ///
    /// When quorum is reached, commits the block, broadcasts Decide,
    /// and advances to the next view.
    pub(super) fn try_form_commit_qc(&mut self) -> ConsensusResult<()> {
        let view = self.round_state.current_view();
        let view_set = self.validator_set_for_view(view);

        let has_quorum = self
            .commit_collector
            .as_ref()
            .is_some_and(|c| c.has_quorum(view_set.quorum_size()));

        if !has_quorum {
            return Ok(());
        }
        let collector = match self.commit_collector.as_ref() {
            Some(c) => c,
            None => return Ok(()),
        };
        let block_hash = collector.block_hash();
        let changes_hash = self.cached_changes_hash(&block_hash);
        let commit_msg = self
            .signing_profile
            .commit_message(view, block_hash, changes_hash);
        let commit_qc =
            collector.build_qc_with_profile_message(view_set, &commit_msg, self.signing_profile)?;

        self.view_timing.commit_qc_formed = Some(std::time::Instant::now());
        self.view_timing.commit_vote_count = collector.vote_count() as u32;

        tracing::info!(target: "n42::cl::voting", view, %block_hash,
            consensus_timing = %self.view_timing.summary(),
            "block committed!");

        self.round_state.commit(commit_qc.clone());

        // Capture changes BEFORE commit clears pending (needed for Decide + BlockCommitted).
        let committed_changes = self.epoch_manager.pending_changes_for_proposal();
        let changes_hash = match &committed_changes {
            Some(c) => crate::EpochManager::hash_changes(c),
            None => alloy_primitives::B256::ZERO,
        };

        // Commit-then-Activate: if validator changes were proposed, stage them now.
        if self.epoch_manager.has_pending_changes() {
            self.epoch_manager.commit_pending_changes()?;
        }

        let decide = n42_h2_primitives::consensus::Decide {
            view,
            block_hash,
            commit_qc: commit_qc.clone(),
            validator_changes_hash: changes_hash,
        };
        self.emit(EngineOutput::BroadcastMessage(ConsensusMessage::Decide(
            decide,
        )))?;
        // Clean up pending tx_root_hash for the committed block.
        self.pending_tx_roots.remove(&block_hash);

        self.emit(EngineOutput::BlockCommitted {
            view,
            block_hash,
            commit_qc,
            validator_changes: committed_changes,
        })?;

        let next_view = view.saturating_add(1);
        self.advance_to_view(next_view)?;

        // Notify the orchestrator that the view has advanced so the next leader
        // can start building immediately instead of waiting for a pacemaker timeout.
        let actual_view = self.round_state.current_view();
        self.emit(EngineOutput::ViewChanged {
            new_view: actual_view,
        })
    }
}
