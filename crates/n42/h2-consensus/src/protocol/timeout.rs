use n42_h2_primitives::consensus::{ConsensusMessage, NewView, TimeoutCertificate, TimeoutMessage};

use super::quorum::TimeoutCollector;
use super::round::Phase;
use super::state_machine::{ConsensusEngine, EngineOutput};
use crate::validator::LeaderSelector;
use crate::error::{ConsensusError, ConsensusResult};

impl ConsensusEngine {
    /// Verifies and collects a timeout vote for a bounded future view.
    ///
    /// A lone future timeout never changes the local view. Only the exact
    /// next-view leader may aggregate a quorum of distinct, verified timeout
    /// signatures into a TC and advance. Validator-set lookup is strict so an
    /// unstaged future epoch can never be verified using the current set as a
    /// fallback.
    pub(super) fn collect_future_timeout(
        &mut self,
        timeout: TimeoutMessage,
    ) -> ConsensusResult<bool> {
        let current_view = self.round_state.current_view();
        if timeout.view <= current_view
            || timeout.view > current_view.saturating_add(super::state_machine::FUTURE_VIEW_WINDOW)
        {
            return Ok(false);
        }

        let Some(view_set) = self
            .epoch_manager
            .known_validator_set_for_view(timeout.view)
            .cloned()
        else {
            tracing::debug!(target: "n42::cl::timeout",
                current_view,
                timeout_view = timeout.view,
                "buffering future timeout without aggregating: validator set is not known exactly"
            );
            return Ok(false);
        };
        let next_view = timeout.view.saturating_add(1);
        let Some(next_view_set) = self
            .epoch_manager
            .known_validator_set_for_view(next_view)
            .cloned()
        else {
            tracing::debug!(target: "n42::cl::timeout",
                current_view,
                timeout_view = timeout.view,
                next_view,
                "buffering future timeout without aggregating: next-view validator set is not known exactly"
            );
            return Ok(false);
        };

        let pk = view_set.get_public_key(timeout.sender)?;
        let msg = self.signing_profile.timeout_message(timeout.view);
        if !self
            .signing_profile
            .verify_single(pk, &msg, &timeout.signature)
        {
            return Err(ConsensusError::InvalidSignature {
                view: timeout.view,
                validator_index: timeout.sender,
            });
        }
        self.verify_embedded_qc(&timeout.high_qc)?;

        // From the set this branch just established is known exactly, not
        // from the engine's fallback resolver; the tenure is the only thing
        // added to the original rule here.
        let next_leader = LeaderSelector::leader_for_view_with_tenure(
            next_view,
            self.leader_tenure,
            &next_view_set,
        );
        let local_timeout_index = view_set.index_of_public_key(&self.local_public_key);
        let local_next_index = next_view_set.index_of_public_key(&self.local_public_key);
        if local_timeout_index != Some(timeout.sender) && local_next_index != Some(next_leader) {
            self.emit(EngineOutput::SendToValidator(
                next_leader,
                ConsensusMessage::Timeout(timeout.clone()),
            ))?;
        }

        let collector = self
            .future_timeout_collectors
            .entry(timeout.view)
            .or_insert_with(|| TimeoutCollector::new(timeout.view, view_set.len()));
        match collector.add_verified_timeout(timeout.sender, timeout.signature, timeout.high_qc) {
            Ok(()) => {}
            Err(ConsensusError::DuplicateVote { .. }) => return Ok(false),
            Err(error) => return Err(error),
        }

        let quorum_size = view_set.quorum_size();
        if local_next_index != Some(next_leader) || !collector.has_quorum(quorum_size) {
            return Ok(false);
        }

        let tc = collector.build_tc_with_profile(&view_set, self.signing_profile)?;
        self.future_timeout_collectors.remove(&timeout.view);
        tracing::info!(target: "n42::cl::timeout",
            local_view = current_view,
            timeout_view = timeout.view,
            next_view,
            "future timeout quorum formed a TC; recovering split-view validators"
        );
        self.advance_with_tc(tc, next_view)?;
        Ok(true)
    }

    /// Verifies a QC embedded in a timeout or NewView message.
    /// Genesis QC (view 0) is exempt only when our own locked_qc is also genesis —
    /// i.e., the chain has just started and no real QC exists yet.
    ///
    /// Allowing any network message to carry a view=0 QC unconditionally would let
    /// an attacker forge a genesis QC and use it to regress our locked_qc back to
    /// view 0, violating HotStuff-2's safety monotonicity invariant.
    ///
    /// The R2 commit-domain fallback in `verify_qc_any_domain` reads the
    /// cached `changes_hash` for this QC's block; on cache miss it falls back
    /// to zero (acceptable: a TC's high_qc usually points at an already
    /// committed block whose proposal is no longer in the pending cache).
    fn verify_embedded_qc(
        &self,
        qc: &n42_h2_primitives::consensus::QuorumCertificate,
    ) -> ConsensusResult<()> {
        if qc.view == 0 {
            // Only accept a genesis QC if our own locked_qc is still at genesis.
            // Once we have advanced past genesis, any incoming view=0 QC is suspicious.
            if self.round_state.locked_qc().view == 0 {
                return Ok(());
            }
            return Err(crate::error::ConsensusError::InvalidQC {
                view: 0,
                reason: "genesis QC rejected: local locked_qc has already advanced".to_string(),
            });
        }
        self.verify_qc_any_domain_or_known(qc)
    }

    /// Handles a view timeout triggered by the pacemaker.
    pub fn on_timeout(&mut self) -> ConsensusResult<()> {
        let view = self.round_state.current_view();

        // Observer guard: if our local key is not a validator for this view
        // (or my_index is stale and points at someone else's key), do not
        // broadcast a timeout. Sending one would carry our signature under
        // a foreign sender index, fail BLS verification on every receiver,
        // and stall the network.
        if !self.is_local_validator_active_for_view(view) {
            tracing::debug!(
                target: "n42::cl::timeout",
                view,
                my_index = self.my_index,
                "observer (or stale my_index): skipping timeout broadcast"
            );
            self.round_state.timeout();
            self.pacemaker
                .reset_for_view(view, self.round_state.consecutive_timeouts());
            return Ok(());
        }

        if self.round_state.phase() == Phase::TimedOut {
            // Already timed out in this view: reset pacemaker and re-broadcast timeout.
            // Re-broadcasting ensures validators who missed the first message (network
            // jitter, late join) can still collect our vote for TC formation.
            tracing::warn!(target: "n42::cl::timeout", view, "view timed out (repeat, re-broadcasting timeout)");
            self.pacemaker
                .reset_for_view(view, self.round_state.consecutive_timeouts());

            let message = self.signing_profile.timeout_message(view);
            let signature = self.signing_profile.sign(&self.secret_key, &message);
            let timeout_msg = TimeoutMessage {
                view,
                high_qc: self.round_state.locked_qc().clone(),
                sender: self.my_index,
                signature,
            };
            self.emit(EngineOutput::BroadcastMessage(ConsensusMessage::Timeout(
                timeout_msg,
            )))?;

            // Check if quorum was reached while we were waiting (messages may have
            // arrived between repeats). Only the next leader can form the TC.
            let quorum_size = self.validator_set_for_view(view).quorum_size();
            let next_view = view.saturating_add(1);
            // edition-2021: N42-26 writes this as a let-chain.
            let collector_has_quorum = self
                .timeout_collector
                .as_ref()
                .is_some_and(|collector| collector.has_quorum(quorum_size));
            if collector_has_quorum && self.is_leader_for_view(next_view) {
                self.try_form_tc_and_advance(view, next_view)?;
            }
            return Ok(());
        }

        tracing::warn!(target: "n42::cl::timeout", view, "view timed out");
        self.round_state.timeout();

        // Reset pacemaker BEFORE processing to prevent the select! loop from spinning
        // on a deadline that stays in the past. If process_timeout forms a TC and calls
        // advance_to_view, the pacemaker will be reset again — a harmless double reset.
        self.pacemaker
            .reset_for_view(view, self.round_state.consecutive_timeouts());

        // Clear pending block data: similar to Tendermint's "prevote nil".
        self.pending_proposal = None;
        if !matches!(
            self.signing_profile,
            super::quorum::ConsensusSigningProfile::H2V4(_)
        ) {
            self.imported_blocks.clear();
            self.imported_block_fifo.clear();
        }

        // Preserve any timeouts already collected from validators who timed out before us.
        // Unconditional replacement would discard those votes, potentially preventing
        // quorum from ever being reached (permanent stall).
        let n_validators = self.validator_set_for_view(view).len();
        self.timeout_collector
            .get_or_insert_with(|| TimeoutCollector::new(view, n_validators));

        let message = self.signing_profile.timeout_message(view);
        let signature = self.signing_profile.sign(&self.secret_key, &message);

        let timeout_msg = TimeoutMessage {
            view,
            high_qc: self.round_state.locked_qc().clone(),
            sender: self.my_index,
            signature,
        };

        self.emit(EngineOutput::BroadcastMessage(ConsensusMessage::Timeout(
            timeout_msg.clone(),
        )))?;

        self.process_timeout(timeout_msg)
    }

    /// Processes a timeout message for the current view.
    ///
    /// Future timeouts are buffered by `process_message`; a single validator's
    /// timeout is never sufficient evidence to advance the local view.
    pub(super) fn process_timeout(&mut self, timeout: TimeoutMessage) -> ConsensusResult<()> {
        let view = self.round_state.current_view();

        if timeout.view < view {
            return Ok(());
        }

        if timeout.view > view {
            tracing::debug!(target: "n42::cl::timeout",
                current_view = view,
                timeout_view = timeout.view,
                sender = timeout.sender,
                "ignoring directly-dispatched future timeout without a quorum TC"
            );
            return Ok(());
        }

        // Current-view timeout processing.
        let view_set = self.validator_set_for_view(view);
        let pk = view_set.get_public_key(timeout.sender)?;
        let msg = self.signing_profile.timeout_message(view);
        if !self
            .signing_profile
            .verify_single(pk, &msg, &timeout.signature)
        {
            return Err(ConsensusError::InvalidSignature {
                view,
                validator_index: timeout.sender,
            });
        }

        // Verify the embedded high_qc to prevent Byzantine validators from injecting
        // forged QCs that could manipulate the locked_qc via TC formation.
        self.verify_embedded_qc(&timeout.high_qc).map_err(|e| {
            tracing::warn!(target: "n42::cl::timeout", view, sender = timeout.sender, qc_view = timeout.high_qc.view,
                "rejecting timeout with invalid high_qc: {e}");
            e
        })?;

        let n_validators = view_set.len();
        let quorum_size = view_set.quorum_size();
        let next_view = view.saturating_add(1);
        let next_leader = self.leader_index_for_view(next_view);
        let relay_timeout = (timeout.sender != self.my_index && next_leader != self.my_index)
            .then(|| timeout.clone());

        let (has_quorum, timeout_count) = {
            let collector = self
                .timeout_collector
                .get_or_insert_with(|| TimeoutCollector::new(view, n_validators));

            match collector.add_verified_timeout(timeout.sender, timeout.signature, timeout.high_qc)
            {
                Ok(()) => {}
                Err(ConsensusError::DuplicateVote { .. }) => {
                    tracing::debug!(target: "n42::cl::timeout",
                        view,
                        sender = timeout.sender,
                        "ignoring duplicate timeout (GossipSub multi-path)"
                    );
                    return Ok(());
                }
                Err(e) => return Err(e),
            }

            (collector.has_quorum(quorum_size), collector.timeout_count())
        };

        // Only the next-view leader can form and sign NewView, so make a
        // non-leader receiver relay each newly observed timeout vote once.
        //
        // This must happen after collector deduplication. H2-v4 carries the same
        // timeout over two GossipSub topics plus validator direct streams, and
        // SendToValidator uses those same redundant transports. Relaying every
        // duplicate therefore creates a positive feedback loop: each copy is
        // fanned out again, eventually exhausting request-response stream
        // capacity and preventing missing-block recovery. The timeout originator
        // already periodically re-broadcasts while the view remains timed out,
        // so a reconnecting next leader still receives a fresh copy without
        // duplicate-triggered relay amplification.
        if let Some(timeout) = relay_timeout {
            self.emit(EngineOutput::SendToValidator(
                next_leader,
                ConsensusMessage::Timeout(timeout),
            ))?;
        }

        tracing::debug!(target: "n42::cl::timeout",
            view,
            sender = timeout.sender,
            count = timeout_count,
            "received timeout"
        );

        let should_form_tc = has_quorum && self.is_leader_for_view(next_view);

        if should_form_tc {
            self.try_form_tc_and_advance(view, next_view)?;
        }

        Ok(())
    }

    /// Processes a NewView message from the new leader.
    pub(super) fn process_new_view(&mut self, nv: NewView) -> ConsensusResult<()> {
        let view = self.round_state.current_view();

        if nv.view <= view {
            return Ok(());
        }

        let new_view_set = self.validator_set_for_view(nv.view);
        let expected_leader = self.leader_index_for_view(nv.view);
        if nv.leader != expected_leader {
            return Err(ConsensusError::InvalidProposer {
                view: nv.view,
                expected: expected_leader,
                actual: nv.leader,
            });
        }

        // Verify leader's signature to prevent Byzantine nodes from forging NewView messages.
        let pk = new_view_set.get_public_key(nv.leader)?;
        let nv_msg = self.signing_profile.new_view_message(nv.view);
        if !self
            .signing_profile
            .verify_single(pk, &nv_msg, &nv.signature)
        {
            return Err(ConsensusError::InvalidSignature {
                view: nv.view,
                validator_index: nv.leader,
            });
        }

        // TC must be for the previous view (nv.view - 1).
        if nv.timeout_cert.view != nv.view.saturating_sub(1) {
            return Err(ConsensusError::InvalidTC {
                view: nv.timeout_cert.view,
                reason: format!(
                    "TC view {} does not match expected view {} (nv.view - 1)",
                    nv.timeout_cert.view,
                    nv.view.saturating_sub(1)
                ),
            });
        }
        super::quorum::verify_tc_with_profile(
            &nv.timeout_cert,
            self.validator_set_for_view(nv.timeout_cert.view),
            self.signing_profile,
        )?;

        // Verify TC's high_qc signature to prevent injection of forged QCs.
        self.verify_embedded_qc(&nv.timeout_cert.high_qc)?;

        self.round_state.update_locked_qc(&nv.timeout_cert.high_qc);

        tracing::info!(target: "n42::cl::timeout", old_view = view, new_view = nv.view, "received NewView, advancing");

        self.advance_to_view(nv.view)?;
        // Use actual view after advance: buffered-message replay may push view beyond nv.view.
        let actual_view = self.round_state.current_view();
        self.emit(EngineOutput::ViewChanged {
            new_view: actual_view,
        })
    }

    /// Builds a TC from the current timeout_collector and broadcasts NewView.
    ///
    /// Centralises TC-formation logic so the actual-view ViewChanged fix is applied
    /// consistently across all callsites.
    pub(super) fn try_form_tc_and_advance(
        &mut self,
        current_view: u64,
        next_view: u64,
    ) -> ConsensusResult<()> {
        let tc = match self.timeout_collector.as_ref() {
            Some(c) => c.build_tc_with_profile(
                self.validator_set_for_view(current_view),
                self.signing_profile,
            )?,
            None => {
                tracing::warn!(target: "n42::cl::timeout", view = current_view, "timeout_collector disappeared during TC formation");
                return Ok(());
            }
        };

        self.advance_with_tc(tc, next_view)
    }

    fn advance_with_tc(&mut self, tc: TimeoutCertificate, next_view: u64) -> ConsensusResult<()> {
        tracing::info!(target: "n42::cl::timeout",
            view = tc.view,
            "TC formed, I am the new leader for view {}", next_view
        );

        self.round_state.update_locked_qc(&tc.high_qc);

        let nv_message = self.signing_profile.new_view_message(next_view);
        let nv_sig = self.signing_profile.sign(&self.secret_key, &nv_message);

        let leader = self.local_validator_index_for_view(next_view).ok_or(
            ConsensusError::LocalValidatorNotInSet {
                epoch: self.epoch_manager.current_epoch() + 1,
            },
        )?;

        let new_view = NewView {
            view: next_view,
            timeout_cert: tc,
            leader,
            signature: nv_sig,
        };

        self.emit(EngineOutput::BroadcastMessage(ConsensusMessage::NewView(
            new_view,
        )))?;

        self.advance_to_view(next_view)?;
        // Use actual view: advance_to_view may replay buffered messages pushing view further.
        let actual_view = self.round_state.current_view();
        self.emit(EngineOutput::ViewChanged {
            new_view: actual_view,
        })
    }
}
