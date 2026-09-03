// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Connects the HotStuff-2 state machine to an execution layer.
//!
//! The consensus engine speaks in two directions and this driver services both:
//!
//! | Consensus says | Driver does | Consensus hears back |
//! |---|---|---|
//! | (leader for this view) | FCU-with-attrs, then resolve the build | [`ConsensusEvent::BlockReady`] |
//! | [`EngineOutput::ExecuteBlock`] | `new_payload` for that hash | [`ConsensusEvent::BlockImported`] |
//! | [`EngineOutput::BlockCommitted`] | FCU with head = safe = finalized | — |
//!
//! The middle row is the one that matters for safety: N42 votes are
//! *import-gated*, so a follower only votes after its own execution layer has
//! accepted the block. That is what stops a validator from endorsing a block it
//! cannot execute.

use std::collections::HashMap;

use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    ExecutionData, ForkchoiceState, PayloadAttributes, PayloadStatusEnum,
};
use n42_h2_consensus::{ConsensusEvent, EngineOutput};
use tracing::{debug, info, warn};

use crate::{
    el::{BuiltBlock, ElError, ExecutionLayer, ResolveKind},
    ExecutionPath,
};

/// What the driver produced for one consensus output.
///
/// Not `Clone`/`PartialEq`: [`ConsensusEvent`] is neither, and wrapping it in
/// something that is would mean cloning payloads on a path that never needs to.
/// Tests use the accessors below.
#[derive(Debug)]
pub enum DriverAction {
    /// Feed this back into [`n42_h2_consensus::ConsensusEngine::process_event`].
    ///
    /// Boxed because [`ConsensusEvent`] is ~800 bytes (its `Message` variant
    /// carries a whole consensus message) while every other action here is a
    /// hash or a string. Unboxed, every `DriverAction` would cost that much —
    /// and the driver only ever produces the tiny `BlockImported` variant.
    Consensus(Box<ConsensusEvent>),
    /// The execution layer accepted a commit; nothing to feed back.
    Finalized {
        /// The finalised block.
        block_hash: B256,
    },
    /// Consensus asked to execute a block whose payload the driver has not seen.
    ///
    /// Not an error: the proposal carries only a hash, and the block body
    /// arrives separately (direct push or fetch-on-miss). The caller should
    /// fetch it, call [`ExecutionDriver::cache_payload`], and retry.
    PayloadMissing {
        /// The block that could not be executed yet.
        block_hash: B256,
    },
    /// The execution layer rejected a block. Consensus must not vote for it.
    Rejected {
        /// The block that was rejected.
        block_hash: B256,
        /// Why.
        reason: String,
    },
    /// The output needed nothing from the execution layer.
    Ignored,
}

impl DriverAction {
    /// The block this action says was imported, if it is an import event.
    pub fn imported_block(&self) -> Option<B256> {
        match self {
            Self::Consensus(event) => match event.as_ref() {
                ConsensusEvent::BlockImported(hash) => Some(*hash),
                _ => None,
            },
            _ => None,
        }
    }

    /// The block this action finalised, if any.
    pub fn finalized_block(&self) -> Option<B256> {
        match self {
            Self::Finalized { block_hash } => Some(*block_hash),
            _ => None,
        }
    }

    /// The block whose payload is still missing, if any.
    pub fn missing_block(&self) -> Option<B256> {
        match self {
            Self::PayloadMissing { block_hash } => Some(*block_hash),
            _ => None,
        }
    }

    /// The rejection reason, if the execution layer refused the block.
    pub fn rejection(&self) -> Option<(B256, &str)> {
        match self {
            Self::Rejected { block_hash, reason } => Some((*block_hash, reason.as_str())),
            _ => None,
        }
    }
}

/// Rewrites a freshly built payload into the block this node will propose.
///
/// Called with the payload and the view it is proposed in. The execution
/// layer builds without knowing the view, and on a chain whose header
/// commits to it (gov5's HotStuff profile) the header has to be finished —
/// view stamped, seal signed, hash re-formed — before anyone else sees it.
/// The result is what gets cached, imported, and proposed.
pub type PayloadNormalizer = dyn Fn(&ExecutionData, Option<&alloy_consensus::Header>, u64)
        -> Result<(ExecutionData, Option<alloy_consensus::Header>), String>
    + Send
    + Sync;

struct Normalizer(Box<PayloadNormalizer>);

impl std::fmt::Debug for Normalizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PayloadNormalizer")
    }
}

/// A block being built before this node is leader.
///
/// Resolved the moment its first build is done rather than when the proposal
/// wants it, because a payload job that is still open holds a build lease in
/// reth's engine, and the engine (2.5.1, `wait_for_event`) stops taking any
/// message at all -- imports, forkchoice, everything -- from the moment a
/// persistence completes until every lease is released. A job left open for
/// the rest of the view therefore deadlocks with the very loop that would
/// close it, and the deadlock is only broken by the 8-second RPC timeout.
/// Measured as seven of those per round with a tenure of 16. Resolved at once,
/// the job lives for one build.
#[derive(Debug)]
struct AheadBuild {
    parent: B256,
    attrs: PayloadAttributes,
    task: tokio::task::JoinHandle<Result<BuiltBlock, ElError>>,
}

/// Drives an [`ExecutionLayer`] on behalf of the consensus engine.
#[derive(Debug)]
pub struct ExecutionDriver<E> {
    /// Shared so a leader's import of its own block can be handed to a task
    /// instead of awaited. See [`Self::spawn_import_own_block`].
    el: std::sync::Arc<E>,
    /// Finishes a built payload before it is proposed. `None` proposes the
    /// payload exactly as built.
    normalizer: Option<Normalizer>,
    /// A build started before this node needed the block. See
    /// [`Self::prepare_build_on`].
    prepared: Option<AheadBuild>,
    /// Where [`Self::spawn_import_own_block`] reports a block the execution
    /// layer has taken, for the loop to build ahead on: a leader's own block
    /// raises no `BlockImported` -- that event belongs to the follower path
    /// -- and with a tenure the next build waits for exactly this.
    own_imports: tokio::sync::mpsc::UnboundedSender<B256>,
    /// The receiving end, until the loop takes it.
    own_imports_rx: Option<tokio::sync::mpsc::UnboundedReceiver<B256>>,
    /// Payloads seen but not yet executed, keyed by block hash. Populated from
    /// proposals, direct pushes, and our own builds.
    payloads: HashMap<B256, ExecutionData>,
    /// Current head, as consensus understands it.
    head: B256,
    /// Last block consensus committed.
    finalized: B256,
    /// Bounds `payloads` so a peer cannot make us buffer without limit.
    max_cached_payloads: usize,
    /// Insertion order, for evicting the oldest cached payload.
    payload_order: Vec<B256>,
}

impl<E: ExecutionLayer> ExecutionDriver<E> {
    /// Default payload cache size — a few views' worth of blocks.
    pub const DEFAULT_MAX_CACHED_PAYLOADS: usize = 64;

    /// Builds a driver whose head and finalised block are `genesis`.
    pub fn new(el: E, genesis: B256) -> Self {
        let (own_imports_tx, own_imports_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            el: std::sync::Arc::new(el),
            normalizer: None,
            prepared: None,
            own_imports: own_imports_tx,
            own_imports_rx: Some(own_imports_rx),
            payloads: HashMap::new(),
            head: genesis,
            finalized: genesis,
            max_cached_payloads: Self::DEFAULT_MAX_CACHED_PAYLOADS,
            payload_order: Vec::new(),
        }
    }

    /// Installs a [`PayloadNormalizer`] applied to every block this node builds.
    pub fn set_payload_normalizer(
        &mut self,
        normalizer: impl Fn(&ExecutionData, Option<&alloy_consensus::Header>, u64) -> Result<(ExecutionData, Option<alloy_consensus::Header>), String>
            + Send
            + Sync
            + 'static,
    ) {
        self.normalizer = Some(Normalizer(Box::new(normalizer)));
    }

    /// Overrides the payload cache bound.
    pub fn with_max_cached_payloads(mut self, max: usize) -> Self {
        self.max_cached_payloads = max.max(1);
        self
    }

    /// The execution layer this driver owns.
    pub fn execution_layer(&self) -> &E {
        &self.el
    }

    /// Current head.
    pub fn head(&self) -> B256 {
        self.head
    }

    /// Last committed block.
    pub fn finalized(&self) -> B256 {
        self.finalized
    }

    /// Records a block payload so a later `ExecuteBlock` for it can proceed.
    pub fn cache_payload(&mut self, block_hash: B256, payload: ExecutionData) {
        if self.payloads.insert(block_hash, payload).is_none() {
            self.payload_order.push(block_hash);
            while self.payload_order.len() > self.max_cached_payloads {
                let oldest = self.payload_order.remove(0);
                self.payloads.remove(&oldest);
            }
        }
    }

    /// Whether a payload is cached for `block_hash`.
    pub fn has_payload(&self, block_hash: &B256) -> bool {
        self.payloads.contains_key(block_hash)
    }

    /// The forkchoice this driver would send right now.
    fn forkchoice(&self, head: B256) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: head,
            safe_block_hash: self.finalized,
            finalized_block_hash: self.finalized,
        }
    }

    /// Starts a build now for a block this node expects to propose later.
    ///
    /// The execution layer needs time to fill a block -- measured at the 480M
    /// tier as 95 ms of a 195 ms leader path, which is the largest single
    /// piece of it -- and that time is only on the critical path because the
    /// build starts when the node becomes leader. It does not have to.
    ///
    /// The parent of the block a leader proposes is the block committed in the
    /// view before it, and a node knows that block when it *imports* it, which
    /// is before the fleet has finished voting on it. Starting the build there
    /// overlaps it with the rest of the consensus round, so by the time this
    /// node is leader the payload is waiting.
    ///
    /// Speculative and cheap to be wrong about: if that view ends in a timeout
    /// instead of a commit, the parent this was started on is not the parent
    /// the proposal needs, the prepared build is discarded on the mismatch, and
    /// the leader starts one the old way.
    pub async fn prepare_build_on(
        &mut self,
        parent: B256,
        attrs: PayloadAttributes,
    ) -> Result<(), ElError> {
        if self
            .prepared
            .as_ref()
            .is_some_and(|ahead| ahead.parent == parent && ahead.attrs == attrs)
        {
            return Ok(());
        }
        if let Some(stale) = self.prepared.take() {
            stale.task.abort();
        }
        // Off the caller's loop entirely: the forkchoice call that starts the
        // build is answered by the same engine the loop's other calls queue
        // behind, and a loop that awaits it here is the loop that cannot
        // resolve the build when the engine waits for that.
        let el = std::sync::Arc::clone(&self.el);
        let state = self.forkchoice(parent);
        let task_attrs = attrs.clone();
        info!(target: "n42.h2.el", ?parent, "starting a build ahead of leading");
        let task = tokio::spawn(async move {
            let started = std::time::Instant::now();
            let updated = el
                .fork_choice_updated_with_attrs_for(ExecutionPath::LIVE_SEQUENTIAL, state, task_attrs)
                .await?;
            let id = updated.payload_id.ok_or_else(|| {
                ElError::new(format!(
                    "forkchoiceUpdated started no build ahead of leading (status {:?})",
                    updated.payload_status.status
                ))
            })?;
            let after_fcu = started.elapsed();
            let built = el
                .resolve_payload_for(ExecutionPath::LIVE_SEQUENTIAL, id, ResolveKind::WaitForPending)
                .await
                .ok_or_else(|| ElError::new(format!("no payload build for id {id}")))??;
            info!(
                target: "n42.h2.el",
                ?parent,
                number = built.number,
                fcu_ms = after_fcu.as_millis() as u64,
                build_ms = (started.elapsed() - after_fcu).as_millis() as u64,
                "built a block ahead of leading"
            );
            Ok(built)
        });
        self.prepared = Some(AheadBuild { parent, attrs, task });
        Ok(())
    }

    /// Leader path: builds a block on top of the current head.
    ///
    /// Returns the built block *and* caches its payload, so the subsequent
    /// `ExecuteBlock` for our own proposal is served locally rather than
    /// requiring a round trip.
    pub async fn build_block(
        &mut self,
        attrs: PayloadAttributes,
        view: u64,
    ) -> Result<BuiltBlock, ElError> {
        self.build_block_on(self.head, attrs, view).await
    }

    /// Builds on `parent` rather than on the head: what a leader does when the
    /// block its highest QC certifies is not the last block its execution
    /// layer imported. The forkchoice that starts the build makes `parent`
    /// the head (safe and finalized stay where they are), so the execution
    /// layer has to know the block already.
    pub async fn build_block_on(
        &mut self,
        parent: B256,
        attrs: PayloadAttributes,
        view: u64,
    ) -> Result<BuiltBlock, ElError> {
        // Timed in four parts because the leader's whole path is 396.5 ms
        // against 82.7 ms of block execution, and which part holds the rest
        // decides between two different fixes: building ahead of being leader
        // (so the wait leaves the critical path) or not building the block
        // twice (so the work is not done twice). Guessing between them is how
        // this file has been wrong before.
        let started = std::time::Instant::now();
        // A build prepared earlier counts only if it was started on this exact
        // parent with these exact attributes. Anything else and the block it
        // assembled is not the block this node is about to propose. One that
        // failed is reported and replaced, not propagated: the proposal is
        // worth more than the shortcut.
        let ahead = match self.prepared.take() {
            Some(prepared) if prepared.parent == parent && prepared.attrs == attrs => {
                match prepared.task.await {
                    Ok(Ok(built)) => Some(built),
                    Ok(Err(err)) => {
                        warn!(target: "n42.h2.el", %err, ?parent, "the build prepared ahead failed; building now");
                        None
                    }
                    Err(err) => {
                        warn!(target: "n42.h2.el", %err, ?parent, "the build prepared ahead was lost; building now");
                        None
                    }
                }
            }
            Some(prepared) => {
                info!(
                    target: "n42.h2.el",
                    prepared_on = ?prepared.parent,
                    asked = ?parent,
                    same_parent = prepared.parent == parent,
                    same_attrs = prepared.attrs == attrs,
                    "a build prepared ahead does not match the proposal; discarded"
                );
                prepared.task.abort();
                None
            }
            None => None,
        };
        // With a build from ahead, fcu_ms below is the wait for one still in
        // flight and build_ms is nothing. Without, the status is reported
        // rather than a bare "no payload id": VALID-without-an-id and SYNCING
        // mean very different things to an operator.
        let (mut built, after_fcu, after_resolve, ahead) = match ahead {
            Some(built) => (built, started.elapsed(), started.elapsed(), true),
            None => {
                let updated = self
                    .el
                    .fork_choice_updated_with_attrs_for(
                        ExecutionPath::LIVE_SEQUENTIAL,
                        self.forkchoice(parent),
                        attrs,
                    )
                    .await?;
                let after_fcu = started.elapsed();
                let payload_id = updated.payload_id.ok_or_else(|| {
                    ElError::new(format!(
                        "forkchoiceUpdated returned no payload id (status {:?})",
                        updated.payload_status.status
                    ))
                })?;
                let built = self
                    .el
                    .resolve_payload_for(
                        ExecutionPath::LIVE_SEQUENTIAL,
                        payload_id,
                        ResolveKind::WaitForPending,
                    )
                    .await
                    .ok_or_else(|| ElError::new(format!("no payload build for id {payload_id}")))??;
                (built, after_fcu, started.elapsed(), false)
            }
        };

        // The block the execution layer built is not necessarily the block
        // this node proposes: a chain whose header carries the view needs it
        // stamped and sealed first, and that changes the hash. From here on
        // only the finished block exists — it is what gets imported, and the
        // hash consensus sees.
        if let Some(normalize) = &self.normalizer {
            // The header the execution layer handed over, when it did: the
            // seal then touches the header alone and never decodes the block.
            let (finished, header) = (normalize.0)(&built.execution_data, built.header.as_ref(), view)
                .map_err(|e| ElError::new(format!("finishing the built block: {e}")))?;
            built.hash = finished.block_hash();
            built.execution_data = finished;
            built.header = header;
        }

        let after_seal = started.elapsed();
        self.cache_payload(built.hash, built.execution_data.clone());

        info!(
            target: "n42.h2.el",
            view,
            ahead,
            fcu_ms = after_fcu.as_millis() as u64,
            build_ms = (after_resolve - after_fcu).as_millis() as u64,
            seal_ms = (after_seal - after_resolve).as_millis() as u64,
            total_ms = started.elapsed().as_millis() as u64,
            "leader build path"
        );
        Ok(built)
    }

    /// Inserts a block this node built into its own execution layer.
    ///
    /// Separate from building, and called *after* the proposal has gone out,
    /// because it is not on the fleet's critical path and used to be on it.
    /// `getPayload` builds a block without inserting it, and the leader never
    /// receives its own proposal back over gossip, so nothing else ever will:
    /// the block would be committed by consensus and then rejected by the
    /// leader's own execution layer, which answers the commit's
    /// forkchoiceUpdated with SYNCING and leaves the chain stuck at the parent.
    /// So it has to happen -- it just does not have to happen first.
    ///
    /// It costs a second full execution of the block. Sealing the view into
    /// the header changes the hash, so the execution layer cannot recognise
    /// the block as the one it assembled and runs every transaction again;
    /// reth short-circuits a block already in its tree, and a block from
    /// `getPayload` is not in it. Measured at the 480M tier as 80 ms of a
    /// 195 ms leader path, against 95 ms of waiting for the build and 17 ms of
    /// sealing. Ahead of the proposal it delayed every follower by that much;
    /// behind it, the followers have had the body for 80 ms already and are
    /// executing it in parallel with this.
    /// Starts the import of a block this node built, without waiting for it.
    ///
    /// The wait was the point of moving it behind the proposal and it is not
    /// enough on its own: at the 163,000-transaction tier the import is 710 ms,
    /// and awaiting it holds the consensus loop for that long -- during which
    /// the leader cannot read the votes for the block it has just proposed.
    ///
    /// Nothing needs to come back from it. The consensus engine asks for the
    /// block to be executed like any other, and that request finds it already
    /// in the execution layer's tree and returns at once; if this task has not
    /// finished by then, the request executes the block itself and the only
    /// cost is that the saving did not happen. gov5's sibling client calls
    /// those the two cases and falls back the same way.
    ///
    /// Two `newPayload` calls for one block cannot race: reth serialises engine
    /// requests through one channel, and the second finds the block in the tree.
    pub fn spawn_import_own_block(&self, built: &BuiltBlock) {
        let el = std::sync::Arc::clone(&self.el);
        let payload = built.execution_data.clone();
        let hash = built.hash;
        let imported = self.own_imports.clone();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            match el.new_payload_for(ExecutionPath::LIVE_SEQUENTIAL, payload).await {
                Ok(status) => {
                    info!(
                        target: "n42.h2.el",
                        block = ?hash,
                        import_ms = started.elapsed().as_millis() as u64,
                        status = ?status.status,
                        "imported our own block"
                    );
                    if status.status.is_valid() {
                        let _ = imported.send(hash);
                    }
                }
                Err(err) => warn!(
                    target: "n42.h2.el",
                    block = ?hash, %err,
                    "our own execution layer would not take the block we built"
                ),
            }
        });
    }

    /// Imports a block this node built and waits for the verdict.
    /// Drops a build prepared ahead, if any. A leader whose proposal timed out
    /// prepared its next build on the block that was not voted for; the next
    /// proposal extends the last QC's block instead, and a build on the wrong
    /// parent is discarded on the mismatch anyway -- this only stops the
    /// execution layer finishing a build nobody will collect.
    pub fn discard_prepared(&mut self) {
        if let Some(prepared) = self.prepared.take() {
            prepared.task.abort();
        }
    }

    /// The channel [`Self::spawn_import_own_block`] reports on, once.
    pub fn take_own_imports(&mut self) -> Option<tokio::sync::mpsc::UnboundedReceiver<B256>> {
        self.own_imports_rx.take()
    }

    pub async fn import_own_block(&mut self, built: &BuiltBlock) -> Result<(), ElError> {
        let started = std::time::Instant::now();
        let status = self
            .el
            .new_payload_for(ExecutionPath::LIVE_SEQUENTIAL, built.execution_data.clone())
            .await?;
        info!(
            target: "n42.h2.el",
            block = ?built.hash,
            import_ms = started.elapsed().as_millis() as u64,
            "imported our own block"
        );
        match status.status {
            PayloadStatusEnum::Valid => {
                self.head = built.hash;
                Ok(())
            }
            // A block this node's own execution layer will not accept has
            // already been proposed by the time we know. The view is lost
            // either way; what matters is that it is loud.
            PayloadStatusEnum::Invalid { validation_error } => Err(ElError::new(format!(
                "our own execution layer rejected the block we built: {validation_error}"
            ))),
            other => Err(ElError::new(format!(
                "our own execution layer did not accept the block we built: {other:?}"
            ))),
        }
    }

    /// Imports a block pulled from a peer to catch up and makes it the head.
    ///
    /// Head and safe, not finalized: the peer says this is the fleet's
    /// chain, and execution says the block is valid, but neither is a
    /// commit certificate. Finality follows the next Decide this node sees,
    /// which finalizes the block it names and, with it, everything pulled
    /// beneath; until then a peer that served a sibling chain costs a reorg
    /// rather than a node stuck behind a wrong finalized block. Returns the
    /// hash on success; any verdict but VALID is an error, because a
    /// catch-up that skips a block leaves every later one without a parent.
    pub async fn import_pulled(&mut self, payload: ExecutionData) -> Result<B256, ElError> {
        let block_hash = payload.block_hash();
        let status = self
            .el
            .new_payload_for(ExecutionPath::HISTORICAL_SEQUENTIAL, payload)
            .await?;
        match status.status {
            PayloadStatusEnum::Valid => {}
            PayloadStatusEnum::Invalid { validation_error } => {
                return Err(ElError::new(format!("execution layer rejected block {block_hash}: {validation_error}")));
            }
            other => {
                return Err(ElError::new(format!("execution layer did not accept block {block_hash}: {other:?}")));
            }
        }
        let state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash,
            finalized_block_hash: self.finalized,
        };
        let updated = self
            .el
            .fork_choice_updated_for(ExecutionPath::HISTORICAL_SEQUENTIAL, state)
            .await?;
        if let PayloadStatusEnum::Invalid { validation_error } = updated.payload_status.status {
            return Err(ElError::new(format!("forkchoice to {block_hash} refused: {validation_error}")));
        }
        self.head = block_hash;
        Ok(block_hash)
    }

    /// Handles one consensus output.
    pub async fn handle_output(&mut self, output: &EngineOutput) -> DriverAction {
        match output {
            EngineOutput::ExecuteBlock(block_hash) => self.execute(*block_hash).await,
            EngineOutput::BlockCommitted { block_hash, .. } => self.commit(*block_hash).await,
            _ => DriverAction::Ignored,
        }
    }

    /// Follower path: executes a proposed block and, on acceptance, produces the
    /// event that releases the import-gated vote.
    async fn execute(&mut self, block_hash: B256) -> DriverAction {
        let Some(payload) = self.payloads.get(&block_hash).cloned() else {
            return DriverAction::PayloadMissing { block_hash };
        };
        let txs = payload.payload.as_v1().transactions.len();
        let started = std::time::Instant::now();
        let outcome = self
            .el
            .new_payload_for(ExecutionPath::LIVE_SEQUENTIAL, payload)
            .await;
        if txs >= 10_000 {
            info!(
                target: "n42.h2.el",
                block = ?block_hash,
                txs,
                import_ms = started.elapsed().as_millis() as u64,
                "imported a block"
            );
        }
        match outcome {
            Ok(status) => match status.status {
                PayloadStatusEnum::Valid => {
                    self.head = block_hash;
                    DriverAction::Consensus(Box::new(ConsensusEvent::BlockImported(block_hash)))
                }
                // SYNCING/ACCEPTED are not a verdict: the EL has not executed the
                // block yet, so voting now would be voting blind. Treat it the
                // same as a missing payload — the caller retries.
                PayloadStatusEnum::Syncing | PayloadStatusEnum::Accepted => {
                    DriverAction::PayloadMissing { block_hash }
                }
                PayloadStatusEnum::Invalid { validation_error } => DriverAction::Rejected {
                    block_hash,
                    reason: validation_error.to_string(),
                },
            },
            Err(error) => DriverAction::Rejected {
                block_hash,
                reason: error.to_string(),
            },
        }
    }

    /// Commit path: makes a committed block the head and the finalised block.
    async fn commit(&mut self, block_hash: B256) -> DriverAction {
        self.finalized = block_hash;
        let state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash,
            finalized_block_hash: block_hash,
        };
        match self
            .el
            .fork_choice_updated_for(ExecutionPath::LIVE_SEQUENTIAL, state)
            .await
        {
            Ok(updated) => match updated.payload_status.status {
                PayloadStatusEnum::Invalid { validation_error } => DriverAction::Rejected {
                    block_hash,
                    reason: validation_error.to_string(),
                },
                _ => {
                    self.head = block_hash;
                    // Committed blocks never need re-execution.
                    self.payloads.remove(&block_hash);
                    self.payload_order.retain(|h| h != &block_hash);
                    DriverAction::Finalized { block_hash }
                }
            },
            Err(error) => DriverAction::Rejected {
                block_hash,
                reason: error.to_string(),
            },
        }
    }
}
