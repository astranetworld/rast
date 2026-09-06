// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The execution-layer seam.
//!
//! A trait boundary over the Engine API that consensus drives, so the HotStuff-2
//! state machine never holds reth handles directly. Everything here is alloy or
//! std — no reth types cross this line — which is what lets the consensus side
//! stay independent of the reth version underneath.
//!
//! Ported from N42-26's `n42-consensus-service/src/el.rs`. The concrete adapter
//! that implements this against reth lives node-side; this crate holds the trait,
//! the node-neutral types, and the driver that connects them to consensus.

use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    ExecutionData, ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadId, PayloadStatus,
    PayloadStatusEnum,
};

use crate::ExecutionPath;

fn payload_outcome(status: &PayloadStatusEnum) -> &'static str {
    match status {
        PayloadStatusEnum::Valid => "valid",
        PayloadStatusEnum::Invalid { .. } => "invalid",
        PayloadStatusEnum::Syncing => "syncing",
        PayloadStatusEnum::Accepted => "accepted",
    }
}

fn record_call(
    path: ExecutionPath,
    phase: &'static str,
    started: std::time::Instant,
    outcome: &'static str,
) {
    metrics::histogram!(
        "n42_evm_path_duration_ms",
        "path" => path.label(),
        "phase" => phase,
    )
    .record(started.elapsed().as_secs_f64() * 1_000.0);
    metrics::counter!(
        "n42_evm_path_calls_total",
        "path" => path.label(),
        "phase" => phase,
        "outcome" => outcome,
    )
    .increment(1);
}

/// Error at the EL boundary.
///
/// Erases reth's concrete engine error enums — every call site here only logs
/// the message and branches on `Ok`/`Err`, so carrying the reth types across the
/// seam would buy nothing and would pin this crate to a reth version.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ElError(pub String);

impl ElError {
    /// Builds an error from anything printable.
    pub fn new(message: impl std::fmt::Display) -> Self {
        Self(message.to_string())
    }
}

/// Node-neutral result of a completed payload build.
#[derive(Debug, Clone)]
pub struct BuiltBlock {
    /// Block hash of the built block.
    pub hash: B256,
    /// Block number.
    pub number: u64,
    /// Block timestamp (seconds).
    pub timestamp: u64,
    /// Number of transactions in the block.
    pub tx_count: usize,
    /// Engine-API execution payload, for re-import via `new_payload` and for
    /// serialisation to followers.
    pub execution_data: ExecutionData,
    /// Transaction hashes of the EIP-4844 transactions in this block, used to
    /// gather and broadcast their sidecars.
    pub blob_tx_hashes: Vec<B256>,
    /// The header, when the normalizer built one.
    ///
    /// Carried rather than recovered: sealing constructs the header to hash it,
    /// and the caller needs the same header a moment later. Decoding the
    /// payload again to get it back is a clone and a full RLP walk of the whole
    /// block -- 648 ms at the 163,000-transaction tier, on a path where sealing
    /// itself is 150 ms.
    pub header: Option<alloy_consensus::Header>,
}

/// A block as the execution layer holds it: header, transactions and, on a
/// post-Shanghai chain, its withdrawals — which on a gov5 chain are its
/// rewards.
#[derive(Debug, Clone)]
pub struct ChainBlock {
    /// The header.
    pub header: alloy_consensus::Header,
    /// The transactions' EIP-2718 bytes, in order. Bytes rather than a typed
    /// envelope: a block may carry transaction types this crate does not
    /// model (N42's 0x50), and every consumer wants the bytes anyway.
    pub transactions: Vec<alloy_primitives::Bytes>,
    /// The withdrawals; `None` before Shanghai.
    pub withdrawals: Option<Vec<alloy_eips::eip4895::Withdrawal>>,
}

/// How to resolve a started build — the node-neutral stand-in for reth's
/// `PayloadKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveKind {
    /// Block until the pending build finishes packing.
    WaitForPending,
}

/// The execution layer, as consensus sees it.
#[async_trait::async_trait]
pub trait ExecutionLayer: Send + Sync + 'static {
    /// The execution layer's canonical head number, for telling how far
    /// behind a peer this node is. `None` when not offered.
    async fn latest_block_number(&self) -> Result<Option<u64>, ElError> {
        Ok(None)
    }

    /// A block by hash, canonical or not, as its header and transactions —
    /// for serving a peer's fetch-on-miss when the body is no longer in the
    /// consensus layer's own store. `None` when not held or not offered.
    async fn block_by_hash(&self, hash: B256) -> Result<Option<ChainBlock>, ElError> {
        let _ = hash;
        Ok(None)
    }

    /// A canonical block by number, as its header and transactions, for
    /// serving peers that sync by range. `None` when the execution layer
    /// does not have it — or, in the default, does not offer the lookup.
    async fn block_by_number(&self, number: u64) -> Result<Option<ChainBlock>, ElError> {
        let _ = number;
        Ok(None)
    }

    /// Hands a transaction to the execution layer's pool
    /// (`eth_sendRawTransaction`), returning its hash. The default declines:
    /// an execution layer that does not offer the method.
    async fn send_raw_transaction(&self, raw: alloy_primitives::Bytes) -> Result<B256, ElError> {
        let _ = raw;
        Err(ElError::new("the execution layer does not accept transactions here"))
    }

    /// Hands a batch of transactions to the pool, returning how many it took.
    ///
    /// One call for many transactions, because the caller is a consensus loop.
    /// Forwarding a gossiped batch one round trip at a time blocks that loop for
    /// as long as the batch takes — measured on the seven-node fleet as a
    /// median block cycle of 0.5 s with a p90 of 6 s and a p99 body arrival of
    /// 14 s, because the libp2p swarm is not polled while the loop is inside
    /// those awaits. The default implementation is the sequential one, so an
    /// execution layer that has nothing better keeps working; the JSON-RPC
    /// client overrides it with a single batched request.
    async fn send_raw_transactions(&self, raws: Vec<alloy_primitives::Bytes>) -> usize {
        let mut accepted = 0;
        for raw in raws {
            if self.send_raw_transaction(raw).await.is_ok() {
                accepted += 1;
            }
        }
        accepted
    }
    /// Engine-API `newPayload` — insert and validate a block.
    async fn new_payload(&self, payload: ExecutionData) -> Result<PayloadStatus, ElError>;

    /// Imports a block this node built. An execution layer that keeps its
    /// builds can take the sealed header alone (`header`) and skip the
    /// payload's round trip -- encode 17 ms, 19 MB of wire, decode 10 ms on
    /// the leader's cycle at the 163,000-transaction tier -- falling back to
    /// the payload when it no longer has the build. The default sends the
    /// payload.
    async fn import_own_block(
        &self,
        header: Option<&alloy_consensus::Header>,
        payload: ExecutionData,
    ) -> Result<PayloadStatus, ElError> {
        let _ = header;
        self.new_payload_for(ExecutionPath::LIVE_SEQUENTIAL, payload).await
    }

    /// Classified Engine-API `newPayload` call.
    ///
    /// Raw methods remain the adapter/test-double seam. Production callers use
    /// the classified wrappers so historical catch-up is never aggregated with
    /// live execution and unsupported PEVM cannot silently fall back.
    async fn new_payload_for(
        &self,
        path: ExecutionPath,
        payload: ExecutionData,
    ) -> Result<PayloadStatus, ElError> {
        let started = std::time::Instant::now();
        if !path.uses_current_engine_api() {
            record_call(path, "new_payload", started, "unsupported");
            return Err(ElError::new(format!(
                "execution path {} is not implemented by the canonical Engine API adapter",
                path.label()
            )));
        }

        let result = self.new_payload(payload).await;
        let outcome = result
            .as_ref()
            .map_or("error", |status| payload_outcome(&status.status));
        record_call(path, "new_payload", started, outcome);
        result
    }

    /// Engine-API `forkchoiceUpdated` without attributes — the finalise and
    /// import path.
    async fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, ElError>;

    /// Classified canonical-head update paired with [`Self::new_payload_for`].
    async fn fork_choice_updated_for(
        &self,
        path: ExecutionPath,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, ElError> {
        let started = std::time::Instant::now();
        if !path.uses_current_engine_api() || !path.may_write_canonical_state() {
            record_call(path, "forkchoice_updated", started, "unsupported");
            return Err(ElError::new(format!(
                "execution path {} may not update canonical fork choice",
                path.label()
            )));
        }

        let result = self.fork_choice_updated(state).await;
        let outcome = result.as_ref().map_or("error", |updated| {
            payload_outcome(&updated.payload_status.status)
        });
        record_call(path, "forkchoice_updated", started, outcome);
        result
    }

    /// `forkchoiceUpdated` with attributes — starts a payload build. Kept
    /// separate from the attribute-less call so the finalise path can later move
    /// off the consensus hot path.
    async fn fork_choice_updated_with_attrs(
        &self,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError>;

    /// Classified FCU with payload attributes, used only to start a live build.
    async fn fork_choice_updated_with_attrs_for(
        &self,
        path: ExecutionPath,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError> {
        let started = std::time::Instant::now();
        if !path.may_start_payload_build() {
            record_call(
                path,
                "forkchoice_updated_with_attrs",
                started,
                "unsupported",
            );
            return Err(ElError::new(format!(
                "execution path {} may not start a canonical payload build",
                path.label()
            )));
        }

        let result = self.fork_choice_updated_with_attrs(state, attrs).await;
        let outcome = result.as_ref().map_or("error", |updated| {
            payload_outcome(&updated.payload_status.status)
        });
        record_call(path, "forkchoice_updated_with_attrs", started, outcome);
        result
    }

    /// Resolves a started build. `None` means no such job.
    async fn resolve_payload(
        &self,
        id: PayloadId,
        kind: ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>>;

    /// Classified resolution of a live payload build.
    async fn resolve_payload_for(
        &self,
        path: ExecutionPath,
        id: PayloadId,
        kind: ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>> {
        let started = std::time::Instant::now();
        if !path.may_start_payload_build() {
            record_call(path, "resolve_payload", started, "unsupported");
            return Some(Err(ElError::new(format!(
                "execution path {} may not resolve a canonical payload build",
                path.label()
            ))));
        }

        let result = self.resolve_payload(id, kind).await;
        let outcome = match &result {
            Some(Ok(_)) => "ok",
            Some(Err(_)) => "error",
            None => "missing",
        };
        record_call(path, "resolve_payload", started, outcome);
        result
    }
}
