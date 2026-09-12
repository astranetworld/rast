// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A loopback TCP channel that hands a built block to the validator as bytes.
//!
//! `n42Engine_getPayloadRaw` took the transactions out of the JSON but left
//! the block in it: a 12 MB RLP became a 24 MB hex string, serialised on this
//! side, parsed and decoded on the other. Measured at the 163,000-transaction
//! tier the validator saw a build take about 150 ms longer than the builder
//! spent on it, and this hop is most of that.
//!
//! This is the same block over a socket, length-prefixed, nothing encoded
//! twice. The RLP is produced with the transactions encoded in parallel, which
//! `alloy_rlp::encode` on a block does not do. The validator learns the address
//! from `n42Engine_payloadEndpoint` on the auth transport, so the channel needs
//! no flag on its side; on this side it is `N42_PAYLOAD_SERVE=<addr>`, loopback
//! only, because it is unauthenticated and answers with whatever this node has
//! built.
//!
//! # Wire
//!
//! ```text
//! request  := u8 kind (n42_h2_execution::raw_engine::request), then:
//!   GET_PAYLOAD: u64 payload id (the Engine API's 8 bytes, little-endian)
//!   reply    := u8 status            0 = unknown build, 1 = block follows, 2 = error (u32 len + message)
//!               u32 len, block RLP   [header, transactions, ommers, withdrawals]
//!               u8 has_requests, [u32 n, n x (u32 len, bytes)]
//!               u8 has_bal, [u32 len, bytes]
//!   NEW_PAYLOAD: u32 len, encoded ExecutionData (raw_engine::encode_execution_data)
//!   reply    := u8 status            1 = payload status follows, 2 = error (u32 len + message)
//!               u32 len, encoded PayloadStatus
//! ```
//!
//! `NEW_PAYLOAD` is the follower's half: the same `engine_newPayload`, handed
//! to the engine as the [`ExecutionData`] it wants without 39 MB of hex on the
//! way. Measured before it existed: ~285 ms between a body arriving at the
//! validator and its vote that the execution layer's own import (637 ms) did
//! not account for.

use std::net::SocketAddr;

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use alloy_eips::Encodable2718;
use alloy_rlp::Encodable;
use n42_h2_execution::raw_engine::{self, request};
use reth_engine_primitives::ConsensusEngineHandle;
use n42_engine_types::N42BuiltPayload;
use reth_primitives_traits::transaction::TxHashRef as _;
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{BuiltPayload, PayloadKind, PayloadTypes};
use reth_primitives_traits::{Block as _, BlockBody as _, SealedBlock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// The block's RLP, `[header, transactions, ommers, withdrawals]`, with the
/// transactions encoded on the worker pool.
///
/// Byte-identical to `alloy_rlp::encode(block)`: a typed transaction is an
/// RLP string wrapping its EIP-2718 bytes, a legacy one is its own RLP list.
pub fn encode_block_parallel<B>(block: &SealedBlock<B>) -> Vec<u8>
where
    B: reth_primitives_traits::Block,
    B::Body: reth_primitives_traits::BlockBody<Transaction: Encodable2718 + Sync>,
{
    use rayon::prelude::*;
    let header = alloy_rlp::encode(block.header());
    let transactions: Vec<Vec<u8>> = block
        .body()
        .transactions()
        .par_iter()
        .map(|tx| {
            let inner = tx.encoded_2718();
            if tx.type_flag().is_some() {
                let mut out = Vec::with_capacity(inner.len() + 4);
                alloy_rlp::Header { list: false, payload_length: inner.len() }.encode(&mut out);
                out.extend_from_slice(&inner);
                out
            } else {
                inner
            }
        })
        .collect();
    let transactions_len: usize = transactions.iter().map(Vec::len).sum();
    let transactions_header = alloy_rlp::Header { list: true, payload_length: transactions_len };
    let ommers: &[u8] = &[0xc0];
    let withdrawals = block.body().withdrawals().map(|w| alloy_rlp::encode(w));
    let payload_length = header.len()
        + transactions_header.length_with_payload()
        + ommers.len()
        + withdrawals.as_ref().map_or(0, Vec::len);
    let mut out = Vec::with_capacity(payload_length + 8);
    alloy_rlp::Header { list: true, payload_length }.encode(&mut out);
    out.extend_from_slice(&header);
    transactions_header.encode(&mut out);
    for tx in &transactions {
        out.extend_from_slice(tx);
    }
    out.extend_from_slice(ommers);
    if let Some(withdrawals) = withdrawals {
        out.extend_from_slice(&withdrawals);
    }
    out
}

/// Serves built blocks and imports on `addr` until the process ends.
/// What importing our own sealed block without re-executing it needs: the
/// validator that turns a payload into the sealed block, the QMDB state the
/// builder filed the block's root in (under the builder's hash), and the way
/// into the engine loop. See `n42_engine_types::built_executions`.
#[derive(Clone)]
pub struct OwnBlockReuse {
    /// Converts a payload into the sealed block, exactly as the engine would.
    pub validator: std::sync::Arc<n42_engine_types::engine_validator::N42EngineValidator<reth_chainspec::ChainSpec>>,
    /// The QMDB state, on a chain that declares one.
    pub qmdb: Option<n42_qmdb_reth::QmdbNodeState>,
    /// Into the engine loop.
    pub inserts: tokio::sync::mpsc::UnboundedSender<reth_node_builder::executed_inserts::ExecutedInsert>,
    /// Takes the block's transactions out of the pool the moment the block is
    /// in the tree, so the next build does not select them again. Opt-in.
    ///
    /// The pool learns of a canonical block through its maintenance task,
    /// asynchronously, and at 163,000 transactions a block that lags behind
    /// a leader that builds every view: a tenure leader's builder was
    /// measured pulling 327,000 transactions a build of which 163,000 were
    /// the previous block's, paying the pool iteration twice and an account
    /// read per stale transaction. Pruning here made `stale` zero and the
    /// round slower: reth removes transactions one at a time under the
    /// pool's write lock, 260-293 ms for a block's worth, and that is the
    /// same cost the maintenance pays later -- so on the import path it is
    /// on the critical path instead of beside it. The pool's per-transaction
    /// removal is the wall, not when it happens.
    pub prune_pool: Option<std::sync::Arc<dyn Fn(Vec<alloy_primitives::B256>) + Send + Sync>>,
    /// `N42_FOLLOWER_EXEC_PROBE=1`: after the engine has imported a block of
    /// another node's, execute it once more with the plain block executor on
    /// the parent's state and log how long that takes -- the time an import
    /// without the engine's payload-processor plumbing would cost. An
    /// instrument: it adds its own time to the import, and a leg run with it
    /// is not a measurement of the chain. Returns (ms, gas used, receipts).
    pub exec_probe: Option<
        std::sync::Arc<
            dyn Fn(reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>) -> Result<(u64, u64, usize), String>
                + Send
                + Sync,
        >,
    >,
    /// `N42_FOLLOWER_DIRECT_IMPORT=1`: another node's block is executed here
    /// with the plain block executor, checked against its header by the
    /// consensus rules and the QMDB root, and handed to the engine as
    /// executed -- the leader's own-block mechanism, for every block. The
    /// engine's `newPayload` still follows, finds the block in its tree and
    /// answers; it is the proof the insert landed and the fallback when it
    /// did not. Round 38 measured the plain executor at 121 ms a block
    /// against ~340 ms in the engine's payload-processor path.
    pub import_foreign: Option<std::sync::Arc<ForeignImport>>,
}

/// Executes and checks another node's block; see [`OwnBlockReuse::import_foreign`].
/// Returns the executed block for the engine and the phase timings in
/// milliseconds: header checks, senders, execution, post-execution checks,
/// state root, hashed state, then the senders served from the cache and the
/// parent-state lookup.
pub type ForeignImport = dyn Fn(
        SealedBlock<n42_tx_types::Block>,
        Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<
        (Box<reth_payload_primitives::BuiltPayloadExecutedBlock<n42_tx_types::N42Primitives>>, [u64; 9]),
        String,
    > + Send
    + Sync;

impl std::fmt::Debug for OwnBlockReuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnBlockReuse").field("qmdb", &self.qmdb.is_some()).finish_non_exhaustive()
    }
}

/// Imports a payload that is one of our own builds under consensus's seal by
/// handing the engine the build's execution, so `newPayload` for it finds
/// the block already in the tree.
///
/// Returns `Some(built hash)` when the block went in that way. `None` means
/// the payload is not a build this node kept, or the sealed header did not
/// hash to the payload's hash, or the engine refused it -- and the caller
/// imports it the ordinary way, so nothing here can make a block invalid,
/// only slow.
async fn reuse_own_build<T>(
    reuse: &OwnBlockReuse,
    data: &alloy_rpc_types_engine::ExecutionData,
) -> Option<B256>
where
    T: PayloadTypes<ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    use reth_engine_primitives::PayloadValidator as _;
    let v1 = data.payload.as_v1();
    let (parent_hash, number, state_root, receipts_root, gas_used) =
        (v1.parent_hash, v1.block_number, v1.state_root, v1.receipts_root, v1.gas_used);
    // On a thread: a build sealed before its finish is waited for.
    let (built_hash, built) = tokio::task::spawn_blocking(move || {
        n42_engine_types::built_executions::take(parent_hash, number, state_root, receipts_root, gas_used, None)
    })
    .await
    .ok()??;
    let started = std::time::Instant::now();
    let expected_hash = data.payload.block_hash();
    // The sealed header, first from the fields alone: the payload carries
    // everything the seal may have changed, the build carries everything it
    // cannot, and the hash says whether the pairing is right. That is a
    // few microseconds; the full conversion below decodes 163,000
    // transactions to reach the same header, 50-100 ms, and is kept for the
    // day a profile changes a field this does not expect.
    let sealed_header = match sealed_header_from_fields(data, built.block.header()) {
        Some(header) if header.hash() == expected_hash => header,
        _ => {
            let sealed = match <n42_engine_types::engine_validator::N42EngineValidator<reth_chainspec::ChainSpec> as reth_engine_primitives::PayloadValidator<T>>::convert_payload_to_block(&reuse.validator, data.clone()) {
                Ok(sealed) => sealed,
                Err(err) => {
                    debug!(target: "n42.payload_serve", %err, "own build's payload did not convert; importing it the ordinary way");
                    return None;
                }
            };
            if sealed.hash() != expected_hash
                || sealed.header().transactions_root != built.block.header().transactions_root
                || sealed.body().transactions.len() != built.block.body().transactions.len()
            {
                return None;
            }
            sealed.split_sealed_header_body().0
        }
    };
    let converted = started.elapsed();
    if v1.transactions.len() != built.block.body().transactions.len() {
        return None;
    }
    hand_off_own_build::<T>(reuse, built_hash, built, sealed_header, converted).await
}

/// The hand-off of a build this node kept, under the sealed header consensus
/// gave it: the sealed block registered for the engine's own conversion, the
/// build's execution inserted as executed, the QMDB root filed under the
/// sealed hash, the queue told, the pool pruned. Shared by the payload path
/// (`reuse_own_build`) and the header-only path (`request::OWN_BLOCK`).
async fn hand_off_own_build<T>(
    reuse: &OwnBlockReuse,
    built_hash: B256,
    built: n42_engine_types::built_executions::BuiltExecution,
    sealed_header: reth_primitives_traits::SealedHeader,
    converted: std::time::Duration,
) -> Option<B256>
where
    T: PayloadTypes<ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    let started = std::time::Instant::now();
    let block_number = sealed_header.number;
    let sealed_hash = sealed_header.hash();
    // The build's block is moved out when this is its last holder (the
    // registry gave it up in `take`): one clone of the 163,000-transaction
    // body for the engine's copy instead of two.
    let (body, senders) = match std::sync::Arc::try_unwrap(built.block) {
        Ok(block) => {
            let (sealed, senders) = block.split_sealed();
            (sealed.split_sealed_header_body().1, senders)
        }
        Err(shared) => (shared.body().clone(), shared.senders().to_vec()),
    };
    // For the engine's newPayload of this block, which follows the hand-off:
    // its conversion finds the block here instead of decoding the payload.
    n42_engine_types::built_executions::remember_sealed(
        sealed_hash,
        SealedBlock::from_sealed_parts(sealed_header.clone(), body.clone()),
    );
    let recovered: reth_primitives_traits::RecoveredBlock<n42_tx_types::Block> = reth_primitives_traits::RecoveredBlock::new_sealed(
        SealedBlock::from_sealed_parts(sealed_header, body),
        senders,
    );
    // For the pool prune below, taken now: the block moves into the engine's
    // insert.
    let pool_prune_hashes: Option<Vec<B256>> = reuse
        .prune_pool
        .is_some()
        .then(|| recovered.body().transactions().map(|tx| *tx.tx_hash()).collect::<Vec<B256>>());
    if let Some(qmdb) = &reuse.qmdb {
        if let Err(err) = qmdb.rename(built_hash, sealed_hash) {
            warn!(target: "n42.payload_serve", %err, %built_hash, %sealed_hash, "could not file the build's QMDB root under the sealed hash; importing the ordinary way");
            return None;
        }
    }
    // The build's own execution result, recorded by the builder under the
    // build's hash: under deferred execution the next block's header is
    // checked against it under the sealed hash.
    if built_hash != sealed_hash {
        if let Some(fields) = n42_engine_types::executed_fields::get(&built_hash) {
            n42_engine_types::executed_fields::remember(sealed_hash, fields);
        }
    }
    let executed = reth_payload_primitives::BuiltPayloadExecutedBlock::<n42_tx_types::N42Primitives> {
        recovered_block: std::sync::Arc::new(recovered),
        execution_output: built.execution_output,
        hashed_state: built.hashed_state,
        trie_updates: built.trie_updates,
    };
    // The block's transactions leave the queue before this returns, as a
    // foreign block's do: the build ahead starts on the return, and a queue
    // that still lists this build as the last one gives its 163,000
    // transactions back to the lanes at the next build's start (57 ms of a
    // full block's build, under the lock) for the canonical pruner to take
    // out again 100 ms later (78 ms, waiting on the same lock).
    //
    // Not by removing them from the lanes (`remove_mined_batch`: 39-51 ms
    // here, most of it freeing the 163,000 transactions its retain drops)
    // but by forgetting the mined part of the build's taken list, with the
    // drop on a blocking thread. Forgetting the *whole* list lost the
    // puller's batches in flight when the block filled -- a few thousand
    // transactions across every sender -- and every sender's lane then
    // started above the chain's nonce (loop29E400a: 7% occupancy).
    let queue_prune_ms = n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>().map(|queue| {
        let at = std::time::Instant::now();
        let mined = executed
            .recovered_block
            .transactions_with_sender()
            .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)));
        let dropped = queue.forget_mined(executed.recovered_block.header().parent_hash, mined);
        debug!(target: "n42.payload_serve", forgotten = dropped.len(), "own block's transactions forgotten by the queue");
        // Held, not dropped, until the chain settles this height: a block
        // consensus never commits gives them back (round 43).
        queue.hold_own_block(executed.recovered_block.number(), executed.recovered_block.hash(), dropped);
        at.elapsed().as_millis() as u64
    });
    let (done, handed) = tokio::sync::oneshot::channel();
    if reuse
        .inserts
        .send(reth_node_builder::executed_inserts::ExecutedInsert { block: Box::new(executed), done })
        .is_err()
    {
        return None;
    }
    let handed = tokio::time::timeout(std::time::Duration::from_secs(2), handed).await;
    match handed {
        Ok(Ok(true)) => {
            crate::follower_import::note_import_landed();
            if let (Some(prune), Some(hashes)) = (reuse.prune_pool.clone(), pool_prune_hashes) {
                let count = hashes.len();
                let pruned_at = std::time::Instant::now();
                // Synchronous, on a blocking thread: the removal holds the
                // pool's write lock, and it has to be done before this returns
                // so the next build, armed by this import, starts on a pool
                // without them.
                let _ = tokio::task::spawn_blocking(move || prune(hashes)).await;
                info!(
                    target: "n42.payload_serve",
                    count,
                    prune_ms = pruned_at.elapsed().as_millis() as u64,
                    "own block's transactions taken out of the pool"
                );
            }
            info!(
                target: "n42.payload_serve",
                number = block_number,
                convert_ms = converted.as_millis() as u64,
                queue_prune_ms,
                total_ms = started.elapsed().as_millis() as u64,
                "own block handed to the engine as executed"
            );
            Some(built_hash)
        }
        other => {
            warn!(target: "n42.payload_serve", ?other, "the engine did not take our executed block; importing the ordinary way");
            None
        }
    }
}

/// A block this node built, imported by its sealed header alone
/// (`request::OWN_BLOCK`): the build is found by the header's parent, number
/// and roots, handed to the engine as executed under the sealed hash, and
/// the engine's `newPayload` then runs on a payload assembled here from the
/// build's own transactions -- 19 MB that no longer cross the wire twice.
/// Returns the status, the block number, and the hand-off and payload
/// assembly times in milliseconds; an `Err` is the message to send back
/// (`unknown build`), on which the caller sends the payload the old way.
async fn own_block_by_header<T>(
    reuse: Option<&OwnBlockReuse>,
    engine: &ConsensusEngineHandle<T>,
    frame: &[u8],
) -> Result<(alloy_rpc_types_engine::PayloadStatus, u64, u64, u64), String>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    use alloy_rlp::Decodable;
    let reuse = reuse.ok_or("no own-block reuse on this node")?;
    let header = alloy_consensus::Header::decode(&mut &frame[..]).map_err(|e| format!("header: {e}"))?;
    if header.block_access_list_hash.is_some() {
        // The build registry does not keep the access list the payload
        // carries; the payload path does.
        return Err("unknown build: block access list".to_owned());
    }
    // Taken out of the registry, so the hand-off can move the body instead
    // of cloning it -- unless the validator builds on seal: then a
    // `BUILD_ON_OWN` for this same block is on another connection at this
    // very moment and must still find it (loop110 S1: taking it here won
    // the race on 383 of 384 blocks, every build on seal was refused, and the
    // leader fell back to building on its critical path). Left in place, the
    // registry's own bound (two builds) retires it two blocks later; the
    // hand-off clones the body once (~10 ms, beside the leader's chain now).
    // On a thread: a build that sealed before its finish is waited for
    // (docs/PHASE_D_DEFERRED_EXECUTION.md section 13), and that wait must
    // not hold a runtime worker.
    let (parent_hash, number, state_root, receipts_root, gas_used, transactions_root) =
        (header.parent_hash, header.number, header.state_root, header.receipts_root, header.gas_used, Some(header.transactions_root));
    let (built_hash, built) = tokio::task::spawn_blocking(move || {
        if build_on_seal() {
            n42_engine_types::built_executions::find(parent_hash, number, state_root, receipts_root, gas_used, transactions_root)
        } else {
            n42_engine_types::built_executions::take(parent_hash, number, state_root, receipts_root, gas_used, transactions_root)
        }
    })
    .await
    .map_err(|err| format!("build lookup: {err}"))?
    .ok_or("unknown build")?;
    let sealed_hash = header.hash_slow();
    let sealed_header = reth_primitives_traits::SealedHeader::new(header.clone(), sealed_hash);
    let withdrawals = built.block.body().withdrawals.clone().map(|w| w.to_vec()).unwrap_or_default();
    let handoff_at = std::time::Instant::now();
    hand_off_own_build::<T>(reuse, built_hash, built, sealed_header, std::time::Duration::ZERO)
        .await
        .ok_or("the engine did not take the executed block")?;
    let handoff_ms = handoff_at.elapsed().as_millis() as u64;
    // The payload for the engine's `newPayload`: its conversion takes the
    // sealed block registered above by the payload's block hash before it
    // looks at anything else, so the transactions need not travel at all --
    // an empty list here saves encoding 163,000 of them (15 ms and as many
    // allocations). If the engine ever answered other than Valid, the
    // validator's fallback sends the whole payload and the engine converts
    // it the ordinary way.
    let payload_at = std::time::Instant::now();
    let data = n42_h2_consensus::execution_data_from_raw_parts(sealed_hash, &header, Vec::new(), withdrawals, None);
    let payload_ms = payload_at.elapsed().as_millis() as u64;
    let status = engine.new_payload(data).await.map_err(|e| format!("engine: {e}"))?;
    if !status.status.is_valid() {
        return Err(format!("engine answered {:?} to the header-only payload", status.status));
    }
    Ok((status, header.number, handoff_ms, payload_ms))
}

/// Where a build on an own block spent its time, for the log line.
#[derive(Debug, Default, Clone, Copy)]
struct BuildOnOwnTimes {
    find_ms: u64,
    queue_ms: u64,
    rename_ms: u64,
    build_ms: u64,
}

/// The next block, built on a block this node built and consensus has just
/// sealed (`request::BUILD_ON_OWN`) -- before the engine has imported that
/// block, and without the forkchoice and the payload service that used to
/// stand between the seal and the build (own import 62 ms + forkchoice 72 +
/// service ~35 on the leader's chain, loop108; `docs/FLEET7_PLAN_V2.md`).
///
/// The parent is found in the build registry by the sealed header's parent,
/// number, roots and gas, exactly as the header-only import finds it, and is
/// *not* taken out: that import follows and takes it. What this does first is
/// what the import's hand-off would otherwise do before the next build could
/// start: the queue forgets the parent's mined transactions (or the build
/// would select them again), and the QMDB tree moves to the sealed hash (the
/// hand-off's later rename finds it there and is content). Then the builder
/// runs on a blocking thread with the parent's bundle laid over the chain's
/// state. An `Err` is the message sent back, on which the validator builds
/// ahead the ordinary way.
async fn build_on_own_block(
    reuse: Option<&OwnBlockReuse>,
    frame: &[u8],
) -> Result<(N42BuiltPayload, BuildOnOwnTimes), String> {
    let reuse = reuse.ok_or("no own-block reuse on this node")?;
    let builder = n42_engine_types::direct_build::get().ok_or("no direct builder")?;
    let (header, attributes) = raw_engine::decode_build_on_own(frame)?;
    if header.block_access_list_hash.is_some() {
        return Err("unknown build: block access list".to_owned());
    }
    let mut times = BuildOnOwnTimes::default();
    let at = std::time::Instant::now();
    // The parent's post-state is what the build needs (`StateReady`); a
    // parent sealed before its finish is waited for, on a thread.
    let (parent_hash, number, state_root, receipts_root, gas_used) =
        (header.parent_hash, header.number, header.state_root, header.receipts_root, header.gas_used);
    let transactions_root = Some(header.transactions_root);
    let (built_hash, built) = tokio::task::spawn_blocking(move || {
        n42_engine_types::built_executions::find_kept_at(
            parent_hash,
            number,
            state_root,
            receipts_root,
            gas_used,
            transactions_root,
            n42_engine_types::built_executions::Stage::StateReady,
        )
    })
    .await
    .map_err(|err| format!("build lookup: {err}"))?
    .ok_or("unknown build")?;
    times.find_ms = at.elapsed().as_millis() as u64;
    let sealed_hash = header.hash_slow();
    let parent = reth_primitives_traits::SealedHeader::new(header, sealed_hash);
    // The parent's transactions leave the build's taken list now, held until
    // the chain settles the height -- the same bookkeeping as the hand-off,
    // which finds nothing left to forget when it runs.
    if let Some(queue) = n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>() {
        let at = std::time::Instant::now();
        let mined = built
            .block
            .transactions_with_sender()
            .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)));
        let dropped = queue.forget_mined(built.block.header().parent_hash, mined);
        debug!(target: "n42.payload_serve", forgotten = dropped.len(), "own block's transactions forgotten by the queue ahead of the build");
        queue.hold_own_block(built.block.number(), sealed_hash, dropped);
        times.queue_ms = at.elapsed().as_millis() as u64;
    }
    if let Some(qmdb) = &reuse.qmdb {
        let at = std::time::Instant::now();
        // A parent still finishing behind its seal has no tree yet; the
        // build renames it under the sealed hash when it needs it.
        if qmdb.root_of(&built_hash).is_some() {
            qmdb.rename(built_hash, sealed_hash).map_err(|err| format!("qmdb rename: {err}"))?;
        }
        times.rename_ms = at.elapsed().as_millis() as u64;
    }
    let at = std::time::Instant::now();
    let request = n42_engine_types::direct_build::BuildOnOwnRequest { parent, parent_execution: built, attributes };
    let payload = tokio::task::spawn_blocking(move || builder.build_on_own(request))
        .await
        .map_err(|err| format!("build task: {err}"))??;
    times.build_ms = at.elapsed().as_millis() as u64;
    Ok((payload, times))
}

/// Writes a built payload in the channel's answer shape (status 1, the
/// block's RLP, the requests, the access list); returns the block's size and
/// how long the encoding took.
fn push_built_payload(out: &mut Vec<u8>, payload: &N42BuiltPayload) -> (usize, std::time::Duration) {
    let encode_at = std::time::Instant::now();
    let block = encode_block_parallel(payload.block());
    let encoded = encode_at.elapsed();
    out.reserve(block.len() + 64);
    out.push(1);
    out.extend_from_slice(&(block.len() as u32).to_le_bytes());
    out.extend_from_slice(&block);
    match payload.requests() {
        Some(requests) => {
            let requests = requests.take();
            out.push(1);
            out.extend_from_slice(&(requests.len() as u32).to_le_bytes());
            for request in &requests {
                out.extend_from_slice(&(request.len() as u32).to_le_bytes());
                out.extend_from_slice(request);
            }
        }
        None => out.push(0),
    }
    match payload.block_access_list() {
        Some(bal) => {
            out.push(1);
            out.extend_from_slice(&(bal.len() as u32).to_le_bytes());
            out.extend_from_slice(bal);
        }
        None => out.push(0),
    }
    (block.len(), encoded)
}

/// The sealed header a payload describes, given the build it came from: the
/// payload's fields where the seal may have touched them, the build's where it
/// cannot. `None` if the shapes disagree; the caller checks the hash.
fn sealed_header_from_fields(
    data: &alloy_rpc_types_engine::ExecutionData,
    built: &alloy_consensus::Header,
) -> Option<reth_primitives_traits::SealedHeader> {
    let v1 = data.payload.as_v1();
    if v1.block_number != built.number || v1.parent_hash != built.parent_hash {
        return None;
    }
    let mut header = built.clone();
    header.beneficiary = v1.fee_recipient;
    header.state_root = v1.state_root;
    header.receipts_root = v1.receipts_root;
    header.logs_bloom = v1.logs_bloom;
    header.mix_hash = v1.prev_randao;
    header.gas_limit = v1.gas_limit;
    header.gas_used = v1.gas_used;
    header.timestamp = v1.timestamp;
    header.extra_data = v1.extra_data.clone();
    header.base_fee_per_gas = Some(v1.base_fee_per_gas.try_into().ok()?);
    // The fields gov5's profile is free to leave in either of two shapes --
    // the same candidates the engine's own conversion tries, a few dozen
    // header hashes at most.
    let expected = data.payload.block_hash();
    let withdrawals_roots: Vec<Option<B256>> = match (built.withdrawals_root, data.payload.as_v2()) {
        (Some(root), Some(v2)) => {
            let rewards = n42_h2_consensus::withdrawals_to_rewards(v2.withdrawals.as_slice());
            vec![Some(root), Some(n42_h2_consensus::gov5_rewards_root(rewards))]
        }
        (root, _) => vec![root],
    };
    let requests_hashes: Vec<Option<B256>> = match built.requests_hash {
        Some(hash) => vec![
            Some(hash),
            Some(n42_h2_consensus::GOV5_EMPTY_REQUESTS_HASH),
            Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
        ],
        None => vec![None],
    };
    for ommers_hash in [built.ommers_hash, B256::ZERO, alloy_consensus::EMPTY_OMMER_ROOT_HASH] {
        for difficulty in [built.difficulty, alloy_primitives::U256::ZERO, alloy_primitives::U256::from(1)] {
            for withdrawals_root in &withdrawals_roots {
                for requests_hash in &requests_hashes {
                    header.ommers_hash = ommers_hash;
                    header.difficulty = difficulty;
                    header.withdrawals_root = *withdrawals_root;
                    header.requests_hash = *requests_hash;
                    if header.hash_slow() == expected {
                        return Some(reth_primitives_traits::SealedHeader::new(header, expected));
                    }
                }
            }
        }
    }
    None
}

/// Whether the validators build on seal (`N42_BUILD_ON_SEAL`, the same
/// variable the validator reads; the fleet launcher sets it for both). It
/// decides whether the header-only import may take the build out of the
/// registry or must leave it for the `BUILD_ON_OWN` racing it.
fn build_on_seal() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_BUILD_ON_SEAL").is_ok_and(|v| v != "0"))
}

/// `N42_RAW_SHARED_DECODE`, read once.
fn raw_shared_decode() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_RAW_SHARED_DECODE").is_ok_and(|v| v == "1"))
}

/// `N42_PAYLOAD_SERVE_FRESH_BUFFERS`, read once.
fn fresh_buffers() -> bool {
    static FRESH: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FRESH.get_or_init(|| std::env::var("N42_PAYLOAD_SERVE_FRESH_BUFFERS").is_ok())
}

pub async fn serve<T>(
    addr: SocketAddr,
    payloads: PayloadBuilderHandle<T>,
    engine: ConsensusEngineHandle<T>,
    reuse: Option<OwnBlockReuse>,
) -> std::io::Result<()>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    // Said at start-up so a round can grep that its switch reached this
    // process: a variable that is set but never arrived measures nothing.
    info!(
        target: "n42.payload_serve",
        %addr,
        fresh_buffers = fresh_buffers(),
        own_block_reuse = reuse.is_some(),
        "raw payload channel listening"
    );
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(target: "n42.payload_serve", %err, "accept failed");
                continue;
            }
        };
        let payloads = payloads.clone();
        let engine = engine.clone();
        let reuse = reuse.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_connection(stream, payloads, engine, reuse).await {
                debug!(target: "n42.payload_serve", %peer, %err, "raw payload connection ended");
            }
        });
    }
}

async fn serve_connection<T>(
    mut stream: TcpStream,
    payloads: PayloadBuilderHandle<T>,
    engine: ConsensusEngineHandle<T>,
    reuse: Option<OwnBlockReuse>,
) -> std::io::Result<()>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    stream.set_nodelay(true)?;
    // Buffers retained across frames. A newPayload frame is ~19 MB at the
    // bench tier and a served payload the same; allocated fresh per block
    // they are fresh pages first-touched on every block on every node --
    // measured as the followers' page-fault rate doubling in a round and
    // their runtime threads' time going to the kernel. Grown once, reused.
    let mut frame: Vec<u8> = Vec::new();
    let mut out: Vec<u8> = Vec::new();
    loop {
        let kind = match stream.read_u8().await {
            Ok(kind) => kind,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        if kind == request::OWN_BLOCK {
            let len = stream.read_u32_le().await? as usize;
            if len > 1 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "header frame too large"));
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            out.clear();
            let started = std::time::Instant::now();
            let reply = own_block_by_header::<T>(reuse.as_ref(), &engine, &buf).await;
            match reply {
                Ok((status, number, handoff_ms, payload_ms)) => {
                    info!(
                        target: "n42.payload_serve",
                        number,
                        handoff_ms,
                        payload_ms,
                        total_ms = started.elapsed().as_millis() as u64,
                        status = ?status.status,
                        "own block imported by header"
                    );
                    let encoded = raw_engine::encode_payload_status(&status);
                    out.push(1);
                    out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                    out.extend_from_slice(&encoded);
                }
                Err(message) => {
                    debug!(target: "n42.payload_serve", %message, "own block by header refused");
                    out.push(2);
                    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                    out.extend_from_slice(message.as_bytes());
                }
            }
            stream.write_all(&out).await?;
            continue;
        }
        if kind == request::BUILD_ON_OWN {
            let len = stream.read_u32_le().await? as usize;
            if len > 1 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "build request frame too large"));
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            out.clear();
            let started = std::time::Instant::now();
            match build_on_own_block(reuse.as_ref(), &buf).await {
                Ok((payload, times)) => {
                    let (bytes, encoded) = push_built_payload(&mut out, &payload);
                    info!(
                        target: "n42.payload_serve",
                        number = payload.block().number(),
                        txs = payload.block().body().transactions.len(),
                        bytes,
                        find_ms = times.find_ms,
                        queue_ms = times.queue_ms,
                        rename_ms = times.rename_ms,
                        build_ms = times.build_ms,
                        encode_ms = encoded.as_millis() as u64,
                        total_ms = started.elapsed().as_millis() as u64,
                        "built ahead on the sealed own block"
                    );
                }
                Err(message) => {
                    info!(target: "n42.payload_serve", %message, "build on own block refused");
                    out.push(2);
                    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                    out.extend_from_slice(message.as_bytes());
                }
            }
            stream.write_all(&out).await?;
            continue;
        }
        if kind == request::NEW_PAYLOAD {
            let len = stream.read_u32_le().await? as usize;
            if len > 256 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "payload frame too large"));
            }
            // N42_PAYLOAD_SERVE_FRESH_BUFFERS=1 restores a fresh allocation per
            // frame, for the A-B-A that separates buffer reuse from the box.
            if fresh_buffers() {
                frame = Vec::new();
                out = Vec::new();
            }
            frame.clear();
            frame.resize(len, 0);
            stream.read_exact(&mut frame[..]).await?;
            let started = std::time::Instant::now();
            out.clear();
            // Decoded with a copy per transaction, deliberately: decoding the
            // payload as slices of one shared 19 MB buffer (loop60N1) grew the
            // execution layer by ~19 MB a block -- something downstream keeps
            // a few of a payload's transaction bytes per block, and a slice
            // keeps the whole buffer alive with them. 4.2 -> 8.5 GB in two
            // minutes, then the fault storm.
            // `N42_RAW_SHARED_DECODE=1` decodes as slices of one shared copy of
            // the frame instead -- the variant that grew the execution layer,
            // kept for finding what holds the bytes.
            let shared_frame = raw_shared_decode().then(|| alloy_primitives::Bytes::copy_from_slice(&frame[..]));
            let decoded_data = match &shared_frame {
                Some(shared) => raw_engine::decode_execution_data_shared(shared),
                None => raw_engine::decode_execution_data(&frame),
            };
            match decoded_data {
                Err(err) => {
                    out.push(2);
                    out.extend_from_slice(&(err.len() as u32).to_le_bytes());
                    out.extend_from_slice(err.as_bytes());
                }
                Ok(data) => {
                    let decoded = started.elapsed();
                    let number = data.payload.block_number();
                    let txs = data.payload.as_v1().transactions.len();
                    // One of ours, sealed: hand the engine the build's execution
                    // first, and the newPayload below finds the block known.
                    let reused = match &reuse {
                        Some(reuse) => reuse_own_build::<T>(reuse, &data).await.is_some(),
                        None => false,
                    };
                    // The transactions' bytes, kept for the prune below; the
                    // payload itself goes to the engine.
                    let raw_transactions = data.payload.as_v1().transactions.clone();
                    let probe = reuse.as_ref().and_then(|r| r.exec_probe.clone()).filter(|_| !reused && txs > 10_000);
                    let probe_data = probe.as_ref().map(|_| data.clone());
                    // Another node's block: executed here and handed to the
                    // engine as executed, when configured. Any failure logs
                    // and leaves the block to the engine's own path.
                    let mut direct_ms: Option<[u64; 13]> = None;
                    // The block's transaction hashes, known once the direct
                    // import converted the payload: the prune below then
                    // needs no keccak over the raw bytes.
                    let mut mined_hashes: Option<Vec<B256>> = None;
                    // The executed block kept for the engine's own conversion when
                    // the answer goes out before that pass.
                    let mut remembered: Option<std::sync::Arc<reth_primitives_traits::RecoveredBlock<n42_tx_types::Block>>> = None;
                    let fast_taken = direct_fast_answer();
                    if let Some(reuse) = reuse.as_ref().filter(|r| !reused && r.import_foreign.is_some()) {
                        let import = reuse.import_foreign.clone().expect("checked");
                        let validator = reuse.validator.clone();
                        let inserts = reuse.inserts.clone();
                        let payload = data.clone();
                        let fast = direct_fast_answer();
                        let started = std::time::Instant::now();
                        // Under deferred execution the import says when the
                        // block is checked, and the validator hears it on a
                        // CHECKED frame before the import's answer.
                        let (checked_tx, checked_rx) = tokio::sync::oneshot::channel::<()>();
                        let handed = tokio::task::spawn_blocking(move || {
                            let sealed = <n42_engine_types::engine_validator::N42EngineValidator<reth_chainspec::ChainSpec> as reth_engine_primitives::PayloadValidator<T>>::convert_payload_to_block(&validator, payload)
                                .map_err(|err| format!("conversion: {err}"))?;
                            let converted = started.elapsed().as_millis() as u64;
                            // The engine's newPayload, next, converts the same
                            // payload: let it take this block instead.
                            // The engine's own conversion of the same payload takes
                            // this instead of decoding 163,000 transactions again.
                            // With the fast answer the clone moves off this path
                            // instead: the block is remembered from the executed
                            // block's `Arc` on a worker thread below, well before
                            // the engine's pass runs.
                            if !fast {
                                n42_engine_types::built_executions::remember_sealed(sealed.hash(), sealed.clone());
                            }
                            let (executed, phases) = import(sealed, Some(checked_tx))?;
                            Ok::<_, String>((executed, phases, converted))
                        });
                        tokio::pin!(handed);
                        let mut finished = None;
                        tokio::select! {
                            checked = checked_rx => {
                                if checked.is_ok() {
                                    let status = alloy_rpc_types_engine::PayloadStatus::from_status(
                                        alloy_rpc_types_engine::PayloadStatusEnum::Valid,
                                    )
                                    .with_latest_valid_hash(data.payload.block_hash());
                                    let encoded = raw_engine::encode_payload_status(&status);
                                    let mut frame = Vec::with_capacity(encoded.len() + 5);
                                    frame.push(raw_engine::reply::CHECKED);
                                    frame.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                                    frame.extend_from_slice(&encoded);
                                    stream.write_all(&frame).await?;
                                    info!(
                                        target: "n42.payload_serve",
                                        number,
                                        txs,
                                        checked_ms = started.elapsed().as_millis() as u64,
                                        "checked: answered before the execution"
                                    );
                                }
                            }
                            done = &mut handed => finished = Some(done),
                        }
                        let handed = match finished {
                            Some(done) => done,
                            None => handed.await,
                        }
                        .map_err(|err| err.to_string())
                        .and_then(|r| r);
                        match handed {
                            Ok((executed, phases, converted)) => {
                                let handed_at = std::time::Instant::now();
                                // The block's transactions leave the queue now, not
                                // when the canonical pruner gets to them: a build
                                // ahead starts the moment this import returns and
                                // would otherwise take them again (87,800 stale
                                // transactions in one build, round 38).
                                // `N42_QUEUE_WORK_OFFLOAD=1`: the queue's and the
                                // pool's bookkeeping goes to a worker thread holding
                                // the block, because the two walks of a 163,000-
                                // transaction block (one for the mined senders and
                                // nonces, one for the hashes) sit on the vote's path
                                // and nothing reads their result before the answer.
                                // Off by default: it also delays the queue's removal
                                // by those walks, and a build ahead that starts before
                                // the removal takes the mined transactions again
                                // (87,800 stale ones in one build, round 38).
                                // The block for the engine's own conversion, taken
                                // from the executed block before it is handed over.
                                if fast_taken {
                                    remembered = Some(std::sync::Arc::clone(&executed.recovered_block));
                                }
                                let queue_offloaded = queue_work_offload();
                                if let Some(queue) = n42_tx_queue::global::<n42_engine_types::N42PooledTransaction>() {
                                    if queue_offloaded {
                                        let block = std::sync::Arc::clone(&executed.recovered_block);
                                        let prune = reuse.prune_pool.clone();
                                        tokio::task::spawn_blocking(move || {
                                            let at = std::time::Instant::now();
                                            let mined: Vec<(alloy_primitives::Address, u64)> = block
                                                .transactions_with_sender()
                                                .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)))
                                                .collect();
                                            let (number, hash) = (block.number(), block.hash());
                                            let removed = queue.remove_mined_batch_collecting(mined);
                                            // Held until the chain settles the height (round 43).
                                            queue.hold_own_block(number, hash, removed);
                                            let count = block.body().transactions().count();
                                            if let Some(prune) = prune {
                                                prune(block.body().transactions().map(|tx| *tx.tx_hash()).collect());
                                            }
                                            if count > 10_000 {
                                                info!(
                                                    target: "n42.payload_serve",
                                                    number,
                                                    count,
                                                    queue_ms = at.elapsed().as_millis() as u64,
                                                    "imported block's transactions taken out of the queue and the pool"
                                                );
                                            }
                                        });
                                    } else {
                                        let mined: Vec<(alloy_primitives::Address, u64)> = executed
                                            .recovered_block
                                            .transactions_with_sender()
                                            .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)))
                                            .collect();
                                        let (number, hash) =
                                            (executed.recovered_block.number(), executed.recovered_block.hash());
                                        mined_hashes = Some(
                                            executed.recovered_block.body().transactions().map(|tx| *tx.tx_hash()).collect(),
                                        );
                                        tokio::task::spawn_blocking(move || {
                                            let removed = queue.remove_mined_batch_collecting(mined);
                                            queue.hold_own_block(number, hash, removed);
                                        });
                                    }
                                }
                                // The mined-transaction bookkeeping above walks the
                                // block twice; time it and the engine's acknowledgement
                                // apart, because together they were most of the ~78 ms
                                // of a 438 ms import that no phase accounted for.
                                let mined_ms = handed_at.elapsed().as_millis() as u64;
                                let insert_at = std::time::Instant::now();
                                let (done, handed) = tokio::sync::oneshot::channel();
                                let sent = inserts
                                    .send(reth_node_builder::executed_inserts::ExecutedInsert { block: executed, done })
                                    .is_ok();
                                let landed = sent
                                    && matches!(tokio::time::timeout(std::time::Duration::from_secs(2), handed).await, Ok(Ok(true)));
                                if landed {
                                    crate::follower_import::note_import_landed();
                                    direct_ms = Some([
                                        converted,
                                        phases[0],
                                        phases[1],
                                        phases[2],
                                        phases[3],
                                        phases[4],
                                        phases[5],
                                        started.elapsed().as_millis() as u64,
                                        phases[6],
                                        phases[7],
                                        phases[8],
                                        mined_ms,
                                        insert_at.elapsed().as_millis() as u64,
                                    ]);
                                } else {
                                    warn!(target: "n42.payload_serve", number, "direct import: the engine did not take the executed block; importing the ordinary way");
                                }
                            }
                            Err(err) => warn!(target: "n42.payload_serve", number, %err, "direct import failed; importing the ordinary way"),
                        }
                    }
                    // The fast answer (`N42_DIRECT_FAST_ANSWER=1`): this node
                    // executed the block and the engine holds it as executed, so
                    // the validator's vote does not wait for the engine's own
                    // pass. Everything the pass would check has been checked here
                    // -- the header against its parent, the transactions root, the
                    // receipts root, the gas, and the QMDB state root -- so it is
                    // bookkeeping; it runs below, after the answer is on the wire,
                    // and a verdict other than VALID is logged loudly.
                    if direct_ms.is_some() && direct_fast_answer() {
                        let hash = data.payload.block_hash();
                        let status = alloy_rpc_types_engine::PayloadStatus::from_status(
                            alloy_rpc_types_engine::PayloadStatusEnum::Valid,
                        )
                        .with_latest_valid_hash(hash);
                        let encoded = raw_engine::encode_payload_status(&status);
                        out.push(1);
                        out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                        out.extend_from_slice(&encoded);
                        stream.write_all(&out).await?;
                        let answered = started.elapsed().saturating_sub(decoded).as_millis() as u64;
                        if let Some(ms) = direct_ms {
                            info!(
                                target: "n42.payload_serve",
                                number,
                                txs,
                                convert_ms = ms[0],
                                header_ms = ms[1],
                                senders_ms = ms[2],
                                exec_ms = ms[3],
                                checks_ms = ms[4],
                                root_ms = ms[5],
                                hashed_ms = ms[6],
                                total_ms = ms[7],
                                senders_cached = ms[8],
                                state_ms = ms[9],
                                carry_ms = ms[10],
                                mined_ms = ms[11],
                                insert_ms = ms[12],
                                answered_ms = answered,
                                "direct import: answered before the engine's own pass"
                            );
                        }
                        // The engine's pass would otherwise decode the payload's
                        // 163,000 transactions again (round 43, loop100: its pass
                        // went 35 -> 102 ms without the remembered block). The
                        // clone is made here, off the answered path, and always
                        // finishes before the pass below reads it.
                        if let Some(block) = remembered.take() {
                            let hash = block.hash();
                            let cloned = tokio::task::spawn_blocking(move || {
                                n42_engine_types::built_executions::remember_sealed(hash, block.sealed_block().clone());
                            })
                            .await;
                            if let Err(err) = cloned {
                                warn!(target: "n42.payload_serve", number, %err, "remembering the sealed block failed; the engine will decode it again");
                            }
                        }
                        let engine_at = std::time::Instant::now();
                        match engine.new_payload(data).await {
                            Ok(status) if !status.status.is_valid() => warn!(
                                target: "n42.payload_serve", number, status = ?status.status,
                                "the engine disagreed with a block this node executed and answered VALID for"
                            ),
                            Err(err) => warn!(target: "n42.payload_serve", number, %err, "the engine's own pass failed after the fast answer"),
                            _ => {}
                        }
                        // Only when the walks stayed on this path; the worker thread
                        // above prunes for itself otherwise.
                        if let (Some(prune), Some(hashes)) = (reuse.as_ref().and_then(|r| r.prune_pool.clone()), mined_hashes.take()) {
                            let count = hashes.len();
                            let pruned_at = std::time::Instant::now();
                            let _ = tokio::task::spawn_blocking(move || {
                                prune(hashes);
                                if count > 10_000 {
                                    info!(
                                        target: "n42.payload_serve",
                                        number,
                                        count,
                                        prune_ms = pruned_at.elapsed().as_millis() as u64,
                                        "imported block's transactions taken out of the pool"
                                    );
                                }
                            });
                        }
                        if txs > 10_000 {
                            info!(
                                target: "n42.payload_serve",
                                number,
                                txs,
                                engine_after_ms = engine_at.elapsed().as_millis() as u64,
                                "the engine's own pass, behind the answer"
                            );
                        }
                        continue;
                    }
                    match engine.new_payload(data).await {
                        Ok(status) => {
                            if let (Some(probe), Some(probe_data)) = (probe, probe_data) {
                                let validator = reuse.as_ref().map(|r| r.validator.clone());
                                if let Some(validator) = validator {
                                    let _ = tokio::task::spawn_blocking(move || {
                                        let converted = match <n42_engine_types::engine_validator::N42EngineValidator<reth_chainspec::ChainSpec> as reth_engine_primitives::PayloadValidator<T>>::convert_payload_to_block(&validator, probe_data) {
                                            Ok(block) => block,
                                            Err(err) => { warn!(target: "n42.payload_serve", %err, "exec probe: conversion failed"); return; }
                                        };
                                        let recovered = match converted.try_recover() {
                                            Ok(block) => block,
                                            Err(_) => { warn!(target: "n42.payload_serve", "exec probe: sender recovery failed"); return; }
                                        };
                                        let header_gas = recovered.gas_used;
                                        match probe(recovered) {
                                            Ok((exec_ms, gas, receipts)) => info!(
                                                target: "n42.payload_serve",
                                                number, txs, exec_ms, gas, header_gas, receipts,
                                                "follower exec probe: the block executed again with the plain executor"
                                            ),
                                            Err(err) => warn!(target: "n42.payload_serve", %err, "exec probe failed"),
                                        }
                                    })
                                    .await;
                                }
                            }
                            // A block this node now holds: its transactions
                            // leave the pool at once rather than when the
                            // pool's maintenance gets to them. On a follower
                            // that is what keeps `pending` honest -- the
                            // ingest gate reads it, and a block's 163,000
                            // still counted as pending after the block was
                            // imported is what stalled the whole fleet's
                            // supply for the length of one node's maintenance.
                            if status.status == alloy_rpc_types_engine::PayloadStatusEnum::Valid
                                && !reused
                                && (mined_hashes.is_some() || direct_ms.is_none())
                                && let Some(prune) = reuse.as_ref().and_then(|r| r.prune_pool.clone())
                            {
                                let pruned_at = std::time::Instant::now();
                                let count = raw_transactions.len();
                                // Not awaited: the answer to this payload is
                                // what the validator's vote waits for, and the
                                // prune of a full block was 66 ms of it (round
                                // 43, loop94). The pool is a few tens of
                                // milliseconds behind the chain instead of the
                                // length of its maintenance, which is what the
                                // `pending` the ingest gate reads needed.
                                let mined_hashes = mined_hashes.take();
                                let pruning = tokio::task::spawn_blocking(move || {
                                    let hashes: Vec<B256> = mined_hashes.unwrap_or_else(|| {
                                        use rayon::prelude::*;
                                        raw_transactions.par_iter().map(|tx| alloy_primitives::keccak256(tx)).collect()
                                    });
                                    prune(hashes);
                                    if count > 10_000 {
                                        info!(
                                            target: "n42.payload_serve",
                                            number,
                                            count,
                                            prune_ms = pruned_at.elapsed().as_millis() as u64,
                                            "imported block's transactions taken out of the pool"
                                        );
                                    }
                                });
                                // `N42_PRUNE_ASYNC=0`: the answer waits for the prune, as before round 43's loop98.
                                if !prune_async() {
                                    let _ = pruning.await;
                                }
                            }
                            if let Some(ms) = direct_ms {
                                info!(
                                    target: "n42.payload_serve",
                                    number,
                                    txs,
                                    convert_ms = ms[0],
                                    header_ms = ms[1],
                                    senders_ms = ms[2],
                                    exec_ms = ms[3],
                                    checks_ms = ms[4],
                                    root_ms = ms[5],
                                    hashed_ms = ms[6],
                                    total_ms = ms[7],
                                    senders_cached = ms[8],
                                    state_ms = ms[9],
                                    carry_ms = ms[10],
                                    mined_ms = ms[11],
                                    insert_ms = ms[12],
                                    engine_ms = (started.elapsed().saturating_sub(decoded).as_millis() as u64).saturating_sub(ms[7]),
                                    status = ?status.status,
                                    "direct import: executed here, handed to the engine as executed"
                                );
                            }
                            if txs > 10_000 {
                                info!(
                                    target: "n42.payload_serve",
                                    number,
                                    txs,
                                    decode_ms = decoded.as_millis() as u64,
                                    engine_ms = started.elapsed().saturating_sub(decoded).as_millis() as u64,
                                    status = ?status.status,
                                    reused,
                                    "raw newPayload"
                                );
                            }
                            let encoded = raw_engine::encode_payload_status(&status);
                            out.push(1);
                            out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                            out.extend_from_slice(&encoded);
                        }
                        Err(err) => {
                            let message = err.to_string();
                            out.push(2);
                            out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                            out.extend_from_slice(message.as_bytes());
                        }
                    }
                }
            }
            stream.write_all(&out).await?;
            continue;
        }
        if kind != request::GET_PAYLOAD {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("request kind {kind}")));
        }
        let id = stream.read_u64_le().await?;
        let id = alloy_rpc_types_engine::PayloadId::new(id.to_le_bytes());
        let started = std::time::Instant::now();
        let resolved = payloads.resolve_kind(id, PayloadKind::WaitForPending).await;
        let waited = started.elapsed();
        out.clear();
        match resolved {
            None => out.push(0),
            Some(Err(err)) => {
                let message = err.to_string();
                out.push(2);
                out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                out.extend_from_slice(message.as_bytes());
            }
            Some(Ok(payload)) => {
                let (bytes, encoded) = push_built_payload(&mut out, &payload);
                if bytes > 1_000_000 {
                    info!(
                        target: "n42.payload_serve",
                        number = payload.block().number(),
                        bytes,
                        waited_ms = waited.as_millis() as u64,
                        encode_ms = encoded.as_millis() as u64,
                        "raw payload served"
                    );
                }
            }
        }
        stream.write_all(&out).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Block, BlockBody, Header, Signed, TxEip1559, TxLegacy};
    use alloy_primitives::{Address, Signature, TxKind, U256};
    use reth_ethereum_primitives::TransactionSigned;

    /// The parallel encoding is alloy's, byte for byte.
    #[test]
    fn parallel_block_rlp_is_alloys() {
        let txs: Vec<TransactionSigned> = (0..40u64)
            .map(|n| {
                if n % 3 == 0 {
                    let tx = TxLegacy { chain_id: Some(1), nonce: n, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(n), ..Default::default() };
                    Signed::new_unchecked(tx, Signature::test_signature(), Default::default()).into()
                } else {
                    let tx = TxEip1559 { chain_id: 1, nonce: n, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(n), ..Default::default() };
                    Signed::new_unchecked(tx, Signature::test_signature(), Default::default()).into()
                }
            })
            .collect();
        let header = Header { number: 9, base_fee_per_gas: Some(7), withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH), ..Default::default() };
        let withdrawals = alloy_eips::eip4895::Withdrawals(vec![alloy_eips::eip4895::Withdrawal { index: 1, validator_index: 2, address: Address::repeat_byte(7), amount: 3 }]);
        let block = Block { header, body: BlockBody { transactions: txs, ommers: Vec::new(), withdrawals: Some(withdrawals) } };
        let sealed = SealedBlock::seal_slow(block);
        assert_eq!(encode_block_parallel(&sealed), alloy_rlp::encode(&sealed));
    }
}

/// Whether the queue's and the pool's bookkeeping for an imported block runs
/// on a worker thread (`N42_QUEUE_WORK_OFFLOAD=1`) instead of on this path.
/// Inline it walks the block twice -- once for the mined senders and nonces,
/// once for the hashes -- while the validator waits for the answer. Off until
/// a round shows the walks cost more than the delayed queue removal does
/// (round 38: a build ahead that starts first takes the mined transactions
/// again).
fn queue_work_offload() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_QUEUE_WORK_OFFLOAD").is_ok_and(|v| v == "1"))
}

/// Whether a block the direct import executed is answered VALID at once, with
/// the engine's own `newPayload` run behind the answer (`N42_DIRECT_FAST_ANSWER=1`,
/// off by default). The block was validated here; the engine's pass is
/// bookkeeping. Round 43: the engine's pass was 35 ms of a 533 ms import
/// barrier, and remembering the sealed block for it cost a deep clone of the
/// block's 163,000 transactions on the same path.
fn direct_fast_answer() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_DIRECT_FAST_ANSWER").is_ok_and(|v| v == "1"))
}

/// Whether an imported block's pool prune runs off the payload answer's path
/// (default; `N42_PRUNE_ASYNC=0` makes the answer wait for it, the behaviour
/// before round 43's loop98).
fn prune_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_PRUNE_ASYNC").map_or(true, |v| v != "0"))
}
