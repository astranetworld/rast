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
use reth_ethereum_engine_primitives::EthBuiltPayload;
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
}

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
    let (built_hash, built) = n42_engine_types::built_executions::find(
        v1.parent_hash,
        v1.block_number,
        v1.state_root,
        v1.receipts_root,
        v1.gas_used,
    )?;
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
    let sealed_hash = sealed_header.hash();
    if v1.transactions.len() != built.block.body().transactions.len() {
        return None;
    }
    let body = built.block.body().clone();
    let recovered = reth_primitives_traits::RecoveredBlock::new_sealed(
        SealedBlock::from_sealed_parts(sealed_header, body),
        built.block.senders().to_vec(),
    );
    if let Some(qmdb) = &reuse.qmdb {
        if let Err(err) = qmdb.rename(built_hash, sealed_hash) {
            warn!(target: "n42.payload_serve", %err, %built_hash, %sealed_hash, "could not file the build's QMDB root under the sealed hash; importing the ordinary way");
            return None;
        }
    }
    let executed = reth_payload_primitives::BuiltPayloadExecutedBlock::<reth_ethereum_primitives::EthPrimitives> {
        recovered_block: std::sync::Arc::new(recovered),
        execution_output: built.execution_output,
        hashed_state: built.hashed_state,
        trie_updates: built.trie_updates,
    };
    let (done, handed) = tokio::sync::oneshot::channel();
    if reuse
        .inserts
        .send(reth_node_builder::executed_inserts::ExecutedInsert { block: Box::new(executed), done })
        .is_err()
    {
        return None;
    }
    match tokio::time::timeout(std::time::Duration::from_secs(2), handed).await {
        Ok(Ok(true)) => {
            if let Some(prune) = reuse.prune_pool.clone() {
                let hashes: Vec<alloy_primitives::B256> =
                    built.block.body().transactions().map(|tx| *tx.tx_hash()).collect();
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
                number = v1.block_number,
                convert_ms = converted.as_millis() as u64,
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
    T: PayloadTypes<BuiltPayload = EthBuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
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
    T: PayloadTypes<BuiltPayload = EthBuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
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
            match raw_engine::decode_execution_data(&frame) {
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
                    // A build of ours the engine has just been handed as
                    // executed is in its tree before anything sent after it,
                    // and the engine's newPayload would only convert the
                    // payload again (48 ms of decoding 163,000 transactions
                    // at the bench tier) to find the block known. Answer
                    // Valid here; the forkchoice update that follows on the
                    // same channel reports it if the tree refused the insert.
                    let status = if reused && !own_block_recheck() {
                        Ok(alloy_rpc_types_engine::PayloadStatus::new(
                            alloy_rpc_types_engine::PayloadStatusEnum::Valid,
                            Some(data.payload.block_hash()),
                        ))
                    } else {
                        engine.new_payload(data).await
                    };
                    match status {
                        Ok(status) => {
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
                                && let Some(prune) = reuse.as_ref().and_then(|r| r.prune_pool.clone())
                            {
                                let pruned_at = std::time::Instant::now();
                                let count = raw_transactions.len();
                                let _ = tokio::task::spawn_blocking(move || {
                                    use rayon::prelude::*;
                                    let hashes: Vec<B256> =
                                        raw_transactions.par_iter().map(|tx| alloy_primitives::keccak256(tx)).collect();
                                    prune(hashes);
                                })
                                .await;
                                if count > 10_000 {
                                    info!(
                                        target: "n42.payload_serve",
                                        number,
                                        count,
                                        prune_ms = pruned_at.elapsed().as_millis() as u64,
                                        "imported block's transactions taken out of the pool"
                                    );
                                }
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
                if block.len() > 1_000_000 {
                    info!(
                        target: "n42.payload_serve",
                        number = payload.block().number(),
                        bytes = block.len(),
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


/// `N42_OWN_BLOCK_RECHECK=1` sends a build of ours through the engine's
/// newPayload after it was handed over as executed, the way it was done
/// before round 37, instead of answering Valid at the hand-off.
fn own_block_recheck() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_OWN_BLOCK_RECHECK").map(|v| v == "1").unwrap_or(false))
}
