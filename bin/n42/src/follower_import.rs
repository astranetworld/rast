// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Another node's block, executed and checked here rather than in the engine.
//!
//! The engine imports a block through its payload processor: transactions
//! streamed to the executor over a channel, receipts to a receipt-root task,
//! every transaction's state through a hook into the cross-block cache, and
//! metrics on each. Round 38 measured that path at ~340 ms a block against
//! 121 ms for reth's plain block executor on the same blocks. This module is
//! the plain path with everything the engine's path also guarantees: the
//! consensus rules on the header and body, gas, receipts root and logs bloom
//! against the header after execution, the QMDB root against the header's
//! state root (which also files the block's tree), and the hashed post-state
//! the engine needs to carry the block. What it produces is handed to the
//! engine as an executed block; the engine's own `newPayload` then finds it
//! in the tree, and executes it itself if anything here was refused.

use std::sync::Arc;

use alloy_primitives::{Address, B256};
use reth_consensus::{Consensus, FullConsensus, HeaderValidator};
use n42_tx_types::{Block, N42Primitives as EthPrimitives, N42TxEnvelope as TransactionSigned};
use reth_primitives_traits::transaction::TxHashRef as _;
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_payload_primitives::BuiltPayloadExecutedBlock;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SignerRecoverable};
use reth_provider::{HeaderProvider, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use reth_provider::HashedPostStateProvider;
use reth_revm::cached::CachedReads;
use reth_trie::updates::TrieUpdates;
use std::sync::Mutex;

/// The read cache carried from one direct import to the next: the previous
/// block's post-state (its senders above all -- every sender of the next
/// block is one of the same 6,000 at the bench tier), keyed by the block it
/// is the state of. What reth's payload builder does with its `pre_cached`.
pub type CarriedReads = Mutex<Option<(B256, CachedReads)>>;

/// Where a direct import is, for the watchdog: `block_number << 8 | stage`,
/// 0 when none is running. Stages: 1 header, 2 senders, 3 execution,
/// 4 post-execution checks, 5 carry, 6 QMDB root, 7 hashed state.
pub static IMPORT_STAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Names the stages of [`IMPORT_STAGE`].
pub const IMPORT_STAGES: [&str; 8] = ["idle", "header", "senders", "execution", "checks", "carry", "qmdb-root", "hashed-state"];

struct ImportStage(u64);

impl ImportStage {
    fn at(&self, stage: u64) {
        IMPORT_STAGE.store((self.0 << 8) | stage, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for ImportStage {
    fn drop(&mut self) {
        IMPORT_STAGE.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}


/// Above this many cached accounts the carry starts again from the block's
/// own post-state: a follower sees every block, and the reads would grow
/// without bound.
const CARRY_CAP: usize = 1_000_000;

/// Executes and checks `sealed` on its parent's state. See the module docs.
/// Returns the executed block and the phase timings in milliseconds:
/// header checks, senders, execution, the post-execution checks, state root,
/// hashed state; then the number of senders the recovery cache held.
#[allow(clippy::too_many_arguments)]
pub fn import_foreign_block<Provider, Evm, ChainSpec>(
    sealed: SealedBlock<Block>,
    provider: &Provider,
    evm_config: &Evm,
    senders_cache: Option<&reth_evm::SenderRecoveryCache>,
    carry: &CarriedReads,
    qmdb: Option<&n42_qmdb_reth::QmdbNodeState>,
    consensus: &(dyn FullConsensus<EthPrimitives> + Send + Sync),
    chain_spec: &ChainSpec,
) -> Result<(Box<BuiltPayloadExecutedBlock<EthPrimitives>>, [u64; 9]), String>
where
    Provider: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Sync,
    Evm: ConfigureEvm<
        Primitives = EthPrimitives,
        BlockExecutorFactory = n42_engine_types::parallel_transfer::FastExecutorFactory,
    >,
    ChainSpec: reth_chainspec::EthereumHardforks,
{
    let qmdb = qmdb.ok_or("no QMDB state: the direct import needs the chain's root")?;
    let started = std::time::Instant::now();
    let stage = ImportStage(sealed.number);
    stage.at(1);
    let parent_hash = sealed.parent_hash;
    let number = sealed.number;
    let block_hash = sealed.hash();

    // The header and body, by the consensus rules the engine would apply.
    let parent = provider
        .sealed_header_by_hash(parent_hash)
        .map_err(|err| format!("parent header: {err}"))?
        .ok_or_else(|| format!("parent {parent_hash} unknown"))?;
    consensus.validate_header(sealed.sealed_header()).map_err(|err| format!("header: {err}"))?;
    consensus
        .validate_header_against_parent(sealed.sealed_header(), &parent)
        .map_err(|err| format!("header against parent: {err}"))?;
    // The transactions root was computed and matched against the sealed hash
    // by the payload's conversion; the body check takes it as known.
    consensus
        .validate_block_pre_execution_with_tx_root(&sealed, Some(sealed.transactions_root))
        .map_err(|err| format!("body: {err}"))?;
    let header_ms = started.elapsed().as_millis() as u64;
    let senders_at = std::time::Instant::now();
    stage.at(2);

    // Senders: the recovery cache the ingest fills (what the engine's own
    // path reads), the rest recovered on the worker pool. 0x50 transactions
    // read the shared Ed25519 sender cache; the misses are verified in
    // batches rather than one signature at a time.
    let cache_hits = std::sync::atomic::AtomicU64::new(0);
    let alt_cache = n42_tx_types::AltSigSenderCache::global();
    let txs: Vec<&TransactionSigned> = sealed.body().transactions().collect();
    let mut senders: Vec<Option<Address>> = {
        use rayon::prelude::*;
        // Collected into a `Vec<Result>` (written in place) and checked after:
        // a parallel collect straight into `Result<Vec>` takes rayon's
        // short-circuiting path, three times the cost at 163,000 items
        // (round 43, `bench_convert_payload`).
        let looked_up: Vec<Result<Option<Address>, String>> = txs
            .par_iter()
            .map(|tx| match tx {
                TransactionSigned::AltSig(alt) => Ok(alt_cache.get(alt.hash()).inspect(|_| {
                    cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                })),
                TransactionSigned::Eth(_) => {
                    if let Some(sender) = senders_cache.and_then(|cache| cache.get(tx.tx_hash())) {
                        cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Ok(Some(sender));
                    }
                    tx.recover_signer().map(Some).map_err(|err| format!("sender of {}: {err}", tx.tx_hash()))
                }
            })
            .collect();
        looked_up.into_iter().collect::<Result<Vec<_>, String>>()?
    };
    let misses: Vec<usize> = senders.iter().enumerate().filter(|(_, s)| s.is_none()).map(|(i, _)| i).collect();
    if !misses.is_empty() {
        use rayon::prelude::*;
        let batch = n42_tx_types::ed25519_batch_size();
        let verified: Vec<(usize, Result<Address, n42_tx_types::AltSigError>)> = misses
            .par_chunks(batch)
            .flat_map_iter(|chunk| {
                let refs: Vec<&n42_tx_types::AltSigTx> = chunk
                    .iter()
                    .filter_map(|&i| txs[i].as_alt_sig())
                    .collect();
                chunk.iter().copied().zip(n42_tx_types::verify_batch(&refs)).collect::<Vec<_>>()
            })
            .collect();
        for (i, verdict) in verified {
            let sender = verdict.map_err(|err| format!("sender of {}: {err}", txs[i].tx_hash()))?;
            alt_cache.insert(*txs[i].tx_hash(), sender);
            senders[i] = Some(sender);
        }
    }
    let senders: Vec<Address> = senders.into_iter().map(|s| s.expect("every sender resolved")).collect();
    let cache_hits = cache_hits.into_inner();
    let recovered = RecoveredBlock::new_sealed(sealed, senders);
    let senders_ms = senders_at.elapsed().as_millis() as u64;

    // Execution on the parent's state, then gas, receipts root and bloom
    // against the header.
    let state_at = std::time::Instant::now();
    let state = provider.state_by_block_hash(parent_hash).map_err(|err| format!("parent state: {err}"))?;
    let state_ms = state_at.elapsed().as_millis() as u64;
    let executed_at = std::time::Instant::now();
    stage.at(3);
    let mut cached = match carry.lock().unwrap_or_else(|p| p.into_inner()).take() {
        Some((of, cached)) if of == parent_hash => cached,
        _ => CachedReads::default(),
    };
    // `N42_FOLLOWER_PARALLEL=1`: a block of plain transfers executes on the
    // worker pool (`parallel_transfer`), partitioned by the accounts it
    // touches; anything it cannot take falls back to the serial executor.
    let mut output = None;
    if follower_parallel() {
        let open = || provider.state_by_block_hash(parent_hash).ok().map(StateProviderDatabase::new);
        match n42_engine_types::parallel_transfer::execute_transfers(
            evm_config,
            &recovered,
            cached.as_db_mut(StateProviderDatabase::new(&state)),
            &open,
        )
        .map_err(|err| format!("parallel execution: {err}"))?
        {
            Ok((out, phases)) => {
                tracing::info!(
                    target: "n42.follower_import",
                    number,
                    groups = phases.groups,
                    partition_ms = phases.partition_ms,
                    groups_ms = phases.groups_ms,
                    merge_ms = phases.merge_ms,
                    finish_ms = phases.finish_ms,
                    "parallel import phases"
                );
                output = Some(out);
            }
            Err(why) => tracing::debug!(target: "n42.follower_import", number, %why, "not parallel; executing serially"),
        }
    }
    let output = match output {
        Some(out) => out,
        None => evm_config
            .executor(cached.as_db_mut(StateProviderDatabase::new(&state)))
            .execute(&recovered)
            .map_err(|err| format!("execution: {err}"))?,
    };
    let exec_ms = executed_at.elapsed().as_millis() as u64;
    let checks_at = std::time::Instant::now();
    stage.at(4);
    consensus
        .validate_block_post_execution(&recovered, &output.result, None, None)
        .map_err(|err| format!("post-execution: {err}"))?;
    let checks_ms = checks_at.elapsed().as_millis() as u64;
    // The carry for the next block: this block's post-state over the reads.
    let carry_at = std::time::Instant::now();
    {
        if cached.accounts.len() > CARRY_CAP {
            cached = CachedReads::default();
        }
        // 129,000 accounts copied into the next block's read cache, one insert
        // at a time, on the path the vote waits for: the last untimed step of
        // the import (round 43, loop100: 44 ms of a 438 ms import was in here
        // and the spawn dispatch).
        for (address, account) in &output.state.state {
            match &account.info {
                Some(info) => cached.insert_account(*address, info.clone(), Default::default()),
                None => {
                    cached.accounts.insert(*address, reth_revm::cached::CachedAccount { info: None, storage: Default::default() });
                }
            }
        }
        stage.at(5);
        *carry.lock().unwrap_or_else(|p| p.into_inner()) = Some((block_hash, cached));
    }
    let carry_ms = carry_at.elapsed().as_millis() as u64;

    // The QMDB root against the header's, which also files the block's tree
    // under its hash for the engine and the next block.
    let root_at = std::time::Instant::now();
    stage.at(6);
    let prague = chain_spec.is_prague_active_at_timestamp(recovered.timestamp);
    // The QMDB root and the hashed post-state read the same bundle and neither
    // needs the other's result, but they run one after the other: 63 and 26 ms
    // of a 438 ms import (round 43, loop99). `N42_ROOT_HASHED_PARALLEL=1` puts
    // them on the worker pool together.
    let bundle = &output.state;
    let root_job = || -> Result<B256, String> {
        if parallel_state_commit() {
            // The leaf operations keyed, encoded and sorted on the worker pool,
            // straight from the bundle (the change set and its serial
            // `operations()` were 75 ms of this phase at 147,000 accounts).
            let ops = n42_qmdb_reth::sorted_operations_from_execution(bundle, prague);
            qmdb.validate_block_operations(parent_hash, block_hash, number, ops, recovered.state_root)
                .map_err(|err| format!("state root: {err}"))
        } else {
            let changes = n42_qmdb_reth::changes_from_execution(bundle, prague);
            qmdb.validate_block(parent_hash, block_hash, number, &changes, recovered.state_root)
                .map_err(|err| format!("state root: {err}"))
        }
    };
    // The provider is `Send` but not `Sync`, so the hashed job takes it by
    // value; both jobs borrow the bundle, which is plain data.
    let hashed_job = move || state.hashed_post_state(bundle).map_err(|err| format!("hashed state: {err}"));
    let (root_ms, hashed_ms, hashed_state) = if !root_hashed_parallel() {
        root_job()?;
        let root_ms = root_at.elapsed().as_millis() as u64;
        let hashed_at = std::time::Instant::now();
        stage.at(7);
        let hashed_state = hashed_job()?;
        (root_ms, hashed_at.elapsed().as_millis() as u64, hashed_state)
    } else {
        stage.at(7);
        let (root, hashed) = rayon::join(root_job, hashed_job);
        root?;
        let both = root_at.elapsed().as_millis() as u64;
        (both, 0, hashed?)
    };

    Ok((
        Box::new(BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(recovered),
            execution_output: Arc::new(output),
            hashed_state: Arc::new(hashed_state),
            trie_updates: Arc::new(TrieUpdates::default()),
        }),
        [header_ms, senders_ms, exec_ms, checks_ms, root_ms, hashed_ms, cache_hits, state_ms, carry_ms],
    ))
}

/// Whether the QMDB root and the hashed post-state run together on the worker
/// pool (`N42_ROOT_HASHED_PARALLEL=1`) instead of one after the other. They
/// read the same bundle and neither needs the other; in parallel the pair is
/// reported as `root_ms` with `hashed_ms` zero. Off until loop102 measures it.
fn root_hashed_parallel() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_ROOT_HASHED_PARALLEL").is_ok_and(|v| v == "1"))
}

/// `N42_FOLLOWER_PARALLEL`, read once.
fn follower_parallel() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FOLLOWER_PARALLEL").is_ok_and(|v| v == "1"))
}

/// Whether the parallel state commit is on (default; `N42_PARALLEL_STATE_COMMIT=0` turns it off): the QMDB leaf operations are
/// keyed, encoded and sorted on the worker pool instead of through the change set
/// (round 43: 190 -> 104 ms of a follower's import at 147,000 accounts).
pub fn parallel_state_commit() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    // On by default since round 43's loop82 (223-228k against 189-201k on
    // window 1 at 147,000 accounts a block, the follower's import 488-562 ms
    // against 605-690); `N42_PARALLEL_STATE_COMMIT=0` is the serial path.
    *ON.get_or_init(|| std::env::var("N42_PARALLEL_STATE_COMMIT").map_or(true, |v| v != "0"))
}

