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
use std::sync::{Condvar, Mutex};

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

/// Bumped every time a block lands in the engine here (a direct import, the
/// leader's own block), for [`wait_for_parent`]: under deferred execution
/// the next block's check starts the moment its parent is in.
static IMPORT_LANDED: (Mutex<u64>, Condvar) = (Mutex::new(0), Condvar::new());

/// Says a block has landed in the engine (see [`IMPORT_LANDED`]).
pub fn note_import_landed() {
    let (count, landed) = &IMPORT_LANDED;
    *count.lock().unwrap_or_else(|p| p.into_inner()) += 1;
    landed.notify_all();
}

/// How long a check waits for the block's parent to land before giving the
/// block up to the engine's ordinary path (which answers SYNCING).
const PARENT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The parent's sealed header once the parent is in: known to the provider
/// and, under deferred execution, executed here (its result recorded), so
/// the header's fields can be checked and the transactions read against its
/// post-state. Blocks arrive in order but their imports overlap from the
/// fork on, so the parent of the block being checked may still be
/// executing; this waits for it, up to [`PARENT_WAIT`].
fn wait_for_parent<Provider>(
    provider: &Provider,
    parent_hash: B256,
    genesis: &alloy_genesis::Genesis,
    deferred: bool,
) -> Result<reth_primitives_traits::SealedHeader, String>
where
    Provider: HeaderProvider<Header = alloy_consensus::Header>,
{
    let deadline = std::time::Instant::now() + PARENT_WAIT;
    let (count, landed) = &IMPORT_LANDED;
    let mut seen = *count.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        if let Some(parent) = provider
            .sealed_header_by_hash(parent_hash)
            .map_err(|err| format!("parent header: {err}"))?
        {
            // A parent before the fork carries its own result in its header;
            // one past it has its result recorded here once executed.
            let executed_here = deferred
                && parent.number > 0
                && reth_chainspec::qmdb::deferred_execution_active_at(genesis, parent.timestamp);
            if !executed_here || n42_engine_types::executed_fields::get(&parent_hash).is_some() {
                return Ok(parent);
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(format!("parent {parent_hash} not imported within {PARENT_WAIT:?}"));
        }
        // A landing bumps the count; a block that arrives by the engine's
        // own path bumps nothing, so the wait is also a poll.
        let guard = count.lock().unwrap_or_else(|p| p.into_inner());
        let (guard, _) = landed
            .wait_timeout_while(guard, (deadline - now).min(std::time::Duration::from_millis(20)), |c| *c == seen)
            .unwrap_or_else(|p| p.into_inner());
        seen = *guard;
    }
}

/// The includability of a block's transactions on its parent's post-state
/// (docs/PHASE_D_DEFERRED_EXECUTION.md, section 8.4): what a follower's
/// vote attests under deferred execution, since the block's execution is
/// checked only by the next header. Per sender, one account read: the
/// nonces contiguous from the account's, the balance covering every
/// transaction's value and gas at its fee cap; per transaction, the chain
/// id, the fee cap against the block's base fee, the priority fee under the
/// cap, a gas limit at least a transfer's; for the block, the gas limits
/// within the header's. Senders are read on the worker pool, each chunk on
/// a state provider of its own.
fn check_includable<Provider>(
    provider: &Provider,
    parent_hash: B256,
    block: &RecoveredBlock<Block>,
    chain_id: u64,
) -> Result<(), String>
where
    Provider: StateProviderFactory + Sync,
{
    use alloy_consensus::Transaction as _;
    use rayon::prelude::*;
    use reth_provider::AccountReader as _;
    use std::collections::HashMap;

    let header = block.header();
    let base_fee = u128::from(header.base_fee_per_gas.unwrap_or(0));
    let mut gas_total: u64 = 0;
    let mut by_sender: HashMap<Address, Vec<usize>> = HashMap::new();
    for (index, (sender, tx)) in block.transactions_with_sender().enumerate() {
        if let Some(id) = tx.chain_id() {
            if id != chain_id {
                return Err(format!("transaction {index}: chain id {id}, the chain's is {chain_id}"));
            }
        }
        let cap = tx.max_fee_per_gas();
        if cap < base_fee {
            return Err(format!("transaction {index}: fee cap {cap} under the base fee {base_fee}"));
        }
        if tx.max_priority_fee_per_gas().is_some_and(|tip| tip > cap) {
            return Err(format!("transaction {index}: priority fee over the fee cap"));
        }
        if tx.gas_limit() < 21_000 {
            return Err(format!("transaction {index}: gas limit {} under a transfer's", tx.gas_limit()));
        }
        if tx.authorization_list().is_some_and(|list| list.is_empty()) {
            return Err(format!("transaction {index}: empty authorization list"));
        }
        gas_total = gas_total.saturating_add(tx.gas_limit());
        by_sender.entry(*sender).or_default().push(index);
    }
    if gas_total > header.gas_limit {
        return Err(format!("gas limits sum to {gas_total}, over the block's {}", header.gas_limit));
    }
    let txs: Vec<&TransactionSigned> = block.body().transactions().collect();
    let groups: Vec<(Address, Vec<usize>)> = by_sender.into_iter().collect();
    let chunk = groups.len().div_ceil(32).max(1);
    let checked: Vec<Result<(), String>> = groups
        .par_chunks(chunk)
        .map(|chunk| {
            let state = provider.state_by_block_hash(parent_hash).map_err(|err| format!("parent state: {err}"))?;
            for (sender, indexes) in chunk {
                let account = state
                    .basic_account(sender)
                    .map_err(|err| format!("account {sender}: {err}"))?
                    .unwrap_or_default();
                let mut nonce = account.nonce;
                let mut cost = alloy_primitives::U256::ZERO;
                for &index in indexes {
                    let tx = txs[index];
                    if tx.nonce() != nonce {
                        return Err(format!("transaction {index}: nonce {}, {sender} is at {nonce}", tx.nonce()));
                    }
                    nonce += 1;
                    let gas = alloy_primitives::U256::from(tx.gas_limit()) * alloy_primitives::U256::from(tx.max_fee_per_gas());
                    let blobs = alloy_primitives::U256::from(tx.blob_gas_used().unwrap_or(0))
                        * alloy_primitives::U256::from(tx.max_fee_per_blob_gas().unwrap_or(0));
                    cost = cost.saturating_add(tx.value()).saturating_add(gas).saturating_add(blobs);
                }
                if cost > account.balance {
                    return Err(format!("{sender}: {} transactions cost {cost} of a balance of {}", indexes.len(), account.balance));
                }
            }
            Ok(())
        })
        .collect();
    checked.into_iter().collect()
}

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
///
/// Under deferred execution (a block stamped at or past the chain's
/// `deferredExecutionTime`) the block is *checked* first -- its header's
/// execution fields against this node's result for the parent, its
/// transactions' includability on the parent's post-state -- and `checked`
/// is told so before the execution starts: that is the follower's vote. A
/// block before the fork sends nothing on it.
#[allow(clippy::too_many_arguments)]
pub fn import_foreign_block<Provider, Evm, ChainSpec>(
    sealed: SealedBlock<Block>,
    provider: &Provider,
    evm_config: &Evm,
    senders_cache: Option<&reth_evm::SenderRecoveryCache>,
    carry: &Arc<CarriedReads>,
    qmdb: Option<&n42_qmdb_reth::QmdbNodeState>,
    consensus: &(dyn FullConsensus<EthPrimitives> + Send + Sync),
    chain_spec: &ChainSpec,
    checked: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(Box<BuiltPayloadExecutedBlock<EthPrimitives>>, [u64; 9]), String>
where
    Provider: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header> + Sync,
    Evm: ConfigureEvm<
        Primitives = EthPrimitives,
        BlockExecutorFactory = n42_engine_types::parallel_transfer::FastExecutorFactory,
    >,
    ChainSpec: reth_chainspec::EthereumHardforks + reth_chainspec::EthChainSpec,
{
    let qmdb = qmdb.ok_or("no QMDB state: the direct import needs the chain's root")?;
    let started = std::time::Instant::now();
    let stage = ImportStage(sealed.number);
    stage.at(1);
    let parent_hash = sealed.parent_hash;
    let number = sealed.number;
    let block_hash = sealed.hash();

    let deferred = reth_chainspec::qmdb::deferred_execution_active_at(chain_spec.genesis(), sealed.timestamp);
    // The header and body, by the consensus rules the engine would apply;
    // what needs no parent first, so it overlaps the parent's import.
    consensus.validate_header(sealed.sealed_header()).map_err(|err| format!("header: {err}"))?;
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

    // The parent: in, and under deferred execution executed here, since the
    // header's fields are checked against its result and the transactions
    // against its post-state.
    let parent = wait_for_parent(provider, parent_hash, chain_spec.genesis(), deferred)?;
    consensus
        .validate_header_against_parent(recovered.sealed_header(), &parent)
        .map_err(|err| format!("header against parent: {err}"))?;
    if deferred {
        let check_at = std::time::Instant::now();
        check_includable(provider, parent_hash, &recovered, chain_spec.chain().id())?;
        tracing::debug!(
            target: "n42.follower_import",
            number,
            check_ms = check_at.elapsed().as_millis() as u64,
            "checked: the header carries the parent's result and the transactions are includable"
        );
        if let Some(checked) = checked {
            let _ = checked.send(());
        }
    }

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
    // The carry: this block's post-state over the reads, for the next block.
    // Nothing reads it until the next import, ~650 ms away, so with
    // `N42_CARRY_ASYNC=1` the copy of 129,000 accounts happens on the worker
    // pool after this returns instead of while the validator waits for its
    // answer (round 43, loop100: it was most of the 44 ms the import could not
    // account for). A carry that is not ready in time is not a correctness
    // problem: the next import simply reads the state provider instead.
    let carry_at = std::time::Instant::now();
    let carry_async = carry_async();
    if !carry_async {
        fill_carry(&mut cached, &output.state, block_hash, carry);
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
        if deferred {
            // The header carries the parent's root (checked against the
            // parent's result by the consensus rules above); this block's
            // own root is filed and remembered for its child's header.
            let ops = n42_qmdb_reth::sorted_operations_from_execution(bundle, prague);
            let root = qmdb
                .insert_block_operations(parent_hash, block_hash, number, ops)
                .map_err(|err| format!("state root: {err}"))?;
            n42_engine_types::executed_fields::remember_state_root(block_hash, root);
            return Ok(root);
        }
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
    //
    // `N42_HASHED_STATE=0` skips the pass entirely -- and stops the chain; see
    // `hashed_state_enabled`. It exists for reth's
    // Merkle-Patricia trie -- `MemoryOverlayStateProvider::trie_input` feeds
    // it to `state_root`, `proof`, `multiproof` and `witness`, and
    // `save_blocks` writes it to `HashedAccounts`/`HashedStorages` -- and this
    // chain's state root and proofs come from QMDB instead, so on the paths
    // the node actually runs nothing reads it. Ordinary account and storage
    // reads do not: the overlay answers those from the bundle. It costs 26 ms
    // of every import and holds ~15 MB a block until the block is persisted.
    let hashed_job = move || {
        if hashed_state_enabled() {
            state.hashed_post_state(bundle).map_err(|err| format!("hashed state: {err}"))
        } else {
            Ok(reth_trie::HashedPostState::default())
        }
    };
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

    let execution_output = Arc::new(output);
    if carry_async {
        let state = Arc::clone(&execution_output);
        let carry = Arc::clone(carry);
        rayon::spawn(move || {
            let mut cached = cached;
            fill_carry(&mut cached, &state.state, block_hash, &carry);
        });
    }

    Ok((
        Box::new(BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(recovered),
            execution_output,
            hashed_state: Arc::new(hashed_state),
            trie_updates: Arc::new(TrieUpdates::default()),
        }),
        [header_ms, senders_ms, exec_ms, checks_ms, root_ms, hashed_ms, cache_hits, state_ms, carry_ms],
    ))
}

/// Copies a block's post-state into the read cache the next import starts
/// from, and files it under the block's hash.
fn fill_carry(
    cached: &mut CachedReads,
    bundle: &reth_revm::db::BundleState,
    block_hash: B256,
    carry: &CarriedReads,
) {
    if cached.accounts.len() > CARRY_CAP {
        *cached = CachedReads::default();
    }
    for (address, account) in &bundle.state {
        match &account.info {
            Some(info) => cached.insert_account(*address, info.clone(), Default::default()),
            None => {
                cached.accounts.insert(*address, reth_revm::cached::CachedAccount { info: None, storage: Default::default() });
            }
        }
    }
    *carry.lock().unwrap_or_else(|p| p.into_inner()) = Some((block_hash, std::mem::take(cached)));
}

/// Whether the follower computes the Merkle-Patricia hashed post-state
/// (default).
///
/// **`N42_HASHED_STATE=0` stops the chain.** It is kept as the one-line
/// reproduction, not as an option: loop106 ran it twice and the fleet produced
/// zero blocks both times, dying on the first full block with
/// `block gas used mismatch: got 0, expected 3423000000; gas spent by each
/// transaction: []` -- the engine validating an executed block that has no
/// receipts at all -- while the same binary with the pass left in read 199,751
/// and 249,924. Reading the code says nothing on this chain's paths consumes
/// the hashed state (the state root and the proofs come from QMDB; the
/// overlay answers account and storage reads from the bundle; only reth's
/// trie methods, two debug RPCs and the `HashedAccounts`/`HashedStorages`
/// tables touch it). The fleet says otherwise, and the failure is a hard
/// rejection rather than a missing index, so the dependency is somewhere in
/// the engine's insert-and-validate path. Removing this pass -- 26 ms of every
/// import and ~15 MB a block -- needs that path understood first, and the
/// leader's own build handled too.
fn hashed_state_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_HASHED_STATE").map_or(true, |v| v != "0"))
}

/// Whether the carry is filled on the worker pool after the import returns
/// (`N42_CARRY_ASYNC=1`) instead of on the path the validator's vote waits
/// for. Nothing reads the carry until the next block, ~650 ms later.
fn carry_async() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_CARRY_ASYNC").is_ok_and(|v| v == "1"))
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

