// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The execution results of the blocks this node built, kept so its own
//! block can be imported without being executed a second time.
//!
//! A leader executes its block once to build it and, on this chain, once
//! more to import it: consensus seals the header (view, QC, signature in
//! `extra_data`), the hash changes, and the execution layer sees a block it
//! has never met. reth's engine can insert an already-executed block
//! (`InsertExecutedBlock`, the path sequencers use), but the payload types
//! carry no execution result; this store carries it, keyed by the hash the
//! builder gave the block, for the raw payload channel to find when the
//! sealed block comes back. At the bench tier the second execution is ~500
//! ms on the leader's critical path, ahead of the build that could otherwise
//! start the moment the block exists.

use alloy_primitives::B256;
use n42_tx_types::{Block, Receipt};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_trie::{updates::TrieUpdates, HashedPostState};
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, OnceLock},
};

/// What the engine needs to insert a block as executed.
#[derive(Debug, Clone)]
pub struct BuiltExecution {
    /// The block as built, under the builder's hash; its body and senders are
    /// the sealed block's too.
    pub block: Arc<RecoveredBlock<Block>>,
    /// The bundle state and receipts of executing it.
    pub execution_output: Arc<BlockExecutionOutput<Receipt>>,
    /// The hashed post-state, as the builder computed it.
    pub hashed_state: Arc<HashedPostState>,
    /// Trie updates, empty on a chain whose root is not the trie's.
    pub trie_updates: Arc<TrieUpdates>,
}

/// How many recent builds are kept. A leader's block is sealed and comes
/// back within a view, so one is in flight and one may be the build ahead;
/// each is ~100 MB at 163,000 transactions (block, bundle state, receipts),
/// and on a box whose page cache is the contended resource every retained
/// hundred megabytes is a hundred megabytes of state pages evicted.
const KEEP: usize = 2;

/// How far a build that was sealed before it finished has come
/// (docs/PHASE_D_DEFERRED_EXECUTION.md section 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// The block is sealed and published; its state is still being folded.
    Sealed,
    /// The post-state is final: the next block can be built on it. The
    /// execution kept here has the bundle, but placeholder receipts and
    /// hashed state.
    StateReady,
    /// Everything: the executed block the engine takes at the handoff.
    Complete,
}

/// A build, at whatever stage it has reached.
#[derive(Debug, Clone)]
struct Entry {
    stage: Stage,
    /// The block, from the seal on.
    block: Arc<RecoveredBlock<Block>>,
    /// The execution, from `StateReady` on (provisional until `Complete`).
    execution: Option<BuiltExecution>,
}

/// How long a caller waits for a stage a build has not reached: a finish
/// behind the seal is ~250 ms on a full block, so this is a stall guard, not
/// a budget.
const WAIT: std::time::Duration = std::time::Duration::from_secs(3);

fn store() -> &'static (Mutex<VecDeque<(B256, Entry)>>, Condvar) {
    static STORE: OnceLock<(Mutex<VecDeque<(B256, Entry)>>, Condvar)> = OnceLock::new();
    STORE.get_or_init(|| (Mutex::new(VecDeque::with_capacity(KEEP)), Condvar::new()))
}

fn put(built_hash: B256, entry: Entry) {
    let (store, advanced) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    store.retain(|(hash, _)| *hash != built_hash);
    while store.len() >= KEEP {
        store.pop_front();
    }
    store.push_back((built_hash, entry));
    advanced.notify_all();
}

/// Remembers a finished build under the hash the builder gave it.
pub fn remember(built_hash: B256, execution: BuiltExecution) {
    put(built_hash, Entry { stage: Stage::Complete, block: execution.block.clone(), execution: Some(execution) });
}

/// A block sealed before its finish: known from here on, waited for by
/// whoever needs its state or its execution.
pub fn remember_pending(built_hash: B256, block: Arc<RecoveredBlock<Block>>) {
    put(built_hash, Entry { stage: Stage::Sealed, block, execution: None });
}

/// The pending build's post-state is final (`execution` carries the bundle;
/// receipts and hashed state are placeholders until [`complete`]).
pub fn state_ready(built_hash: B256, execution: BuiltExecution) {
    advance(built_hash, Stage::StateReady, execution);
}

/// The pending build is finished.
pub fn complete(built_hash: B256, execution: BuiltExecution) {
    advance(built_hash, Stage::Complete, execution);
}

fn advance(built_hash: B256, stage: Stage, execution: BuiltExecution) {
    let (store, advanced) = store();
    let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
    match store.iter_mut().find(|(hash, _)| *hash == built_hash) {
        Some((_, entry)) => {
            entry.stage = stage;
            entry.execution = Some(execution);
        }
        // Evicted, or never pending: kept as a build at this stage regardless.
        None => {
            while store.len() >= KEEP {
                store.pop_front();
            }
            store.push_back((built_hash, Entry { stage, block: execution.block.clone(), execution: Some(execution) }));
        }
    }
    drop(store);
    // A copy on the handed list (taken before it was complete) is refreshed.
    if stage == Stage::Complete {
        let mut handed = handed().lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, kept)) = handed.iter_mut().find(|(hash, _)| *hash == built_hash) {
            *kept = execution_of(&store_get(built_hash)).unwrap_or_else(|| kept.clone());
        }
    }
    advanced.notify_all();
}

fn store_get(built_hash: B256) -> Option<Entry> {
    let (store, _) = store();
    let store = store.lock().unwrap_or_else(|p| p.into_inner());
    store.iter().find(|(hash, _)| *hash == built_hash).map(|(_, entry)| entry.clone())
}

fn execution_of(entry: &Option<Entry>) -> Option<BuiltExecution> {
    entry.as_ref().and_then(|entry| entry.execution.clone())
}

/// The stage `built_hash` has reached, if it is known here.
pub fn stage_of(built_hash: B256) -> Option<Stage> {
    store_get(built_hash).map(|entry| entry.stage)
}

/// Waits until the build under `built_hash` reaches `stage`, up to [`WAIT`],
/// and gives its execution then. A build not filed here (or already handed to
/// the engine) is looked for on the handed list at once.
pub fn wait_for(built_hash: B256, stage: Stage) -> Option<BuiltExecution> {
    let (store, advanced) = store();
    let deadline = std::time::Instant::now() + WAIT;
    let mut guard = store.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        match guard.iter().find(|(hash, _)| *hash == built_hash) {
            Some((_, entry)) if entry.stage >= stage => return entry.execution.clone(),
            Some(_) => {}
            None => {
                drop(guard);
                let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
                return handed.iter().rev().find(|(hash, _)| *hash == built_hash).map(|(_, built)| built.clone());
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let (g, _) = advanced.wait_timeout(guard, deadline - now).unwrap_or_else(|p| p.into_inner());
        guard = g;
    }
}

/// The build whose block is `number` on `parent` with these roots and gas,
/// if one was kept -- the fields a seal cannot change, which together pin
/// the transactions and the state they produced. The caller still proves the
/// sealed header hashes to the hash it was given before trusting this. A
/// build still finishing behind its seal is waited for, up to [`WAIT`].
pub fn find(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64) -> Option<(B256, BuiltExecution)> {
    find_at(parent, number, state_root, receipts_root, gas_used, Stage::Complete)
}

/// [`find`] at a given stage.
pub fn find_at(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, stage: Stage) -> Option<(B256, BuiltExecution)> {
    let (store, advanced) = store();
    let deadline = std::time::Instant::now() + WAIT;
    let mut guard = store.lock().unwrap_or_else(|p| p.into_inner());
    loop {
        let found = guard
            .iter()
            .rev()
            .find(|(_, entry)| matches_block(&entry.block, parent, number, state_root, receipts_root, gas_used))
            .map(|(hash, entry)| (*hash, entry.stage, entry.execution.clone()));
        match found {
            Some((hash, at, Some(built))) if at >= stage => return Some((hash, built)),
            Some(_) => {}
            None => return None,
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let (g, _) = advanced.wait_timeout(guard, deadline - now).unwrap_or_else(|p| p.into_inner());
        guard = g;
    }
}

/// [`find`], taking the build out of the store: the caller becomes the
/// block's only holder and can move it instead of cloning its body.
pub fn take(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64) -> Option<(B256, BuiltExecution)> {
    let taken = {
        // Complete first (waiting for a finish behind the seal), then out.
        let (hash, built) = find(parent, number, state_root, receipts_root, gas_used)?;
        let (store, _) = store();
        let mut store = store.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(at) = store.iter().rposition(|(h, _)| *h == hash) {
            store.remove(at);
        }
        (hash, built)
    };
    // Kept a little longer for the build on the sealed block: the own-block
    // import that takes the build and that build leave the validator in the
    // same breath on separate connections, and the import wins the race more
    // often than not (loop110 S1: 49 of 52 on-seal builds refused, silently).
    // The execution is four `Arc`s, so the copy costs nothing; the budget is
    // the store's.
    let mut handed = handed().lock().unwrap_or_else(|p| p.into_inner());
    handed.retain(|(hash, _)| *hash != taken.0);
    while handed.len() >= KEEP {
        handed.pop_front();
    }
    handed.push_back(taken.clone());
    Some(taken)
}

/// Builds [`take`] handed to the engine, still findable by [`find_kept`].
fn handed() -> &'static Mutex<VecDeque<(B256, BuiltExecution)>> {
    static HANDED: OnceLock<Mutex<VecDeque<(B256, BuiltExecution)>>> = OnceLock::new();
    HANDED.get_or_init(|| Mutex::new(VecDeque::with_capacity(KEEP)))
}

/// [`find`], also among the builds already taken by the engine's import --
/// what a build on the sealed block wants, whichever of the two requests the
/// execution layer served first.
pub fn find_kept(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64) -> Option<(B256, BuiltExecution)> {
    find_kept_at(parent, number, state_root, receipts_root, gas_used, Stage::Complete)
}

/// [`find_kept`] at a given stage: the build on the sealed block needs the
/// parent's post-state (`StateReady`), not its receipts.
pub fn find_kept_at(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64, stage: Stage) -> Option<(B256, BuiltExecution)> {
    // The handed list first: a build the engine already took is complete,
    // and looking there costs nothing where a wait on the store would.
    {
        let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(found) = handed.iter().rev().find(|(_, built)| matches_build(built, parent, number, state_root, receipts_root, gas_used)) {
            return Some(found.clone());
        }
    }
    find_at(parent, number, state_root, receipts_root, gas_used, stage)
}

fn matches_build(built: &BuiltExecution, parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64) -> bool {
    matches_block(&built.block, parent, number, state_root, receipts_root, gas_used)
}

fn matches_block(block: &RecoveredBlock<Block>, parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64) -> bool {
    let header = block.header();
    header.parent_hash == parent
        && header.number == number
        && header.state_root == state_root
        && header.receipts_root == receipts_root
        && header.gas_used == gas_used
}

/// The sealed blocks this node has handed to the engine as executed, kept
/// for the engine's own `newPayload` of the same block, which follows the
/// hand-off as the check that the insert landed (and the fallback when it
/// did not). Its conversion of the payload would decode every transaction
/// again -- 48 ms at 163,000 transactions, on the leader's path between one
/// proposal and the next build -- to produce the block that is already here.
fn sealed_store() -> &'static Mutex<VecDeque<(B256, SealedBlock<Block>)>> {
    static STORE: OnceLock<Mutex<VecDeque<(B256, SealedBlock<Block>)>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(VecDeque::with_capacity(KEEP)))
}

/// Keeps the sealed block under its sealed hash.
pub fn remember_sealed(sealed_hash: B256, block: SealedBlock<Block>) {
    let mut store = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    store.retain(|(hash, _)| *hash != sealed_hash);
    while store.len() >= KEEP {
        store.pop_front();
    }
    store.push_back((sealed_hash, block));
}

/// The sealed block under this hash, if one was kept; taken out, so a
/// payload converted twice decodes the second time.
pub fn take_sealed(sealed_hash: B256) -> Option<SealedBlock<Block>> {
    let mut store = sealed_store().lock().unwrap_or_else(|p| p.into_inner());
    let at = store.iter().position(|(hash, _)| *hash == sealed_hash)?;
    store.remove(at).map(|(_, block)| block)
}
