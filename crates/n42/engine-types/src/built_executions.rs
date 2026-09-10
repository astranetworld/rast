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
    sync::{Arc, Mutex, OnceLock},
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

fn store() -> &'static Mutex<VecDeque<(B256, BuiltExecution)>> {
    static STORE: OnceLock<Mutex<VecDeque<(B256, BuiltExecution)>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(VecDeque::with_capacity(KEEP)))
}

/// Remembers a build under the hash the builder gave it.
pub fn remember(built_hash: B256, execution: BuiltExecution) {
    let mut store = store().lock().unwrap_or_else(|p| p.into_inner());
    store.retain(|(hash, _)| *hash != built_hash);
    while store.len() >= KEEP {
        store.pop_front();
    }
    store.push_back((built_hash, execution));
}

/// The build whose block is `number` on `parent` with these roots and gas,
/// if one was kept -- the fields a seal cannot change, which together pin
/// the transactions and the state they produced. The caller still proves the
/// sealed header hashes to the hash it was given before trusting this.
pub fn find(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64) -> Option<(B256, BuiltExecution)> {
    let store = store().lock().unwrap_or_else(|p| p.into_inner());
    store.iter().rev().find(|(_, built)| matches_build(built, parent, number, state_root, receipts_root, gas_used)).cloned()
}

/// [`find`], taking the build out of the store: the caller becomes the
/// block's only holder and can move it instead of cloning its body.
pub fn take(parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64) -> Option<(B256, BuiltExecution)> {
    let taken = {
        let mut store = store().lock().unwrap_or_else(|p| p.into_inner());
        let at = store.iter().rposition(|(_, built)| matches_build(built, parent, number, state_root, receipts_root, gas_used))?;
        store.remove(at)?
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
    find(parent, number, state_root, receipts_root, gas_used).or_else(|| {
        let handed = handed().lock().unwrap_or_else(|p| p.into_inner());
        handed.iter().rev().find(|(_, built)| matches_build(built, parent, number, state_root, receipts_root, gas_used)).cloned()
    })
}

fn matches_build(built: &BuiltExecution, parent: B256, number: u64, state_root: B256, receipts_root: B256, gas_used: u64) -> bool {
    let header = built.block.header();
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
