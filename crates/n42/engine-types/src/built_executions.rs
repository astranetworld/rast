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
use reth_ethereum_primitives::{Block, Receipt};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::RecoveredBlock;
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
/// back within a view; builds that were never proposed age out.
const KEEP: usize = 4;

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
    store
        .iter()
        .rev()
        .find(|(_, built)| {
            let header = built.block.header();
            header.parent_hash == parent
                && header.number == number
                && header.state_root == state_root
                && header.receipts_root == receipts_root
                && header.gas_used == gas_used
        })
        .cloned()
}
