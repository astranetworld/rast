// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Building the next block on a block this node built a moment ago -- before
//! the engine has imported it, and without a forkchoice to name it.
//!
//! On the leader's chain the build ahead used to start only after two round
//! trips through the engine: the own block's header import (62 ms at the
//! 163,000-transaction tier) and the forkchoiceUpdated that creates the
//! payload job (72 ms), then reth's payload service around the builder
//! (~35 ms) -- some 170 ms of a 570 ms cycle that builds nothing
//! (`docs/FLEET7_PLAN_V2.md`, phase A). The builder had the parent's
//! post-state in hand the whole time: it executed the block. This module
//! lets the raw payload channel call the builder directly with that state.
//!
//! The parent is a build the node keeps (`built_executions`), addressed by
//! the sealed header consensus gave it; its bundle is laid over the chain's
//! state at the grandparent with reth's own in-memory overlay, so the
//! builder reads the parent's nonces and balances without the parent being
//! in the engine's tree. The engine's import and forkchoice still happen --
//! beside the build instead of ahead of it.

use std::sync::{Arc, OnceLock};

use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadAttributes;
use n42_tx_types::N42Primitives;
use reth_chain_state::{ExecutedBlock, MemoryOverlayStateProvider};
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use reth_storage_api::{errors::ProviderResult, StateProviderBox, StateProviderFactory};
use reth_trie::{ComputedTrieData, LazyTrieData};

use crate::{built_executions::BuiltExecution, engine_types::N42BuiltPayload};

/// Opens the state a build reads from, when it is not the state the client
/// would find by the parent's hash.
pub type ParentStateOpener = Arc<dyn Fn() -> ProviderResult<StateProviderBox> + Send + Sync>;

/// What a build on an own block needs.
#[derive(Debug, Clone)]
pub struct BuildOnOwnRequest {
    /// The parent, under the hash consensus sealed it with.
    pub parent: SealedHeader,
    /// The parent's execution, as the builder kept it (its block is under
    /// the builder's own hash).
    pub parent_execution: BuiltExecution,
    /// The attributes of the block to build.
    pub attributes: PayloadAttributes,
}

/// A builder the raw payload channel can call directly.
pub trait DirectBuilder: Send + Sync {
    /// Builds a block on `request.parent`, reading the parent's post-state
    /// from `request.parent_execution`.
    fn build_on_own(&self, request: BuildOnOwnRequest) -> Result<N42BuiltPayload, String>;
}

fn registry() -> &'static OnceLock<Arc<dyn DirectBuilder>> {
    static REGISTRY: OnceLock<Arc<dyn DirectBuilder>> = OnceLock::new();
    &REGISTRY
}

/// Registers the node's builder; the first registration wins.
pub fn register(builder: Arc<dyn DirectBuilder>) {
    let _ = registry().set(builder);
}

/// The registered builder, once the payload service has started one.
pub fn get() -> Option<Arc<dyn DirectBuilder>> {
    registry().get().cloned()
}

/// The parent as an executed block under its sealed header, so the overlay
/// answers `BLOCKHASH` with the hash the chain knows rather than the
/// builder's. One copy of the body (163,000 transactions, ~10 ms) per build.
pub fn executed_under_seal(parent: &SealedHeader, execution: &BuiltExecution) -> ExecutedBlock<N42Primitives> {
    let sealed = SealedBlock::from_sealed_parts(parent.clone(), execution.block.body().clone());
    let recovered = RecoveredBlock::new_sealed(sealed, execution.block.senders().to_vec());
    let hashed = execution.hashed_state.clone();
    let updates = execution.trie_updates.clone();
    ExecutedBlock {
        recovered_block: Arc::new(recovered),
        execution_output: execution.execution_output.clone(),
        // Only reth's trie methods read this, and nothing on a QMDB chain's
        // build path calls them; computed if anything ever does.
        trie_data: LazyTrieData::deferred(move || {
            ComputedTrieData::new(Arc::new((*hashed).clone().into_sorted()), Arc::new((*updates).clone().into_sorted()))
        }),
    }
}

/// An opener for the parent's post-state: the chain's state at the
/// grandparent with the parent's bundle laid over it.
pub fn opener_on_built_parent<C>(client: C, grandparent: B256, executed: ExecutedBlock<N42Primitives>) -> ParentStateOpener
where
    C: StateProviderFactory + Send + Sync + 'static,
{
    Arc::new(move || {
        let historical = client.state_by_block_hash(grandparent)?;
        Ok(Box::new(MemoryOverlayStateProvider::<N42Primitives>::new(historical, vec![executed.clone()])) as StateProviderBox)
    })
}
