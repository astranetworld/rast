// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The QMDB root, installed where reth's engine tree checks a block's state root.
//!
//! reth validates every block the Engine API hands it by executing it and
//! comparing a computed state root to the header. Which computation runs is a
//! [`StateRootStrategy`], installed once per node through
//! `BasicEngineValidator::with_state_root_strategy` — a public seam, so none of
//! this touches reth itself. [`QmdbStateRootStrategy`] is that strategy for a
//! QMDB chain: after execution it turns the block's bundle into the leaves the
//! block wrote and asks the node's forest for the root.
//!
//! The payload-builder half of the same seam is deliberately left at its
//! default. reth's stock builders drive their root computation through a
//! background task handle; this node's builder is its own code and asks the
//! forest directly, which is simpler and shares the same trees.
//!
//! What this leaves behind: reth's own trie tables. The outcome reports no trie
//! updates, so from the first QMDB block on, `eth_getProof` and anything else
//! that reads the stored Merkle-Patricia trie is stale. Proofs on a QMDB chain
//! come from the forest — `mobile_getProof` — not from the trie.
//!
//! And one constraint on the node, not on this code: the engine tree is the
//! only path that consults a strategy. Pipeline (backfill) sync computes
//! Merkle-Patricia roots in its own stage, and would reject every QMDB header.
//! A QMDB node syncs by replaying blocks through the engine, or from a forest
//! snapshot; it must not be allowed to fall into backfill.

use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use reth_engine_tree::tree::state_root_strategy::{
    LazyHashedPostState, PreparedStateRootJob, StateRootJob, StateRootJobContext,
    StateRootJobOutcome, StateRootStrategy,
};
use reth_engine_tree::tree::{BasicEngineValidator, TreeConfig};
use reth_node_api::{
    AddOnsContext, BlockTy, ConfigureEngineEvm, FullNodeComponents, NodeTypes, PayloadTypes,
    PrimitivesTy,
};
use reth_node_builder::rpc::{
    BasicEngineValidatorBuilder, EngineValidatorBuilder, PayloadValidatorBuilder,
};
use reth_primitives_traits::{NodePrimitives, RecoveredBlock};
use reth_provider::{BlockExecutionOutput, ProviderError, ProviderResult};
use reth_storage_overlay::OverlayManager;
use reth_trie::updates::TrieUpdates;
use tracing::debug;

use crate::changes::changes_from_execution;
use reth_chainspec::EthereumHardforks;
use crate::node_state::QmdbNodeState;

/// Computes QMDB roots for blocks the engine tree validates.
#[derive(Clone)]
pub struct QmdbStateRootStrategy {
    state: QmdbNodeState,
    /// Whether Prague is active at a timestamp: it decides whether the block
    /// wrote the system caller leaf. See `changes::with_prague_system_caller`.
    prague_at: PragueAt,
    /// Whether deferred execution is active at a timestamp
    /// (`deferredExecutionTime`): the header then carries the parent's root.
    deferred_at: PragueAt,
}

/// Fork lookup captured from the chain spec, so the strategy needs no type
/// parameter for it.
pub type PragueAt = Arc<dyn Fn(u64) -> bool + Send + Sync>;

impl std::fmt::Debug for QmdbStateRootStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbStateRootStrategy").field("state", &self.state).finish_non_exhaustive()
    }
}

impl QmdbStateRootStrategy {
    /// A strategy over the node's forest.
    /// A strategy over `state`, on a chain whose Prague activation `chain_spec`
    /// knows.
    pub fn new<C: EthereumHardforks + Send + Sync + 'static>(
        state: QmdbNodeState,
        chain_spec: Arc<C>,
        deferred_execution_time: Option<u64>,
    ) -> Self {
        Self {
            state,
            prague_at: Arc::new(move |timestamp| chain_spec.is_prague_active_at_timestamp(timestamp)),
            deferred_at: Arc::new(move |timestamp| deferred_execution_time.is_some_and(|at| timestamp >= at)),
        }
    }
}

impl<N, P, Evm> StateRootStrategy<N, P, Evm> for QmdbStateRootStrategy
where
    N: NodePrimitives,
    Evm: reth_node_api::ConfigureEvm<Primitives = N>,
{
    fn prepare(
        &self,
        _ctx: StateRootJobContext<'_, N, P, Evm>,
    ) -> ProviderResult<PreparedStateRootJob<N>> {
        // No streaming capability: the whole bundle arrives at `finish`, and a
        // QMDB root is an ordered batch over the whole block anyway — there is
        // nothing to compute incrementally per transaction.
        Ok(PreparedStateRootJob::new(
            Box::new(QmdbStateRootJob {
                state: self.state.clone(),
                prague_at: self.prague_at.clone(),
                deferred_at: self.deferred_at.clone(),
            }),
            None,
        ))
    }
}

struct QmdbStateRootJob {
    state: QmdbNodeState,
    prague_at: PragueAt,
    deferred_at: PragueAt,
}

impl<N: NodePrimitives> StateRootJob<N> for QmdbStateRootJob {
    fn name(&self) -> &'static str {
        "qmdb"
    }

    fn finish(
        &mut self,
        block: &RecoveredBlock<N::Block>,
        output: Arc<BlockExecutionOutput<N::Receipt>>,
        _hashed_state: &LazyHashedPostState,
    ) -> ProviderResult<StateRootJobOutcome> {
        let header = block.header();
        let changes = changes_from_execution(&output.state, (self.prague_at)(header.timestamp()));
        if (self.deferred_at)(header.timestamp()) {
            // Deferred execution: the header's root is the parent's, checked
            // by the consensus rules; this block's own root is filed and
            // remembered for its child. reth compares the outcome with the
            // header, so the outcome is what the header carries.
            let ops = crate::sorted_operations_from_execution(&output.state, (self.prague_at)(header.timestamp()));
            let root = self
                .state
                .insert_block_operations(header.parent_hash(), block.hash(), header.number(), ops)
                .map_err(ProviderError::other)?;
            crate::executed_fields::remember_state_root(block.hash(), root);
            debug!(
                target: "n42.qmdb",
                block = header.number(), hash = %block.hash(), %root,
                "computed and filed the QMDB root of a block under deferred execution",
            );
            return Ok(StateRootJobOutcome::new(header.state_root(), Arc::new(TrieUpdates::default())));
        }
        let root = self
            .state
            .validate_block(
                header.parent_hash(),
                block.hash(),
                header.number(),
                &changes,
                header.state_root(),
            )
            .map_err(ProviderError::other)?;
        debug!(
            target: "n42.qmdb",
            block = header.number(), hash = %block.hash(), %root, leaves = changes.len(),
            "computed the QMDB root for a validated block",
        );
        // No trie updates: the Merkle-Patricia trie is not maintained on a QMDB
        // chain. See the module docs.
        Ok(StateRootJobOutcome::new(root, Arc::new(TrieUpdates::default())))
    }
}

/// An [`EngineValidatorBuilder`] that installs the QMDB strategy when the node
/// has QMDB state, and builds reth's stock validator otherwise.
///
/// Wrapping rather than replacing: everything about validation except the
/// root computation is reth's, and stays reth's.
#[derive(Debug, Clone)]
pub struct QmdbEngineValidatorBuilder<PVB> {
    inner: BasicEngineValidatorBuilder<PVB>,
    state: Option<QmdbNodeState>,
}

impl<PVB: Default> QmdbEngineValidatorBuilder<PVB> {
    /// A builder that installs the QMDB strategy when `state` is given.
    pub fn new(state: Option<QmdbNodeState>) -> Self {
        Self {
            inner: BasicEngineValidatorBuilder::default(),
            state,
        }
    }
}

impl<PVB: Default> Default for QmdbEngineValidatorBuilder<PVB> {
    fn default() -> Self {
        Self::new(None)
    }
}

// The bounds are reth's own, from its `BasicEngineValidatorBuilder` impl: this
// builder adds nothing to what the stock one needs.
impl<Node, PVB> EngineValidatorBuilder<Node> for QmdbEngineValidatorBuilder<PVB>
where
    Node: FullNodeComponents<
        Evm: ConfigureEngineEvm<
            <<Node::Types as NodeTypes>::Payload as PayloadTypes>::ExecutionData,
        >,
    >,
    PVB: PayloadValidatorBuilder<Node>,
    PVB::Validator: reth_engine_primitives::PayloadValidator<
            <Node::Types as NodeTypes>::Payload,
            Block = BlockTy<Node::Types>,
        > + Clone,
    <Node::Types as NodeTypes>::ChainSpec: EthereumHardforks,
{
    type EngineValidator = BasicEngineValidator<Node::Provider, Node::Evm, PVB::Validator>;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: TreeConfig,
        overlay_manager: OverlayManager<PrimitivesTy<Node::Types>>,
    ) -> eyre::Result<Self::EngineValidator> {
        let validator = self
            .inner
            .build_tree_validator(ctx, tree_config, overlay_manager)
            .await?;
        Ok(match self.state {
            Some(state) => {
                let strategy: Arc<
                    dyn StateRootStrategy<PrimitivesTy<Node::Types>, Node::Provider, Node::Evm>,
                > = Arc::new(QmdbStateRootStrategy::new(
                    state,
                    ctx.config.chain.clone(),
                    reth_chainspec::qmdb::deferred_execution_time(reth_chainspec::EthChainSpec::genesis(&*ctx.config.chain)),
                ));
                validator.with_state_root_strategy(strategy)
            }
            None => validator,
        })
    }
}
