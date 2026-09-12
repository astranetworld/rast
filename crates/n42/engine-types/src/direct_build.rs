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

#[cfg(test)]
mod tests {
    //! The hazard of building on a block the engine has not imported: a state
    //! read that misses the parent's bundle and answers from the grandparent
    //! (a nonce one block stale refuses every transaction of that sender in
    //! the block being built), or a `BLOCKHASH` that answers the builder's
    //! hash instead of the one consensus sealed. A round lost to either would
    //! be the first on-seal block refusing 163,000 transactions.
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{Address, U256};
    use n42_tx_types::{Block, BlockBody};
    use reth_execution_types::BlockExecutionOutput;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::{AccountReader, BlockHashReader};
    use reth_trie::{updates::TrieUpdates, HashedPostState};
    use revm::{database::BundleState, state::AccountInfo};

    fn execution_of(header: &Header, bundle: BundleState) -> BuiltExecution {
        let block = Block { header: header.clone(), body: BlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: Some(Vec::new().into()) } };
        BuiltExecution {
            block: Arc::new(RecoveredBlock::new_sealed(SealedBlock::seal_slow(block), Vec::new())),
            execution_output: Arc::new(BlockExecutionOutput { result: Default::default(), state: bundle }),
            hashed_state: Arc::new(HashedPostState::default()),
            trie_updates: Arc::new(TrieUpdates::default()),
        }
    }

    #[test]
    fn the_parent_state_is_its_bundle_over_the_grandparent_under_the_sealed_hash() {
        let sender = Address::with_last_byte(1);
        let created = Address::with_last_byte(2);
        let untouched = Address::with_last_byte(3);
        let grandparent = B256::with_last_byte(9);

        // The chain's state at the grandparent: the sender at nonce 0, an
        // account the parent never touches, and no `created` yet.
        let client = MockEthProvider::default();
        client.add_account(sender, ExtendedAccount::new(0, U256::from(100)));
        client.add_account(untouched, ExtendedAccount::new(4, U256::from(40)));

        // The parent as the builder executed it: the sender moved to nonce 5,
        // `created` came into being.
        let bundle = BundleState::builder(11..=11)
            .state_present_account_info(sender, AccountInfo { nonce: 5, balance: U256::from(50), ..Default::default() })
            .state_present_account_info(created, AccountInfo { nonce: 0, balance: U256::from(7), ..Default::default() })
            .build();
        let header = Header { number: 11, parent_hash: grandparent, gas_used: 21_000, ..Default::default() };
        let execution = execution_of(&header, bundle);
        let built_hash = execution.block.hash();

        // Consensus seals the header (the view and the signature go into
        // `extra_data`), so the hash the chain knows is not the builder's.
        let sealed = SealedHeader::seal_slow(Header { extra_data: b"view 7".as_slice().into(), ..header.clone() });
        assert_ne!(sealed.hash(), built_hash);

        // The registry finds the build by what a seal cannot change.
        crate::built_executions::remember(built_hash, execution.clone());
        let (found, _) = crate::built_executions::find(grandparent, 11, header.state_root, header.receipts_root, 21_000, None)
            .expect("the build is found under the sealed header's parent, number, roots and gas");
        assert_eq!(found, built_hash);
        // The own-block import takes the build; the build on the sealed block
        // must still find it, whichever request the execution layer served first.
        let (taken, _) = crate::built_executions::take(grandparent, 11, header.state_root, header.receipts_root, 21_000, None).expect("taken");
        assert_eq!(taken, built_hash);
        assert!(crate::built_executions::find(grandparent, 11, header.state_root, header.receipts_root, 21_000, None).is_none());
        let (kept, _) = crate::built_executions::find_kept(grandparent, 11, header.state_root, header.receipts_root, 21_000, None)
            .expect("a taken build is still there for the build on the sealed block");
        assert_eq!(kept, built_hash);

        let executed = executed_under_seal(&sealed, &execution);
        assert_eq!(executed.recovered_block.hash(), sealed.hash(), "the overlay's block carries the sealed hash");
        assert_eq!(executed.recovered_block.header().number, 11);

        let state = opener_on_built_parent(client, grandparent, executed)().expect("the parent's state opens");
        let account = |a: &Address| state.basic_account(a).expect("read");
        assert_eq!(account(&sender).map(|a| a.nonce), Some(5), "the sender's nonce is the parent's, not the grandparent's");
        assert_eq!(account(&sender).map(|a| a.balance), Some(U256::from(50)));
        assert_eq!(account(&created).map(|a| a.balance), Some(U256::from(7)), "an account the parent created exists");
        assert_eq!(account(&untouched).map(|a| a.nonce), Some(4), "an untouched account reads through to the grandparent");
        assert_eq!(state.block_hash(11).expect("read"), Some(sealed.hash()), "BLOCKHASH of the parent is the sealed hash");
    }
}
