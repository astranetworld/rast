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
use reth_ethereum_primitives::{Block, EthPrimitives, TransactionSigned};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_payload_primitives::BuiltPayloadExecutedBlock;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SignerRecoverable};
use reth_provider::{HeaderProvider, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use reth_provider::HashedPostStateProvider;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_trie::updates::TrieUpdates;

/// Executes and checks `sealed` on its parent's state. See the module docs.
/// Returns the executed block and the phase timings in milliseconds:
/// senders, execution (with the post-execution checks), state root, hashed
/// state.
#[allow(clippy::too_many_arguments)]
pub fn import_foreign_block<Provider, Evm, Pool, ChainSpec>(
    sealed: SealedBlock<Block>,
    provider: &Provider,
    evm_config: &Evm,
    pool: &Pool,
    qmdb: Option<&n42_qmdb_reth::QmdbNodeState>,
    consensus: &(dyn FullConsensus<EthPrimitives> + Send + Sync),
    chain_spec: &ChainSpec,
) -> Result<(Box<BuiltPayloadExecutedBlock<EthPrimitives>>, [u64; 4]), String>
where
    Provider: StateProviderFactory + HeaderProvider<Header = alloy_consensus::Header>,
    Evm: ConfigureEvm<Primitives = EthPrimitives>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    ChainSpec: reth_chainspec::EthereumHardforks,
{
    let qmdb = qmdb.ok_or("no QMDB state: the direct import needs the chain's root")?;
    let started = std::time::Instant::now();
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
    consensus.validate_block_pre_execution(&sealed).map_err(|err| format!("body: {err}"))?;

    // Senders: the pool knows most of them (every node ingests the flood);
    // the rest are recovered on the worker pool.
    let hashes: Vec<B256> = sealed.body().transactions().map(|tx| *tx.tx_hash()).collect();
    let known: alloy_primitives::map::B256Map<Address> = pool
        .get_all(hashes.clone())
        .into_iter()
        .map(|tx| (*tx.hash(), tx.sender()))
        .collect();
    let senders: Vec<Address> = {
        use rayon::prelude::*;
        sealed
            .body()
            .transactions()
            .collect::<Vec<_>>()
            .par_iter()
            .zip(hashes.par_iter())
            .map(|(tx, hash)| match known.get(hash) {
                Some(sender) => Ok(*sender),
                None => tx.recover_signer().map_err(|err| format!("sender of {hash}: {err}")),
            })
            .collect::<Result<Vec<_>, String>>()?
    };
    let recovered = RecoveredBlock::new_sealed(sealed, senders);
    let senders_ms = started.elapsed().as_millis() as u64;

    // Execution on the parent's state, then gas, receipts root and bloom
    // against the header.
    let state = provider.state_by_block_hash(parent_hash).map_err(|err| format!("parent state: {err}"))?;
    let executed_at = std::time::Instant::now();
    let output = evm_config
        .executor(StateProviderDatabase::new(&state))
        .execute(&recovered)
        .map_err(|err| format!("execution: {err}"))?;
    consensus
        .validate_block_post_execution(&recovered, &output.result, None, None)
        .map_err(|err| format!("post-execution: {err}"))?;
    let exec_ms = executed_at.elapsed().as_millis() as u64;

    // The QMDB root against the header's, which also files the block's tree
    // under its hash for the engine and the next block.
    let root_at = std::time::Instant::now();
    let prague = chain_spec.is_prague_active_at_timestamp(recovered.timestamp);
    let changes = n42_qmdb_reth::changes_from_execution(&output.state, prague);
    qmdb.validate_block(parent_hash, block_hash, number, &changes, recovered.state_root)
        .map_err(|err| format!("state root: {err}"))?;
    let root_ms = root_at.elapsed().as_millis() as u64;

    let hashed_at = std::time::Instant::now();
    let hashed_state = state.hashed_post_state(&output.state).map_err(|err| format!("hashed state: {err}"))?;
    let hashed_ms = hashed_at.elapsed().as_millis() as u64;

    Ok((
        Box::new(BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(recovered),
            execution_output: Arc::new(output),
            hashed_state: Arc::new(hashed_state),
            trie_updates: Arc::new(TrieUpdates::default()),
        }),
        [senders_ms, exec_ms, root_ms, hashed_ms],
    ))
}
