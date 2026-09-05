// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: Apache-2.0

//! A follower's execution of a block of plain transfers on the worker pool.
//!
//! The serial import executes 163,000 transfers in ~145 ms, one after the
//! other, on one core, while the box has thirty more idle; and that execution
//! is on the fleet's cycle twice over (the followers vote after it, the
//! leader builds ahead against it). Plain transfers between externally owned
//! accounts conflict only through the accounts they touch, so the block is
//! partitioned into groups that share no sender or recipient, each group is
//! executed in block order on its own [`State`] over the parent, and the
//! groups' account changes are folded into one state as *deltas* -- which is
//! what lets the block's rewards (withdrawals) and the beneficiary's tips,
//! both applied to accounts several groups may touch, come out the same as
//! the serial executor's.
//!
//! Anything the transfer path refuses -- a contract call, a transaction the
//! path would send to the interpreter, a transfer to or from the beneficiary
//! -- makes the whole block fall back to the serial executor: this path is
//! never wrong, only absent.

use alloy_primitives::{Address, U256};
use reth_ethereum_primitives::{Block, EthPrimitives, Receipt};
use reth_evm::{
    execute::{BlockExecutionError, BlockExecutor as _, BlockExecutorFactory},
    ConfigureEvm, Evm as _, EvmFactory as _,
};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{RecoveredBlock, SignedTransaction};
use reth_revm::db::State;
use revm::{
    context::TxEnv,
    database::{states::bundle_state::BundleRetention, BundleAccount},
    state::{Account, AccountStatus},
    Database, DatabaseCommit,
};
use std::collections::HashMap;

use crate::fast_transfer::N42EvmFactory;

/// The block executor factory of a node with the transfer path: what
/// [`execute_transfers`] requires of its EVM configuration.
pub type FastExecutorFactory = reth_evm::eth::EthBlockExecutorFactory<
    reth_evm_ethereum::RethReceiptBuilder,
    std::sync::Arc<reth_chainspec::ChainSpec>,
    N42EvmFactory,
>;

/// The executor's phase timings, in milliseconds: partitioning, the groups'
/// execution (wall), the merge into the block's state, the finish.
#[derive(Debug, Clone, Copy, Default)]
pub struct Phases {
    /// Partitioning the transactions into conflict-free groups.
    pub partition_ms: u64,
    /// The groups' execution on the worker pool, wall time.
    pub groups_ms: u64,
    /// Folding the groups' changes into the block's state.
    pub merge_ms: u64,
    /// Pre- and post-execution changes and the bundle.
    pub finish_ms: u64,
    /// How many groups there were.
    pub groups: usize,
}

/// Why the parallel path did not run; the caller executes serially.
#[derive(Debug)]
pub enum NotParallel {
    /// A transaction the transfer path does not take (index).
    NotATransfer(usize),
    /// A transfer to or from the block's beneficiary (index).
    TouchesBeneficiary(usize),
    /// A transfer failed on the path (index, message): the serial executor
    /// produces the exact error.
    Failed(usize, String),
    /// The parent's state could not be opened for a group.
    NoState,
}

impl std::fmt::Display for NotParallel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotATransfer(i) => write!(f, "transaction {i} is not a plain transfer"),
            Self::TouchesBeneficiary(i) => write!(f, "transaction {i} touches the beneficiary"),
            Self::Failed(i, m) => write!(f, "transaction {i} failed on the transfer path: {m}"),
            Self::NoState => write!(f, "the parent's state could not be opened"),
        }
    }
}

/// Disjoint-set forest over the accounts a block touches.
struct Groups {
    parent: Vec<usize>,
}

impl Groups {
    fn new(n: usize) -> Self {
        Self { parent: (0..n).collect() }
    }
    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }
    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.parent[a] = b;
        }
    }
}

/// Executes `block` with its transfers spread over the worker pool, or says
/// why it cannot. `main_db` is the parent's state the block's own executor
/// runs its pre- and post-execution changes on; `open` yields a fresh view of
/// the same parent for each group.
pub fn execute_transfers<EvmConfig, DB, G>(
    evm_config: &EvmConfig,
    block: &RecoveredBlock<Block>,
    main_db: DB,
    open: &(dyn Fn() -> Option<G> + Sync),
) -> Result<Result<(BlockExecutionOutput<Receipt>, Phases), NotParallel>, BlockExecutionError>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, BlockExecutorFactory = FastExecutorFactory>,
    DB: Database + std::fmt::Debug,
    DB::Error: Send + Sync + 'static,
    G: Database + std::fmt::Debug + Send,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut phases = Phases::default();
    let evm_env = evm_config.evm_env(block.header()).map_err(BlockExecutionError::other)?;
    let beneficiary = evm_env.block_env.beneficiary;

    // The transactions' environments, and the partition.
    let at = std::time::Instant::now();
    let txs: Vec<TxEnv> = block.transactions_recovered().map(|tx| evm_config.tx_env(tx)).collect();
    let mut index_of: HashMap<Address, usize> = HashMap::with_capacity(txs.len() * 2);
    let mut party = |a: Address| -> usize {
        let next = index_of.len();
        *index_of.entry(a).or_insert(next)
    };
    let mut edges: Vec<(usize, usize)> = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let alloy_primitives::TxKind::Call(to) = tx.kind else {
            return Ok(Err(NotParallel::NotATransfer(i)));
        };
        if !tx.data.is_empty() {
            return Ok(Err(NotParallel::NotATransfer(i)));
        }
        if tx.caller == beneficiary || to == beneficiary {
            return Ok(Err(NotParallel::TouchesBeneficiary(i)));
        }
        edges.push((party(tx.caller), party(to)));
    }
    let mut sets = Groups::new(index_of.len());
    for (a, b) in &edges {
        sets.union(*a, *b);
    }
    // Group id per transaction, then the transactions of each group in block
    // order.
    let mut group_of_root: HashMap<usize, usize> = HashMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, (a, _)) in edges.iter().enumerate() {
        let root = sets.find(*a);
        let next = groups.len();
        let g = *group_of_root.entry(root).or_insert_with(|| {
            groups.push(Vec::new());
            next
        });
        groups[g].push(i);
    }
    phases.partition_ms = at.elapsed().as_millis() as u64;
    phases.groups = groups.len();

    // The groups, on the worker pool. Each yields its bundle (the accounts
    // it changed, with their originals) and the gas each transaction used.
    let at = std::time::Instant::now();
    let results: Vec<Result<(revm::database::BundleState, Vec<(usize, u64)>), NotParallel>> = {
        use rayon::prelude::*;
        groups
            .par_iter()
            .map(|members| {
                let db = open().ok_or(NotParallel::NoState)?;
                let mut state = State::builder().with_database(db).with_bundle_update().build();
                let mut gas = Vec::with_capacity(members.len());
                {
                    let mut evm =
                        N42EvmFactory::with_fast_transfers(true).create_evm(&mut state, evm_env.clone());
                    for &i in members {
                        match evm.transfer(&txs[i]) {
                            Ok(Some(out)) => {
                                gas.push((i, out.result.gas_used()));
                                evm.db_mut().commit(out.state);
                            }
                            Ok(None) => return Err(NotParallel::NotATransfer(i)),
                            Err(err) => return Err(NotParallel::Failed(i, err.to_string())),
                        }
                    }
                }
                state.merge_transitions(BundleRetention::Reverts);
                Ok((state.take_bundle(), gas))
            })
            .collect()
    };
    phases.groups_ms = at.elapsed().as_millis() as u64;
    let mut bundles = Vec::with_capacity(results.len());
    let mut gas_of = vec![0u64; txs.len()];
    for r in results {
        match r {
            Ok((bundle, gas)) => {
                for (i, g) in gas {
                    gas_of[i] = g;
                }
                bundles.push(bundle);
            }
            Err(why) => return Ok(Err(why)),
        }
    }

    // The block's own executor: pre-execution changes (the system calls),
    // then -- with no transactions -- the post-execution changes (the
    // rewards), on the main state.
    let at = std::time::Instant::now();
    let mut state = State::builder().with_database(main_db).with_bundle_update().build();
    let result = {
        let ctx = evm_config.context_for_block(block.sealed_block()).map_err(BlockExecutionError::other)?;
        let evm = evm_config.evm_with_env(&mut state, evm_env.clone());
        let mut executor = evm_config.create_executor(evm, ctx);
        executor.apply_pre_execution_changes()?;
        let (_, result) = executor.finish()?;
        result
    };
    phases.finish_ms = at.elapsed().as_millis() as u64;

    // The groups' changes, as deltas on whatever the main state holds now:
    // an account a reward reached and a transfer touched gets both.
    let at = std::time::Instant::now();
    let mut changes: revm::state::EvmState = Default::default();
    changes.reserve(index_of.len() + 1);
    let mut beneficiary_delta = U256::ZERO;
    for bundle in &bundles {
        for (address, account) in &bundle.state {
            let BundleAccount { info, original_info, .. } = account;
            let (new_balance, new_nonce) = match info {
                Some(info) => (info.balance, info.nonce),
                None => continue,
            };
            let (old_balance, old_nonce) = match original_info {
                Some(orig) => (orig.balance, orig.nonce),
                None => (U256::ZERO, 0),
            };
            if *address == beneficiary {
                beneficiary_delta = beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
                continue;
            }
            // The main state's view, loaded so the transition records the
            // parent's original.
            let current = state.basic(*address).map_err(|e| BlockExecutionError::other(std::io::Error::other(e.to_string())))?;
            let existed = current.is_some();
            let mut merged = current.unwrap_or_default();
            merged.balance = if new_balance >= old_balance {
                merged.balance.saturating_add(new_balance - old_balance)
            } else {
                merged.balance.saturating_sub(old_balance - new_balance)
            };
            if new_nonce != old_nonce {
                merged.nonce = merged.nonce + (new_nonce - old_nonce);
            }
            let mut acc = Account::from(merged);
            acc.status = AccountStatus::Touched;
            if !existed && original_info.is_none() {
                acc.status |= AccountStatus::Created;
            }
            changes.insert(*address, acc);
        }
    }
    if !beneficiary_delta.is_zero() {
        let current = state.basic(beneficiary).map_err(|e| BlockExecutionError::other(std::io::Error::other(e.to_string())))?;
        let existed = current.is_some();
        let mut merged = current.unwrap_or_default();
        merged.balance = merged.balance.saturating_add(beneficiary_delta);
        let mut acc = Account::from(merged);
        acc.status = AccountStatus::Touched;
        if !existed {
            acc.status |= AccountStatus::Created;
        }
        changes.insert(beneficiary, acc);
    }
    state.commit(changes);
    state.merge_transitions(BundleRetention::Reverts);
    let bundle = state.take_bundle();
    phases.merge_ms = at.elapsed().as_millis() as u64;

    // Receipts in block order, gas cumulated.
    let mut cumulative = 0u64;
    let receipts: Vec<Receipt> = block
        .body()
        .transactions()
        .enumerate()
        .map(|(i, tx)| {
            cumulative += gas_of[i];
            Receipt { tx_type: tx.tx_type(), success: true, cumulative_gas_used: cumulative, logs: Vec::new() }
        })
        .collect();
    let result = reth_execution_types::BlockExecutionResult { receipts, gas_used: cumulative, ..result };
    Ok(Ok((BlockExecutionOutput { state: bundle, result }, phases)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, Signed, TxEip1559};
    use alloy_primitives::{Bytes, Signature, TxKind, B256};
    use reth_chainspec::MAINNET;
    use reth_ethereum_primitives::TransactionSigned;
    use reth_evm::execute::Executor as _;
    use reth_evm_ethereum::EthEvmConfig;
    use reth_primitives_traits::{Recovered, SealedBlock};
    use revm::database::{CacheDB, EmptyDB};
    use revm::state::AccountInfo;

    fn addr(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    /// A block of `n` transfers among `senders` accounts, every sender
    /// paying a few recipients in turn, some of them fresh, some shared.
    fn fixture(senders: u64, per: u64) -> (RecoveredBlock<Block>, CacheDB<EmptyDB>) {
        let mut db = CacheDB::new(EmptyDB::default());
        let beneficiary = addr(1);
        db.insert_account_info(beneficiary, AccountInfo { balance: U256::from(7), ..Default::default() });
        let mut txs = Vec::new();
        let mut recovered = Vec::new();
        for s in 0..senders {
            let sender = addr(100 + s);
            db.insert_account_info(sender, AccountInfo { balance: U256::from(10u128.pow(21)), nonce: 3, ..Default::default() });
            for k in 0..per {
                // Recipients: another sender (shared), a fresh account, and
                // the same fresh account again from a different sender.
                let to = match k % 3 {
                    0 => addr(100 + (s + 1) % senders),
                    1 => addr(10_000 + s * per + k),
                    _ => addr(20_000 + k),
                };
                let inner = TxEip1559 {
                    chain_id: 1,
                    nonce: 3 + k,
                    gas_limit: 21_000,
                    max_fee_per_gas: 10_000_000_000,
                    max_priority_fee_per_gas: 1_000_000_000,
                    to: TxKind::Call(to),
                    value: U256::from(1_000 + k),
                    input: Bytes::new(),
                    ..Default::default()
                };
                let signed = Signed::new_unchecked(inner, Signature::test_signature(), B256::random());
                let tx = TransactionSigned::from(signed);
                txs.push(tx.clone());
                recovered.push(sender);
            }
        }
        let header = Header {
            number: 1,
            beneficiary,
            gas_limit: 1_000_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            timestamp: 1_800_000_000,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            ..Default::default()
        };
        let body = reth_ethereum_primitives::BlockBody {
            transactions: txs,
            ommers: Vec::new(),
            withdrawals: Some(vec![alloy_eips::eip4895::Withdrawal { index: 0, validator_index: 0, address: addr(100), amount: 5 }].into()),
        };
        let block = SealedBlock::seal_slow(Block { header, body });
        (RecoveredBlock::new_sealed(block, recovered), db)
    }

    #[test]
    fn parallel_matches_serial() {
        let (block, db) = fixture(8, 6);
        let evm_config = EthEvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let serial = evm_config.executor(db.clone()).execute(&block).expect("serial execution");
        let (parallel, phases) = execute_transfers(&evm_config, &block, db.clone(), &|| Some(db.clone()))
            .expect("no execution error")
            .expect("the block qualifies");
        assert!(phases.groups >= 1);
        assert_eq!(parallel.result.gas_used, serial.result.gas_used, "gas used");
        assert_eq!(parallel.result.receipts, serial.result.receipts, "receipts");
        assert_eq!(parallel.result.requests, serial.result.requests, "requests");
        assert_eq!(parallel.state.state.len(), serial.state.state.len(), "accounts in the bundle");
        for (address, theirs) in &serial.state.state {
            let ours = parallel.state.state.get(address).unwrap_or_else(|| panic!("account {address} missing"));
            assert_eq!(ours.info, theirs.info, "info {address}");
            assert_eq!(ours.original_info, theirs.original_info, "original {address}");
            assert_eq!(ours.status, theirs.status, "status {address}");
        }
        assert_eq!(parallel.state.reverts.len(), serial.state.reverts.len(), "revert blocks");
        let mut ours: Vec<_> = parallel.state.reverts[0].iter().map(|(a, r)| (*a, r.clone())).collect();
        let mut theirs: Vec<_> = serial.state.reverts[0].iter().map(|(a, r)| (*a, r.clone())).collect();
        ours.sort_by_key(|(a, _)| *a);
        theirs.sort_by_key(|(a, _)| *a);
        assert_eq!(ours, theirs, "reverts");
    }

    #[test]
    fn a_transfer_to_the_beneficiary_falls_back() {
        let (mut block, db) = fixture(2, 1);
        // Point the first transfer at the beneficiary.
        let hash = block.hash();
        let mut raw = block.clone_sealed_block().into_block();
        if let TransactionSigned::Eip1559(signed) = &mut raw.body.transactions[0] {
            let (mut tx, sig, _) = signed.clone().into_parts();
            tx.to = TxKind::Call(addr(1));
            *signed = Signed::new_unchecked(tx, sig, B256::random());
        }
        let senders = block.senders().to_vec();
        block = RecoveredBlock::new_unhashed(raw, senders);
        let _ = hash;
        let evm_config = EthEvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let out = execute_transfers(&evm_config, &block, db.clone(), &|| Some(db.clone())).expect("no execution error");
        assert!(matches!(out, Err(NotParallel::TouchesBeneficiary(0))), "{out:?}");
    }
}
