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
use n42_tx_types::{Block, N42Primitives as EthPrimitives, Receipt};
use alloy_consensus::TransactionEnvelope as _;
use reth_evm::{
    execute::{BlockExecutionError, BlockExecutor as _, BlockExecutorFactory},
    ConfigureEvm, Evm as _, EvmFactory as _,
};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{RecoveredBlock, SignedTransaction};
use reth_revm::db::State;
use revm::{
    context::TxEnv,
    database::{states::bundle_state::BundleRetention, states::CacheAccount, AccountRevert, BundleAccount, BundleState, PlainAccount},
    state::{Account, AccountStatus},
    Database, DatabaseCommit,
};

use crate::fast_transfer::N42EvmFactory;

/// The block executor factory of a node with the transfer path: what
/// [`execute_transfers`] requires of its EVM configuration.
pub type FastExecutorFactory = crate::n42_evm::N42BlockExecutorFactory<reth_chainspec::ChainSpec>;

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
    /// How many batches of groups ran (the build's [`execute_for_build`]
    /// runs a sender per group and several groups per batch).
    pub batches: usize,
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


/// Partitions transfers into groups that share no sender or recipient: the
/// groups can execute in any order relative to each other. Returns the groups
/// (indices into `txs`, in order) and the number of distinct parties.
pub fn partition(txs: &[TxEnv], beneficiary: Address) -> Result<(Vec<Vec<usize>>, usize), NotParallel> {
    let mut index_of: alloy_primitives::map::AddressHashMap<usize> = alloy_primitives::map::AddressHashMap::default();
    index_of.reserve(txs.len() * 2);
    let mut party = |a: Address| -> usize {
        let next = index_of.len();
        *index_of.entry(a).or_insert(next)
    };
    let mut edges: Vec<(usize, usize)> = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let alloy_primitives::TxKind::Call(to) = tx.kind else {
            return Err(NotParallel::NotATransfer(i));
        };
        if !tx.data.is_empty() {
            return Err(NotParallel::NotATransfer(i));
        }
        if tx.caller == beneficiary || to == beneficiary {
            return Err(NotParallel::TouchesBeneficiary(i));
        }
        edges.push((party(tx.caller), party(to)));
    }
    let mut sets = Groups::new(index_of.len());
    for (a, b) in &edges {
        sets.union(*a, *b);
    }
    let mut group_of_root: Vec<usize> = vec![usize::MAX; index_of.len()];
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, (a, _)) in edges.iter().enumerate() {
        let root = sets.find(*a);
        if group_of_root[root] == usize::MAX {
            group_of_root[root] = groups.len();
            groups.push(Vec::new());
        }
        groups[group_of_root[root]].push(i);
    }
    Ok((groups, index_of.len()))
}

/// Groups candidate transfers by sender: every sender's transfers, in
/// candidate order, form one group. Recipients do not join groups -- a
/// transfer only adds to its recipient's balance, and additions commute, so
/// [`rebase`] can fold groups that share a recipient in any order. (Grouping
/// by connected component, as the follower's [`partition`] does, merges a
/// full block of random transfers into a handful of giant groups: round 43.)
///
/// Returns `Err` when a candidate is not a plain transfer or touches the
/// beneficiary.
pub fn partition_by_sender(txs: &[TxEnv], beneficiary: Address) -> Result<Vec<Vec<usize>>, NotParallel> {
    let mut group_of: alloy_primitives::map::AddressHashMap<usize> = alloy_primitives::map::AddressHashMap::default();
    group_of.reserve(txs.len() / 8);
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, tx) in txs.iter().enumerate() {
        let alloy_primitives::TxKind::Call(to) = tx.kind else {
            return Err(NotParallel::NotATransfer(i));
        };
        if !tx.data.is_empty() {
            return Err(NotParallel::NotATransfer(i));
        }
        if tx.caller == beneficiary || to == beneficiary {
            return Err(NotParallel::TouchesBeneficiary(i));
        }
        let next = groups.len();
        let g = *group_of.entry(tx.caller).or_insert(next);
        if g == next {
            groups.push(Vec::new());
        }
        groups[g].push(i);
    }
    Ok(groups)
}

/// One transfer executed for a block being built: its index in the candidate
/// list, the EVM's result, and the gas it used. Its state changes are in its
/// batch's bundle ([`BuildRun::bundles`]).
#[derive(Debug)]
pub struct BuiltTransfer {
    /// Index into the candidates.
    pub index: usize,
    /// The EVM's result, for the receipt.
    pub result: revm::context::result::ExecutionResult<revm::context::result::HaltReason>,
    /// Gas used.
    pub gas_used: u64,
}

/// What [`execute_for_build`] produced.
#[derive(Debug, Default)]
pub struct BuildRun {
    /// The transfers that executed, in the order they must appear in the
    /// block: batch by batch, sender by sender, each sender in candidate
    /// order.
    pub executed: Vec<BuiltTransfer>,
    /// Candidates the transfer path refused (a nonce that is not the
    /// account's, a balance short, a shape it does not take): left for the
    /// serial builder, in candidate order.
    pub skipped: Vec<usize>,
    /// Each batch's changes against the parent's state, with reverts, for
    /// [`graft_bundles`].
    pub bundles: Vec<BundleState>,
    /// Phase timings.
    pub phases: Phases,
}

/// Folds bundles that were each computed against the parent's state into
/// one set of changes on `state`, the block's state as it stands: every
/// account gets what the bundles changed it by, added to what `state` holds
/// (an account two bundles credited gets both credits; one a reward reached
/// and a transfer touched gets both). The beneficiary is left out and its
/// total credit returned, for the caller to apply with the block's other
/// credits. Nothing is committed here.
pub fn fold_bundles<DB: Database>(
    state: &mut State<DB>,
    bundles: &[revm::database::BundleState],
    beneficiary: Address,
) -> Result<(revm::state::EvmState, U256), <State<DB> as Database>::Error> {
    let mut changes: revm::state::EvmState = Default::default();
    changes.reserve(bundles.iter().map(|b| b.state.len()).sum::<usize>() + 1);
    let mut beneficiary_delta = U256::ZERO;
    for bundle in bundles {
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
            // Another bundle's change to the same account is already in
            // `changes`; otherwise the block's view, loaded so the transition
            // records the parent's original.
            let (mut merged, existed) = match changes.remove(address) {
                Some(acc) => (acc.info, !acc.status.contains(AccountStatus::Created)),
                None => {
                    let current = state.basic(*address)?;
                    let existed = current.is_some();
                    (current.unwrap_or_default(), existed)
                }
            };
            merged.balance = if new_balance >= old_balance {
                merged.balance.saturating_add(new_balance - old_balance)
            } else {
                merged.balance.saturating_sub(old_balance - new_balance)
            };
            if new_nonce != old_nonce {
                merged.nonce += new_nonce - old_nonce;
            }
            let mut acc = Account::from(merged);
            acc.status = AccountStatus::Touched;
            if !existed && original_info.is_none() {
                acc.status |= AccountStatus::Created;
            }
            changes.insert(*address, acc);
        }
    }
    Ok((changes, beneficiary_delta))
}

/// What [`graft_bundles`] left for the caller.
#[derive(Debug, Default)]
pub struct Graft {
    /// The beneficiary's total credit across the bundles, not applied.
    pub beneficiary_delta: U256,
    /// The grafted accounts' reverts. They belong to the block's revert set,
    /// which the state's own merge creates later: append them to it once the
    /// bundle is taken (see [`append_reverts`]).
    pub reverts: Vec<(Address, AccountRevert)>,
    /// Accounts grafted.
    pub accounts: usize,
    /// Accounts the block's state already held and that went in as deltas
    /// through a commit instead.
    pub committed: usize,
}

/// Grafts the batches' bundles onto the block's state directly: each account
/// goes into the state's cache and bundle as its batch left it (the batch's
/// original is the parent's, which is what the block's state holds for an
/// account nothing before it touched), an account two batches touched gets
/// both changes added together, and the beneficiary is left out with its
/// credit returned. This goes around the state's transition machinery, which
/// is the point: committing 160,000 accounts through it and merging the
/// transitions cost more than executing the transfers did (round 43). The
/// few accounts the block's state already has in its cache (a system
/// contract, an earlier transaction's) are applied as deltas through a
/// commit, as [`fold_bundles`] does for all.
///
/// Each bundle must have been built with [`BundleRetention::Reverts`] against
/// the parent's state.
pub fn graft_bundles<DB: Database>(
    state: &mut State<DB>,
    bundles: Vec<BundleState>,
    beneficiary: Address,
) -> Result<Graft, <State<DB> as Database>::Error> {
    let mut graft = Graft::default();
    let total: usize = bundles.iter().map(|b| b.state.len()).sum();
    state.cache.accounts.reserve(total);
    state.bundle_state.state.reserve(total);
    graft.reverts.reserve(total);
    let mut slow: revm::state::EvmState = Default::default();
    for bundle in bundles {
        let BundleState { state: accounts, reverts, .. } = bundle;
        // Addresses this bundle changed that an earlier one had already put
        // in: their reverts are the earlier one's.
        let mut repeated: alloy_primitives::map::AddressHashSet = Default::default();
        for (address, account) in accounts {
            let Some(info) = account.info.as_ref() else { continue };
            let (new_balance, new_nonce) = (info.balance, info.nonce);
            let (old_balance, old_nonce) = match &account.original_info {
                Some(orig) => (orig.balance, orig.nonce),
                None => (U256::ZERO, 0),
            };
            if address == beneficiary {
                graft.beneficiary_delta = graft.beneficiary_delta.saturating_add(new_balance.saturating_sub(old_balance));
                repeated.insert(address);
                continue;
            }
            if state.bundle_state.state.contains_key(&address) {
                // An earlier bundle put it in (or an earlier merge did, in
                // which case the cache holds the block's view too): added to
                // what is there, in both places.
                repeated.insert(address);
                let add = |info: &mut revm::state::AccountInfo| {
                    info.balance = if new_balance >= old_balance {
                        info.balance.saturating_add(new_balance - old_balance)
                    } else {
                        info.balance.saturating_sub(old_balance - new_balance)
                    };
                    info.nonce += new_nonce - old_nonce;
                };
                if let Some(info) = state.bundle_state.state.get_mut(&address).and_then(|a| a.info.as_mut()) {
                    add(info);
                }
                if let Some(info) = state.cache.accounts.get_mut(&address).and_then(|a| a.account.as_mut()) {
                    add(&mut info.info);
                }
                continue;
            }
            if let Some(cached) = state.cache.accounts.get(&address) {
                // The block's state has its own view of this account; a
                // delta through the ordinary path.
                repeated.insert(address);
                let existed = cached.account.is_some();
                let mut merged = cached.account.as_ref().map(|a| a.info.clone()).unwrap_or_default();
                merged.balance = if new_balance >= old_balance {
                    merged.balance.saturating_add(new_balance - old_balance)
                } else {
                    merged.balance.saturating_sub(old_balance - new_balance)
                };
                merged.nonce += new_nonce - old_nonce;
                let mut acc = Account::from(merged);
                acc.status = AccountStatus::Touched;
                if !existed && account.original_info.is_none() {
                    acc.status |= AccountStatus::Created;
                }
                slow.insert(address, acc);
                continue;
            }
            state.cache.accounts.insert(
                address,
                CacheAccount {
                    account: Some(PlainAccount { info: info.clone(), storage: Default::default() }),
                    status: account.status,
                },
            );
            state.bundle_state.state_size += account.size_hint();
            state.bundle_state.state.insert(address, account);
            graft.accounts += 1;
        }
        let mut reverts = reverts;
        for (address, revert) in std::mem::take(&mut *reverts).into_iter().flatten() {
            if !repeated.contains(&address) {
                graft.reverts.push((address, revert));
            }
        }
    }
    if !slow.is_empty() {
        graft.committed = slow.len();
        state.commit(slow);
    }
    Ok(graft)
}

/// Appends a graft's reverts to a taken bundle's revert set for the block
/// (the last one, which the state's merge created; a new one if the merge
/// found nothing to revert).
pub fn append_reverts(bundle: &mut BundleState, reverts: Vec<(Address, AccountRevert)>) {
    if reverts.is_empty() {
        return;
    }
    if bundle.reverts.is_empty() {
        bundle.reverts.push(Vec::new());
    }
    let last = bundle.reverts.len() - 1;
    bundle.reverts_size += reverts.len();
    bundle.reverts[last].extend(reverts);
}

/// Executes candidate transfers for a block being built, one group per
/// sender ([`partition_by_sender`]), the groups spread over batches on the
/// worker pool, each batch on its own view of the parent's state from `open`
/// and yielding its own bundle.
///
/// Unlike [`execute_transfers`], which must reproduce a sealed block exactly,
/// this may drop candidates: one the transfer path refuses is reported in
/// `skipped` and the group goes on (a later transfer of the same sender then
/// fails its nonce check and is skipped too, which keeps the sender's order).
/// A sender's view lacks what other groups credit it in the same block, so a
/// transfer that only those credits would fund is skipped rather than built:
/// conservative, and the serial builder that follows may still take it.
///
/// The caller grafts the bundles onto the block's state with
/// [`graft_bundles`]: committing each transfer's state on its own is what
/// the serial path spends half its time on (round 43: 112 ms of execution,
/// 110 ms of commits and 55 ms of transition merging for 163,000 transfers),
/// and one commit of the folded changes ([`fold_bundles`]) costs the same.
///
/// Returns `Err` when the candidates are not all plain transfers away from
/// the beneficiary: then the serial builder takes all of them.
pub fn execute_for_build<G>(
    evm_env: &reth_evm::EvmEnv,
    txs: &[TxEnv],
    open: &(dyn Fn() -> Option<G> + Sync),
) -> Result<BuildRun, NotParallel>
where
    G: Database + std::fmt::Debug + Send,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let beneficiary = evm_env.block_env.beneficiary;
    let mut phases = Phases::default();
    let at = std::time::Instant::now();
    let groups = partition_by_sender(txs, beneficiary)?;
    phases.groups = groups.len();
    // Batches of whole groups, about equal in transfers: a couple of
    // thousand transfers each, at most two per worker. Each batch opens its
    // own view of the parent, which is not free.
    let workers = rayon::current_num_threads().max(1);
    let wanted = (txs.len() / 2048).clamp(1, workers * 2);
    let per_batch = txs.len().div_ceil(wanted).max(1);
    let mut batches: Vec<Vec<&Vec<usize>>> = Vec::with_capacity(wanted + 1);
    let mut current: Vec<&Vec<usize>> = Vec::new();
    let mut filled = 0usize;
    for group in &groups {
        current.push(group);
        filled += group.len();
        if filled >= per_batch {
            batches.push(std::mem::take(&mut current));
            filled = 0;
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    phases.batches = batches.len();
    phases.partition_ms = at.elapsed().as_millis() as u64;

    let at = std::time::Instant::now();
    let results: Vec<Result<(Vec<BuiltTransfer>, Vec<usize>, revm::database::BundleState), NotParallel>> = {
        use rayon::prelude::*;
        batches
            .par_iter()
            .map(|members| {
                let db = open().ok_or(NotParallel::NoState)?;
                let mut state = State::builder().with_database(db).with_bundle_update().build();
                let mut done = Vec::with_capacity(members.iter().map(|g| g.len()).sum());
                let mut skipped = Vec::new();
                {
                    let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(&mut state, evm_env.clone());
                    for group in members {
                        for &i in group.iter() {
                            match evm.transfer(&txs[i]) {
                                Ok(Some(out)) => {
                                    let gas_used = out.result.gas_used();
                                    evm.db_mut().commit(out.state);
                                    done.push(BuiltTransfer { index: i, result: out.result, gas_used });
                                }
                                Ok(None) => skipped.push(i),
                                Err(err) => return Err(NotParallel::Failed(i, err.to_string())),
                            }
                        }
                    }
                }
                state.merge_transitions(BundleRetention::Reverts);
                Ok((done, skipped, state.take_bundle()))
            })
            .collect()
    };
    phases.groups_ms = at.elapsed().as_millis() as u64;

    let mut run = BuildRun { phases, ..Default::default() };
    for r in results {
        let (done, skipped, bundle) = r?;
        run.executed.extend(done);
        run.skipped.extend(skipped);
        run.bundles.push(bundle);
    }
    run.skipped.sort_unstable();
    Ok(run)
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
    // Address-keyed with the fixed-bytes hasher: the default hasher was
    // ~29 ms of a 163,000-transfer block's partition.
    let (groups, _parties) = match partition(&txs, beneficiary) {
        Ok(p) => p,
        Err(why) => return Ok(Err(why)),
    };
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
    let (mut changes, beneficiary_delta) = fold_bundles(&mut state, &bundles, beneficiary)
        .map_err(|e| BlockExecutionError::other(std::io::Error::other(e.to_string())))?;
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
                let tx = n42_tx_types::N42TxEnvelope::from(TransactionSigned::from(signed));
                txs.push(tx.clone());
                recovered.push(sender);
            }
        }
        // Past the merge on mainnet, so the serial executor pays no
        // block reward: the builder path credits only the fees.
        let header = Header {
            number: 20_000_000,
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
        let body = n42_tx_types::BlockBody {
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
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
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


    /// The build-mode run, committed in its order with the beneficiary
    /// credited once, ends in the same state as the serial executor.
    #[test]
    fn build_run_matches_serial() {
        use alloy_consensus::Transaction as _;
        let (block, db) = fixture(8, 6);
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let serial = evm_config.executor(db.clone()).execute(&block).expect("serial execution");
        let evm_env = evm_config.evm_env(block.header()).expect("env");
        let envs: Vec<TxEnv> = block.transactions_recovered().map(|tx| evm_config.tx_env(tx)).collect();
        let run = execute_for_build(&evm_env, &envs, &|| Some(db.clone())).expect("a block of transfers");
        assert!(run.skipped.is_empty(), "{:?}", run.skipped);
        assert_eq!(run.executed.len(), envs.len());
        assert_eq!(run.phases.groups, 8, "one group per sender");
        assert!(run.phases.batches >= 1);

        let beneficiary = evm_env.block_env.beneficiary;
        let base_fee = evm_env.block_env.basefee;
        let txs: Vec<_> = block.transactions_recovered().collect();
        let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
        let mut fees = U256::ZERO;
        let mut gas = 0u64;
        for built in &run.executed {
            let tip = txs[built.index].effective_tip_per_gas(base_fee).unwrap_or_default();
            fees += U256::from(tip) * U256::from(built.gas_used);
            gas += built.gas_used;
        }
        let graft = graft_bundles(&mut state, run.bundles, beneficiary).unwrap();
        assert_eq!(graft.beneficiary_delta, fees, "the batches credited the beneficiary the summed tips");
        assert_eq!(graft.committed, 0, "nothing was in the block's cache yet");
        assert!(!state.cache.accounts.contains_key(&beneficiary), "beneficiary left out");
        let mut changes = revm::state::EvmState::default();
        let current = state.basic(beneficiary).unwrap();
        let existed = current.is_some();
        let mut info = current.unwrap_or_default();
        info.balance += graft.beneficiary_delta;
        let mut account = Account::from(info);
        account.status = AccountStatus::Touched;
        if !existed {
            account.status |= AccountStatus::Created;
        }
        changes.insert(beneficiary, account);
        state.commit(changes);
        // The block executor pays the withdrawal at finish; the builder's
        // parallel step does not, so apply it here before comparing.
        for w in block.body().withdrawals.as_ref().unwrap().iter() {
            let mut info = state.basic(w.address).unwrap().unwrap_or_default();
            info.balance += U256::from(w.amount_wei());
            let mut account = Account::from(info);
            account.status = AccountStatus::Touched;
            let mut changes = revm::state::EvmState::default();
            changes.insert(w.address, account);
            state.commit(changes);
        }
        state.merge_transitions(BundleRetention::Reverts);
        let mut bundle = state.take_bundle();
        append_reverts(&mut bundle, graft.reverts);

        assert_eq!(gas, serial.result.gas_used, "gas used");
        assert_eq!(bundle.state.len(), serial.state.state.len(), "accounts in the bundle");
        for (address, theirs) in &serial.state.state {
            let ours = bundle.state.get(address).unwrap_or_else(|| panic!("account {address} missing"));
            assert_eq!(ours.info, theirs.info, "info {address}");
            assert_eq!(ours.original_info, theirs.original_info, "original {address}");
            assert_eq!(ours.status, theirs.status, "status {address}");
        }
        // The reverts: one set for the block, the same entry per account.
        assert_eq!(bundle.reverts.len(), 1);
        assert_eq!(serial.state.reverts.len(), 1);
        let ours: std::collections::BTreeMap<_, _> = bundle.reverts[0].iter().cloned().collect();
        let theirs: std::collections::BTreeMap<_, _> = serial.state.reverts[0].iter().cloned().collect();
        assert_eq!(ours.len(), theirs.len(), "reverts");
        for (address, revert) in &theirs {
            assert_eq!(ours.get(address), Some(revert), "revert {address}");
        }
    }

    /// A full bench-tier block (163,000 transfers, 6,000 senders, recipients
    /// drawn from two million) through the serial transfer path and through
    /// `execute_for_build`, timed. `cargo test -p n42-engine-types --release
    /// bench_build_run -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing"]
    fn bench_build_run() {
        let senders = 6_000u64;
        let per = 27u64;
        let mut db = CacheDB::new(EmptyDB::default());
        let beneficiary = addr(1);
        db.insert_account_info(beneficiary, AccountInfo { balance: U256::from(7), ..Default::default() });
        let mut envs = Vec::new();
        let mut seed = 0x9e3779b97f4a7c15u64;
        for s in 0..senders {
            let sender = addr(100 + s);
            db.insert_account_info(sender, AccountInfo { balance: U256::from(10u128.pow(21)), nonce: 0, ..Default::default() });
            for k in 0..per {
                seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                let to = addr(1_000_000 + seed % 2_000_000);
                let mut env = TxEnv::default();
                env.caller = sender;
                env.kind = TxKind::Call(to);
                env.value = U256::from(1_000 + k);
                env.gas_limit = 21_000;
                env.gas_price = 10_000_000_000;
                env.gas_priority_fee = Some(1_000_000_000);
                env.nonce = k;
                env.tx_type = 2;
                env.chain_id = Some(1);
                envs.push(env);
            }
        }
        // Interleave senders as the queue does.
        let mut order: Vec<TxEnv> = Vec::with_capacity(envs.len());
        for k in 0..per as usize {
            for s in 0..senders as usize {
                order.push(envs[s * per as usize + k].clone());
            }
        }
        let envs = order;
        let header = Header { number: 20_000_000, beneficiary, gas_limit: 5_000_000_000, base_fee_per_gas: Some(1_000_000_000), timestamp: 1_800_000_000, ..Default::default() };
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let evm_env = evm_config.evm_env(&header).expect("env");
        for round in 0..3 {
            let at = std::time::Instant::now();
            let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
            let mut in_transfer = std::time::Duration::ZERO;
            let mut in_commit = std::time::Duration::ZERO;
            {
                let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(&mut state, evm_env.clone());
                for env in &envs {
                    let t = std::time::Instant::now();
                    let out = evm.transfer(env).unwrap().expect("a transfer");
                    in_transfer += t.elapsed();
                    let t = std::time::Instant::now();
                    evm.db_mut().commit(out.state);
                    in_commit += t.elapsed();
                }
            }
            let serial = at.elapsed();
            let at = std::time::Instant::now();
            state.merge_transitions(BundleRetention::PlainState);
            let bundle = state.take_bundle();
            let merge = at.elapsed();
            eprintln!("serial: transfer {in_transfer:?} commit {in_commit:?} merge {merge:?} ({} accounts)", bundle.state.len());
            let at = std::time::Instant::now();
            let run = execute_for_build(&evm_env, &envs, &|| Some(db.clone())).expect("a block of transfers");
            let groups = at.elapsed();
            let at = std::time::Instant::now();
            let mut state = State::builder().with_database(db.clone()).with_bundle_update().build();
            let graft = graft_bundles(&mut state, run.bundles, beneficiary).unwrap();
            let grafted = at.elapsed();
            let at = std::time::Instant::now();
            state.merge_transitions(BundleRetention::Reverts);
            let mut bundle = state.take_bundle();
            append_reverts(&mut bundle, graft.reverts);
            let merge = at.elapsed();
            eprintln!(
                "round {round}: serial {serial:?}; parallel {groups:?} (partition {} ms, {} groups in {} batches, exec {} ms, skipped {}) + graft {grafted:?} ({} accounts, {} committed) + merge {merge:?} ({} accounts, {} reverts)",
                run.phases.partition_ms, run.phases.groups, run.phases.batches, run.phases.groups_ms, run.skipped.len(), graft.accounts, graft.committed, bundle.state.len(), bundle.reverts[0].len()
            );
        }
    }

    #[test]
    fn a_transfer_to_the_beneficiary_falls_back() {
        let (mut block, db) = fixture(2, 1);
        // Point the first transfer at the beneficiary.
        let hash = block.hash();
        let mut raw = block.clone_sealed_block().into_block();
        if let n42_tx_types::N42TxEnvelope::Eth(TransactionSigned::Eip1559(signed)) = &mut raw.body.transactions[0] {
            let (mut tx, sig, _) = signed.clone().into_parts();
            tx.to = TxKind::Call(addr(1));
            *signed = Signed::new_unchecked(tx, sig, B256::random());
        }
        let senders = block.senders().to_vec();
        block = RecoveredBlock::new_unhashed(raw, senders);
        let _ = hash;
        let evm_config = crate::n42_evm::N42EvmConfig::new_with_evm_factory(MAINNET.clone(), N42EvmFactory::with_fast_transfers(true));
        let out = execute_transfers(&evm_config, &block, db.clone(), &|| Some(db.clone())).expect("no execution error");
        assert!(matches!(out, Err(NotParallel::TouchesBeneficiary(0))), "{out:?}");
    }
}
