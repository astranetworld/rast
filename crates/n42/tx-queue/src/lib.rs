// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A transaction source for the block builder that lives beside reth's pool
//! rather than inside it.
//!
//! reth's pool was measured, on a leader that builds every view at 163,000
//! transactions a block, to cost about half a second per block: 116-220 ms
//! to select from its ordered sets and ~300 ms to remove the block's
//! transactions one at a time under its write lock -- the lock the ingest
//! needs to admit anything. The pool is right for a mainnet node and wrong
//! for that.
//!
//! This queue takes the same transactions the binary ingest has already
//! validated and recovered, keeps them per sender in nonce order, and hands
//! them to the builder in the order the senders' first transactions arrived,
//! one per sender per pass, so no sender starves another. Selection is a
//! walk; taking is a pop. reth's pool still receives everything for RPC and
//! gossip, off the builder's path.
//!
//! What goes out for a build is remembered until the next build. A build on
//! the same parent again means the previous block was not committed, and its
//! transactions go back to the front; a build on a new parent means it was,
//! and they are dropped. Canonical blocks prune the queue on every node by
//! (sender, nonce), so a follower that becomes leader does not offer what the
//! chain already holds.
//!
//! Enabled by `N42_TX_QUEUE=1`. The queue is fed from the pool's
//! new-transaction listener, so a transaction that came in by the ingest,
//! by RPC or by gossip is offered alike; the builder finds the queue through
//! [`global`].

use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, OnceLock};

use alloy_primitives::{map::{AddressHashMap, AddressHashSet}, Address, B256};
use parking_lot::Mutex;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
    identifier::{SenderId, TransactionId},
    BestTransactions, PoolTransaction, TransactionOrigin, ValidPoolTransaction,
};

/// One sender's queued transactions, nonce-ordered.
struct Lane<T: PoolTransaction> {
    by_nonce: BTreeMap<u64, Arc<ValidPoolTransaction<T>>>,
    /// Whether the sender is in the arrival order right now.
    queued: bool,
    id: SenderId,
}

struct Inner<T: PoolTransaction> {
    // Keyed by address with alloy's fixed-bytes hasher: the builder looks a
    // lane up per transaction, and std's SipHash was 3% of its thread.
    lanes: AddressHashMap<Lane<T>>,
    /// Senders with queued transactions, in the order their queued run began;
    /// a sender taken from the front goes to the back if it has more.
    arrivals: VecDeque<Address>,
    next_sender_id: u64,
    len: usize,
    /// What the last build took, and the parent it built on.
    last_build: Option<(B256, Vec<Arc<ValidPoolTransaction<T>>>)>,
    /// Holes a build ran into: (sender, the account's next nonce, the lowest
    /// queued nonce above it). The feed fills them from the pool.
    gaps: Vec<(Address, u64, u64)>,
    /// The sender a build is taking a run from, and how much of the run is
    /// left. See [`run_length`].
    current: Option<(Address, usize)>,
}

/// How many consecutive nonces a build takes from one sender before moving
/// to the next: `N42_TX_QUEUE_RUN`, 1 by default (strict rotation).
///
/// A block drawn from a deep queue by strict rotation alternates among
/// every queued sender -- 6,000 of them at the bench tier -- so each
/// transaction touches two cold accounts; a block drawn from a shallow queue
/// alternates among the few dozen senders that have arrived, and the same
/// follower imports it at half the cost per transaction (round gcA1/gcB:
/// 2.1-2.3 us/tx for partial blocks, 4.0 for full ones of any size). Runs
/// keep a sender's account hot across its consecutive transactions.
fn run_length() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("N42_TX_QUEUE_RUN").ok().and_then(|v| v.parse().ok()).filter(|n: &usize| *n > 0).unwrap_or(1)
    })
}

/// A transaction handed in but not yet in its lane.
enum Staged<T: PoolTransaction> {
    Raw(T, std::time::Instant),
    Valid(Arc<ValidPoolTransaction<T>>),
}

/// The queue. Cheap to clone; every clone is the same queue.
///
/// Pushes go to an inbox under their own lock, held for a `Vec` push; the
/// lanes' lock is taken only by the builder, the pruner and the feed's
/// drain. Sixty-four ingest connections pushing straight into the lanes
/// while a build took the lock 163,000 times and a prune held it for tens
/// of milliseconds put every node's runtime threads into a spin (round
/// prof3: 72% of a follower's samples on one kernel address).
pub struct TxQueue<T: PoolTransaction> {
    inner: Arc<Mutex<Inner<T>>>,
    inbox: Arc<Mutex<Vec<Staged<T>>>>,
    staged: Arc<std::sync::atomic::AtomicUsize>,
}

impl<T: PoolTransaction> Clone for TxQueue<T> {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner), inbox: Arc::clone(&self.inbox), staged: Arc::clone(&self.staged) }
    }
}

impl<T: PoolTransaction> std::fmt::Debug for TxQueue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxQueue").field("len", &self.len()).finish()
    }
}

impl<T: PoolTransaction> Default for TxQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: PoolTransaction> TxQueue<T> {
    /// An empty queue.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                lanes: AddressHashMap::default(),
                arrivals: VecDeque::new(),
                next_sender_id: 1,
                len: 0,
                last_build: None,
                gaps: Vec::new(),
                current: None,
            })),
            inbox: Arc::new(Mutex::new(Vec::new())),
            staged: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Moves what was pushed since the last drain into the lanes. Called
    /// with the lanes' lock held; a no-op when nothing was pushed.
    fn drain_inbox(&self, inner: &mut Inner<T>) {
        use std::sync::atomic::Ordering;
        if self.staged.load(Ordering::Acquire) == 0 {
            return;
        }
        let staged = std::mem::take(&mut *self.inbox.lock());
        self.staged.fetch_sub(staged.len(), Ordering::AcqRel);
        for item in staged {
            match item {
                Staged::Raw(transaction, at) => inner.insert(transaction, at, TransactionOrigin::External),
                Staged::Valid(valid) => inner.insert_valid(valid),
            }
        }
    }

    /// The holes builds ran into since the last call: (sender, first missing
    /// nonce, first queued nonce above the hole). A hole is a transaction the
    /// queue never saw -- the pool's listener drops on a full channel -- or
    /// one still on its way in; the feed looks the pool up for it.
    pub fn take_gaps(&self) -> Vec<(Address, u64, u64)> {
        std::mem::take(&mut self.inner.lock().gaps)
    }

    /// How many transactions are queued.
    pub fn len(&self) -> usize {
        self.inner.lock().len + self.staged.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queues validated, recovered transactions. A (sender, nonce) already
    /// queued keeps its first arrival.
    pub fn push(&self, transactions: impl IntoIterator<Item = T>) {
        let now = std::time::Instant::now();
        let staged: Vec<Staged<T>> = transactions.into_iter().map(|t| Staged::Raw(t, now)).collect();
        let count = staged.len();
        self.inbox.lock().extend(staged);
        self.staged.fetch_add(count, std::sync::atomic::Ordering::AcqRel);
    }

    /// Queues transactions the pool has already validated, as the pool holds
    /// them. What the pool's new-transaction listener yields; the queue is a
    /// view of the pool's arrivals, whichever door they came in by.
    pub fn push_valid(&self, transactions: impl IntoIterator<Item = Arc<ValidPoolTransaction<T>>>) {
        let staged: Vec<Staged<T>> = transactions.into_iter().map(Staged::Valid).collect();
        let count = staged.len();
        self.inbox.lock().extend(staged);
        self.staged.fetch_add(count, std::sync::atomic::Ordering::AcqRel);
    }

    /// Drops everything at or below `nonce` for `sender`: a block carrying
    /// (sender, nonce) has made every lower nonce unusable as well.
    pub fn remove_mined(&self, sender: Address, nonce: u64) {
        let mut inner = self.inner.lock();
        self.drain_inbox(&mut inner);
        inner.remove_mined(sender, nonce);
    }

    /// Drops a batch of mined (sender, nonce) pairs.
    pub fn remove_mined_batch(&self, mined: impl IntoIterator<Item = (Address, u64)>) {
        let mut inner = self.inner.lock();
        self.drain_inbox(&mut inner);
        // Folded to the highest nonce per sender first: a lane is split once
        // per sender, not once per transaction. Splitting per transaction
        // was 163,000 tree splits and as many allocations a block, 54-128 ms
        // under the lock the next build's puller is waiting on.
        let mut highest: AddressHashMap<u64> = AddressHashMap::default();
        for (sender, nonce) in mined {
            let entry = highest.entry(sender).or_insert(nonce);
            *entry = (*entry).max(nonce);
        }
        for (sender, nonce) in &highest {
            inner.remove_mined(*sender, *nonce);
        }
        // What a build has taken is not in the lanes, so the removal above
        // misses it; when the build is superseded its transactions are
        // offered again, and a mined one offered again is a stale
        // transaction the builder pays to refuse (42,000 a build in round
        // 38). Forget the mined ones here.
        if let Some((_, taken)) = inner.last_build.as_mut() {
            if !taken.is_empty() {
                taken.retain(|t| highest.get(&t.sender()).is_none_or(|mined| t.nonce() > *mined));
            }
        }
    }

    /// Moves what the inbox holds into the lanes now. The builder does this
    /// on its own pulls otherwise, and at the bench tier that is ~0.7 us a
    /// transaction of a full block's build (118 ms of 440, round 38) spent
    /// inserting arrivals rather than building; a task calling this every
    /// few milliseconds (`N42_TX_QUEUE_DRAINER=1`) takes it off the builder.
    pub fn drain_now(&self) {
        use std::sync::atomic::Ordering;
        if self.staged.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut inner = self.inner.lock();
        self.drain_inbox(&mut inner);
    }

    /// The transactions for a build on `parent`, as the pool's iterator would
    /// hand them. Taking returns what the previous build on the same parent
    /// took, first.
    pub fn best_for_build(&self, parent: B256) -> QueueBest<T> {
        {
            let mut inner = self.inner.lock();
            self.drain_inbox(&mut inner);
            match inner.last_build.take() {
                Some((previous, taken)) if previous == parent => {
                    let count = taken.len();
                    inner.give_back(taken);
                    tracing::info!(target: "n42.tx_queue", count, "previous build on the same parent was not committed; its transactions are offered again");
                }
                // A build on another parent -- a build ahead superseded by the
                // next block -- took transactions the queue must not lose: they
                // go back too, and the canonical pruner removes the ones the
                // chain has meanwhile mined. Dropping them here starved the
                // builder while the pool sat at its gate (round 38).
                Some((previous, taken)) if !taken.is_empty() => {
                    let count = taken.len();
                    inner.give_back(taken);
                    tracing::debug!(target: "n42.tx_queue", count, ?previous, ?parent, "a build on another parent was superseded; its transactions are offered again");
                }
                _ => {}
            }
            inner.last_build = Some((parent, Vec::new()));
            inner.current = None;
        }
        QueueBest { queue: self.clone(), skipped: AddressHashSet::default(), buffer: VecDeque::new(), batch: queue_batch() }
    }
}

impl<T: PoolTransaction> Inner<T> {
    fn insert(&mut self, transaction: T, now: std::time::Instant, origin: TransactionOrigin) {
        let sender = transaction.sender();
        let nonce = transaction.nonce();
        let next_id = &mut self.next_sender_id;
        let lane = self.lanes.entry(sender).or_insert_with(|| {
            let id = SenderId::from(*next_id);
            *next_id += 1;
            Lane { by_nonce: BTreeMap::new(), queued: false, id }
        });
        if lane.by_nonce.contains_key(&nonce) {
            return;
        }
        let valid = Arc::new(ValidPoolTransaction {
            transaction,
            transaction_id: TransactionId::new(lane.id, nonce),
            propagate: false,
            timestamp: now,
            origin,
            authority_ids: None,
        });
        lane.by_nonce.insert(nonce, valid);
        self.len += 1;
        if !lane.queued {
            lane.queued = true;
            self.arrivals.push_back(sender);
        }
    }

    fn insert_valid(&mut self, valid: Arc<ValidPoolTransaction<T>>) {
        let sender = valid.sender();
        let nonce = valid.nonce();
        let next_id = &mut self.next_sender_id;
        let lane = self.lanes.entry(sender).or_insert_with(|| {
            let id = SenderId::from(*next_id);
            *next_id += 1;
            Lane { by_nonce: BTreeMap::new(), queued: false, id }
        });
        if lane.by_nonce.contains_key(&nonce) {
            return;
        }
        lane.by_nonce.insert(nonce, valid);
        self.len += 1;
        if !lane.queued {
            lane.queued = true;
            self.arrivals.push_back(sender);
        }
    }

    /// Puts transactions a build took back at their nonces; their senders go
    /// to the front so they are offered before anything newer.
    fn give_back(&mut self, taken: Vec<Arc<ValidPoolTransaction<T>>>) {
        let mut senders: Vec<Address> = Vec::new();
        for valid in taken {
            let sender = valid.sender();
            let nonce = valid.nonce();
            let Some(lane) = self.lanes.get_mut(&sender) else { continue };
            if lane.by_nonce.insert(nonce, valid).is_none() {
                self.len += 1;
            }
            if !lane.queued {
                lane.queued = true;
                senders.push(sender);
            }
        }
        for sender in senders.into_iter().rev() {
            self.arrivals.push_front(sender);
        }
    }

    fn remove_mined(&mut self, sender: Address, nonce: u64) {
        let Some(lane) = self.lanes.get_mut(&sender) else { return };
        let keep = lane.by_nonce.split_off(&(nonce + 1));
        self.len -= lane.by_nonce.len();
        lane.by_nonce = keep;
        // A now-empty lane leaves the arrival order when its turn comes.
    }

    /// The next transaction: the lowest nonce of the sender at the front of
    /// the arrival order, skipping senders the build marked.
    fn next_ready(&mut self, skipped: &AddressHashSet) -> Option<Arc<ValidPoolTransaction<T>>> {
        // Continue the current sender's run first.
        if let Some((sender, left)) = self.current.take() {
            if left > 0 && !skipped.contains(&sender) {
                if let Some(lane) = self.lanes.get_mut(&sender) {
                    if let Some((_, valid)) = lane.by_nonce.pop_first() {
                        self.len -= 1;
                        if lane.by_nonce.is_empty() {
                            lane.queued = false;
                        } else if left > 1 {
                            self.current = Some((sender, left - 1));
                        } else {
                            self.arrivals.push_back(sender);
                        }
                        if let Some((_, taken)) = self.last_build.as_mut() {
                            taken.push(Arc::clone(&valid));
                        }
                        return Some(valid);
                    }
                }
            }
            // The run ended, was refused, or the lane emptied: the sender
            // rejoins the rotation if it still has anything.
            if let Some(lane) = self.lanes.get_mut(&sender) {
                if lane.by_nonce.is_empty() {
                    lane.queued = false;
                } else {
                    self.arrivals.push_back(sender);
                }
            }
        }
        let run = run_length();
        let mut passes = self.arrivals.len();
        while passes > 0 {
            passes -= 1;
            let sender = self.arrivals.pop_front()?;
            let Some(lane) = self.lanes.get_mut(&sender) else { continue };
            if lane.by_nonce.is_empty() {
                lane.queued = false;
                continue;
            }
            if skipped.contains(&sender) {
                self.arrivals.push_back(sender);
                continue;
            }
            let (_, valid) = lane.by_nonce.pop_first()?;
            self.len -= 1;
            if lane.by_nonce.is_empty() {
                lane.queued = false;
            } else if run > 1 {
                self.current = Some((sender, run - 1));
            } else {
                self.arrivals.push_back(sender);
            }
            if let Some((_, taken)) = self.last_build.as_mut() {
                taken.push(Arc::clone(&valid));
            }
            return Some(valid);
        }
        None
    }
}

/// The builder's iterator over the queue. Implements reth's
/// [`BestTransactions`], so the payload builder takes it in place of the
/// pool's.
pub struct QueueBest<T: PoolTransaction> {
    queue: TxQueue<T>,
    skipped: AddressHashSet,
    /// Transactions taken under one lock and not yet handed to the builder.
    /// `N42_TX_QUEUE_BATCH=<n>` sets how many are taken at a time; 1 (the
    /// default) locks once per transaction, which at the bench tier was
    /// ~100 ms of a full block's build, 0.6 us a transaction, in the lock
    /// and the inbox drain alone.
    buffer: VecDeque<Arc<ValidPoolTransaction<T>>>,
    batch: usize,
}

/// `N42_TX_QUEUE_BATCH`, read once.
fn queue_batch() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| std::env::var("N42_TX_QUEUE_BATCH").ok().and_then(|v| v.parse().ok()).filter(|n| *n >= 1).unwrap_or(1))
}

impl<T: PoolTransaction> QueueBest<T> {
    /// Returns a transaction taken but not built to the queue, and forgets
    /// that the build took it. The taken list ends with the buffered ones,
    /// so the search from the back is short.
    fn untake(inner: &mut Inner<T>, transaction: Arc<ValidPoolTransaction<T>>) {
        if let Some((_, taken)) = inner.last_build.as_mut() {
            if let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, &transaction)) {
                taken.remove(at);
            }
        }
        inner.give_back(vec![transaction]);
    }
}

impl<T: PoolTransaction> Drop for QueueBest<T> {
    fn drop(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let mut inner = self.queue.inner.lock();
        for transaction in self.buffer.drain(..) {
            Self::untake(&mut inner, transaction);
        }
    }
}

impl<T: PoolTransaction> std::fmt::Debug for QueueBest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueBest").field("skipped", &self.skipped.len()).finish()
    }
}

impl<T: PoolTransaction> Iterator for QueueBest<T> {
    type Item = Arc<ValidPoolTransaction<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(transaction) = self.buffer.pop_front() {
                // A sender the build refused meanwhile: its buffered
                // transactions go back rather than to the builder.
                if self.skipped.contains(&transaction.sender()) {
                    let mut inner = self.queue.inner.lock();
                    Self::untake(&mut inner, transaction);
                    continue;
                }
                return Some(transaction);
            }
            let mut inner = self.queue.inner.lock();
            self.queue.drain_inbox(&mut inner);
            if self.batch <= 1 {
                return inner.next_ready(&self.skipped);
            }
            for _ in 0..self.batch {
                match inner.next_ready(&self.skipped) {
                    Some(transaction) => self.buffer.push_back(transaction),
                    None => break,
                }
            }
            if self.buffer.is_empty() {
                return None;
            }
        }
    }
}

impl<T: PoolTransaction> BestTransactions for QueueBest<T> {
    /// The build refused this transaction: it goes back where it was and the
    /// sender's later nonces are not offered again in this build. A stale
    /// one (nonce below the account's) is dropped instead.
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let sender = transaction.sender();
        self.skipped.insert(sender);
        let stale = matches!(&kind, InvalidPoolTransactionError::Consensus(err) if err.is_nonce_too_low());
        if stale {
            return;
        }
        let mut inner = self.queue.inner.lock();
        if let Some((_, taken)) = inner.last_build.as_mut() {
            // The refused transaction is the one just yielded or one of the
            // few buffered after it: found from the back. A scan of
            // everything the build took (165,000 at the bench tier, once
            // per refused sender) was most of a full block's loop tail.
            if let Some(at) = taken.iter().rposition(|t| Arc::ptr_eq(t, transaction)) {
                taken.remove(at);
            }
        }
        if let InvalidPoolTransactionError::Consensus(InvalidTransactionError::NonceNotConsistent {
            tx,
            state,
        }) = &kind
        {
            if tx > state {
                inner.gaps.push((sender, *state, *tx));
            }
        }
        inner.give_back(vec![Arc::clone(transaction)]);
    }

    fn no_updates(&mut self) {}

    fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
}

static GLOBAL: OnceLock<Option<Box<dyn Any + Send + Sync>>> = OnceLock::new();

/// Installs the fleet-wide queue for `T`, once. Returns whether this call
/// installed it.
pub fn install<T: PoolTransaction + 'static>(queue: TxQueue<T>) -> bool {
    GLOBAL.set(Some(Box::new(queue))).is_ok()
}

/// The installed queue for `T`, if one was installed with that type.
pub fn global<T: PoolTransaction + 'static>() -> Option<TxQueue<T>> {
    GLOBAL.get()?.as_ref()?.downcast_ref::<TxQueue<T>>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Signature, TxKind, U256};
    use reth_transaction_pool::EthPooledTransaction;

    fn tx(sender_seed: u8, nonce: u64) -> EthPooledTransaction {
        use alloy_consensus::{Signed, TxEip1559};
        let inner = TxEip1559 { chain_id: 1, nonce, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(9)), value: U256::from(1), ..Default::default() };
        let signed = Signed::new_unchecked(inner, Signature::test_signature(), Default::default());
        let recovered = reth_primitives_traits::Recovered::new_unchecked(reth_ethereum_primitives::TransactionSigned::from(signed), Address::repeat_byte(sender_seed));
        EthPooledTransaction::new(recovered, 120)
    }

    fn tx_of(sender: Address, nonce: u64) -> EthPooledTransaction {
        use alloy_consensus::{Signed, TxEip1559};
        let inner = TxEip1559 { chain_id: 1, nonce, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(9)), value: U256::from(1), ..Default::default() };
        let signed = Signed::new_unchecked(inner, Signature::test_signature(), Default::default());
        let recovered = reth_primitives_traits::Recovered::new_unchecked(reth_ethereum_primitives::TransactionSigned::from(signed), sender);
        EthPooledTransaction::new(recovered, 120)
    }

    /// The queue's own cost per transaction at the bench tier's shape
    /// (6,000 senders, 30 transactions each), apart from everything the
    /// builder does around it. `cargo test -p n42-tx-queue --release -- --ignored bench_ --nocapture`.
    #[test]
    #[ignore]
    fn bench_next_at_the_bench_tier() {
        let senders = 6_000u64;
        let per = 30u64;
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        let mut all = Vec::with_capacity((senders * per) as usize);
        for n in 0..per {
            for s in 0..senders {
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&(s + 1).to_be_bytes());
                all.push(tx_of(Address::from(a), n));
            }
        }
        let pushed_at = std::time::Instant::now();
        queue.push(all);
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        assert!(best.next().is_some());
        let pushed = pushed_at.elapsed();
        drop(best);
        for round in 0..3 {
            let mut best = queue.best_for_build(B256::repeat_byte(2 + round));
            let at = std::time::Instant::now();
            let mut n = 0u64;
            while let Some(t) = best.next() {
                n += 1;
                std::hint::black_box(&t);
                if n == 163_000 { break; }
            }
            let took = at.elapsed();
            eprintln!("round {round}: {n} next() in {:?} = {:.0} ns/tx (push+drain {:?})", took, took.as_nanos() as f64 / n as f64, pushed);
            drop(best);
        }
        // The canonical prune of a full block whose transactions a build took.
        let mut best = queue.best_for_build(B256::repeat_byte(9));
        let mined: Vec<(Address, u64)> = std::iter::from_fn(|| best.next()).take(163_000).map(|t| (t.sender(), t.nonce())).collect();
        drop(best);
        let at = std::time::Instant::now();
        queue.remove_mined_batch(mined);
        eprintln!("remove_mined_batch of 163,000 taken: {:?}", at.elapsed());
    }

    #[test]
    fn senders_take_turns_in_nonce_order_and_a_failed_build_is_offered_again() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(2, 0), tx(1, 2), tx(3, 5)]);
        assert_eq!(queue.len(), 5);
        let parent = B256::repeat_byte(7);
        let mut best = queue.best_for_build(parent);
        let order: Vec<(u8, u64)> = std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        assert_eq!(order, vec![(1, 0), (2, 0), (3, 5), (1, 1), (1, 2)]);
        assert!(queue.is_empty());
        // Same parent again: everything comes back, same order.
        let mut best = queue.best_for_build(parent);
        let again: Vec<(u8, u64)> = std::iter::from_fn(|| best.next()).map(|t| (t.sender().as_slice()[0], t.nonce())).collect();
        assert_eq!(again.len(), 5);
        assert_eq!(again[0], (1, 0));
        // A new parent before the chain pruned anything: the previous build
        // may have been superseded, so what it took is offered again.
        let mut best = queue.best_for_build(B256::repeat_byte(8));
        assert_eq!(best.next().map(|t| t.nonce()), Some(0));
        drop(best);
        // The chain mined the lot: pruned from the lanes and from the build's
        // taken list alike, so a build on yet another parent gets nothing.
        queue.remove_mined_batch([
            (Address::repeat_byte(1), 2),
            (Address::repeat_byte(2), 0),
            (Address::repeat_byte(3), 5),
        ]);
        let mut best = queue.best_for_build(B256::repeat_byte(9));
        assert!(best.next().is_none());
    }

    #[test]
    fn mined_nonces_and_refused_transactions_are_handled() {
        let queue: TxQueue<EthPooledTransaction> = TxQueue::new();
        queue.push([tx(1, 0), tx(1, 1), tx(1, 2), tx(2, 4)]);
        queue.remove_mined(Address::repeat_byte(1), 1);
        assert_eq!(queue.len(), 2);
        let mut best = queue.best_for_build(B256::ZERO);
        let first = best.next().unwrap();
        assert_eq!((first.sender(), first.nonce()), (Address::repeat_byte(1), 2));
        let second = best.next().unwrap();
        assert_eq!(second.nonce(), 4);
        // Refused for a gap: back in the queue, sender skipped for this build.
        best.mark_invalid(&second, InvalidPoolTransactionError::Underpriced);
        assert!(best.next().is_none());
        assert_eq!(queue.len(), 1);
        drop(best);
        // The chain mined sender 1's nonce 2 (taken by the build above): a
        // build on the next block gets only the refused one back.
        queue.remove_mined_batch([(Address::repeat_byte(1), 2)]);
        let mut best = queue.best_for_build(B256::repeat_byte(1));
        assert_eq!(best.next().unwrap().nonce(), 4);
        assert!(best.next().is_none());
    }
}
