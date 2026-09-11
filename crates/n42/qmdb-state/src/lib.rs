// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The QMDB state commitment: a block's state root, and the proofs cut from it.
//!
//! On a QMDB chain the block header's state root is **not** a Merkle-Patricia
//! root — it is the root of a QMDB twig forest. gov5 makes this swap by handing
//! its `IntraBlockState` a `QMDBRootComputer` in place of the trie one, so
//! `IntermediateRoot()` returns the forest root and that is what goes into the
//! header. A node that computes an MPT root produces headers a QMDB fleet
//! rejects, and cannot serve a state proof anyone can check, because both are
//! anchored to the same value.
//!
//! This crate is the Rust side of that computer: state changes in, root and
//! membership proofs out. It holds no reth types, for the same reason
//! [`n42_h2_execution`](https://docs.rs/n42-h2-execution) holds none — the
//! commitment scheme should not move when the execution client does.
//!
//! # The root depends on the order of writes, not just their contents
//!
//! QMDB is append-only: every `set` consumes a new slot, so the root is a
//! function of the *application order* as well as the final state. Two nodes
//! that end a block with byte-identical state but applied its writes in
//! different orders have different roots and have forked.
//!
//! gov5 handles this by collecting every operation for a block, sorting by key
//! hash, and applying in that order — Go map iteration is randomized, so
//! applying dirty maps directly would not even be reproducible on one machine.
//! [`QmdbState::apply_block`] does the same, and this is why it takes a whole
//! block's changes at once rather than offering a `set` for each.
//!
//! Two consequences worth stating plainly, both from gov5's own notes:
//!
//! - **A reorg cannot be handled by re-applying state.** Executing a competing
//!   block on top of an un-reverted tree appends at shifted slots and forks the
//!   root permanently, even if the resulting state is correct. The tree must be
//!   reverted first — see [`QmdbState::checkpoint`].
//! - **Replay must follow the same block sequence.** A node that syncs by
//!   applying the same blocks in the same order arrives at the same root; one
//!   that reconstructs state some other way does not.

use std::collections::{BTreeMap, BTreeSet};

pub mod alloc;
pub mod forest;

use alloy_primitives::{Address, B256, U256};
pub use alloc::changes_from_alloc;
pub use forest::{ForestCheckpoint, ForestDelta, ForestSnapshot, PreparedBlock, QmdbForest, StateProofProvider,
    DEFAULT_RETAIN_DEPTH,
};
use n42_twig_core::qmdb_compat::{
    encode_gov5_account_value, gov5_account_key, gov5_storage_key, QmdbCompatTree, QmdbOperation,
    QmdbOperationError, QmdbProof, GOV5_EMPTY_CODE_HASH,
};

/// An account as the state commitment sees it.
///
/// Deliberately not reth's `AccountInfo`: only these three fields reach the
/// leaf, and taking the execution client's type would tie the commitment to its
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    /// Transaction count.
    pub nonce: u64,
    /// Balance in wei.
    pub balance: U256,
    /// Keccak-256 of the account's code, or the empty-code hash.
    pub code_hash: B256,
}

impl AccountState {
    /// Whether gov5 would treat this account as absent and delete its leaf.
    ///
    /// gov5's test is `Nonce == 0 && Balance.IsZero() && !Initialised`, where
    /// `Initialised` marks an account its state machine has touched. There is no
    /// such flag on this side, so the stand-in is "no nonce, no balance, no
    /// code" — the EIP-161 empty account, which is exactly the set an execution
    /// client destroys anyway. An account that is empty by this test but which
    /// gov5 considers initialised would diverge; that requires a chain where
    /// something creates an account with no nonce, no balance and no code and
    /// expects it to persist, which post-EIP-161 execution does not do.
    pub fn is_empty(&self) -> bool {
        self.nonce == 0
            && self.balance.is_zero()
            && (self.code_hash == B256::ZERO || self.code_hash.0 == GOV5_EMPTY_CODE_HASH)
    }
}

/// One block's state changes, in the form the commitment consumes.
///
/// Ordered maps, not hash maps: the iteration order feeds a root that depends on
/// application order, and while [`QmdbState::apply_block`] sorts before applying,
/// a structure that cannot be iterated twice the same way is a hazard to leave
/// lying around in this crate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockChanges {
    /// Accounts touched this block. `None` deletes. An [`AccountState::is_empty`]
    /// account deletes too unless it is in `initialised`, matching gov5's
    /// `isAccountEmpty`: nonce 0, balance 0, and *not initialised*.
    pub accounts: BTreeMap<Address, Option<AccountState>>,
    /// Accounts gov5 would hold as state objects. Every state object Erigon
    /// loads or creates is `Initialised`, so an execution client's touched
    /// account is a live leaf even when it is empty — the system caller of a
    /// Prague block being the everyday case. Genesis alloc entries are not
    /// marked; the root of an alloc is verified against gov5 as is.
    pub initialised: BTreeSet<Address>,
    /// Storage slots touched this block. A zero value deletes the slot.
    pub storage: BTreeMap<Address, BTreeMap<B256, U256>>,
}

impl BlockChanges {
    /// An empty change set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an account's post-block state.
    pub fn set_account(&mut self, address: Address, account: AccountState) -> &mut Self {
        self.accounts.insert(address, Some(account));
        self
    }

    /// Records an account's post-block state as gov5 records a state object:
    /// live even when empty. See `initialised`.
    pub fn set_account_initialised(&mut self, address: Address, account: AccountState) -> &mut Self {
        self.accounts.insert(address, Some(account));
        self.initialised.insert(address);
        self
    }

    /// Records that an account was destroyed.
    pub fn delete_account(&mut self, address: Address) -> &mut Self {
        self.accounts.insert(address, None);
        self
    }

    /// Records a storage slot's post-block value. Zero deletes the slot.
    pub fn set_storage(&mut self, address: Address, slot: B256, value: U256) -> &mut Self {
        self.storage.entry(address).or_default().insert(slot, value);
        self
    }

    /// What was recorded for an account: `None` if untouched, `Some(None)` if
    /// deleted, `Some(Some(state))` if written.
    pub fn account(&self, address: &Address) -> Option<Option<&AccountState>> {
        self.accounts.get(address).map(Option::as_ref)
    }

    /// How many leaf operations this produces.
    pub fn len(&self) -> usize {
        self.accounts.len() + self.storage.values().map(BTreeMap::len).sum::<usize>()
    }

    /// Whether the block touched no state.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The leaf operations, in gov5's encoding and unsorted.
    ///
    /// Public because it is the exact point where this side and gov5 have to
    /// agree byte for byte, and a caller comparing the two wants the operations
    /// rather than only the root they produce.
    pub fn operations(&self) -> Vec<QmdbOperation> {
        let mut operations = Vec::with_capacity(self.len());
        for (address, account) in &self.accounts {
            let key = gov5_account_key(&address.0 .0);
            let live = self.initialised.contains(address);
            let value = account.filter(|state| live || !state.is_empty()).map(|state| {
                encode_gov5_account_value(
                    state.nonce,
                    &state.balance.to_be_bytes::<32>(),
                    &state.code_hash.0,
                )
            });
            operations.push(QmdbOperation { key, value });
        }
        for (address, slots) in &self.storage {
            for (slot, value) in slots {
                operations.push(QmdbOperation {
                    key: gov5_storage_key(&address.0 .0, &slot.0),
                    // A zero slot is a deletion, not a leaf holding zero: gov5
                    // writes 32 big-endian bytes for a non-zero value and
                    // deletes otherwise, and a leaf of 32 zero bytes is a
                    // different tree.
                    value: (!value.is_zero()).then(|| value.to_be_bytes::<32>().to_vec()),
                });
            }
        }
        operations
    }
}

/// Why a block could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// The entry file could not be created, written, read or reopened.
    #[error("QMDB entry file: {0}")]
    EntryFile(String),
    /// Two operations named the same leaf. Applying either would leave the tree
    /// in a state that depends on which one won, so neither is applied.
    #[error("state change produced a duplicate leaf key: {0}")]
    Duplicate(#[from] QmdbOperationError),
    /// A checkpoint was rolled back to that this tree does not hold.
    #[error("no checkpoint at block {0}")]
    UnknownCheckpoint(u64),
    /// A block was built on a parent whose tree is not held — either never
    /// validated here, or already outside the retention window. Its root
    /// cannot be computed, because the root depends on the parent's append
    /// history and not only on its state.
    #[error("no QMDB tree for parent block {0}")]
    UnknownParent(B256),
    /// A block was named that no tree is held for.
    #[error("no QMDB tree for block {0}")]
    UnknownBlock(B256),
    /// A snapshot was written by a different layout of this crate.
    #[error("QMDB snapshot layout {found} is not the {expected} this build reads")]
    SnapshotVersion {
        /// The version in the snapshot.
        found: u32,
        /// The version this build writes.
        expected: u32,
    },
    /// A snapshot did not decode into a tree.
    #[error("QMDB snapshot: {0}")]
    Snapshot(String),
    /// An undo record could not be applied — the tree and the record do not
    /// belong to the same history.
    #[error("QMDB undo: {0}")]
    Undo(String),
    /// Two held blocks share no ancestor within the retained window, so the
    /// tree cannot be walked from one to the other.
    #[error("no held ancestor connects block {from} to block {to}")]
    Unreachable {
        /// Where the tree stands.
        from: B256,
        /// Where it was asked to go.
        to: B256,
    },
    /// A block on the tree's current path has no undo record — the forest's
    /// bookkeeping is inconsistent, which is a bug, not an input problem.
    #[error("block {0} is on the applied path but holds no undo record")]
    NotApplied(B256),
    /// Re-applying a held block produced a different root than it had the
    /// first time. Re-application is deterministic; this means the tree it
    /// was re-applied to is not the tree it was first applied to.
    #[error("re-applying block {block} gave root {got}, expected {expected}")]
    Replay {
        /// The block.
        block: B256,
        /// Its recorded root.
        expected: B256,
        /// What re-application produced.
        got: B256,
    },
    /// A delta was taken against, or applied to, a different append cursor than
    /// the one it describes. A QMDB root depends on the append history, so a
    /// delta applied to the wrong base does not produce a merely stale tree —
    /// it produces one that never existed.
    #[error("QMDB delta expected append cursor {expected}, found {found}")]
    DeltaBase {
        /// The cursor that was required.
        expected: u64,
        /// The cursor that was offered.
        found: u64,
    },
    /// A delta named a slot the tree does not have.
    #[error("QMDB delta names slot {0}, which the tree does not hold")]
    DeltaSlot(u64),
}

/// A point the tree can be rolled back to.
///
/// A QMDB root depends on the order writes were appended in, so a competing
/// block at the same height has to be executed against the tree as it was — not
/// against the tree with the loser's writes still in it. This is what makes that
/// possible.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// The block this tree stood at.
    pub block_number: u64,
    /// Its root.
    pub root: B256,
    tree: QmdbCompatTree,
}

/// The QMDB state commitment.
#[derive(Debug)]
pub struct QmdbState {
    tree: QmdbCompatTree,
    block_number: u64,
    /// Recent trees, newest last, for reverting a reorg.
    checkpoints: Vec<Checkpoint>,
    max_checkpoints: usize,
}

impl Default for QmdbState {
    fn default() -> Self {
        Self::new()
    }
}

impl QmdbState {
    /// An empty state at block zero.
    pub fn new() -> Self {
        Self {
            tree: QmdbCompatTree::new(),
            block_number: 0,
            checkpoints: Vec::new(),
            // Deep enough for the reorgs a BFT chain actually produces — a
            // committed block never reverts, so this only covers same-height
            // sibling switches and the unfinalised tip.
            max_checkpoints: 64,
        }
    }

    /// Sets how many blocks can be rolled back. Zero disables checkpointing.
    pub fn with_checkpoint_depth(mut self, depth: usize) -> Self {
        self.max_checkpoints = depth;
        self.checkpoints.truncate(depth);
        self
    }

    /// The current state root — the value that belongs in a block header.
    pub fn root(&self) -> B256 {
        B256::from(self.tree.root())
    }

    /// The block this state stands at.
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    /// The number of leaves the tree holds.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Applies one block's changes and returns the new root.
    ///
    /// Takes the whole block at once because the root depends on application
    /// order: the operations are sorted by key hash before any of them touches
    /// the tree, which is what makes two nodes replaying the same block agree.
    pub fn apply_block(
        &mut self,
        block_number: u64,
        changes: &BlockChanges,
    ) -> Result<B256, StateError> {
        self.take_checkpoint();
        let root = self.tree.apply_sorted_ops(changes.operations())?;
        self.block_number = block_number;
        Ok(B256::from(root))
    }

    /// Proves that `address` holds the account state this tree commits to.
    ///
    /// `None` means the account has no live leaf — it was never written, or was
    /// deleted. That is not the same as a proof of absence, which QMDB's
    /// membership proofs do not provide.
    pub fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.tree.prove(&gov5_account_key(&address.0 .0))
    }

    /// Proves the value of one storage slot.
    pub fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.tree.prove(&gov5_storage_key(&address.0 .0, &slot.0))
    }

    /// The raw leaf an account key commits to, in gov5's encoding.
    pub fn account_leaf(&self, address: Address) -> Option<&[u8]> {
        self.tree.get(&gov5_account_key(&address.0 .0))
    }

    /// The raw leaf a storage key commits to.
    pub fn storage_leaf(&self, address: Address, slot: B256) -> Option<&[u8]> {
        self.tree.get(&gov5_storage_key(&address.0 .0, &slot.0))
    }

    /// The most recent checkpoint, if any.
    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    /// Rolls the tree back to how it stood at the end of `block_number`.
    ///
    /// Required before executing a competing block at the same height. Executing
    /// it on top of the un-reverted tree appends at shifted slots and produces a
    /// root that no node which only ever applied the winner will agree with —
    /// permanently, since the divergence is in the tree's physical layout rather
    /// than its contents.
    pub fn revert_to(&mut self, block_number: u64) -> Result<B256, StateError> {
        let index = self
            .checkpoints
            .iter()
            .rposition(|checkpoint| checkpoint.block_number == block_number)
            .ok_or(StateError::UnknownCheckpoint(block_number))?;
        let checkpoint = self.checkpoints.remove(index);
        self.checkpoints.truncate(index);
        self.tree = checkpoint.tree;
        self.block_number = checkpoint.block_number;
        Ok(checkpoint.root)
    }

    fn take_checkpoint(&mut self) {
        if self.max_checkpoints == 0 {
            return;
        }
        self.checkpoints.push(Checkpoint {
            block_number: self.block_number,
            root: self.root(),
            tree: self.tree.clone(),
        });
        if self.checkpoints.len() > self.max_checkpoints {
            self.checkpoints.remove(0);
        }
    }
}
