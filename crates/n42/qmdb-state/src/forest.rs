// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The QMDB tree a node holds while blocks are still contested.
//!
//! [`super::QmdbState`] is one tree with a linear history — right for a chain
//! whose blocks arrive already decided. An execution client's engine tree is
//! not that: it validates blocks *before* consensus settles them, and two
//! proposals for the same height can both be valid at once. Each has to be
//! committed against the tree as it stood after their common parent.
//!
//! One tree, moved with undo records. A QMDB root is a function of the
//! append history, not just the state, so a second proposal cannot be
//! computed on top of the first: the first has to be rolled back. This is
//! gov5's design (`RevertBlock` + re-execute): every applied block keeps its
//! operations and the undo record that reverts it, and moving the tree to any
//! held block is a walk — revert up to the common ancestor, re-apply down.
//! Re-applying is deterministic, so a re-applied block lands on the same slots
//! and the same root it had the first time; the forest checks that it did.
//!
//! The window of held blocks is bounded, so it stays a window.

use std::collections::{BTreeSet, HashMap};

use alloy_primitives::{Address, B256};
use n42_twig_core::qmdb_compat::{
    gov5_account_key, gov5_storage_key, BlockUndo, QmdbCompatTree, QmdbEntrySnapshot,
    QmdbOperation, QmdbProof, QmdbSnapshot,
};
use serde::{Deserialize, Serialize};

use crate::{BlockChanges, StateError};

/// How many blocks behind the canonical head a block is kept.
///
/// A committed HotStuff-2 block never reverts, so this only has to cover the
/// unfinalised tip plus sibling proposals at the same heights.
pub const DEFAULT_RETAIN_DEPTH: u64 = 64;

/// A block's root and operations, computed but not yet filed under its hash.
///
/// A block producer does not know its block's hash until the header — state
/// root included — is sealed, so computing the root and recording the block
/// have to be two steps. Validation knows the hash up front and does both at
/// once with [`QmdbForest::apply`].
#[derive(Debug, Clone)]
pub struct PreparedBlock {
    /// The root the block's header must carry.
    pub root: B256,
    parent: B256,
    ops: Vec<QmdbOperation>,
}

impl PreparedBlock {
    /// The root the block's header must carry.
    pub const fn root(&self) -> B256 {
        self.root
    }

    /// The block this was computed on top of.
    pub const fn parent(&self) -> B256 {
        self.parent
    }
}

/// Everything needed to rebuild the canonical head's tree after a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForestSnapshot {
    /// Layout version, so a future change to the tree encoding is detected
    /// rather than misread.
    pub version: u32,
    /// The block the tree stands at.
    pub head_number: u64,
    /// Its hash.
    pub head_hash: B256,
    /// The tree.
    pub tree: QmdbSnapshot,
}

impl ForestSnapshot {
    /// The layout this crate writes.
    pub const VERSION: u32 = 1;

    /// Moves this snapshot forward by one delta, in place.
    ///
    /// The inverse of [`QmdbForest::delta_since`], and the reason a node can
    /// restore its head without ever having written the whole tree at that
    /// head: a checkpoint plus the deltas taken since it is the same state.
    pub fn apply_delta(&mut self, delta: &ForestDelta) -> Result<(), StateError> {
        if delta.version != ForestDelta::VERSION {
            return Err(StateError::SnapshotVersion {
                found: delta.version,
                expected: ForestDelta::VERSION,
            });
        }
        // A delta is only meaningful on the state it was taken against. Applying
        // one to a different base would produce a tree that is neither the base
        // nor the head, and whose root would be wrong in a way nothing downstream
        // could attribute.
        if delta.base_next_slot != self.tree.next_slot {
            return Err(StateError::DeltaBase {
                expected: self.tree.next_slot,
                found: delta.base_next_slot,
            });
        }
        // Everything is checked before anything is written. A delta that fails
        // halfway leaves a snapshot that is neither state, and a caller holding
        // one has no way to tell.
        if delta.base_next_slot + delta.appended.len() as u64 != delta.next_slot {
            return Err(StateError::DeltaBase {
                expected: delta.next_slot,
                found: delta.base_next_slot + delta.appended.len() as u64,
            });
        }
        for (slot, _) in &delta.changed {
            let index = usize::try_from(*slot).map_err(|_| StateError::DeltaSlot(*slot))?;
            if index >= self.tree.entries.len() {
                return Err(StateError::DeltaSlot(*slot));
            }
        }
        for (slot, entry) in &delta.changed {
            self.tree.entries[*slot as usize] = entry.clone();
        }
        self.tree.entries.extend(delta.appended.iter().cloned());
        self.tree.next_slot = delta.next_slot;
        self.head_number = delta.head_number;
        self.head_hash = delta.head_hash;
        Ok(())
    }
}

/// What changed between one persisted head and the next.
///
/// QMDB only ever appends at a cursor and deactivates slots below it, so the
/// whole of a move is a contiguous run of new slots plus the handful of older
/// ones the block touched. That is what makes incremental persistence possible
/// at all: writing this costs the size of the block, while writing a
/// [`ForestSnapshot`] costs the size of the world state, every block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForestDelta {
    /// Layout version, checked on the way in.
    pub version: u32,
    /// The block this delta lands on.
    pub head_number: u64,
    /// Its hash.
    pub head_hash: B256,
    /// The append cursor this delta was taken against.
    pub base_next_slot: u64,
    /// The append cursor afterwards.
    pub next_slot: u64,
    /// Slots `base_next_slot..next_slot`, in order.
    pub appended: Vec<QmdbEntrySnapshot>,
    /// Slots below `base_next_slot` whose entry differs afterwards — in
    /// practice the ones the moved blocks deactivated or revived.
    pub changed: Vec<(u64, QmdbEntrySnapshot)>,
}

impl ForestDelta {
    /// The layout this crate writes.
    pub const VERSION: u32 = 1;

    /// Roughly what this costs to store, for a caller deciding when a run of
    /// deltas has grown longer than the checkpoint it is replacing.
    pub fn weight(&self) -> usize {
        let entry = |e: &QmdbEntrySnapshot| e.value.len() + 33;
        self.appended.iter().map(entry).sum::<usize>()
            + self.changed.iter().map(|(_, e)| entry(e) + 8).sum::<usize>()
    }
}

/// What the forest remembers about a held block.
#[derive(Debug, Clone)]
struct BlockRecord {
    parent: B256,
    number: u64,
    /// The sorted leaf operations, kept so the block can be re-applied after
    /// a revert. Empty for the block the forest was restored at, which is
    /// never re-applied because nothing lies beneath it.
    ops: Vec<QmdbOperation>,
    root: B256,
    /// Present exactly while the block is applied on the tree's current path.
    undo: Option<BlockUndo>,
}

/// Trees for recent blocks, keyed by block hash, over one shared tree.
#[derive(Debug)]
pub struct QmdbForest {
    tree: QmdbCompatTree,
    /// The block the tree currently reflects.
    tip: B256,
    /// A block computed but not yet filed, still applied on the tree. Any
    /// move of the tree reverts it first.
    pending: Option<(B256, BlockUndo)>,
    records: HashMap<B256, BlockRecord>,
    head: (u64, B256),
    retain_depth: u64,
    /// Slots the tree has deactivated or revived since the last delta was
    /// taken. Every move of the tree goes through a [`BlockUndo`], and an undo
    /// record names exactly the slots it flips, so recording them here — on the
    /// way in and on the way out — describes that half of the move without
    /// comparing two trees.
    dirty_slots: BTreeSet<u64>,
    /// The lowest the append cursor has been since the last delta was taken.
    ///
    /// The other half of a move, and the one that is easy to miss: reverting a
    /// block rewinds the cursor, and the block applied in its place appends
    /// over the very slots the reverted one held. Those slots were never
    /// deactivated — they were abandoned and reused — so nothing names them but
    /// the cursor's low-water mark.
    min_cursor: u64,
}

impl QmdbForest {
    /// A forest whose only block is the genesis state.
    ///
    /// The root of that tree is what a QMDB chain's genesis header carries as
    /// its state root: gov5 seeds the forest from the alloc at init and writes
    /// the resulting root into the header, and a node that computed the
    /// Merkle-Patricia root of the same alloc would disagree with it about the
    /// genesis hash before the first block.
    pub fn genesis(genesis_hash: B256, alloc: &BlockChanges) -> Result<Self, StateError> {
        let mut tree = QmdbCompatTree::new();
        tree.apply_sorted_ops(alloc.operations())?;
        Ok(Self::at(0, genesis_hash, tree))
    }

    /// A forest restored from a snapshot of its canonical head.
    pub fn from_snapshot(snapshot: &ForestSnapshot) -> Result<Self, StateError> {
        if snapshot.version != ForestSnapshot::VERSION {
            return Err(StateError::SnapshotVersion {
                found: snapshot.version,
                expected: ForestSnapshot::VERSION,
            });
        }
        let tree = QmdbCompatTree::from_snapshot(&snapshot.tree)
            .map_err(|error| StateError::Snapshot(error.to_string()))?;
        Ok(Self::at(snapshot.head_number, snapshot.head_hash, tree))
    }

    /// A forest whose head is `(number, hash)` and whose state is `tree` —
    /// how a node that did not execute the chain, but received its state,
    /// begins. The tree's root must be the head's state root; the caller
    /// checks that against the header it trusts.
    pub fn from_tree(number: u64, hash: B256, tree: QmdbCompatTree) -> Self {
        Self::at(number, hash, tree)
    }

    fn at(number: u64, hash: B256, tree: QmdbCompatTree) -> Self {
        let root = B256::from(tree.root());
        let next_slot = tree.next_slot();
        let mut records = HashMap::new();
        records.insert(
            hash,
            BlockRecord {
                parent: B256::ZERO,
                number,
                ops: Vec::new(),
                root,
                undo: None,
            },
        );
        Self {
            tree,
            tip: hash,
            pending: None,
            records,
            head: (number, hash),
            retain_depth: DEFAULT_RETAIN_DEPTH,
            dirty_slots: BTreeSet::new(),
            min_cursor: next_slot,
        }
    }

    /// Records what a move touched: the slots the undo names, and how far back
    /// it left the append cursor.
    fn note_move(&mut self, undo: &BlockUndo) {
        self.dirty_slots.extend(undo.entries.iter().map(|entry| entry.slot));
        self.min_cursor = self.min_cursor.min(self.tree.next_slot());
    }

    /// Sets how many blocks behind the head are kept.
    pub const fn with_retain_depth(mut self, depth: u64) -> Self {
        self.retain_depth = depth;
        self
    }

    /// The canonical head, as `(number, hash)`.
    pub const fn head(&self) -> (u64, B256) {
        self.head
    }

    /// Whether `block_hash` is held.
    pub fn contains(&self, block_hash: &B256) -> bool {
        self.records.contains_key(block_hash)
    }

    /// The state root after `block_hash`, if it is held.
    pub fn root_of(&self, block_hash: &B256) -> Option<B256> {
        self.records.get(block_hash).map(|record| record.root)
    }

    /// Files a computed block under a different hash.
    ///
    /// A builder computes a block's root before consensus seals its header,
    /// and the seal changes the hash; when the sealed block is imported with
    /// the builder's execution rather than re-executed, the record filed
    /// under the builder's hash is the sealed block's record. Moved, not
    /// copied: a record's undo describes what is applied on the tree, and two
    /// records claiming the same application would apply it twice. A rename
    /// onto a hash already filed, or of the head, is refused; renaming a hash
    /// that is not filed is an error naming it.
    pub fn rename(&mut self, from: B256, to: B256) -> Result<(), StateError> {
        if from == to {
            return Ok(());
        }
        let from_root = self.root_of(&from).ok_or(StateError::UnknownBlock(from))?;
        if let Some(existing) = self.root_of(&to) {
            // Already filed under the sealed hash -- by an earlier rename, or by
            // a validation that computed it -- with the same root: nothing to do.
            // A different root under that hash is a block this is not.
            return if existing == from_root { Ok(()) } else { Err(StateError::UnknownBlock(to)) };
        }
        let record = self.records.remove(&from).ok_or(StateError::UnknownBlock(from))?;
        self.records.insert(to, record);
        // Every reference to the old hash follows it: the tip the tree stands
        // at, the canonical head, the parent of pending work, and the parent
        // of any block already computed on it.
        if self.tip == from {
            self.tip = to;
        }
        if self.head.1 == from {
            self.head.1 = to;
        }
        if let Some((parent, _)) = self.pending.as_mut() {
            if *parent == from {
                *parent = to;
            }
        }
        for child in self.records.values_mut() {
            if child.parent == from {
                child.parent = to;
            }
        }
        Ok(())
    }

    /// The state root at the canonical head.
    pub fn root(&self) -> B256 {
        self.root_of(&self.head.1).unwrap_or_default()
    }

    /// How many blocks are held.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no blocks are held — never true for a constructed forest.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The block the tree currently stands at. For tests and diagnostics; a
    /// caller never needs to know, since every operation moves the tree where
    /// it has to be.
    pub const fn tip(&self) -> B256 {
        self.tip
    }

    /// Computes the root a block would have on top of `parent`.
    ///
    /// Nothing is filed: the caller seals its header with the root, learns the
    /// block hash, and files the block with [`Self::insert`]. Until then the
    /// block stays applied on the tree as pending work, and any other move of
    /// the tree reverts it first.
    pub fn compute(&mut self, parent: B256, changes: &BlockChanges) -> Result<PreparedBlock, StateError> {
        self.move_to(parent)?;
        let ops = changes.operations();
        let (root, undo) = self.tree.apply_sorted_ops_recorded(ops.clone())?;
        self.note_move(&undo);
        self.pending = Some((parent, undo));
        Ok(PreparedBlock {
            root: B256::from(root),
            parent,
            ops,
        })
    }

    /// Files a computed block under the hash it turned out to have.
    ///
    /// Idempotent: a block already held is left as it is. The same block reaches
    /// a producer twice — once when it builds it, once when its own execution
    /// layer validates it — and both arrive at the same root.
    pub fn insert(&mut self, block_hash: B256, number: u64, prepared: PreparedBlock) -> Result<(), StateError> {
        if self.records.contains_key(&block_hash) {
            return Ok(());
        }
        // The pending work is this very block, on the same parent: adopt it as
        // applied rather than reverting and replaying it.
        let undo = match self.pending.take() {
            Some((parent, undo)) if parent == prepared.parent => Some(undo),
            Some((_, undo)) => {
                self.tree.apply_undo(&undo).map_err(|e| StateError::Undo(e.to_string()))?;
                self.note_move(&undo);
                None
            }
            None => None,
        };
        let applied = undo.is_some();
        self.records.insert(
            block_hash,
            BlockRecord {
                parent: prepared.parent,
                number,
                ops: prepared.ops,
                root: prepared.root,
                undo,
            },
        );
        if applied {
            self.tip = block_hash;
        }
        Ok(())
    }

    /// Computes and files a block in one step, for a block whose hash is
    /// already known. Returns the root.
    ///
    /// Idempotent by hash, like [`Self::insert`].
    pub fn apply(
        &mut self,
        parent: B256,
        block_hash: B256,
        number: u64,
        changes: &BlockChanges,
    ) -> Result<B256, StateError> {
        if let Some(root) = self.root_of(&block_hash) {
            return Ok(root);
        }
        let prepared = self.compute(parent, changes)?;
        let root = prepared.root;
        self.insert(block_hash, number, prepared)?;
        Ok(root)
    }

    /// Advances the canonical head and drops blocks that have fallen out of
    /// the retention window.
    ///
    /// The head must already be held: a block becomes canonical only after it
    /// was validated, and validation is what files it.
    pub fn set_canonical(&mut self, block_hash: B256) -> Result<(), StateError> {
        let number = self
            .records
            .get(&block_hash)
            .ok_or(StateError::UnknownBlock(block_hash))?
            .number;
        // Stand the tree at the head before pruning: once records below the
        // window are gone, nothing can be walked through them.
        self.move_to(block_hash)?;
        self.head = (number, block_hash);
        let cutoff = number.saturating_sub(self.retain_depth);
        self.records
            .retain(|hash, record| record.number >= cutoff || *hash == block_hash);
        Ok(())
    }

    /// A snapshot of the canonical head, enough to restore this forest.
    ///
    /// Only the head: every other block is either an ancestor a restarted node
    /// no longer needs, or a sibling that lost.
    pub fn snapshot(&mut self) -> Result<ForestSnapshot, StateError> {
        let head = self.head.1;
        self.move_to(head)?;
        Ok(ForestSnapshot {
            version: ForestSnapshot::VERSION,
            head_number: self.head.0,
            head_hash: head,
            tree: self.tree.snapshot(),
        })
    }

    /// What changed between the state at `base_next_slot` and the canonical
    /// head, and clears the record so the next call describes the next move.
    ///
    /// The caller owns the pairing: `base_next_slot` must be the cursor of the
    /// state this delta will be applied to, which is the `next_slot` the last
    /// delta (or checkpoint) left behind. A mismatch is refused by
    /// [`ForestSnapshot::apply_delta`] rather than silently producing a wrong
    /// tree.
    pub fn delta_since(&mut self, base_next_slot: u64) -> Result<ForestDelta, StateError> {
        let head = self.head.1;
        self.move_to(head)?;
        let next_slot = self.tree.next_slot();
        if base_next_slot > next_slot {
            return Err(StateError::DeltaBase {
                expected: next_slot,
                found: base_next_slot,
            });
        }
        let appended = (base_next_slot..next_slot)
            .map(|slot| self.tree.entry_at(slot).ok_or(StateError::DeltaSlot(slot)))
            .collect::<Result<Vec<_>, _>>()?;
        // What lies below the base and may differ from it: the slots a move
        // flipped, plus every slot the cursor was rewound past and then
        // re-appended over. Slots above the base need no entry here — they are
        // already carried by `appended`, at their current value.
        let rewound_from = self.min_cursor.min(base_next_slot);
        let changed = self
            .dirty_slots
            .iter()
            .copied()
            .filter(|slot| *slot < base_next_slot)
            .chain(rewound_from..base_next_slot)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|slot| {
                self.tree.entry_at(slot).map(|entry| (slot, entry)).ok_or(StateError::DeltaSlot(slot))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.dirty_slots.clear();
        self.min_cursor = next_slot;
        Ok(ForestDelta {
            version: ForestDelta::VERSION,
            head_number: self.head.0,
            head_hash: head,
            base_next_slot,
            next_slot,
            appended,
            changed,
        })
    }

    /// The append cursor the tree currently stands at — what a caller pairs
    /// with a checkpoint so the next [`Self::delta_since`] lands on it.
    pub fn next_slot(&self) -> u64 {
        self.tree.next_slot()
    }

    /// Forgets what has changed, without describing it.
    ///
    /// For a caller that has just written the whole tree: the changes are in
    /// that snapshot, and the next delta must be measured from it rather than
    /// carrying them a second time. Taking a delta and dropping it would do the
    /// same, at the cost of copying every changed entry to discard it.
    pub fn forget_changes(&mut self) {
        self.dirty_slots.clear();
        self.min_cursor = self.tree.next_slot();
    }

    /// Proves an account at the canonical head.
    pub fn prove_account(&mut self, address: Address) -> Option<QmdbProof> {
        self.move_to(self.head.1).ok()?;
        self.tree.prove(&gov5_account_key(&address.0 .0))
    }

    /// Proves a storage slot at the canonical head.
    pub fn prove_storage(&mut self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.move_to(self.head.1).ok()?;
        self.tree.prove(&gov5_storage_key(&address.0 .0, &slot.0))
    }

    /// Stands the tree at `target`: reverts pending work, reverts up to the
    /// common ancestor, re-applies down.
    fn move_to(&mut self, target: B256) -> Result<(), StateError> {
        if let Some((_, undo)) = self.pending.take() {
            self.tree.apply_undo(&undo).map_err(|e| StateError::Undo(e.to_string()))?;
            self.note_move(&undo);
        }
        if self.tip == target {
            return Ok(());
        }
        if !self.records.contains_key(&target) {
            return Err(StateError::UnknownParent(target));
        }

        // Ancestors of each end, nearest first, up to wherever the records run
        // out.
        let up_from_tip = self.ancestry(self.tip);
        let up_from_target = self.ancestry(target);
        let common = up_from_tip
            .iter()
            .find(|hash| up_from_target.contains(hash))
            .copied()
            .ok_or(StateError::Unreachable {
                from: self.tip,
                to: target,
            })?;

        // Revert, newest first, until the tree stands at the common ancestor.
        for hash in up_from_tip.iter().take_while(|hash| **hash != common) {
            let record = self
                .records
                .get_mut(hash)
                .ok_or(StateError::UnknownBlock(*hash))?;
            let undo = record
                .undo
                .take()
                .ok_or(StateError::NotApplied(*hash))?;
            self.tree
                .apply_undo(&undo)
                .map_err(|e| StateError::Undo(e.to_string()))?;
            self.note_move(&undo);
        }
        self.tip = common;

        // Re-apply, oldest first, down to the target. Each block must land on
        // the root it had before — the whole premise of reverting is that it
        // does — so a disagreement is refused rather than filed.
        let descend: Vec<B256> = up_from_target
            .iter()
            .take_while(|hash| **hash != common)
            .copied()
            .collect();
        for hash in descend.iter().rev() {
            let record = self
                .records
                .get(hash)
                .ok_or(StateError::UnknownBlock(*hash))?;
            let (ops, expected) = (record.ops.clone(), record.root);
            let (root, undo) = self.tree.apply_sorted_ops_recorded(ops)?;
            self.note_move(&undo);
            let root = B256::from(root);
            if root != expected {
                return Err(StateError::Replay {
                    block: *hash,
                    expected,
                    got: root,
                });
            }
            self.records
                .get_mut(hash)
                .ok_or(StateError::UnknownBlock(*hash))?
                .undo = Some(undo);
            self.tip = *hash;
        }
        Ok(())
    }

    /// `hash` and its held ancestors, nearest first.
    fn ancestry(&self, hash: B256) -> Vec<B256> {
        let mut chain = vec![hash];
        let mut current = hash;
        while let Some(record) = self.records.get(&current) {
            if !self.records.contains_key(&record.parent) {
                break;
            }
            current = record.parent;
            chain.push(current);
        }
        chain
    }
}

/// Something that can prove state against a root it also reports.
///
/// The root and the proof have to come from the same tree, or a verifier
/// checks one against the other and learns nothing. Implemented for both the
/// linear [`super::QmdbState`] and the [`QmdbForest`] a live node keeps.
pub trait StateProofProvider: Send + Sync {
    /// The state root proofs are anchored to.
    fn state_root(&self) -> B256;
    /// Proves an account's leaf, if it has one.
    fn prove_account(&self, address: Address) -> Option<QmdbProof>;
    /// Proves a storage slot's leaf, if it has one.
    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof>;
}

impl StateProofProvider for std::sync::Mutex<QmdbForest> {
    fn state_root(&self) -> B256 {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .root()
    }

    fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prove_account(address)
    }

    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prove_storage(address, slot)
    }
}

impl StateProofProvider for std::sync::Mutex<super::QmdbState> {
    fn state_root(&self) -> B256 {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .root()
    }

    fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prove_account(address)
    }

    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prove_storage(address, slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountState;
    use alloy_primitives::U256;

    fn changes(byte: u8) -> BlockChanges {
        let mut changes = BlockChanges::new();
        changes.set_account(
            Address::with_last_byte(byte),
            AccountState {
                nonce: byte as u64,
                balance: U256::from(byte),
                code_hash: B256::ZERO,
            },
        );
        changes
    }

    const GENESIS: B256 = B256::repeat_byte(0xA0);

    fn h(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    #[test]
    fn a_renamed_block_keeps_its_root_and_serves_as_a_parent() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        // Filed under the builder's hash, as a build does.
        let root_built = forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        // Consensus sealed it under another hash.
        forest.rename(h(0x0A), h(0xAA)).unwrap();
        assert_eq!(forest.root_of(&h(0x0A)), None);
        assert_eq!(forest.root_of(&h(0xAA)), Some(root_built));
        // The next block builds on the sealed hash.
        let root_next = forest.apply(h(0xAA), h(0xAB), 2, &changes(2)).unwrap();
        let mut linear = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        linear.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        assert_eq!(linear.apply(h(0x0A), h(0xA2), 2, &changes(2)).unwrap(), root_next);
        // Renaming again onto a hash that already holds the same root is nothing.
        assert!(forest.rename(h(0xAB), h(0xAB)).is_ok());
        // Renaming a hash that is not filed names it.
        assert!(matches!(forest.rename(h(0x77), h(0x78)), Err(StateError::UnknownBlock(_))));
    }

    #[test]
    fn two_siblings_are_both_computed_against_their_parent() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let root_a = forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        let root_b = forest.apply(GENESIS, h(0x0B), 1, &changes(2)).unwrap();

        // Neither sibling saw the other. Applying B on top of A would have
        // forked from every node that only ever saw B.
        let mut only_b = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        assert_eq!(only_b.apply(GENESIS, h(0x0B), 1, &changes(2)).unwrap(), root_b);
        assert_ne!(root_a, root_b);
        assert_eq!(forest.tip(), h(0x0B), "the tree stands at the last block applied");
    }

    /// The tree is moved, not copied: after switching between siblings the
    /// first one's root is still reproduced exactly.
    #[test]
    fn moving_back_to_a_sibling_reproduces_its_root() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let root_a = forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        forest.apply(GENESIS, h(0x0B), 1, &changes(2)).unwrap();
        // A child of A: the forest has to revert B and re-apply A first.
        let root_a2 = forest.apply(h(0x0A), h(0xA2), 2, &changes(3)).unwrap();

        let mut linear = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        assert_eq!(linear.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap(), root_a);
        assert_eq!(linear.apply(h(0x0A), h(0xA2), 2, &changes(3)).unwrap(), root_a2);
    }

    /// The property the delta log rests on: a checkpoint plus the deltas taken
    /// since it is the same tree as a snapshot taken at the end, slot for slot
    /// and root for root. Anything less and a restarted node would compute a
    /// root nobody else does.
    #[test]
    fn checkpoint_plus_deltas_is_the_same_tree_as_a_snapshot() {
        let mut forest = QmdbForest::genesis(GENESIS, &changes(0xF0)).unwrap();
        let mut replayed = forest.snapshot().unwrap();
        let mut cursor = forest.next_slot();

        // Forty blocks, each rewriting an account the last few blocks also
        // wrote, so slots are deactivated below the cursor as well as appended
        // above it.
        let mut parent = GENESIS;
        for number in 1..=40u8 {
            let hash = h(number);
            forest.apply(parent, hash, number as u64, &changes(number % 7)).unwrap();
            forest.set_canonical(hash).unwrap();
            let delta = forest.delta_since(cursor).unwrap();
            cursor = delta.next_slot;
            replayed.apply_delta(&delta).unwrap();
            parent = hash;
        }

        let direct = forest.snapshot().unwrap();
        assert_eq!(replayed.head_hash, direct.head_hash);
        assert_eq!(replayed.head_number, direct.head_number);
        assert_eq!(replayed.tree, direct.tree, "the replayed leaf set is the written one");
        assert_eq!(
            QmdbForest::from_snapshot(&replayed).unwrap().root(),
            forest.root(),
            "and it hashes to the same QMDB root",
        );
    }

    /// The same, across a branch switch. A delta taken after the forest moved
    /// off a sibling has to carry the slots that move revived, not only the
    /// ones the new block appended.
    #[test]
    fn a_delta_taken_after_a_branch_switch_carries_the_revert() {
        let mut forest = QmdbForest::genesis(GENESIS, &changes(0xF0)).unwrap();
        let mut replayed = forest.snapshot().unwrap();
        let mut cursor = forest.next_slot();

        forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        forest.set_canonical(h(0x0A)).unwrap();
        let delta = forest.delta_since(cursor).unwrap();
        cursor = delta.next_slot;
        replayed.apply_delta(&delta).unwrap();

        // A sibling of A wins, and then a child of it.
        forest.apply(GENESIS, h(0x0B), 1, &changes(2)).unwrap();
        forest.apply(h(0x0B), h(0xB2), 2, &changes(3)).unwrap();
        forest.set_canonical(h(0xB2)).unwrap();
        let delta = forest.delta_since(cursor).unwrap();
        replayed.apply_delta(&delta).unwrap();

        let direct = forest.snapshot().unwrap();
        assert_eq!(replayed.tree, direct.tree);
        assert_eq!(QmdbForest::from_snapshot(&replayed).unwrap().root(), forest.root());
    }

    /// A delta is refused by the state it does not describe. Applying one to
    /// the wrong base would give a tree that never existed, and a root that
    /// nothing downstream could attribute to a block.
    #[test]
    fn a_delta_is_refused_on_the_wrong_base() {
        let mut forest = QmdbForest::genesis(GENESIS, &changes(0xF0)).unwrap();
        let base = forest.snapshot().unwrap();
        let cursor = forest.next_slot();
        forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        forest.set_canonical(h(0x0A)).unwrap();
        let first = forest.delta_since(cursor).unwrap();
        forest.apply(h(0x0A), h(0x0B), 2, &changes(2)).unwrap();
        forest.set_canonical(h(0x0B)).unwrap();
        let second = forest.delta_since(first.next_slot).unwrap();

        let mut skipped = base;
        assert!(
            matches!(skipped.apply_delta(&second), Err(StateError::DeltaBase { .. })),
            "a delta that skips its predecessor is refused, not applied",
        );
    }

    #[test]
    fn a_block_filed_twice_keeps_its_first_root() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let first = forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        let again = forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        assert_eq!(first, again);
        assert_eq!(forest.len(), 2);
    }

    #[test]
    fn compute_then_insert_matches_apply_and_adopts_the_pending_work() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let prepared = forest.compute(GENESIS, &changes(1)).unwrap();
        let before_insert = forest.tree.next_slot();
        forest.insert(h(0x0A), 1, prepared.clone()).unwrap();
        assert_eq!(forest.tree.next_slot(), before_insert, "no revert-and-replay was needed");
        assert_eq!(forest.tip(), h(0x0A));

        let mut direct = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        assert_eq!(direct.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap(), prepared.root);
        assert_eq!(forest.root_of(&h(0x0A)), Some(prepared.root));
    }

    /// A build that was computed and abandoned must not leak into the next.
    #[test]
    fn abandoned_pending_work_is_reverted_before_the_next_computation() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let abandoned = forest.compute(GENESIS, &changes(7)).unwrap();
        let kept = forest.compute(GENESIS, &changes(1)).unwrap();
        assert_ne!(abandoned.root, kept.root);

        let mut clean = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        assert_eq!(clean.compute(GENESIS, &changes(1)).unwrap().root, kept.root);
    }

    #[test]
    fn an_unknown_parent_is_refused() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        match forest.compute(h(0xEE), &changes(1)) {
            Err(StateError::UnknownParent(_)) => {}
            other => panic!("expected an unknown parent, got {other:?}"),
        }
    }

    #[test]
    fn old_blocks_fall_out_of_the_window_but_the_head_never_does() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new())
            .unwrap()
            .with_retain_depth(2);
        let mut parent = GENESIS;
        for n in 1..=5u8 {
            forest.apply(parent, h(n), n as u64, &changes(n)).unwrap();
            forest.set_canonical(h(n)).unwrap();
            parent = h(n);
        }
        assert_eq!(forest.head(), (5, h(5)));
        assert!(forest.contains(&h(5)));
        assert!(forest.contains(&h(3)));
        assert!(!forest.contains(&h(1)), "block 1 is past the window");
        assert!(!forest.contains(&GENESIS));
        // And the tree still moves within what is left.
        forest.apply(h(4), h(0x45), 5, &changes(9)).unwrap();
        forest.apply(h(5), h(6), 6, &changes(6)).unwrap();
    }

    #[test]
    fn a_snapshot_restores_the_head_tree_exactly() {
        let mut forest = QmdbForest::genesis(GENESIS, &changes(9)).unwrap();
        let root = forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        // A losing sibling applied last: the snapshot must still be of the head.
        forest.apply(GENESIS, h(0x0B), 1, &changes(2)).unwrap();
        forest.set_canonical(h(0x0A)).unwrap();

        let snapshot = forest.snapshot().unwrap();
        let mut restored = QmdbForest::from_snapshot(&snapshot).unwrap();
        assert_eq!(restored.head(), (1, h(0x0A)));
        assert_eq!(restored.root(), root);

        // The restored tree continues the append history, not just the state.
        assert_eq!(
            restored.apply(h(0x0A), h(0x0C), 2, &changes(2)).unwrap(),
            forest.apply(h(0x0A), h(0x0C), 2, &changes(2)).unwrap(),
        );
    }

    #[test]
    fn a_snapshot_from_another_layout_is_refused() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        let mut snapshot = forest.snapshot().unwrap();
        snapshot.version += 1;
        assert!(matches!(
            QmdbForest::from_snapshot(&snapshot),
            Err(StateError::SnapshotVersion { .. })
        ));
    }

    #[test]
    fn proofs_come_from_the_head_even_after_a_sibling_was_applied() {
        let mut forest = QmdbForest::genesis(GENESIS, &BlockChanges::new()).unwrap();
        forest.apply(GENESIS, h(0x0A), 1, &changes(1)).unwrap();
        forest.set_canonical(h(0x0A)).unwrap();
        forest.apply(GENESIS, h(0x0B), 1, &changes(2)).unwrap();

        let proof = forest
            .prove_account(Address::with_last_byte(1))
            .expect("the head holds account 1");
        assert!(proof.verify_for_key(&forest.root().0, &gov5_account_key(&Address::with_last_byte(1).0 .0)));
        assert!(forest.prove_account(Address::with_last_byte(2)).is_none(), "account 2 is only in the sibling");
    }
}
