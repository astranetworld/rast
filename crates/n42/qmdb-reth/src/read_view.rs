// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! QMDB answering account and storage reads for the database's persisted block
//! (`docs/QMDB_UPGRADE_PLAN.md`, stage 6).
//!
//! reth reads state through an in-memory overlay of the blocks it has not persisted, over a base
//! provider at the block its read transaction sees as persisted (the `Finish` checkpoint, F). A
//! base answering at exactly F is correct for every reader, on whichever fork it executes. This
//! view answers at F without the forest's lock:
//!
//! - a key -> record-offset index at the view's head H, the records read through its own mapping
//!   of the entry file (records never change once appended);
//! - for each of the last [`JOURNAL_DEPTH`] blocks up to H, the offset each of its keys held
//!   before it and the file length the view read before it, so a reader whose F is behind H
//!   undoes those blocks for its key, and the view itself can step back through them;
//! - a block being applied publishes its journal before the index changes, so no reader at or
//!   below H sees a half-applied block.
//!
//! It moves as the database persists (`QmdbNodeState::on_persisted`) and declines what it cannot
//! answer exactly (a reader ahead of it, or further behind than its journals). When the database
//! unwinds below H, or the tree is about to cut records the view reads (a revert below H, told
//! through [`TruncationGuard`] before the cut), the view steps back through its journals to the
//! newest block whose records survive -- the index is rewritten while every record it compares
//! is still in the file. It is invalidated for good only when the journals do not reach that
//! far, or when a persisted block is not the one it holds.

use std::{
    collections::VecDeque,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError, RwLock,
    },
};

use alloy_primitives::{Address, B256, U256};
use n42_twig_core::{
    entry_view::EntryFileView,
    qmdb_compat::{gov5_account_key, gov5_storage_key, TruncationGuard},
    Hash, SharedOffsetIndex,
};
use rayon::prelude::*;
use reth_primitives_traits::Account;
use tracing::{info, warn};

/// How many blocks behind its head the view answers for.
pub const JOURNAL_DEPTH: usize = 64;

/// For one block, sorted by key: the offset of each key's live record before the block.
type Journal = Arc<Vec<(Hash, Option<u64>)>>;

/// One block the view advanced by.
#[derive(Debug)]
struct Step {
    number: u64,
    hash: B256,
    journal: Journal,
    /// The entry-file bytes the view read before this block.
    floor_before: u64,
}

#[derive(Debug)]
struct Versions {
    valid: bool,
    /// The head's hash is `B256::ZERO` when the view stepped back past its oldest journal's
    /// block and no longer knows it.
    head: (u64, B256),
    /// The entry-file bytes the view reads at its head.
    head_floor: u64,
    /// Blocks `head - len + 1 ..= head`, oldest first.
    journals: VecDeque<Step>,
    /// The block whose index writes may be in flight (the head's child).
    pending: Option<Journal>,
}

/// Where a persisted block stands against the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// At or below the head, and (where the view can tell) the block it holds.
    Held,
    /// The head's child: the view can advance to it.
    Next,
    /// A different block at a height the view holds.
    Mismatch,
    /// Beyond the head's child.
    Gap,
    /// The view is invalidated.
    Invalid,
}

/// What [`QmdbReadView::raise_floor`] hands to [`QmdbReadView::advance`]: the file length the
/// block's records end at, and the tree's cuts counted when the floor went up -- a cut in
/// between may have taken the block's records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Raised {
    floor: u64,
    cuts: u64,
}

/// The read view: see the module documentation.
pub struct QmdbReadView {
    file: EntryFileView,
    index: SharedOffsetIndex,
    versions: RwLock<Versions>,
    /// Bytes of the entry file the view may read: past its newest block's last record,
    /// including a block whose floor was raised and that has not advanced yet.
    floor: AtomicU64,
    /// Cuts below `floor` the tree announced.
    cuts: AtomicU64,
    /// Advances and steps back one at a time.
    advancing: Mutex<()>,
}

impl std::fmt::Debug for QmdbReadView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let versions = self.versions.read().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("QmdbReadView")
            .field("valid", &versions.valid)
            .field("head", &versions.head)
            .field("journals", &versions.journals.len())
            .finish_non_exhaustive()
    }
}

fn record_end(file: &EntryFileView, offset: u64) -> u64 {
    offset + 36 + file.record(offset).1.len() as u64
}

/// gov5's `StateAccount.MarshalV2` leaf as reth's account: the presence bitmap
/// (nonce 1, balance 2, code 8), the LEB128 nonce, the length-prefixed
/// big-endian balance and the code hash.
fn decode_account(value: &[u8]) -> Option<Account> {
    let bitmap = *value.first()?;
    let mut at = 1;
    let mut nonce = 0u64;
    if bitmap & 1 != 0 {
        let mut shift = 0;
        loop {
            let byte = *value.get(at)?;
            at += 1;
            nonce |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
    }
    let mut balance = U256::ZERO;
    if bitmap & 2 != 0 {
        let len = *value.get(at)? as usize;
        at += 1;
        balance = U256::try_from_be_slice(value.get(at..at + len)?)?;
        at += len;
    }
    let bytecode_hash = if bitmap & 8 != 0 { Some(B256::from_slice(value.get(at..at + 32)?)) } else { None };
    Some(Account { nonce, balance, bytecode_hash })
}

impl QmdbReadView {
    /// A view at `head` over the entry file at `entry_file`, holding `live`
    /// (every live key and its record offset at `head`, records flushed).
    pub fn build(entry_file: &Path, head: (u64, B256), mut live: Vec<(Hash, u64)>) -> std::io::Result<Arc<Self>> {
        let file = EntryFileView::open(entry_file)?;
        live.par_sort_unstable_by_key(|(key, _)| *key);
        let floor = live.iter().map(|(_, offset)| *offset).max().map_or(0, |offset| record_end(&file, offset));
        let changes: Vec<(Hash, Option<u64>)> = live.into_iter().map(|(key, offset)| (key, Some(offset))).collect();
        let index = SharedOffsetIndex::default();
        index.apply_sorted(&changes, |offset| file.key(offset));
        Ok(Arc::new(Self {
            file,
            index,
            versions: RwLock::new(Versions {
                valid: true,
                head,
                head_floor: floor,
                journals: VecDeque::new(),
                pending: None,
            }),
            floor: AtomicU64::new(floor),
            cuts: AtomicU64::new(0),
            advancing: Mutex::new(()),
        }))
    }

    /// The block the view stands at.
    pub fn head(&self) -> (u64, B256) {
        self.versions.read().unwrap_or_else(PoisonError::into_inner).head
    }

    /// Whether the view still answers.
    pub fn is_valid(&self) -> bool {
        self.versions.read().unwrap_or_else(PoisonError::into_inner).valid
    }

    /// Keys indexed at the head.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether no key is indexed.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Reads `key` as of block `at`: `None` when the view cannot answer
    /// exactly, `Some(None)` for an absent key, else the decoded value. The
    /// versions lock is held through the record read, so a truncation waits.
    fn read_at<T>(&self, key: &Hash, at: u64, decode: impl FnOnce(&[u8]) -> T) -> Option<Option<T>> {
        let versions = self.versions.read().unwrap_or_else(PoisonError::into_inner);
        if !versions.valid || at > versions.head.0 {
            return None;
        }
        let behind = (versions.head.0 - at) as usize;
        if behind > versions.journals.len() {
            return None;
        }
        let undone = versions
            .journals
            .iter()
            .skip(versions.journals.len() - behind)
            .map(|step| &step.journal)
            .chain(versions.pending.iter())
            .find_map(|journal| journal.binary_search_by(|(k, _)| k.cmp(key)).ok().map(|i| journal[i].1));
        let offset = match undone {
            Some(offset) => offset,
            None => self.index.get(key, |offset| self.file.key(offset)),
        };
        Some(offset.map(|offset| decode(self.file.record(offset).1)))
    }

    /// An account as of block `at` (see [`Self::read_at`]). A record that does
    /// not decode is declined.
    pub fn account(&self, address: &Address, at: u64) -> Option<Option<Account>> {
        match self.read_at(&gov5_account_key(&address.0 .0), at, decode_account)? {
            None => Some(None),
            Some(Some(account)) => Some(Some(account)),
            Some(None) => None,
        }
    }

    /// A storage slot as of block `at`; `Some(None)` for a zero (absent) slot.
    pub fn storage(&self, address: &Address, slot: &B256, at: u64) -> Option<Option<U256>> {
        match self.read_at(&gov5_storage_key(&address.0 .0, &slot.0), at, U256::try_from_be_slice)? {
            None => Some(None),
            Some(Some(value)) => Some(Some(value)),
            Some(None) => None,
        }
    }

    /// Where a persisted block stands against the view.
    pub fn position(&self, number: u64, hash: B256) -> Position {
        let versions = self.versions.read().unwrap_or_else(PoisonError::into_inner);
        if !versions.valid {
            return Position::Invalid;
        }
        let head = versions.head;
        if number == head.0 + 1 {
            Position::Next
        } else if number > head.0 + 1 {
            Position::Gap
        } else if number == head.0 {
            if hash == head.1 || head.1 == B256::ZERO { Position::Held } else { Position::Mismatch }
        } else {
            match versions.journals.iter().find(|step| step.number == number) {
                Some(step) if step.hash != hash => Position::Mismatch,
                _ => Position::Held,
            }
        }
    }

    /// Raises the floor past the records `changes` names. Called under the
    /// forest's lock, before the lock that could let the tree cut them is
    /// released; the result goes to [`Self::advance`].
    pub fn raise_floor(&self, changes: &[(Hash, Option<u64>)]) -> Raised {
        let floor = changes.iter().filter_map(|(_, offset)| *offset).max().map_or(0, |offset| record_end(&self.file, offset));
        self.floor.fetch_max(floor, Ordering::SeqCst);
        Raised { floor, cuts: self.cuts.load(Ordering::SeqCst) }
    }

    /// Moves the view to its head's child `number`, whose `changes` (sorted by
    /// key: the appended record's offset, or `None` for a deletion) are
    /// flushed to the file and covered by [`Self::raise_floor`], which gave `raised`.
    pub fn advance(&self, number: u64, hash: B256, changes: &[(Hash, Option<u64>)], raised: Raised) {
        let _one = self.advancing.lock().unwrap_or_else(PoisonError::into_inner);
        {
            let versions = self.versions.read().unwrap_or_else(PoisonError::into_inner);
            if !versions.valid {
                return;
            }
            let why = if number != versions.head.0 + 1 {
                Some("advanced to a block that is not the head's child")
            } else if self.cuts.load(Ordering::SeqCst) != raised.cuts {
                Some("the tree cut records between a block's floor and its advance")
            } else {
                None
            };
            if let Some(why) = why {
                drop(versions);
                self.invalidate(why);
                return;
            }
        }
        let key_at = |offset: u64| self.file.key(offset);
        let journal: Vec<(Hash, Option<u64>)> =
            changes.par_iter().with_min_len(1024).map(|(key, _)| (*key, self.index.get(key, key_at))).collect();
        let journal = Arc::new(journal);
        self.versions.write().unwrap_or_else(PoisonError::into_inner).pending = Some(journal.clone());
        self.index.apply_sorted(changes, key_at);
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        versions.pending = None;
        let floor_before = versions.head_floor;
        versions.journals.push_back(Step { number, hash, journal, floor_before });
        versions.head = (number, hash);
        versions.head_floor = floor_before.max(raised.floor);
        while versions.journals.len() > JOURNAL_DEPTH {
            versions.journals.pop_front();
        }
    }

    /// Steps the view back to block `number` (the database unwound the state
    /// above it). Returns whether the view is valid at or below `number`
    /// afterwards; a view whose journals do not reach that far is invalidated.
    pub fn revert_to(&self, number: u64) -> bool {
        let _one = self.advancing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        if !versions.valid {
            return false;
        }
        if self.step_back(&mut versions, number) {
            return true;
        }
        Self::invalidate_locked(&mut versions, "the database unwound below the view's journals");
        false
    }

    /// Undoes the journals above `number`, newest first, one key at a time
    /// (the caller may hold the forest's lock: no work goes to the worker pool,
    /// whose threads could take that lock while this one waits). Every offset
    /// the index compares is the view's own, below its floor, so still in the
    /// file. Callers hold `advancing` and the versions lock.
    fn step_back(&self, versions: &mut Versions, number: u64) -> bool {
        if number >= versions.head.0 {
            return true;
        }
        let depth = (versions.head.0 - number) as usize;
        if depth > versions.journals.len() {
            return false;
        }
        let key_at = |offset: u64| self.file.key(offset);
        let from = versions.head.0;
        for _ in 0..depth {
            let step = versions.journals.pop_back().expect("depth checked against the journals");
            for (key, before) in step.journal.iter() {
                match before {
                    Some(offset) => {
                        self.index.insert(*key, *offset, key_at);
                    }
                    None => {
                        self.index.remove(key, key_at);
                    }
                }
            }
            versions.head_floor = step.floor_before;
        }
        let hash = versions.journals.back().map_or(B256::ZERO, |step| step.hash);
        versions.head = (number, hash);
        self.floor.store(versions.head_floor, Ordering::SeqCst);
        info!(target: "n42.qmdb", from, to = number, journals = versions.journals.len(), "the QMDB read view stepped back");
        true
    }

    /// Stops the view answering, for good.
    pub fn invalidate(&self, why: &str) {
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        Self::invalidate_locked(&mut versions, why);
    }

    fn invalidate_locked(versions: &mut Versions, why: &str) {
        if versions.valid {
            versions.valid = false;
            warn!(target: "n42.qmdb", why, head = versions.head.0, "the QMDB read view is invalidated; state reads go to the database");
        }
    }
}

impl TruncationGuard for QmdbReadView {
    /// The tree is about to cut the entry file to `new_len`. Records the view
    /// reads at its head are among them only when the tree reverts below the
    /// head: the view steps back to the newest block whose records all lie
    /// below `new_len`, before they go. A block whose floor was raised and has
    /// not advanced is caught by the cut count ([`Raised`]).
    fn before_truncate(&self, new_len: u64) {
        if new_len >= self.floor.load(Ordering::SeqCst) {
            return;
        }
        let _one = self.advancing.lock().unwrap_or_else(PoisonError::into_inner);
        self.cuts.fetch_add(1, Ordering::SeqCst);
        let mut versions = self.versions.write().unwrap_or_else(PoisonError::into_inner);
        if !versions.valid || versions.head_floor <= new_len {
            return;
        }
        let target = versions.journals.iter().rev().find(|step| step.floor_before <= new_len).map(|step| step.number - 1);
        match target {
            Some(number) if self.step_back(&mut versions, number) => {}
            _ => Self::invalidate_locked(&mut versions, "the tree cuts entry-file records older than the view's journals"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n42_twig_core::qmdb_compat::encode_gov5_account_value;

    #[test]
    fn accounts_decode_as_gov5_encodes_them() {
        let code = B256::repeat_byte(7);
        for (nonce, balance, code_hash, expected_code) in [
            (0u64, U256::ZERO, B256::ZERO, None),
            (1, U256::from(1), alloy_primitives::KECCAK256_EMPTY, None),
            (300, U256::from(10u64).pow(U256::from(24)), code, Some(code)),
            (u64::MAX, U256::MAX, code, Some(code)),
        ] {
            let value = encode_gov5_account_value(nonce, &balance.to_be_bytes::<32>(), &code_hash.0);
            assert_eq!(decode_account(&value), Some(Account { nonce, balance, bytecode_hash: expected_code }));
        }
        assert_eq!(decode_account(&[]), None);
        assert_eq!(decode_account(&[2, 5, 1]), None, "a truncated balance");
    }
}
