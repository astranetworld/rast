// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reads the entry file by byte offset, outside the tree and its lock.
//!
//! A QMDB read view (`docs/QMDB_UPGRADE_PLAN.md`, stage 6) answers state reads for the persisted
//! head while the tree it was taken from moves on under its own lock. Records in the entry file
//! (`[key 32][len u32 LE][value]`) never change once appended, so the view keeps byte offsets and
//! reads them through its own read-only mapping of the file. The mapping reserves
//! [`VIEW_MAP_BYTES`] of address space once: pages of a shared file mapping follow the file as it
//! grows, so appends made after the mapping are readable without remapping.
//!
//! The contract: a caller reads only offsets of records that are written (flushed to the file,
//! not necessarily synced) and not truncated since. Past the file's end a mapped page is a
//! `SIGBUS`, which is why a tree cutting its file tells a `TruncationGuard` first.

use std::{fs::File, io, path::Path};

use crate::Hash;

/// Address space the view reserves: 1 TiB, the most a 40-bit index value can name.
pub const VIEW_MAP_BYTES: u64 = 1 << 40;

const KEY_LEN: usize = 32;
const LEN_LEN: usize = 4;

/// A read-only mapping of an entry file, addressed by record offset.
pub struct EntryFileView {
    map: memmap2::Mmap,
}

impl std::fmt::Debug for EntryFileView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryFileView").finish_non_exhaustive()
    }
}

impl EntryFileView {
    /// Maps the entry file at `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        // SAFETY: a shared, read-only mapping. The tree only appends to the
        // file, and cuts it only after telling its `TruncationGuard`; readers
        // keep to written, uncut records (the module's contract).
        let map = unsafe { memmap2::MmapOptions::new().len(VIEW_MAP_BYTES as usize).map(&file)? };
        #[cfg(unix)]
        map.advise(memmap2::Advice::Random)?;
        Ok(Self { map })
    }

    /// The key of the record at `offset`.
    #[inline]
    pub fn key(&self, offset: u64) -> Hash {
        let at = offset as usize;
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&self.map[at..at + KEY_LEN]);
        key
    }

    /// The key and value of the record at `offset`.
    #[inline]
    pub fn record(&self, offset: u64) -> (Hash, &[u8]) {
        let at = offset as usize;
        let key = self.key(offset);
        let len_at = at + KEY_LEN;
        let len = u32::from_le_bytes([self.map[len_at], self.map[len_at + 1], self.map[len_at + 2], self.map[len_at + 3]]) as usize;
        let value_at = len_at + LEN_LEN;
        (key, &self.map[value_at..value_at + len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmdb_compat::{QmdbCompatTree, QmdbOperation};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-entry-view-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("entries.log")
    }

    fn key(n: u64) -> Hash {
        *blake3::hash(&n.to_le_bytes()).as_bytes()
    }

    fn block(range: std::ops::Range<u64>, tag: u8) -> Vec<QmdbOperation> {
        let mut ops: Vec<QmdbOperation> =
            range.map(|n| QmdbOperation { key: key(n), value: Some(vec![tag; (n % 90) as usize + 1]) }).collect();
        ops.sort_unstable_by_key(|op| op.key);
        ops
    }

    #[test]
    fn records_read_by_offset_match_the_tree_including_appends_after_the_mapping() {
        let path = scratch("appends");
        let mut tree = QmdbCompatTree::new();
        tree.apply_sorted_ops(block(0..3_000, 1)).unwrap();
        tree.set_entry_file(&path).unwrap();
        let view = EntryFileView::open(&path).unwrap();
        tree.apply_sorted_ops(block(2_000..9_000, 2)).unwrap();
        tree.flush_entries_for_sync().unwrap();
        for slot in 0..tree.next_slot() {
            let entry = tree.entry_at(slot).unwrap();
            let (k, value) = view.record(tree.entry_offset(slot).unwrap());
            assert_eq!(k, entry.key, "slot {slot}");
            assert_eq!(value, entry.value.as_slice(), "slot {slot}");
        }
    }

    #[test]
    fn a_truncating_undo_tells_the_guard_the_new_length_first() {
        struct Record(std::sync::Mutex<Vec<(u64, u64)>>, std::path::PathBuf);
        impl crate::qmdb_compat::TruncationGuard for Record {
            fn before_truncate(&self, new_len: u64) {
                let file_len = std::fs::metadata(&self.1).unwrap().len();
                self.0.lock().unwrap().push((new_len, file_len));
            }
        }
        let path = scratch("guard");
        let mut tree = QmdbCompatTree::new();
        tree.apply_sorted_ops(block(0..1_000, 1)).unwrap();
        tree.set_entry_file(&path).unwrap();
        let calls = std::sync::Arc::new(Record(std::sync::Mutex::new(Vec::new()), path.clone()));
        tree.set_truncation_guard(Some(calls.clone()));
        let cut_at = tree.next_slot();
        let (_, undo) = tree.apply_sorted_ops_recorded(block(500..2_000, 2)).unwrap();
        tree.flush_entries_for_sync().unwrap();
        let expected = tree.entry_offset(cut_at).unwrap();
        tree.apply_undo(&undo).unwrap();
        let calls = calls.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, expected, "told the length the file is cut to");
        assert!(calls[0].1 > expected, "before the cut");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), expected);
    }
}
