// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where a QMDB tree keeps its entries: in the heap, or in an append-only
//! file with only an offset and an active bit per slot in memory.
//!
//! `docs/QMDB_ENTRY_LOG.md` is the design. The tree needs an entry's bytes
//! for the undo record of the slots a block retires, for the delta and the
//! checkpoint (sequential reads), for proofs, and for the mismatch check of a
//! revival; nothing on the hot path needs them in memory. In the heap an
//! entry is ~160 B (the struct and a heap `Vec<u8>` for the value); in the
//! file it is 8 B of offset and a bit, and the page cache -- evictable, which
//! the heap is not -- holds whatever is read often.

use std::{
    fs::{File, OpenOptions},
    io::{self, Seek, Write},
    path::{Path, PathBuf},
};

use crate::Hash;

/// One entry, as the heap store keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) key: Hash,
    pub(crate) value: Vec<u8>,
    pub(crate) active: bool,
}

/// A slot's content, read out of either store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotEntry {
    /// The entry's key.
    pub key: Hash,
    /// Its value bytes.
    pub value: Vec<u8>,
    /// Whether the slot is live.
    pub active: bool,
}

/// The record layout in the file: the key, the value's length, the value.
const KEY_LEN: usize = 32;
const LEN_LEN: usize = 4;
/// The file is mapped in chunks of about this many bytes, each sealed and
/// mapped once, with its page tables populated at that moment, so a read
/// never takes a page fault afterwards: 133,000 random reads a block on a
/// mapping that was just re-established cost 50-80 ms of minor faults
/// (loop123 E1, the follower's root phase 100-135 ms against ~56). Bytes
/// past the last sealed chunk are read from a tail buffer.
const CHUNK_BYTES: usize = 256 << 20;

/// One sealed, populated mapping of `[start, start + len)` of the file.
struct Chunk {
    start: u64,
    map: memmap2::Mmap,
}

/// The append-only entry file, mapped for reads.
pub(crate) struct FileEntries {
    path: PathBuf,
    file: File,
    /// Sealed chunks in file order; `chunks[i].start` ascending.
    chunks: Vec<Chunk>,
    /// Bytes of the file the sealed chunks cover.
    sealed_len: u64,
    /// The file's content from `sealed_len` on. Its first `written` bytes
    /// are on disk; the rest are written in one call by `flush`, so an
    /// append is a memory copy and not a write syscall (147,000 of those a
    /// block were the file store's root phase, loop125).
    tail: Vec<u8>,
    /// How many bytes of `tail` the file already holds.
    written: usize,
    /// Bytes of the file that belong to slots.
    len_bytes: u64,
    /// Where each slot's record starts.
    offsets: Vec<u64>,
    /// One bit per slot.
    active: Vec<u64>,
}

impl std::fmt::Debug for FileEntries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileEntries")
            .field("path", &self.path)
            .field("slots", &self.offsets.len())
            .field("bytes", &self.len_bytes)
            .field("chunks", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

impl FileEntries {
    /// Creates (truncating) the file at `path`.
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            chunks: Vec::new(),
            sealed_len: 0,
            tail: Vec::new(),
            written: 0,
            len_bytes: 0,
            offsets: Vec::new(),
            active: Vec::new(),
        })
    }

    /// Opens the file at `path` as it was left, keeping at most `slots`
    /// records: the records are walked in order, a torn or surplus tail
    /// (records past `slots`, or a record cut short) is dropped and the
    /// file shortened to match, and `active` says which slots are live
    /// (missing bits read as dead). Returns the store and how many records
    /// it holds.
    pub(crate) fn open_existing(path: &Path, slots: u64, active: &[u64]) -> io::Result<(Self, u64)> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        // Walk the record headers: a scan of the whole file's bytes, in
        // 64 MB pieces so the tree's rebuild does not hold the file twice.
        use std::io::Read;
        let mut offsets: Vec<u64> = Vec::new();
        let mut at = 0u64;
        let mut header = [0u8; KEY_LEN + LEN_LEN];
        file.seek(io::SeekFrom::Start(0))?;
        let mut reader = std::io::BufReader::with_capacity(8 << 20, &mut file);
        while (offsets.len() as u64) < slots && at + (KEY_LEN + LEN_LEN) as u64 <= len {
            reader.read_exact(&mut header)?;
            let value_len = u32::from_le_bytes([header[32], header[33], header[34], header[35]]) as u64;
            let end = at + (KEY_LEN + LEN_LEN) as u64 + value_len;
            if end > len {
                break; // torn tail
            }
            offsets.push(at);
            // Skip the value.
            std::io::copy(&mut reader.by_ref().take(value_len), &mut std::io::sink())?;
            at = end;
        }
        drop(reader);
        let kept = offsets.len() as u64;
        let len_bytes = at;
        file.set_len(len_bytes)?;
        let mut store = Self {
            path: path.to_path_buf(),
            file,
            chunks: Vec::new(),
            sealed_len: 0,
            tail: Vec::new(),
            written: 0,
            len_bytes,
            offsets,
            active: vec![0u64; (kept as usize).div_ceil(64)],
        };
        for (word, bits) in store.active.iter_mut().zip(active) {
            *word = *bits;
        }
        // Bits past the kept slots are cleared.
        for slot in kept as usize..store.active.len() * 64 {
            store.set_active(slot, false);
        }
        // Everything on disk is sealed into chunks; the tail starts empty.
        store.seal_existing()?;
        Ok((store, kept))
    }

    /// Maps `[0, len_bytes)` in chunks that end at record boundaries.
    fn seal_existing(&mut self) -> io::Result<()> {
        let mut start = 0u64;
        let mut slot = 0usize;
        while start < self.len_bytes {
            // The first record at or past `start + CHUNK_BYTES` ends the chunk.
            let limit = start + CHUNK_BYTES as u64;
            let mut end_slot = slot;
            while end_slot < self.offsets.len() && self.offsets[end_slot] < limit {
                end_slot += 1;
            }
            let end = if end_slot < self.offsets.len() { self.offsets[end_slot] } else { self.len_bytes };
            // SAFETY: read-only mapping of bytes that are never rewritten in
            // place (see `seal_tail`).
            let map = unsafe {
                memmap2::MmapOptions::new().offset(start).len((end - start) as usize).populate().map(&self.file)?
            };
            self.chunks.push(Chunk { start, map });
            start = end;
            slot = end_slot;
        }
        self.sealed_len = self.len_bytes;
        Ok(())
    }

    /// The active bits, one per slot, 64 to a word.
    pub(crate) fn active_bits(&self) -> &[u64] {
        &self.active
    }

    /// The file this store appends to.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn record(&self, slot: usize) -> &[u8] {
        let start = self.offsets[slot];
        let end = self.offsets.get(slot + 1).copied().unwrap_or(self.len_bytes);
        if start >= self.sealed_len {
            let s = (start - self.sealed_len) as usize;
            let e = (end - self.sealed_len) as usize;
            &self.tail[s..e]
        } else {
            // A record never straddles two chunks: a chunk is sealed at a
            // record boundary.
            let i = self.chunks.partition_point(|chunk| chunk.start <= start) - 1;
            let chunk = &self.chunks[i];
            &chunk.map[(start - chunk.start) as usize..(end - chunk.start) as usize]
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.offsets.len()
    }

    pub(crate) fn key(&self, slot: usize) -> Hash {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&self.record(slot)[..KEY_LEN]);
        key
    }

    pub(crate) fn value(&self, slot: usize) -> &[u8] {
        &self.record(slot)[KEY_LEN + LEN_LEN..]
    }

    pub(crate) fn is_active(&self, slot: usize) -> bool {
        (self.active[slot / 64] >> (slot % 64)) & 1 == 1
    }

    pub(crate) fn set_active(&mut self, slot: usize, active: bool) {
        if active {
            self.active[slot / 64] |= 1 << (slot % 64);
        } else {
            self.active[slot / 64] &= !(1 << (slot % 64));
        }
    }

    /// Appends a live entry as the next slot: into the tail, which reaches
    /// the file at the next `flush` (a sync, a sealed chunk, a truncation).
    pub(crate) fn push(&mut self, key: &Hash, value: &[u8]) -> io::Result<()> {
        let slot = self.offsets.len();
        let record_len = KEY_LEN + LEN_LEN + value.len();
        self.tail.reserve(record_len);
        self.tail.extend_from_slice(key);
        self.tail.extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.tail.extend_from_slice(value);
        self.offsets.push(self.len_bytes);
        if self.active.len() * 64 <= slot {
            self.active.push(0);
        }
        self.set_active(slot, true);
        self.len_bytes += record_len as u64;
        if self.tail.len() >= CHUNK_BYTES {
            self.seal_tail()?;
        }
        Ok(())
    }

    /// Writes the tail's unwritten bytes to the file, in one call.
    fn flush(&mut self) -> io::Result<()> {
        if self.written < self.tail.len() {
            self.file.seek(io::SeekFrom::Start(self.sealed_len + self.written as u64))?;
            self.file.write_all(&self.tail[self.written..])?;
            self.written = self.tail.len();
        }
        Ok(())
    }

    /// Maps the tail as a chunk (page tables populated) and empties it.
    fn seal_tail(&mut self) -> io::Result<()> {
        if self.tail.is_empty() {
            return Ok(());
        }
        self.flush()?;
        // SAFETY: the mapping is read-only over bytes that `push` wrote
        // before this call and that nothing rewrites: the file is only ever
        // shortened, and a shortening below a chunk's start unmaps the chunk
        // first (`truncate`).
        let map = unsafe {
            memmap2::MmapOptions::new()
                .offset(self.sealed_len)
                .len(self.tail.len())
                .populate()
                .map(&self.file)?
        };
        self.chunks.push(Chunk { start: self.sealed_len, map });
        self.sealed_len = self.len_bytes;
        self.tail.clear();
        self.written = 0;
        self.tail.shrink_to(CHUNK_BYTES);
        Ok(())
    }

    /// Writes what the tail still holds and makes every record durable.
    pub(crate) fn sync(&mut self) -> io::Result<()> {
        self.flush()?;
        self.file.sync_data()
    }

    /// Drops every slot from `len` on, and shortens the file to match.
    pub(crate) fn truncate(&mut self, len: usize) -> io::Result<()> {
        if len >= self.offsets.len() {
            return Ok(());
        }
        let new_len_bytes = self.offsets[len];
        self.offsets.truncate(len);
        for slot in len..self.active.len() * 64 {
            self.set_active(slot, false);
        }
        self.active.truncate(len.div_ceil(64));
        self.len_bytes = new_len_bytes;
        if new_len_bytes >= self.sealed_len {
            self.tail.truncate((new_len_bytes - self.sealed_len) as usize);
            self.written = self.written.min(self.tail.len());
        } else {
            // The cut lands inside a sealed chunk: that chunk and every later
            // one go, and the chunk's bytes below the cut become the tail
            // again, re-read from the file.
            let keep = self.chunks.partition_point(|chunk| chunk.start < new_len_bytes);
            let cut = &self.chunks[keep - 1];
            let within = (new_len_bytes - cut.start) as usize;
            let mut bytes = cut.map[..within].to_vec();
            let start = cut.start;
            self.chunks.truncate(keep - 1);
            self.sealed_len = start;
            std::mem::swap(&mut self.tail, &mut bytes);
            // The chunk's bytes are on disk already.
            self.written = self.tail.len();
        }
        self.file.set_len(new_len_bytes)?;
        Ok(())
    }

    /// Reserves room for `additional` more slots' bookkeeping.
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.offsets.reserve(additional);
        self.active.reserve(additional.div_ceil(64));
    }

    /// A second handle on the same file with the same bookkeeping, for a
    /// tree that is cloned. Two handles appending to one file would corrupt
    /// it; a clone is only sensible when at most one of the two appends
    /// afterwards (a checkpoint's read, a test's comparison).
    pub(crate) fn duplicate(&self) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        let mut chunks = Vec::with_capacity(self.chunks.len());
        for chunk in &self.chunks {
            // SAFETY: as in `seal_tail`; the same sealed bytes.
            let map = unsafe {
                memmap2::MmapOptions::new().offset(chunk.start).len(chunk.map.len()).populate().map(&file)?
            };
            chunks.push(Chunk { start: chunk.start, map });
        }
        Ok(Self {
            path: self.path.clone(),
            file,
            chunks,
            sealed_len: self.sealed_len,
            tail: self.tail.clone(),
            written: self.written,
            len_bytes: self.len_bytes,
            offsets: self.offsets.clone(),
            active: self.active.clone(),
        })
    }

    /// Seals the tail now (tests: exercise the chunked reads without
    /// appending 256 MB).
    #[cfg(test)]
    fn seal_now(&mut self) -> io::Result<()> {
        self.seal_tail()
    }
}

/// The tree's entries, wherever they live.
#[derive(Debug)]
pub(crate) enum Entries {
    /// Every entry in the heap.
    Heap(Vec<Entry>),
    /// Entries in the append-only file; offsets and active bits in the heap.
    File(FileEntries),
}

impl Entries {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Heap(entries) => entries.len(),
            Self::File(file) => file.len(),
        }
    }

    pub(crate) fn key(&self, slot: usize) -> Hash {
        match self {
            Self::Heap(entries) => entries[slot].key,
            Self::File(file) => file.key(slot),
        }
    }

    pub(crate) fn value(&self, slot: usize) -> &[u8] {
        match self {
            Self::Heap(entries) => &entries[slot].value,
            Self::File(file) => file.value(slot),
        }
    }

    pub(crate) fn is_active(&self, slot: usize) -> bool {
        match self {
            Self::Heap(entries) => entries[slot].active,
            Self::File(file) => file.is_active(slot),
        }
    }

    pub(crate) fn set_active(&mut self, slot: usize, active: bool) {
        match self {
            Self::Heap(entries) => entries[slot].active = active,
            Self::File(file) => file.set_active(slot, active),
        }
    }

    pub(crate) fn entry(&self, slot: usize) -> SlotEntry {
        match self {
            Self::Heap(entries) => {
                let entry = &entries[slot];
                SlotEntry { key: entry.key, value: entry.value.clone(), active: entry.active }
            }
            Self::File(file) => SlotEntry { key: file.key(slot), value: file.value(slot).to_vec(), active: file.is_active(slot) },
        }
    }

    /// Appends a live entry as the next slot.
    pub(crate) fn push(&mut self, key: Hash, value: Vec<u8>) -> io::Result<()> {
        match self {
            Self::Heap(entries) => {
                entries.push(Entry { key, value, active: true });
                Ok(())
            }
            Self::File(file) => file.push(&key, &value),
        }
    }

    pub(crate) fn truncate(&mut self, len: usize) -> io::Result<()> {
        match self {
            Self::Heap(entries) => {
                entries.truncate(len);
                Ok(())
            }
            Self::File(file) => file.truncate(len),
        }
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        match self {
            Self::Heap(entries) => entries.reserve(additional),
            Self::File(file) => file.reserve(additional),
        }
    }

    /// Clears the active flag of every slot `held` names. In the heap, each
    /// entry checks a bitmap of the slots on the worker pool rather than
    /// 133,000 random writes in sequence; in the file the flags *are* a
    /// bitmap and the clears are the random writes, 64 slots to a word.
    pub(crate) fn retire(&mut self, held: &[Option<u64>]) {
        match self {
            Self::Heap(entries) => {
                let mut bits = vec![0u64; entries.len().div_ceil(64)];
                let mut any = false;
                for slot in held.iter().flatten() {
                    let slot = *slot as usize;
                    debug_assert!(entries[slot].active, "the index named an inactive slot");
                    bits[slot / 64] |= 1 << (slot % 64);
                    any = true;
                }
                if !any {
                    return;
                }
                let clear = |(chunk, word): (&mut [Entry], &u64)| {
                    if *word != 0 {
                        for (i, entry) in chunk.iter_mut().enumerate() {
                            if (*word >> i) & 1 == 1 {
                                entry.active = false;
                            }
                        }
                    }
                };
                #[cfg(feature = "rayon")]
                {
                    use rayon::prelude::*;
                    entries.par_chunks_mut(64).zip(bits.par_iter()).for_each(clear);
                }
                #[cfg(not(feature = "rayon"))]
                {
                    entries.chunks_mut(64).zip(bits.iter()).for_each(clear);
                }
            }
            Self::File(file) => {
                for slot in held.iter().flatten() {
                    debug_assert!(file.is_active(*slot as usize), "the index named an inactive slot");
                    file.set_active(*slot as usize, false);
                }
            }
        }
    }

    /// Makes the file's appends durable; nothing to do for the heap.
    pub(crate) fn sync(&mut self) -> io::Result<()> {
        match self {
            Self::Heap(_) => Ok(()),
            Self::File(file) => file.sync(),
        }
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Heap(entries) => Ok(Self::Heap(entries.clone())),
            Self::File(file) => file.duplicate().map(Self::File),
        }
    }

    /// The active bits, one per slot, 64 to a word (built from the entries
    /// in the heap).
    pub(crate) fn active_bits(&self) -> Vec<u64> {
        match self {
            Self::Heap(entries) => {
                let mut bits = vec![0u64; entries.len().div_ceil(64)];
                for (slot, entry) in entries.iter().enumerate() {
                    if entry.active {
                        bits[slot / 64] |= 1 << (slot % 64);
                    }
                }
                bits
            }
            Self::File(file) => file.active_bits().to_vec(),
        }
    }

    /// Where the entries are, for a caller deciding whether to move them.
    pub(crate) fn file_path(&self) -> Option<&Path> {
        match self {
            Self::Heap(_) => None,
            Self::File(file) => Some(file.path()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("n42-entry-store-{name}-{}", std::process::id())).join("entries.log")
    }

    #[test]
    fn the_file_store_reads_back_what_it_appended_across_remaps_and_truncations() {
        let mut file = FileEntries::create(&scratch("roundtrip")).unwrap();
        let key = |i: usize| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_le_bytes());
            k
        };
        for i in 0..1000 {
            file.push(&key(i), &vec![(i % 256) as u8; 1 + i % 50]).unwrap();
        }
        assert_eq!(file.len(), 1000);
        assert_eq!(file.value(999), &vec![(999 % 256) as u8; 1 + 999 % 50][..]);
        assert_eq!(file.key(17), key(17));
        assert!(file.is_active(17));
        file.set_active(17, false);
        assert!(!file.is_active(17));
        // Seal a chunk, then read through the chunk and the tail both.
        file.seal_now().unwrap();
        for i in 1000..1200 {
            file.push(&key(i), &[7u8; 3]).unwrap();
        }
        assert_eq!(file.value(500), &vec![(500 % 256) as u8; 1 + 500 % 50][..]);
        assert_eq!(file.value(1100), &[7u8; 3]);
        // Truncate into the sealed chunk, then append over it.
        file.truncate(800).unwrap();
        assert_eq!(file.len(), 800);
        file.push(&key(9000), &[9u8; 4]).unwrap();
        assert_eq!(file.len(), 801);
        assert_eq!(file.value(800), &[9u8; 4]);
        assert_eq!(file.value(799), &vec![(799 % 256) as u8; 1 + 799 % 50][..]);
        assert!(file.is_active(800));
        let copy = file.duplicate().unwrap();
        assert_eq!(copy.len(), 801);
        assert_eq!(copy.value(800), &[9u8; 4]);
        assert!(!copy.is_active(17));
    }

    /// The file store must be the heap store to every caller: same roots
    /// block after block, same snapshots, same undo behaviour, same proofs.
    #[test]
    fn a_file_backed_tree_matches_a_heap_tree_through_blocks_reverts_and_proofs() {
        use crate::qmdb_compat::{QmdbCompatTree, QmdbOperation};
        let key = |n: u64| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&n.to_le_bytes());
            k
        };
        // A block: keys `base..base+n` set to a value tagged by the block,
        // sorted by key as the block path requires.
        let block = |base: u64, n: u64, tag: u8| -> Vec<QmdbOperation> {
            let mut ops: Vec<QmdbOperation> =
                (base..base + n).map(|i| QmdbOperation { key: key(i), value: Some(vec![tag; 40 + (i % 7) as usize]) }).collect();
            ops.sort_unstable_by_key(|op| op.key);
            ops
        };
        let mut heap = QmdbCompatTree::new();
        let mut file = QmdbCompatTree::new();
        // Seed both before the move, so the move copies a non-empty set.
        for tree in [&mut heap, &mut file] {
            tree.apply_sorted_ops(block(0, 5000, 1)).unwrap();
        }
        file.set_entry_file(&scratch("parity")).unwrap();
        assert!(file.entry_file().is_some());
        assert_eq!(heap.root(), file.root());

        let mut undos = Vec::new();
        for b in 0..12u64 {
            // Overlapping ranges: every block retires some slots and appends
            // across twig boundaries.
            let ops = block(b * 900, 3000, 10 + b as u8);
            let (root_h, undo_h) = heap.apply_sorted_ops_recorded(ops.clone()).unwrap();
            let (root_f, undo_f) = file.apply_sorted_ops_recorded(ops).unwrap();
            assert_eq!(root_h, root_f, "block {b}");
            // The file tree's record names the same slots but carries no
            // content (it reads a key at revival instead).
            assert!(undo_f.slots_only && !undo_h.slots_only);
            assert_eq!(undo_h.prev_next_slot, undo_f.prev_next_slot);
            assert_eq!(undo_h.appended_keys, undo_f.appended_keys);
            assert_eq!(
                undo_h.entries.iter().map(|e| e.slot).collect::<Vec<_>>(),
                undo_f.entries.iter().map(|e| e.slot).collect::<Vec<_>>(),
                "retired slots of block {b}"
            );
            assert_eq!(heap.snapshot(), file.snapshot(), "snapshot after block {b}");
            undos.push(undo_f);
        }
        assert_eq!(heap.get(&key(1234)), file.get(&key(1234)));
        assert_eq!(heap.prove(&key(1234)), file.prove(&key(1234)));
        // Revert the last three blocks on both, newest first -- the file
        // tree from its slot-only records, the heap tree from the same
        // records (a heap tree revives from a slot-only record by reading
        // the key too).
        for undo in undos.iter().rev().take(3) {
            heap.apply_undo(undo).unwrap();
            file.apply_undo(undo).unwrap();
            assert_eq!(heap.root(), file.root());
            assert_eq!(heap.next_slot(), file.next_slot());
        }
        // A slot-only record from another history is refused: its appended
        // keys are not what the slots hold.
        let mut foreign = undos[5].clone();
        foreign.prev_next_slot = file.next_slot() - foreign.appended_keys.len() as u64;
        assert!(file.apply_undo(&foreign).is_err());
        assert_eq!(heap.snapshot(), file.snapshot(), "after the reverts");
        // A different block on the reverted state, then the file's clone
        // reads the same state.
        let ops = block(777, 2500, 99);
        assert_eq!(heap.apply_sorted_ops(ops.clone()).unwrap(), file.apply_sorted_ops(ops).unwrap());
        let copy = file.clone();
        assert_eq!(copy.root(), file.root());
        assert_eq!(copy.snapshot(), file.snapshot());
        assert_eq!(copy.prove(&key(800)), heap.prove(&key(800)));
    }

    /// Trimming a twig keeps the world root and every proof of a live key,
    /// never touches a twig within the window, and a tree keeps working
    /// (new blocks, snapshots) with trimmed twigs in it.
    #[test]
    fn trimmed_twigs_keep_the_root_and_the_proofs_of_live_keys() {
        use crate::qmdb_compat::{QmdbCompatTree, QmdbOperation};
        use crate::TWIG_SIZE;
        let key = |n: u64| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&n.to_le_bytes());
            k
        };
        let block = |base: u64, n: u64, tag: u8| -> Vec<QmdbOperation> {
            let mut ops: Vec<QmdbOperation> =
                (base..base + n).map(|i| QmdbOperation { key: key(i), value: Some(vec![tag; 20]) }).collect();
            ops.sort_unstable_by_key(|op| op.key);
            ops
        };
        let mut tree = QmdbCompatTree::new();
        // Three twigs' worth of keys, then every one of them rewritten: the
        // first three twigs are all dead, the last ones live.
        let n = 3 * TWIG_SIZE as u64;
        tree.apply_sorted_ops(block(0, n, 1)).unwrap();
        let cursor_after_first = tree.next_slot();
        tree.apply_sorted_ops(block(0, n, 2)).unwrap();
        let root = tree.root();
        let proof = tree.prove(&key(5)).unwrap();
        assert_eq!(tree.trimmed_twigs(), 0);
        // Nothing before the first block's cursor was retired before it.
        assert_eq!(tree.trim_dead_twigs(cursor_after_first), 0, "the retirements are at the second block's cursor");
        // With the window past the second block, the three dead twigs go.
        let trimmed = tree.trim_dead_twigs(tree.next_slot() + 1);
        assert_eq!(trimmed, 3);
        assert_eq!(tree.trimmed_twigs(), 3);
        assert_eq!(tree.root(), root);
        assert_eq!(tree.prove(&key(5)), Some(proof));
        let snap = tree.snapshot();
        assert_eq!(snap.entries.len() as u64, 2 * n);
        // Life goes on: another block, and the root still matches a tree
        // that was never trimmed.
        let mut untrimmed = QmdbCompatTree::from_snapshot(&snap).unwrap();
        let ops = block(10, 100, 3);
        assert_eq!(tree.apply_sorted_ops(ops.clone()).unwrap(), untrimmed.apply_sorted_ops(ops).unwrap());
        // A file-backed tree trims the same way.
        let mut file = QmdbCompatTree::from_snapshot(&snap).unwrap();
        file.set_entry_file(&scratch("trim")).unwrap();
        assert_eq!(file.trim_dead_twigs(file.next_slot() + 1), 3);
        assert_eq!(file.root(), root);
    }
}
