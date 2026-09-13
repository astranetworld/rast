// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A compact key -> slot index for the QMDB tree (`docs/QMDB_UPGRADE_PLAN.md`, stage 1b).
//!
//! The `HashMap<[u8; 32], u64>` it replaces holds the key itself: 40 bytes an entry before the
//! table's slack, ~60 bytes a live key in practice, 3 GB at 50 million keys. The key is already in
//! the entry store, at the slot the index names, so this index keeps only a fingerprint of it:
//!
//! - 256 shards by `key[0]`, as before, so a block's sorted appends insert per shard in parallel;
//! - in each shard an open-addressing table of `u64` buckets, `fingerprint:24 | slot + 1:40`
//!   (zero marks an empty bucket), linear probing, load at most 3/4 (10.7-21 bytes a key);
//! - the fingerprint is 24 bits of a seeded mix of `key[8..16]` (keys are hashes a sender can
//!   grind; the seed is per process and the index is never persisted), and a bucket's home is the
//!   fingerprint's top bits, so growing a table needs no key: every bucket carries its home;
//! - every fingerprint match is confirmed against the key the entry store holds at that slot
//!   (`key_at`), so a lookup is exact. A hit costs that one read, which a caller reading the value
//!   pays anyway; a miss confirms only on a full 24-bit fingerprint collision.
//!
//! Limits: a slot below 2^40 - 1 (1.1 trillion appends) and a shard below 2^24 buckets
//! (about 3.2 billion live keys in all); both are asserted.

use crate::Hash;

const SHARDS: usize = 256;
const FP_BITS: u32 = 24;
const SLOT_BITS: u32 = 40;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
/// The largest slot a bucket can name.
pub(crate) const MAX_SLOT: u64 = SLOT_MASK - 1;
const MIN_BITS: u32 = 4;
const MAX_BITS: u32 = FP_BITS;

/// A random seed per process, taken from std's randomly keyed hasher.
fn seed() -> u64 {
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SEED.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(0x6e34_325f_6964_7832);
        hasher.finish()
    })
}

/// The key's 24-bit fingerprint: splitmix64's finalizer over `key[8..16]` and the seed.
#[inline]
fn fingerprint(key: &Hash) -> u64 {
    let mut x = u64::from_le_bytes([key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]]) ^ seed();
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x >> (64 - FP_BITS)
}

#[derive(Clone, Default)]
struct Shard {
    /// `1 << bits` buckets, or none before the first insert.
    buckets: Vec<u64>,
    bits: u32,
    len: usize,
}

impl Shard {
    #[inline]
    fn home_of_fp(&self, fp: u64) -> usize {
        (fp >> (FP_BITS - self.bits)) as usize
    }

    #[inline]
    fn home_of_bucket(&self, bucket: u64) -> usize {
        self.home_of_fp(bucket >> SLOT_BITS)
    }

    #[inline]
    fn mask(&self) -> usize {
        self.buckets.len() - 1
    }

    fn get(&self, key: &Hash, key_at: &impl Fn(u64) -> Hash) -> Option<(usize, u64)> {
        if self.len == 0 {
            return None;
        }
        let fp = fingerprint(key);
        let mask = self.mask();
        let mut at = self.home_of_fp(fp);
        loop {
            let bucket = self.buckets[at];
            if bucket == 0 {
                return None;
            }
            if bucket >> SLOT_BITS == fp {
                let slot = (bucket & SLOT_MASK) - 1;
                if key_at(slot) == *key {
                    return Some((at, slot));
                }
            }
            at = (at + 1) & mask;
        }
    }

    /// Room for `len` keys at a load of at most 3/4.
    fn ensure_capacity(&mut self, len: usize) {
        let mut bits = self.bits.max(MIN_BITS);
        while (1usize << bits) * 3 < len * 4 {
            bits += 1;
        }
        if bits == self.bits && !self.buckets.is_empty() {
            return;
        }
        assert!(bits <= MAX_BITS, "QMDB key index shard over 2^{MAX_BITS} buckets");
        let old = std::mem::replace(&mut self.buckets, vec![0; 1 << bits]);
        self.bits = bits;
        let mask = self.mask();
        // Every bucket carries its home in its fingerprint: no key is read.
        for bucket in old.into_iter().filter(|bucket| *bucket != 0) {
            let mut at = self.home_of_bucket(bucket);
            while self.buckets[at] != 0 {
                at = (at + 1) & mask;
            }
            self.buckets[at] = bucket;
        }
    }

    fn insert(&mut self, key: &Hash, slot: u64, key_at: &impl Fn(u64) -> Hash) -> Option<u64> {
        assert!(slot <= MAX_SLOT, "QMDB slot {slot} beyond the key index's 40 bits");
        let fp = fingerprint(key);
        let bucket = (fp << SLOT_BITS) | (slot + 1);
        if let Some((at, old)) = self.get(key, key_at) {
            self.buckets[at] = bucket;
            return Some(old);
        }
        self.ensure_capacity(self.len + 1);
        let mask = self.mask();
        let mut at = self.home_of_fp(fp);
        while self.buckets[at] != 0 {
            at = (at + 1) & mask;
        }
        self.buckets[at] = bucket;
        self.len += 1;
        None
    }

    fn remove(&mut self, key: &Hash, key_at: &impl Fn(u64) -> Hash) -> Option<u64> {
        let (mut hole, slot) = self.get(key, key_at)?;
        self.buckets[hole] = 0;
        self.len -= 1;
        // Backward shift: pull later buckets of the run into the hole when the
        // hole lies on their probe path (cyclically within [home, position)).
        let mask = self.mask();
        let mut at = (hole + 1) & mask;
        loop {
            let bucket = self.buckets[at];
            if bucket == 0 {
                break;
            }
            let home = self.home_of_bucket(bucket);
            if (at.wrapping_sub(home) & mask) >= (at.wrapping_sub(hole) & mask) {
                self.buckets[hole] = bucket;
                self.buckets[at] = 0;
                hole = at;
            }
            at = (at + 1) & mask;
        }
        Some(slot)
    }
}

/// The key -> slot index: see the module documentation.
#[derive(Clone)]
pub(crate) struct TagIndex {
    shards: Vec<Shard>,
}

impl Default for TagIndex {
    fn default() -> Self {
        Self { shards: vec![Shard::default(); SHARDS] }
    }
}

impl TagIndex {
    /// The slot holding `key`; `key_at` reads the key the entry store holds at a slot.
    #[inline]
    pub(crate) fn get(&self, key: &Hash, key_at: impl Fn(u64) -> Hash) -> Option<u64> {
        self.shards[key[0] as usize].get(key, &key_at).map(|(_, slot)| slot)
    }

    /// Maps `key` to `slot`, returning the slot it replaced. `key_at` must
    /// already answer for every slot the index holds.
    #[inline]
    pub(crate) fn insert(&mut self, key: Hash, slot: u64, key_at: impl Fn(u64) -> Hash) -> Option<u64> {
        self.shards[key[0] as usize].insert(&key, slot, &key_at)
    }

    #[inline]
    pub(crate) fn remove(&mut self, key: &Hash, key_at: impl Fn(u64) -> Hash) -> Option<u64> {
        self.shards[key[0] as usize].remove(key, &key_at)
    }

    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|shard| shard.len).sum()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.shards.iter().all(|shard| shard.len == 0)
    }

    /// Room for `additional` more keys, spread evenly over the shards.
    pub(crate) fn reserve(&mut self, additional: usize) {
        let per = additional / SHARDS + 1;
        for shard in &mut self.shards {
            shard.ensure_capacity(shard.len + per);
        }
    }

    /// Bytes the tables hold.
    pub(crate) fn memory_bytes(&self) -> usize {
        self.shards.iter().map(|shard| shard.buckets.capacity() * 8).sum::<usize>()
            + self.shards.capacity() * std::mem::size_of::<Shard>()
    }

    /// Inserts `(key, slot)` pairs sorted by key, one shard at a time on the
    /// worker pool (every shard's pairs are one contiguous run).
    pub(crate) fn insert_sorted(&mut self, pairs: &[(Hash, u64)], key_at: impl Fn(u64) -> Hash + Sync) {
        let mut starts = [0usize; SHARDS + 1];
        let mut at = 0usize;
        for (shard, start) in starts.iter_mut().enumerate().take(SHARDS) {
            *start = at;
            while at < pairs.len() && pairs[at].0[0] as usize == shard {
                at += 1;
            }
        }
        starts[SHARDS] = pairs.len();
        debug_assert_eq!(at, pairs.len(), "pairs sorted by key");
        let work = |(index, shard): (usize, &mut Shard)| {
            let run = &pairs[starts[index]..starts[index + 1]];
            if run.is_empty() {
                return;
            }
            shard.ensure_capacity(shard.len + run.len());
            for (key, slot) in run {
                shard.insert(key, *slot, &key_at);
            }
        };
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;
            self.shards.par_iter_mut().enumerate().for_each(work);
        }
        #[cfg(not(feature = "rayon"))]
        {
            self.shards.iter_mut().enumerate().for_each(work);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A deterministic stream of 64-bit values (splitmix64).
    struct Stream(u64);
    impl Stream {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    fn key_of(n: u64, shard_byte: Option<u8>) -> Hash {
        let mut key = *blake3::hash(&n.to_le_bytes()).as_bytes();
        if let Some(byte) = shard_byte {
            key[0] = byte;
        }
        key
    }

    /// Random inserts, overwrites and removes against a `HashMap`, with a
    /// slot store standing in for the entry file (slots are append-only, as
    /// in the tree). `universe` keys in `shard` (or spread when `None`).
    fn differential(seed: u64, ops: usize, universe: u64, shard: Option<u8>) {
        let mut stream = Stream(seed);
        let mut store: Vec<Hash> = Vec::new();
        let mut index = TagIndex::default();
        let mut oracle: HashMap<Hash, u64> = HashMap::new();
        for _ in 0..ops {
            let key = key_of(stream.next() % universe, shard);
            match stream.next() % 4 {
                0 | 1 => {
                    let slot = store.len() as u64;
                    store.push(key);
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(index.insert(key, slot, key_at), oracle.insert(key, slot));
                }
                2 => {
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(index.remove(&key, key_at), oracle.remove(&key));
                }
                _ => {
                    let key_at = |slot: u64| store[slot as usize];
                    assert_eq!(index.get(&key, key_at), oracle.get(&key).copied());
                }
            }
            assert_eq!(index.len(), oracle.len());
        }
        let key_at = |slot: u64| store[slot as usize];
        for (key, slot) in &oracle {
            assert_eq!(index.get(key, key_at), Some(*slot));
        }
        for n in universe..universe + 1000 {
            assert_eq!(index.get(&key_of(n, shard), key_at), None);
        }
    }

    #[test]
    fn matches_a_hash_map_in_one_small_shard_with_wraparound_and_backward_shifts() {
        for seed in 0..20 {
            differential(seed, 20_000, 40, Some(7));
        }
    }

    #[test]
    fn matches_a_hash_map_across_shards_and_growth() {
        differential(99, 400_000, 150_000, None);
    }

    #[test]
    fn sorted_inserts_match_single_inserts() {
        let mut store: Vec<Hash> = Vec::new();
        let mut pairs: Vec<(Hash, u64)> = Vec::new();
        for n in 0..50_000u64 {
            let key = key_of(n, None);
            pairs.push((key, store.len() as u64));
            store.push(key);
        }
        pairs.sort_unstable();
        let key_at = |slot: u64| store[slot as usize];
        let mut sorted = TagIndex::default();
        sorted.reserve(1000);
        sorted.insert_sorted(&pairs[..25_000], key_at);
        sorted.insert_sorted(&pairs[25_000..], key_at);
        let mut single = TagIndex::default();
        for (key, slot) in &pairs {
            assert_eq!(single.insert(*key, *slot, key_at), None);
        }
        assert_eq!(sorted.len(), 50_000);
        for (key, slot) in &pairs {
            assert_eq!(sorted.get(key, key_at), Some(*slot));
            assert_eq!(single.get(key, key_at), Some(*slot));
        }
        assert!(sorted.memory_bytes() < 50_000 * 22, "{} bytes", sorted.memory_bytes());
    }
}
