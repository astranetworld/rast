// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A cache of 0x50 senders by transaction hash, shared by every path that
//! verifies signatures.
//!
//! reth's `SenderRecoveryCache` can only be filled through its own
//! recover-or-insert, one transaction at a time, which is exactly what batch
//! verification avoids. This cache is filled by whoever verified a batch (the
//! ingest, a follower's import) and read by the paths that would otherwise
//! verify again: the block import, the engine's own payload conversion. A
//! miss costs one verification; a hit costs a lookup.
//!
//! Sized by `N42_ALTSIG_SENDER_CACHE` (entries, a power of two; default 2^20,
//! about six blocks of the bench tier).

use alloy_primitives::{map::FbBuildHasher, Address, B256};
use std::sync::OnceLock;

struct Config;

impl fixed_cache::CacheConfig for Config {
    const STATS: bool = false;
}

/// The shared sender cache for 0x50 transactions.
pub struct AltSigSenderCache {
    cache: fixed_cache::Cache<B256, Address, FbBuildHasher<32>, Config>,
}

impl std::fmt::Debug for AltSigSenderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AltSigSenderCache").finish_non_exhaustive()
    }
}

impl AltSigSenderCache {
    /// A cache of `entries` slots; `entries` is rounded up to a power of two
    /// of at least four.
    pub fn new(entries: usize) -> Self {
        let entries = entries.max(4).next_power_of_two();
        Self { cache: fixed_cache::Cache::new(entries, FbBuildHasher::<32>::default()) }
    }

    /// The process-wide cache.
    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<AltSigSenderCache> = OnceLock::new();
        GLOBAL.get_or_init(|| {
            let entries = std::env::var("N42_ALTSIG_SENDER_CACHE")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1 << 20);
            Self::new(entries)
        })
    }

    /// The sender recorded for `hash`, if any.
    pub fn get(&self, hash: &B256) -> Option<Address> {
        self.cache.get(hash)
    }

    /// Records `sender` for `hash`.
    pub fn insert(&self, hash: B256, sender: Address) {
        self.cache.insert(hash, sender);
    }
}

static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this chain admits 0x50 transactions. Off until the node reads its
/// genesis (`altSigTx: true`) and says so with [`set_alt_sig_enabled`]; off,
/// the ingest drops them and block validation rejects a block carrying one.
pub fn alt_sig_enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Records whether the chain admits 0x50 transactions.
pub fn set_alt_sig_enabled(enabled: bool) {
    ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// The batch size for Ed25519 verification, from `N42_ED25519_BATCH`
/// (default 64, at most 256: the per-signature gain flattens past 64 and a
/// failed batch is retried one by one).
pub fn ed25519_batch_size() -> usize {
    static SIZE: OnceLock<usize> = OnceLock::new();
    *SIZE.get_or_init(|| {
        std::env::var("N42_ED25519_BATCH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(64)
            .min(256)
    })
}
