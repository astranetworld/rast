// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42: a process-wide reader that can answer latest-state account and storage reads instead of
//! the hashed tables (`docs/QMDB_UPGRADE_PLAN.md`, stage 6).
//!
//! On a QMDB chain the node registers its QMDB read view here at startup. The providers that read
//! `HashedAccounts`/`HashedStorages` as the latest state ask it first, at the version those tables
//! stand at in their read transaction (the `Finish` checkpoint's partial state/trie frontier, or
//! `Finish` itself). `N42_QMDB_READS` chooses what the answer is used for:
//!
//! - `off` (or unset): the reader is not asked;
//! - `verify`: the database answers, the reader's answer is compared and mismatches are counted
//!   and logged;
//! - `on`: the reader answers whenever it can; the database answers what it declines.
//!
//! A reader declines (`None`) whatever it cannot answer exactly. Persistence and unwinds tell it
//! how the tables moved. Nothing here changes behaviour while no reader is registered.

use alloc::sync::Arc;
use alloy_eips::BlockNumHash;
use alloy_primitives::{Address, BlockNumber, B256, U256};
use core::sync::atomic::{AtomicU64, Ordering};
use reth_primitives_traits::Account;
use std::sync::OnceLock;

/// What registered answers are used for (`N42_QMDB_READS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadsMode {
    /// The reader is not asked.
    Off,
    /// The database answers; the reader's answers are checked against it.
    Verify,
    /// The reader answers what it can.
    On,
}

/// A reader of the latest state at a version.
pub trait N42StateReader: Send + Sync + 'static {
    /// The account at `address` as of block `version`: `None` if the reader cannot answer
    /// exactly, `Some(None)` if the account does not exist.
    fn account(&self, address: &Address, version: BlockNumber) -> Option<Option<Account>>;

    /// The storage slot as of block `version`: `None` if the reader cannot answer exactly,
    /// `Some(None)` for a zero slot.
    fn storage(&self, address: &Address, slot: &B256, version: BlockNumber) -> Option<Option<U256>>;

    /// The hashed state of `blocks` (ascending) was written, ahead of its commit.
    fn on_state_persisted(&self, blocks: &[BlockNumHash]);

    /// The hashed state above `block` is being unwound.
    fn on_state_unwound(&self, block: BlockNumber);
}

static READER: OnceLock<Arc<dyn N42StateReader>> = OnceLock::new();

/// The mode, read from `N42_QMDB_READS` once.
pub fn mode() -> ReadsMode {
    static MODE: OnceLock<ReadsMode> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("N42_QMDB_READS").as_deref() {
        Ok("on") => ReadsMode::On,
        Ok("verify") => ReadsMode::Verify,
        _ => ReadsMode::Off,
    })
}

/// Registers the process's reader. Returns `false` if one was registered already.
pub fn register(reader: Arc<dyn N42StateReader>) -> bool {
    READER.set(reader).is_ok()
}

/// The registered reader, whatever the mode (persistence and unwinds keep it current).
pub fn registered() -> Option<&'static dyn N42StateReader> {
    READER.get().map(|reader| reader.as_ref())
}

/// The registered reader and the mode, when reads should consult it.
#[inline]
pub fn reader() -> Option<(&'static dyn N42StateReader, ReadsMode)> {
    let reader = READER.get()?;
    match mode() {
        ReadsMode::Off => None,
        mode => Some((reader.as_ref(), mode)),
    }
}

static CHECKS: AtomicU64 = AtomicU64::new(0);
static MISMATCHES: AtomicU64 = AtomicU64::new(0);
static DECLINES: AtomicU64 = AtomicU64::new(0);
static ANSWERS: AtomicU64 = AtomicU64::new(0);
/// The first mismatches' descriptions, for a caller that cannot see the log.
static RECENT: std::sync::Mutex<alloc::vec::Vec<alloc::string::String>> = std::sync::Mutex::new(alloc::vec::Vec::new());
const RECENT_CAP: usize = 32;

/// The descriptions of the first mismatches since startup (at most 32).
pub fn recent_mismatches() -> alloc::vec::Vec<alloc::string::String> {
    RECENT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

/// Counters since startup: `(checks, mismatches, declines, answers)` -- verify-mode comparisons,
/// the ones that disagreed, reads the reader declined, and reads it answered in `on` mode.
pub fn stats() -> (u64, u64, u64, u64) {
    (
        CHECKS.load(Ordering::Relaxed),
        MISMATCHES.load(Ordering::Relaxed),
        DECLINES.load(Ordering::Relaxed),
        ANSWERS.load(Ordering::Relaxed),
    )
}

/// Counts a read the reader declined.
#[inline]
pub fn record_decline() {
    DECLINES.fetch_add(1, Ordering::Relaxed);
}

/// Counts a read the reader answered.
#[inline]
pub fn record_answer() {
    ANSWERS.fetch_add(1, Ordering::Relaxed);
}

fn record_check(matched: bool, describe: impl FnOnce() -> String) {
    let checks = CHECKS.fetch_add(1, Ordering::Relaxed) + 1;
    if !matched {
        let mismatches = MISMATCHES.fetch_add(1, Ordering::Relaxed) + 1;
        if mismatches <= RECENT_CAP as u64 || mismatches.is_power_of_two() {
            let detail = describe();
            tracing::warn!(target: "n42::qmdb_reads", mismatches, checks, %detail, "QMDB read disagrees with the database");
            let mut recent = RECENT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if recent.len() < RECENT_CAP {
                recent.push(detail);
            }
        }
    }
    if checks.is_power_of_two() && checks >= 1 << 16 {
        let (_, mismatches, declines, _) = stats();
        tracing::info!(target: "n42::qmdb_reads", checks, mismatches, declines, "QMDB read verification");
    }
}

/// Compares an account the reader answered with the database's. An account's code hash is
/// compared as the EVM sees it (no hash is the empty-code hash).
pub fn verify_account(address: &Address, version: BlockNumber, reader: &Option<Account>, database: &Option<Account>) {
    let same = match (reader, database) {
        (Some(a), Some(b)) => {
            a.nonce == b.nonce && a.balance == b.balance && a.get_bytecode_hash() == b.get_bytecode_hash()
        }
        (None, None) => true,
        _ => false,
    };
    record_check(same, || format!("account {address} at {version}: qmdb {reader:?}, database {database:?}"));
}

/// Compares a storage slot the reader answered with the database's (absent and zero are the same).
pub fn verify_storage(address: &Address, slot: &B256, version: BlockNumber, reader: Option<U256>, database: Option<U256>) {
    let same = reader.unwrap_or_default() == database.unwrap_or_default();
    record_check(same, || format!("slot {slot} of {address} at {version}: qmdb {reader:?}, database {database:?}"));
}
