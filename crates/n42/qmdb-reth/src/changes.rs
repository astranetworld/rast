// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! From what the execution client produced to what the commitment consumes.
//!
//! The one question this module answers is *which leaves a block writes*, and
//! it has to answer it the way gov5 does, because a QMDB root is a function of
//! every write that happened — a leaf written with its existing value still
//! consumes a slot and still moves the root. So this is not "the state diff";
//! it is gov5's dirty set, reconstructed from revm's bundle.
//!
//! gov5 (`IntraBlockState.computeRootViaComputer`) passes every account in
//! `stateObjectsDirty` — the journal's touched set — to the root computer,
//! copying the whole account whether or not a field changed, and for each of
//! those the slots in `dirtyStorage`, which Erigon only populates for a store
//! whose value differs from the previous one. revm's bundle is the same shape
//! from the other side: [`BundleState::state`] holds exactly the accounts a
//! transaction touched, and a bundle account's storage holds the slots whose
//! present value differs from the original. The mapping is therefore direct,
//! and deliberately does not filter "unchanged" accounts out.
//!
//! What cannot be reconstructed from a bundle is the full pre-block slot set
//! of a self-destructed contract, which gov5 wipes leaf by leaf. Post-EIP-6780
//! a contract can only self-destruct in the transaction that created it, so it
//! has no pre-block slots and the two agree; a chain that re-enables the old
//! semantics would need a storage enumerator here.

use alloy_primitives::{address, Address, B256, U256};
use n42_qmdb_state::{AccountState, BlockChanges};
use revm_database::BundleState;
use n42_twig_core::qmdb_compat::QmdbOperation;

/// The leaves a block writes, from the bundle its execution left behind.
pub fn changes_from_bundle(bundle: &BundleState) -> BlockChanges {
    let mut changes = BlockChanges::new();
    for (address, account) in &bundle.state {
        match &account.info {
            Some(info) => {
                tracing::debug!(
                    target: "n42.qmdb.changes",
                    %address, nonce = info.nonce, balance = %info.balance, code_hash = %info.code_hash,
                    "leaf: account",
                );
                // A bundle account is a state object gov5 would hold, and every
                // state object it holds is `Initialised`: live even when empty.
                changes.set_account_initialised(
                    *address,
                    AccountState {
                        nonce: info.nonce,
                        balance: info.balance,
                        code_hash: info.code_hash,
                    },
                );
            }
            // Destroyed, or touched while not existing. gov5 deletes in both
            // cases, and deleting an absent leaf is a no-op in both trees.
            None => {
                tracing::debug!(target: "n42.qmdb.changes", %address, "leaf: account deleted");
                changes.delete_account(*address);
            }
        }
        for (slot, value) in &account.storage {
            tracing::debug!(
                target: "n42.qmdb.changes",
                %address, slot = %B256::from(slot.to_be_bytes::<32>()), value = %value.present_value,
                "leaf: slot",
            );
            changes.set_storage(
                *address,
                B256::from(slot.to_be_bytes::<32>()),
                value.present_value,
            );
        }
    }
    changes
}

/// The leaves a block writes, from its execution, under the rules of the fork
/// it executed in.
///
/// `prague_active` adds the one leaf revm's bundle cannot show: see
/// [`with_prague_system_caller`].
pub fn changes_from_execution(bundle: &BundleState, prague_active: bool) -> BlockChanges {
    let mut changes = changes_from_bundle(bundle);
    if prague_active {
        with_prague_system_caller(&mut changes);
    }
    changes
}

/// The leaf operations of [`changes_from_execution`], built in parallel
/// straight from the bundle and sorted by key: the same operations
/// `changes_from_execution(bundle, prague).operations()` yields (a test
/// says so), without the change set in between. On a 147,000-account block
/// the change set (48 ms, two `BTreeMap`s) and its `operations()` (27 ms,
/// a keccak and an encoding per leaf, serial) were 75 ms of the follower's
/// 190 ms root phase; here the leaves are keyed and encoded on the worker
/// pool and sorted there too.
pub fn sorted_operations_from_execution(bundle: &BundleState, prague_active: bool) -> Vec<QmdbOperation> {
    use n42_twig_core::qmdb_compat::{encode_gov5_account_value, gov5_account_key, gov5_storage_key};
    use rayon::prelude::*;
    let accounts: Vec<(&Address, &revm_database::BundleAccount)> = bundle.state.iter().collect();
    let mut ops: Vec<QmdbOperation> = accounts
        .par_iter()
        .flat_map_iter(|(address, account)| {
            // The system caller's leaf is written below, as gov5 writes it,
            // over whatever the execution left for that address.
            let skip = prague_active && **address == PRAGUE_SYSTEM_CALLER;
            let account_op = (!skip).then(|| QmdbOperation {
                key: gov5_account_key(&address.0 .0),
                // A bundle account is a state object gov5 would hold, live
                // even when empty (`set_account_initialised`); a missing info
                // deletes the leaf.
                value: account.info.as_ref().map(|info| {
                    encode_gov5_account_value(info.nonce, &info.balance.to_be_bytes::<32>(), &info.code_hash.0)
                }),
            });
            let storage_ops = account.storage.iter().map(move |(slot, value)| QmdbOperation {
                key: gov5_storage_key(&address.0 .0, &B256::from(slot.to_be_bytes::<32>()).0),
                value: (!value.present_value.is_zero()).then(|| value.present_value.to_be_bytes::<32>().to_vec()),
            });
            account_op.into_iter().chain(storage_ops)
        })
        .collect();
    if prague_active {
        ops.push(QmdbOperation {
            key: gov5_account_key(&PRAGUE_SYSTEM_CALLER.0 .0),
            value: Some(encode_gov5_account_value(0, &U256::ZERO.to_be_bytes::<32>(), &alloy_primitives::KECCAK256_EMPTY.0)),
        });
    }
    ops.par_sort_unstable_by_key(|op| op.key);
    ops
}

/// `SYSTEM_ADDRESS` (EIP-4788): the caller of every system call.
pub const PRAGUE_SYSTEM_CALLER: Address = address!("fffffffffffffffffffffffffffffffffffffffe");

/// The caller of Prague's end-of-block system calls, as gov5 writes it.
///
/// EIP-7002 and EIP-7251 are executed by calling the request contracts from
/// `SYSTEM_ADDRESS`. Erigon's `SysCallContract` (gov5 `ProcessPragueSystemCalls`)
/// loads that caller as a state object, which puts it in the journal's dirty
/// set, and gov5's root computer writes every dirty account — so every Prague
/// block on a gov5 chain writes `0xffff…fffe` as a live, empty account: nonce
/// 0, balance 0, no code — a one-byte leaf, `[0x00]`, since gov5's
/// `isAccountEmpty` spares an initialised account and `MarshalV2` encodes an
/// empty field bitmap. reth's `SystemCaller` deliberately removes the
/// system address from the state after each call, so it never reaches the
/// bundle. Measured on the devnet: this leaf was the entire difference
/// between the two clients' roots for block 1.
///
/// EIP-4788 and EIP-2935 do not contribute it: gov5 writes those slots
/// directly (`SetState`, `StoreParentBlockHash`) rather than through a call.
pub fn with_prague_system_caller(changes: &mut BlockChanges) {
    changes.set_account_initialised(
        PRAGUE_SYSTEM_CALLER,
        AccountState {
            nonce: 0,
            balance: U256::ZERO,
            code_hash: alloy_primitives::KECCAK256_EMPTY,
        },
    );
}

pub use n42_qmdb_state::changes_from_alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_genesis::GenesisAccount;
    use alloy_primitives::{keccak256, Address, U256};
    use std::collections::BTreeMap;

    const KECCAK_EMPTY: B256 = alloy_primitives::KECCAK256_EMPTY;
    use revm_database::states::bundle_state::BundleBuilder;
    use revm_state::AccountInfo;

    const ALICE: Address = Address::with_last_byte(1);
    const BOB: Address = Address::with_last_byte(2);

    fn info(nonce: u64, balance: u64) -> AccountInfo {
        AccountInfo {
            nonce,
            balance: U256::from(balance),
            code_hash: KECCAK_EMPTY,
            code: None,
            ..Default::default()
        }
    }

    #[test]
    fn a_prague_block_writes_the_system_caller_as_an_empty_live_account() {
        let bundle = BundleState::default();
        let without = changes_from_execution(&bundle, false);
        assert_eq!(without.len(), 0);
        let with = changes_from_execution(&bundle, true);
        assert_eq!(with.len(), 1);
        // Live and empty, not deleted: gov5's root computer sees a state
        // object, and an object is a leaf.
        assert_eq!(
            with.account(&PRAGUE_SYSTEM_CALLER),
            Some(Some(&AccountState {
                nonce: 0,
                balance: U256::ZERO,
                code_hash: alloy_primitives::KECCAK256_EMPTY,
            }))
        );
        // And it is a leaf, not a deletion: gov5's `[0x00]`.
        let ops = with.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].value.as_deref(), Some(&[0u8][..]));
    }

    /// gov5 writes every touched account, changed or not, and the root moves
    /// either way. Filtering unchanged ones out here would agree with gov5 on
    /// state and disagree with it on the root.
    #[test]
    fn a_touched_but_unchanged_account_is_still_written() {
        let bundle = BundleBuilder::new(0..=0)
            .state_present_account_info(ALICE, info(1, 100))
            .state_original_account_info(ALICE, info(1, 100))
            .build();
        let changes = changes_from_bundle(&bundle);
        assert_eq!(
            changes.accounts.get(&ALICE).copied().flatten(),
            Some(AccountState {
                nonce: 1,
                balance: U256::from(100u64),
                code_hash: KECCAK_EMPTY
            }),
        );
    }

    #[test]
    fn a_destroyed_account_deletes_its_leaf_and_zeroes_its_slots() {
        let bundle = BundleBuilder::new(0..=0)
            .state_original_account_info(BOB, info(3, 7))
            .state_storage(BOB, std::iter::once((U256::from(1u64), (U256::from(9u64), U256::ZERO))).collect())
            .build();
        // No present info: the account is gone.
        let changes = changes_from_bundle(&bundle);
        assert_eq!(changes.accounts.get(&BOB), Some(&None));
        let slots = changes.storage.get(&BOB).expect("its slots are named");
        assert_eq!(slots.get(&B256::with_last_byte(1)), Some(&U256::ZERO));
        // And the operation for that slot is a deletion, not a zero leaf.
        let deletions = changes.operations().iter().filter(|op| op.value.is_none()).count();
        assert_eq!(deletions, 2, "account leaf and slot leaf both deleted");
    }

    #[test]
    fn storage_keys_are_big_endian_slot_numbers() {
        let bundle = BundleBuilder::new(0..=0)
            .state_present_account_info(ALICE, info(1, 1))
            .state_storage(
                ALICE,
                std::iter::once((U256::from(0x1234u64), (U256::ZERO, U256::from(42u64)))).collect(),
            )
            .build();
        let changes = changes_from_bundle(&bundle);
        let mut expected = [0u8; 32];
        expected[30] = 0x12;
        expected[31] = 0x34;
        assert_eq!(
            changes.storage[&ALICE].get(&B256::from(expected)),
            Some(&U256::from(42u64))
        );
    }

    #[test]
    fn a_genesis_alloc_is_block_zero() {
        let mut alloc = BTreeMap::new();
        alloc.insert(
            ALICE,
            GenesisAccount {
                balance: U256::from(1_000u64),
                nonce: Some(5),
                code: Some(alloy_primitives::Bytes::from_static(&[0x60, 0x00])),
                storage: Some([(B256::with_last_byte(1), B256::with_last_byte(9))].into()),
                private_key: None,
            },
        );
        alloc.insert(
            BOB,
            GenesisAccount {
                balance: U256::from(7u64),
                ..Default::default()
            },
        );
        let changes = changes_from_alloc(&alloc);

        let alice = changes.accounts[&ALICE].unwrap();
        assert_eq!(alice.nonce, 5);
        assert_eq!(alice.code_hash, keccak256([0x60, 0x00]));
        assert_eq!(
            changes.storage[&ALICE][&B256::with_last_byte(1)],
            U256::from(9u64)
        );

        let bob = changes.accounts[&BOB].unwrap();
        assert_eq!(bob.nonce, 0);
        assert_eq!(bob.code_hash, KECCAK_EMPTY, "no code means the empty-code hash");
        assert!(!changes.storage.contains_key(&BOB));
    }
}

#[cfg(test)]
mod state_commit_bench {
    //! `cargo test -p n42-qmdb-reth --release state_commit_bench -- --ignored --nocapture`:
    //! where the follower's QMDB root phase goes for a bench-tier block
    //! (147,000 accounts touched: 14,000 created, 133,000 updated) on a tree
    //! that already holds a few million accounts.
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use n42_qmdb_state::QmdbForest;
    use revm_state::AccountInfo;
    use revm_database::{BundleAccount, BundleState};

    fn addr(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[..8].copy_from_slice(&(i.wrapping_mul(0x9e3779b97f4a7c15)).to_be_bytes());
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    fn bundle(ids: impl Iterator<Item = u64>, existed: bool) -> BundleState {
        let mut b = BundleState::default();
        for i in ids {
            let info = AccountInfo { balance: U256::from(1_000_000u64 + i), nonce: i % 7, ..Default::default() };
            let original = existed.then(|| AccountInfo { balance: U256::from(i), nonce: i % 7, ..Default::default() });
            b.state.insert(addr(i), BundleAccount::new(original, Some(info), Default::default(), revm_database::AccountStatus::Changed));
        }
        b
    }

    #[test]
    fn sorted_operations_are_the_change_sets_operations() {
        // Updated accounts, new accounts, a deleted one, an empty-but-live
        // one, storage with a zero (deleting) slot, and the system caller
        // both present in the bundle and absent.
        let mut b = bundle(0..500, true);
        for (a, acc) in bundle(10_000..10_200, false).state {
            b.state.insert(a, acc);
        }
        b.state.insert(addr(77), BundleAccount::new(Some(AccountInfo::default()), None, Default::default(), revm_database::AccountStatus::Destroyed));
        b.state.insert(addr(78), BundleAccount::new(None, Some(AccountInfo::default()), Default::default(), revm_database::AccountStatus::InMemoryChange));
        let mut storage = std::collections::HashMap::default();
        storage.insert(U256::from(1), revm_database::states::StorageSlot::new_changed(U256::ZERO, U256::from(9)));
        storage.insert(U256::from(2), revm_database::states::StorageSlot::new_changed(U256::from(5), U256::ZERO));
        b.state.insert(addr(79), BundleAccount::new(Some(AccountInfo::default()), Some(AccountInfo::default()), storage, revm_database::AccountStatus::Changed));
        for prague in [false, true] {
            let mut with_caller = b.clone();
            with_caller.state.insert(PRAGUE_SYSTEM_CALLER, BundleAccount::new(None, Some(AccountInfo { nonce: 3, ..Default::default() }), Default::default(), revm_database::AccountStatus::Changed));
            for bundle in [&b, &with_caller] {
                let mut expected = changes_from_execution(bundle, prague).operations();
                expected.sort_unstable_by_key(|op| op.key);
                let got = sorted_operations_from_execution(bundle, prague);
                assert_eq!(got.len(), expected.len(), "count (prague {prague})");
                for (g, e) in got.iter().zip(&expected) {
                    assert_eq!(g.key, e.key, "key (prague {prague})");
                    assert_eq!(g.value, e.value, "value (prague {prague})");
                }
            }
        }
    }

    #[test]
    #[ignore = "timing"]
    fn where_the_root_phase_goes() {
        // A tree with 3,000,000 accounts, in blocks of 147,000.
        let genesis = changes_from_bundle(&bundle(0..1000, false));
        let mut forest = QmdbForest::genesis(B256::ZERO, &genesis).expect("genesis");
        let mut parent = B256::ZERO;
        let mut next = 1000u64;
        for n in 1..=20u64 {
            let changes = changes_from_bundle(&bundle(next..next + 147_000, false));
            let hash = B256::from(U256::from(n));
            forest.apply(parent, hash, n, &changes).expect("apply");
            forest.set_canonical(hash).expect("canonical");
            parent = hash;
            next += 147_000;
        }
        // The block under test: 133,000 updates of existing accounts, 14,000 new.
        let mut b = bundle(1000..134_000, true);
        for (a, acc) in bundle(next..next + 14_000, false).state {
            b.state.insert(a, acc);
        }
        for round in 0..3 {
            let at = std::time::Instant::now();
            let changes = changes_from_execution(&b, true);
            let t_changes = at.elapsed();
            let at = std::time::Instant::now();
            let ops = changes.operations();
            let t_ops = at.elapsed();
            let at = std::time::Instant::now();
            let mut sorted = ops.clone();
            sorted.sort_unstable_by_key(|o| o.key);
            let t_sort = at.elapsed();
            let at = std::time::Instant::now();
            let sorted_ops = sorted_operations_from_execution(&b, true);
            let t_sorted = at.elapsed();
            let at = std::time::Instant::now();
            let prepared = if round % 2 == 0 {
                forest.compute(parent, &changes).expect("compute")
            } else {
                forest.compute_operations(parent, sorted_ops).expect("compute_operations")
            };
            let t_compute = at.elapsed();
            let at = std::time::Instant::now();
            let hash = B256::from(U256::from(100 + round));
            forest.insert(hash, 21 + round as u64, prepared).expect("insert");
            forest.set_canonical(hash).expect("canonical");
            let t_insert = at.elapsed();
            parent = hash;
            eprintln!(
                "round {round}: changes_from_execution {t_changes:?} | operations() {t_ops:?} ({} ops) | sort alone {t_sort:?} | sorted_operations_from_execution {t_sorted:?} | {} {t_compute:?} | insert+canonical {t_insert:?}",
                ops.len(), if round % 2 == 0 { "forest.compute(changes)" } else { "forest.compute_operations(sorted)" }
            );
        }
    }
}
