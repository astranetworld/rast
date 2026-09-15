// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's QMDB read view as the process's latest-state reader
//! (`reth_storage_api::n42_state`, `docs/QMDB_UPGRADE_PLAN.md` stage 6).

use std::sync::Arc;

use alloy_eips::BlockNumHash;
use alloy_primitives::{Address, BlockNumber, B256, U256};
use reth_primitives_traits::Account;
use reth_storage_api::n42_state::{self, N42StateReader, ReadsMode};

use crate::QmdbNodeState;

/// Answers state reads from the node's QMDB read view and moves the view as
/// the database persists.
#[derive(Debug, Clone)]
pub struct QmdbStateReader {
    state: QmdbNodeState,
}

impl N42StateReader for QmdbStateReader {
    fn account(&self, address: &Address, version: BlockNumber) -> Option<Option<Account>> {
        self.state.read_view_ref()?.account(address, version)
    }

    fn storage(&self, address: &Address, slot: &B256, version: BlockNumber) -> Option<Option<U256>> {
        self.state.read_view_ref()?.storage(address, slot, version)
    }

    fn on_state_persisted(&self, blocks: &[BlockNumHash]) {
        let blocks: Vec<(u64, B256)> = blocks.iter().map(|block| (block.number, block.hash)).collect();
        self.state.on_persisted(&blocks);
    }

    fn on_state_unwound(&self, block: BlockNumber) {
        self.state.on_unwound(block);
    }
}

/// Whether `N42_HASHED_TABLES=off` can hold: it needs `N42_QMDB_READS=on` and a registered
/// reader, since nothing else would answer the latest state once the tables stop being
/// written. Called at startup, after registration.
pub fn check_hashed_tables_setting() -> Result<(), &'static str> {
    if n42_state::hashed_tables_off() && (n42_state::mode() != ReadsMode::On || n42_state::registered().is_none()) {
        return Err("N42_HASHED_TABLES=off stops writing HashedAccounts/HashedStorages, which only a registered QMDB read view in N42_QMDB_READS=on replaces; this node has none");
    }
    Ok(())
}

/// Registers the node's read view as the process's state reader, when
/// `N42_QMDB_READS` asks for one and initialisation built the view. Returns
/// whether it did.
pub fn register_state_reader(state: &QmdbNodeState) -> bool {
    if n42_state::mode() == ReadsMode::Off || state.read_view_ref().is_none() {
        return false;
    }
    n42_state::register(Arc::new(QmdbStateReader { state: state.clone() }))
}
