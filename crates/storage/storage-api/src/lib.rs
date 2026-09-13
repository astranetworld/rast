//! Collection of traits and types for common storage access.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Re-export used error types.
pub use reth_storage_errors as errors;
mod bal;
pub use bal::*;

mod account;
pub use account::*;

mod block;
pub use block::*;

mod block_id;
pub use block_id::*;

mod block_hash;
pub use block_hash::*;

#[cfg(feature = "db-api")]
mod chain;
#[cfg(feature = "db-api")]
pub use chain::*;

mod header;
pub use header::*;

mod prune_checkpoint;
pub use prune_checkpoint::*;

mod receipts;
pub use receipts::*;

mod stage_checkpoint;
pub use stage_checkpoint::*;

mod state;
pub use state::*;

mod storage;
pub use storage::*;

mod transactions;
pub use transactions::*;

mod trie;
pub use trie::*;

mod chain_info;
pub use chain_info::*;

#[cfg(feature = "db-api")]
mod database_provider;
#[cfg(feature = "db-api")]
pub use database_provider::*;

pub mod noop;

/// N42: the latest-state reader registry (a QMDB read view on a QMDB chain).
#[cfg(feature = "std")]
pub mod n42_state;

#[cfg(feature = "db-api")]
mod history;
#[cfg(feature = "db-api")]
pub use history::*;

#[cfg(feature = "db-api")]
mod hashing;
#[cfg(feature = "db-api")]
pub use hashing::*;

#[cfg(feature = "db-api")]
mod stats;
#[cfg(feature = "db-api")]
pub use stats::*;

mod primitives;
pub use primitives::*;

mod block_indices;
pub use block_indices::*;

#[cfg(feature = "std")]
mod block_writer;
#[cfg(feature = "std")]
pub use block_writer::*;

mod state_writer;
pub use state_writer::*;

mod header_sync_gap;
pub use header_sync_gap::HeaderSyncGapProvider;

#[cfg(feature = "db-api")]
pub mod metadata;
#[cfg(all(feature = "db-api", feature = "std"))]
pub use metadata::StoragePath;
#[cfg(feature = "db-api")]
pub use metadata::{MetadataProvider, MetadataWriter, StorageSettingsCache};
#[cfg(feature = "db-api")]
pub use reth_db_api::models::StorageSettings;

mod full;
pub use full::*;

// Helper macros for provider trait implementations
pub mod macros;

// N42-specific beacon storage traits
mod beacon;
pub use beacon::*;

// N42-specific snapshot storage traits
mod snapshot;
pub use snapshot::*;

// N42-specific legacy traits
mod legacy;
pub use legacy::*;

// N42-specific ommers
mod ommers;
pub use ommers::*;

// N42-specific validator
mod validator;
pub use validator::*;

// N42-specific withdrawals
mod withdrawals;
pub use withdrawals::*;
