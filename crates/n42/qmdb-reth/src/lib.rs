// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! QMDB as this node's state commitment, wired into reth.
//!
//! [`n42_qmdb_state`] knows how to turn a block's changes into a root and how
//! to prove leaves against it, and holds no reth types. This crate is the other
//! half: where that root goes, and where the changes come from.
//!
//! - [`chainspec`] reads the scheme a genesis declares (`"stateScheme": "qmdb"`,
//!   the same field gov5 reads) and rebuilds the genesis header with a QMDB root,
//!   which is where the genesis hash gets decided.
//! - [`changes`] turns revm's bundle — what execution left behind — into the
//!   leaves a block writes, following gov5's dirty-set rule rather than a diff.
//! - [`node_state`] is the one forest a node keeps, shared by the payload
//!   builder, the engine validator, and the mobile endpoint, and persisted so a
//!   restart can continue the append history.
//! - [`strategy`] installs the root computation into reth's block validation
//!   through `StateRootStrategy`, a public seam that needs no fork.
//!
//! The payload builder side lives with the builder itself, in
//! `n42-engine-types`, since that builder is this repo's code.

pub mod executed_fields;
pub mod chainspec;
pub mod changes;
pub mod hotstuff;
pub mod node_state;
pub mod strategy;

pub use chainspec::{
    qmdb_genesis_root, state_scheme, with_declared_state_scheme, N42ChainSpecParser, StateScheme,
    STATE_SCHEME_KEY, STATE_SCHEME_QMDB,
};
pub use changes::{
    changes_from_alloc, changes_from_bundle, changes_from_execution, with_prague_system_caller, sorted_operations_from_execution,
};
pub use hotstuff::{GenesisValidator, HotStuffConfigError, HotStuffGenesisConfig};
/// The tree a producer computed for a block it has not yet sealed.
pub use n42_qmdb_state::forest::PreparedBlock;
pub use node_state::{NodeStateError, QmdbNodeState};
pub use strategy::{QmdbEngineValidatorBuilder, QmdbStateRootStrategy};
