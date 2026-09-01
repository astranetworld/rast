// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Execution-layer glue for the HotStuff-2 consensus engine.
//!
//! [`n42_h2_consensus`] can propose, vote, and commit, but on its own it decides
//! about block *hashes* — it never touches a block body. This crate is the part
//! that connects it to something that actually executes: the [`el::ExecutionLayer`]
//! seam (Engine API in alloy types, no reth types) and the [`driver::ExecutionDriver`]
//! that services consensus's requests against it.
//!
//! The seam is deliberately reth-free. A concrete adapter over reth's
//! `ConsensusEngineHandle` / `PayloadBuilderHandle` implements the trait node-side,
//! which keeps the consensus half of this repo independent of the reth version —
//! the thing that made the HotStuff-2 port possible without the reth 2.4.1 upgrade
//! (see `docs/RETH_2_4_1_UPGRADE.md`).

pub mod driver;
pub mod el;
pub mod execution_path;
pub mod mock;
pub mod raw_engine;

pub use driver::{DriverAction, ExecutionDriver};
pub use el::{ChainBlock, BuiltBlock, ElError, ExecutionLayer, ResolveKind};
pub use execution_path::{ExecutionPath, ExecutionScheduling, ExecutionWorkload};
pub use mock::{ElCall, MockBehaviour, MockExecutionLayer};
