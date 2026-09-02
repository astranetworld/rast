// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node service that turns the HotStuff-2 pieces into a fleet member.
//!
//! `n42-h2-net` carries bytes, `n42-h2-consensus` decides what they mean, and
//! `n42-h2-execution` runs the blocks. Each is independently testable and none
//! of them knows about the others. [`H2Service`] is the loop that connects them:
//! inbound envelopes become consensus events, engine outputs become published
//! envelopes and execution calls, and the execution layer's answers come back as
//! further consensus events.
//!
//! This is the layer that was missing between "follows a gov5 fleet" and
//! "participates in one". A node running [`H2Service`] votes.
//!
//! It deliberately does not own peer discovery, key management, or persistence —
//! those belong to whatever builds the service. See `docs/N42_26_PORT.md` for
//! what `../N42-26`'s equivalent (`n42-consensus-service`) carries that this
//! does not.

pub mod persistence;
pub mod service;
pub mod tx_source;

pub mod body_channel;
pub use persistence::{ConsensusCheckpoint, ConsensusStore, FileVoteLog, StoreError};
pub use service::{H2Service, ServiceError, ServiceEvent, ProposalContext};
