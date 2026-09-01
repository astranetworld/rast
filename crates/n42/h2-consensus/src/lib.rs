// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HotStuff-2 consensus: the protocol core, the validator set, and read-only
//! finality verification.
//!
//! This carries both halves of the consensus that do not need an execution
//! engine:
//!
//! - [`protocol`] — the HotStuff-2 state machine: proposal, voting, quorum
//!   assembly, the pacemaker, view changes, and timeout certificates. Enough to
//!   *participate*, not just observe.
//! - [`validator`] — the validator set, epoch management, and leader selection.
//! - [`h2_finality`] — verify a committed gov5 H2-v4 `Decide` without running a
//!   consensus engine, for observers and mobile verifiers.
//!
//! What is deliberately absent is the binding to execution. N42-26's
//! `adapter.rs` (reth `FullConsensus`, header validation, receipts root) and its
//! `n42-consensus-service` orchestrator are not ported, because those are where
//! the reth-version wall actually is. See `docs/N42_26_PORT.md`.

pub mod error;
pub mod h2_finality;
pub mod header_profile;
pub mod protocol;
pub mod rotor;
pub mod validator;
mod validator_info;
pub mod vote_log;
pub mod wire_bridge;

pub mod committee_pool;
pub use committee_pool::{CommitteePoolConfig, CommitteePoolError, ConsensusEvidence, SimulatedCommitteePool};
pub use error::{ConsensusError, ConsensusResult};
pub use header_profile::{
    block_for_header, block_for_header_with_rewards, execution_data_for_block, gov5_receipts_root,
    gov5_rewards_root, header_view, is_empty_requests_hash, normalize_to_gov5_h2,
    normalize_to_gov5_h2_with_header, normalize_to_gov5_h2_from_header,
    execution_data_for_block_with_bal, execution_data_from_raw_parts,
    reconstruct_gov5_h2_block, reconstruct_gov5_h2_block_from, rewards_to_withdrawals, seal_hash, seal_header,
    withdrawals_to_rewards,
    validate_gov5_h2_header, verify_seal, HeaderExtra, HeaderProfileError, N42HeaderProfile,
    ReceiptView,
    EXTRA_SEAL_LEN, GOV5_EMPTY_REQUESTS_HASH, GOV5_HEADER_EXTRA_MAGIC, GOV5_NIL_HASH,
    MAX_HEADER_EXTRA_LEN,
};
pub use protocol::quorum::{
    validator_changes_hash, verify_commit_qc, verify_commit_qc_with_profile, verify_qc, verify_tc,
};
pub use protocol::state_machine::{AuthenticatedConsensusMessage, FUTURE_VIEW_WINDOW};
pub use protocol::{ConsensusEngine, ConsensusEvent, EngineOutput, Pacemaker, Phase, RoundState,
    TimeoutCollector, ViewTiming, VoteCollector};
pub use validator::{
    EpochManager, LeaderSelector, ValidatorSet, DEFAULT_MAX_HISTORICAL_EPOCHS,
    MAX_HISTORICAL_EPOCHS_LIMIT,
};
pub use validator_info::ValidatorInfo;
pub use vote_log::{NoopVoteLog, VoteLogWriter};
