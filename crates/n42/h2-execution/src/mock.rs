// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An in-memory [`ExecutionLayer`] for testing the consensus/execution loop.
//!
//! Not a simulation of the EVM — it executes nothing. It records the Engine API
//! calls consensus makes and returns the statuses a test asks it to, which is
//! exactly what is needed to prove the driver drives the right calls in the
//! right order.

use std::sync::{Arc, Mutex};

use alloy_primitives::{B256, U256};
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, ExecutionPayloadV1, ForkchoiceState, ForkchoiceUpdated,
    PayloadAttributes, PayloadId, PayloadStatus, PayloadStatusEnum,
};

use crate::el::{ChainBlock, BuiltBlock, ElError, ExecutionLayer, ResolveKind};

/// One Engine API call the driver made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElCall {
    /// `newPayload` for a block.
    NewPayload(B256),
    /// `forkchoiceUpdated` without attributes.
    ForkchoiceUpdated(ForkchoiceState),
    /// `forkchoiceUpdated` with attributes (a build request).
    ForkchoiceUpdatedWithAttrs(ForkchoiceState),
    /// A build being resolved.
    ResolvePayload(PayloadId),
}

/// Behaviour a test wants from the execution layer.
#[derive(Debug, Clone)]
pub struct MockBehaviour {
    /// Status returned by `new_payload`.
    pub new_payload_status: PayloadStatusEnum,
    /// Whether a build request yields a payload id.
    pub start_builds: bool,
    /// Whether `new_payload` errors outright.
    pub new_payload_error: Option<String>,
}

impl Default for MockBehaviour {
    fn default() -> Self {
        Self {
            new_payload_status: PayloadStatusEnum::Valid,
            start_builds: true,
            new_payload_error: None,
        }
    }
}

#[derive(Debug, Default)]
struct MockState {
    calls: Vec<ElCall>,
    next_block: u64,
    /// Blocks this mock built or accepted, by number, for range requests
    /// and for the height it reports.
    blocks: std::collections::HashMap<u64, ChainBlock>,
}

/// An [`ExecutionLayer`] that records calls instead of executing.
#[derive(Debug, Clone)]
pub struct MockExecutionLayer {
    state: Arc<Mutex<MockState>>,
    behaviour: Arc<Mutex<MockBehaviour>>,
}

impl Default for MockExecutionLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockExecutionLayer {
    /// A mock that accepts everything.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState::default())),
            behaviour: Arc::new(Mutex::new(MockBehaviour::default())),
        }
    }

    /// A mock with specific behaviour.
    pub fn with_behaviour(behaviour: MockBehaviour) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState::default())),
            behaviour: Arc::new(Mutex::new(behaviour)),
        }
    }

    /// Replaces the behaviour mid-test.
    pub fn set_behaviour(&self, behaviour: MockBehaviour) {
        *self.behaviour.lock().expect("mock behaviour lock") = behaviour;
    }

    /// Every Engine API call made so far, in order.
    pub fn calls(&self) -> Vec<ElCall> {
        self.state.lock().expect("mock state lock").calls.clone()
    }

    fn record(&self, call: ElCall) {
        self.state.lock().expect("mock state lock").calls.push(call);
    }

    /// Builds an [`ExecutionData`] whose block hash is `hash`.
    /// A block whose hash really is the hash of its header, as a built block
    /// from a live execution layer would be. Anything that re-derives the hash
    /// from the payload — gossiping the body to followers does — needs this;
    /// a made-up hash would be refused as a lie about the block.
    pub fn built_block(number: u64) -> BuiltBlock {
        let header = alloy_consensus::Header {
            number,
            timestamp: 1_700_000_000 + number,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(7),
            transactions_root: alloy_consensus::EMPTY_ROOT_HASH,
            receipts_root: alloy_consensus::EMPTY_ROOT_HASH,
            ..Default::default()
        };
        let block = alloy_consensus::Block {
            header,
            body: alloy_consensus::BlockBody {
                transactions: Vec::<alloy_consensus::TxEnvelope>::new(),
                ommers: Vec::new(),
                withdrawals: None,
            },
        };
        let hash = block.header.hash_slow();
        BuiltBlock {
            hash,
            number,
            timestamp: block.header.timestamp,
            tx_count: 0,
            execution_data: ExecutionData::from_block_unchecked(hash, &block),
            blob_tx_hashes: Vec::new(),
            header: None,
        }
    }

    pub fn payload_for(hash: B256, number: u64) -> ExecutionData {
        ExecutionData {
            payload: ExecutionPayload::V1(ExecutionPayloadV1 {
                parent_hash: B256::ZERO,
                fee_recipient: Default::default(),
                state_root: B256::ZERO,
                receipts_root: B256::ZERO,
                logs_bloom: Default::default(),
                prev_randao: B256::ZERO,
                block_number: number,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000 + number,
                extra_data: Default::default(),
                base_fee_per_gas: U256::from(7u64),
                block_hash: hash,
                transactions: Vec::new(),
                // N42-specific: this repo's vendored alloy-rpc-types-engine adds
                // difficulty and nonce to the V1 payload (APoS carries the
                // Clique-style seal there). Upstream alloy has neither.
                difficulty: U256::ZERO,
                nonce: Default::default(),
            }),
            sidecar: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl ExecutionLayer for MockExecutionLayer {
    async fn new_payload(&self, payload: ExecutionData) -> Result<PayloadStatus, ElError> {
        let hash = payload.payload.block_hash();
        self.record(ElCall::NewPayload(hash));
        let behaviour = self.behaviour.lock().expect("mock behaviour lock").clone();
        if let Some(error) = behaviour.new_payload_error {
            return Err(ElError(error));
        }
        // An accepted block is one this mock can serve and count, as a real
        // execution layer would.
        if matches!(behaviour.new_payload_status, PayloadStatusEnum::Valid)
            && let Ok(block) = payload.clone().into_block_raw()
        {
            let number = block.header.number;
            self.state
                .lock()
                .expect("mock state lock")
                .blocks
                .insert(
                    number,
                    ChainBlock {
                        header: block.header,
                        transactions: block.body.transactions,
                        withdrawals: block.body.withdrawals.map(|w| w.0),
                    },
                );
        }
        Ok(PayloadStatus {
            status: behaviour.new_payload_status,
            latest_valid_hash: Some(hash),
        })
    }

    async fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, ElError> {
        self.record(ElCall::ForkchoiceUpdated(state));
        Ok(ForkchoiceUpdated {
            payload_status: PayloadStatus {
                status: PayloadStatusEnum::Valid,
                latest_valid_hash: Some(state.head_block_hash),
            },
            payload_id: None,
        })
    }

    async fn fork_choice_updated_with_attrs(
        &self,
        state: ForkchoiceState,
        _attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError> {
        self.record(ElCall::ForkchoiceUpdatedWithAttrs(state));
        let start = self.behaviour.lock().expect("mock behaviour lock").start_builds;
        Ok(ForkchoiceUpdated {
            payload_status: PayloadStatus {
                status: PayloadStatusEnum::Valid,
                latest_valid_hash: Some(state.head_block_hash),
            },
            payload_id: start.then(|| PayloadId::new([1, 2, 3, 4, 5, 6, 7, 8])),
        })
    }

    async fn latest_block_number(&self) -> Result<Option<u64>, ElError> {
        Ok(Some(self.state.lock().expect("mock state lock").blocks.keys().copied().max().unwrap_or(0)))
    }

    async fn block_by_hash(&self, hash: B256) -> Result<Option<ChainBlock>, ElError> {
        Ok(self
            .state
            .lock()
            .expect("mock state lock")
            .blocks
            .values()
            .find(|block| block.header.hash_slow() == hash)
            .cloned())
    }

    async fn block_by_number(&self, number: u64) -> Result<Option<ChainBlock>, ElError> {
        Ok(self.state.lock().expect("mock state lock").blocks.get(&number).cloned())
    }

    async fn resolve_payload(
        &self,
        id: PayloadId,
        _kind: ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>> {
        self.record(ElCall::ResolvePayload(id));
        let number = {
            // One past the highest block this mock has built or accepted, so
            // a fleet of mocks numbers one chain rather than one per builder.
            let mut state = self.state.lock().expect("mock state lock");
            let known = state.blocks.keys().copied().max().unwrap_or(0);
            state.next_block = state.next_block.max(known) + 1;
            state.next_block
        };
        let built = Self::built_block(number);
        if let Ok(block) = built.execution_data.clone().into_block_raw() {
            self.state
                .lock()
                .expect("mock state lock")
                .blocks
                .insert(
                    number,
                    ChainBlock {
                        header: block.header,
                        transactions: block.body.transactions,
                        withdrawals: block.body.withdrawals.map(|w| w.0),
                    },
                );
        }
        Some(Ok(built))
    }
}
