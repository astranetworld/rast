// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Engine API types over [`N42Primitives`]: the built payload and the
//! payload/engine type set. reth's `EthBuiltPayload` is generic over the
//! primitives but its Engine API conversions exist only for Ethereum's, and
//! `EthEngineTypes` requires Ethereum's block; this is the same type with
//! the conversions for ours.

use alloy_eips::eip7685::Requests;
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types_engine::{
    BlobsBundleV1, BlobsBundleV2, CancunPayloadFields, ExecutionData, ExecutionPayload,
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadEnvelopeV5, ExecutionPayloadEnvelopeV6, ExecutionPayloadFieldV2,
    ExecutionPayloadSidecar, ExecutionPayloadV1, ExecutionPayloadV3, ExecutionPayloadV4,
    PayloadAttributes as EthPayloadAttributes, PraguePayloadFields,
};
use n42_tx_types::{Block, N42Primitives};
use reth_engine_primitives::EngineTypes;
use reth_ethereum_engine_primitives::{BlobSidecars, BuiltPayloadConversionError};
use reth_payload_primitives::{BuiltPayload, PayloadTypes};
use reth_primitives_traits::{NodePrimitives, RecoveredBlock, SealedBlock};
use std::sync::Arc;

/// A block this node built, with what the Engine API asks about it.
#[derive(Debug, Clone)]
pub struct N42BuiltPayload {
    block: Arc<RecoveredBlock<Block>>,
    fees: U256,
    sidecars: BlobSidecars,
    requests: Option<Requests>,
    block_access_list: Option<Bytes>,
}

impl N42BuiltPayload {
    /// A built payload with no blob sidecars.
    pub const fn new(
        block: Arc<RecoveredBlock<Block>>,
        fees: U256,
        requests: Option<Requests>,
        block_access_list: Option<Bytes>,
    ) -> Self {
        Self { block, fees, requests, sidecars: BlobSidecars::Empty, block_access_list }
    }

    /// The sealed block.
    pub fn block(&self) -> &SealedBlock<Block> {
        self.block.sealed_block()
    }

    /// The block with its senders.
    pub fn recovered_block(&self) -> &RecoveredBlock<Block> {
        &self.block
    }

    /// The block, shared.
    pub const fn block_arc(&self) -> &Arc<RecoveredBlock<Block>> {
        &self.block
    }

    /// Into the shared block.
    pub fn into_block_arc(self) -> Arc<RecoveredBlock<Block>> {
        self.block
    }

    /// The fees the block collected.
    pub const fn fees(&self) -> U256 {
        self.fees
    }

    /// The blob sidecars.
    pub const fn sidecars(&self) -> &BlobSidecars {
        &self.sidecars
    }

    /// With these sidecars.
    pub fn with_sidecars(mut self, sidecars: impl Into<BlobSidecars>) -> Self {
        self.sidecars = sidecars.into();
        self
    }

    /// `engine_getPayloadV3`.
    pub fn try_into_v3(self) -> Result<ExecutionPayloadEnvelopeV3, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, .. } = self;
        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV1::empty(),
            BlobSidecars::Eip4844(sidecars) => BlobsBundleV1::from(sidecars),
            BlobSidecars::Eip7594(_) => return Err(BuiltPayloadConversionError::UnexpectedEip7594Sidecars),
        };
        Ok(ExecutionPayloadEnvelopeV3 {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
            block_value: fees,
            should_override_builder: false,
            blobs_bundle,
        })
    }

    /// `engine_getPayloadV4`.
    pub fn try_into_v4(mut self) -> Result<ExecutionPayloadEnvelopeV4, BuiltPayloadConversionError> {
        let execution_requests = self.requests.take().unwrap_or_default();
        Ok(ExecutionPayloadEnvelopeV4 { execution_requests, envelope_inner: self.try_into_v3()? })
    }

    /// `engine_getPayloadV5`.
    pub fn try_into_v5(self) -> Result<ExecutionPayloadEnvelopeV5, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, requests, .. } = self;
        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV2::empty(),
            BlobSidecars::Eip7594(sidecars) => BlobsBundleV2::from(sidecars),
            BlobSidecars::Eip4844(_) => return Err(BuiltPayloadConversionError::UnexpectedEip4844Sidecars),
        };
        Ok(ExecutionPayloadEnvelopeV5 {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
            block_value: fees,
            should_override_builder: false,
            blobs_bundle,
            execution_requests: requests.unwrap_or_default(),
        })
    }

    /// `engine_getPayloadV6`.
    pub fn try_into_v6(self) -> Result<ExecutionPayloadEnvelopeV6, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, requests, block_access_list } = self;
        let block_access_list = block_access_list.ok_or(BuiltPayloadConversionError::MissingBlockAccessList)?;
        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV2::empty(),
            BlobSidecars::Eip7594(sidecars) => BlobsBundleV2::from(sidecars),
            BlobSidecars::Eip4844(_) => return Err(BuiltPayloadConversionError::UnexpectedEip4844Sidecars),
        };
        Ok(ExecutionPayloadEnvelopeV6 {
            execution_payload: ExecutionPayloadV4::from_block_unchecked_with_bal(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
                block_access_list,
            ),
            block_value: fees,
            should_override_builder: false,
            blobs_bundle,
            execution_requests: requests.unwrap_or_default(),
        })
    }

    /// The payload and sidecar `engine_newPayload` would carry.
    pub fn into_execution_data(self) -> ExecutionData {
        let Self { block, requests, block_access_list, .. } = self;
        let block_hash = block.hash();
        let block = Arc::unwrap_or_clone(block).into_block();
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked_with_extras(block_hash, &block, block_access_list);
        let sidecar = if let Some(requests) = requests {
            block.header.parent_beacon_block_root.map_or(sidecar, |parent_beacon_block_root| {
                ExecutionPayloadSidecar::v4(
                    CancunPayloadFields {
                        parent_beacon_block_root,
                        versioned_hashes: block.body.blob_versioned_hashes_iter().copied().collect(),
                    },
                    PraguePayloadFields::new(requests),
                )
            })
        } else {
            sidecar
        };
        ExecutionData::new(payload, sidecar)
    }
}

impl BuiltPayload for N42BuiltPayload {
    type Primitives = N42Primitives;

    fn block(&self) -> &SealedBlock<Block> {
        self.block.sealed_block()
    }

    fn fees(&self) -> U256 {
        self.fees
    }

    fn block_access_list(&self) -> Option<&Bytes> {
        self.block_access_list.as_ref()
    }

    fn requests(&self) -> Option<Requests> {
        self.requests.clone()
    }
}

impl From<N42BuiltPayload> for ExecutionPayloadV1 {
    fn from(value: N42BuiltPayload) -> Self {
        Self::from_block_unchecked(value.block().hash(), &Arc::unwrap_or_clone(value.block).into_block())
    }
}

impl From<N42BuiltPayload> for ExecutionPayloadEnvelopeV2 {
    fn from(value: N42BuiltPayload) -> Self {
        let N42BuiltPayload { block, fees, .. } = value;
        Self {
            block_value: fees,
            execution_payload: ExecutionPayloadFieldV2::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
        }
    }
}

impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV3 {
    type Error = BuiltPayloadConversionError;
    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v3()
    }
}

impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV4 {
    type Error = BuiltPayloadConversionError;
    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v4()
    }
}

impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV5 {
    type Error = BuiltPayloadConversionError;
    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v5()
    }
}

impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV6 {
    type Error = BuiltPayloadConversionError;
    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v6()
    }
}

impl From<N42BuiltPayload> for ExecutionData {
    fn from(value: N42BuiltPayload) -> Self {
        value.into_execution_data()
    }
}

impl From<N42BuiltPayload> for reth_engine_primitives::BigBlockData<ExecutionData> {
    fn from(_value: N42BuiltPayload) -> Self {
        unreachable!("payload building is not supported for big blocks");
    }
}

/// The Engine API type set of the node: Ethereum's payload attributes and
/// execution data, [`N42BuiltPayload`] as the built payload.
#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct N42EngineTypes;

impl PayloadTypes for N42EngineTypes {
    type BuiltPayload = N42BuiltPayload;
    type PayloadAttributes = EthPayloadAttributes;
    type ExecutionData = ExecutionData;

    fn block_to_payload(
        block: SealedBlock<<<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block>,
        bal: Option<Bytes>,
    ) -> Self::ExecutionData {
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked_with_extras(block.hash(), &block.into_block(), bal);
        ExecutionData { payload, sidecar }
    }
}

impl EngineTypes for N42EngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
    type ExecutionPayloadEnvelopeV5 = ExecutionPayloadEnvelopeV5;
    type ExecutionPayloadEnvelopeV6 = ExecutionPayloadEnvelopeV6;
}
