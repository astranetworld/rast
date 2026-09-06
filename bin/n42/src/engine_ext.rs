// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `n42Engine`: the Engine API's `getPayload`, without the JSON.
//!
//! `engine_getPayload` answers with every transaction hex-encoded inside a
//! JSON object. At the 163,000-transaction tier that is a 24 MB document with
//! 163,000 strings in it, built as a `serde_json::Value` tree on the way out
//! and parsed into one on the way in, and the validator then decodes the
//! whole payload again to find the header it has to seal. Measured on the
//! seven-node fleet: the validator sees a build take 862-917 ms where the
//! builder itself took 650-780, and pays another 130 ms sealing.
//!
//! This answers the same question with the block's RLP. The header is the
//! first item and the transactions are already the bytes the wire wants, so a
//! validator seals the header directly and gossips the transactions untouched.
//!
//! On the authenticated transport, like the Engine API it stands beside.

use alloy_primitives::Bytes;
use alloy_rpc_types_engine::PayloadId;
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::{error::INTERNAL_ERROR_CODE, ErrorObject},
};
use n42_engine_types::N42BuiltPayload;
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{BuiltPayload, PayloadKind, PayloadTypes};
use serde::{Deserialize, Serialize};

/// A built block, as bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawBuiltPayload {
    /// The block: RLP `[header, transactions, ommers, withdrawals]`, exactly
    /// what `eth_getBlockByHash` would describe.
    pub block: Bytes,
    /// EIP-7685 execution requests, one encoded request per element. Empty
    /// on a chain that has none; `None` before Prague.
    pub requests: Option<Vec<Bytes>>,
    /// The EIP-7928 block access list, RLP-encoded, when the builder made one.
    pub block_access_list: Option<Bytes>,
}

/// The `n42Engine` namespace.
#[cfg_attr(not(test), rpc(server, namespace = "n42Engine"))]
#[cfg_attr(test, rpc(server, client, namespace = "n42Engine"))]
pub trait N42EngineApi {
    /// The block a `forkchoiceUpdated` with attributes started building, once
    /// the build has finished; `null` for a build this node does not know.
    #[method(name = "getPayloadRaw")]
    async fn get_payload_raw(&self, id: PayloadId) -> RpcResult<Option<RawBuiltPayload>>;

    /// The loopback address of the raw payload channel (`payload_serve`),
    /// when this node runs one; `null` otherwise.
    #[method(name = "payloadEndpoint")]
    async fn payload_endpoint(&self) -> RpcResult<Option<String>>;
}

/// Serves [`N42EngineApi`] from the node's payload service.
pub struct N42EngineExt<T: PayloadTypes> {
    /// The same handle the Engine API resolves builds through.
    pub payloads: PayloadBuilderHandle<T>,
    /// Where `payload_serve` listens, if it does.
    pub raw_endpoint: Option<std::net::SocketAddr>,
}

#[jsonrpsee::core::async_trait]
impl<T> N42EngineApiServer for N42EngineExt<T>
where
    T: PayloadTypes<BuiltPayload = N42BuiltPayload> + 'static,
{
    async fn get_payload_raw(&self, id: PayloadId) -> RpcResult<Option<RawBuiltPayload>> {
        // WaitForPending, as `engine_getPayload` does: a build in progress is
        // finished and answered, not answered with whatever came before it.
        match self.payloads.resolve_kind(id, PayloadKind::WaitForPending).await {
            None => Ok(None),
            Some(Err(err)) => {
                Err(ErrorObject::owned(INTERNAL_ERROR_CODE, err.to_string(), Option::<()>::None))
            }
            Some(Ok(payload)) => Ok(Some(RawBuiltPayload {
                block: alloy_rlp::encode(payload.block()).into(),
                requests: payload.requests().map(|requests| requests.take()),
                block_access_list: payload.block_access_list().cloned(),
            })),
        }
    }

    async fn payload_endpoint(&self) -> RpcResult<Option<String>> {
        Ok(self.raw_endpoint.map(|addr| addr.to_string()))
    }
}
