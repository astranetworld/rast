// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An [`ExecutionLayer`] backed by a standard Engine API endpoint.
//!
//! This is what connects HotStuff-2 to a real execution client. It speaks the
//! published Engine API rather than reth's internal handles, which means the
//! same adapter drives reth, this repo's own node, and gov5's `eth-el` mode —
//! and it does so without the consensus side taking a reth dependency, which is
//! the whole point of the seam in [`n42_h2_execution::el`].
//!
//! ## Choosing a method version
//!
//! The Engine API versions its methods by hard fork, and the mapping is not
//! one-to-one with the payload struct names, which is the main trap here:
//!
//! | payload | sidecar | method |
//! | --- | --- | --- |
//! | V1 | — | `engine_newPayloadV1` |
//! | V2 | — | `engine_newPayloadV2` (as `ExecutionPayloadInputV2`) |
//! | V3 | Cancun | `engine_newPayloadV3` |
//! | V3 | Prague (has requests) | `engine_newPayloadV4` |
//!
//! So a Prague block is a *V3* payload sent to `newPayloadV4`. Reading the
//! version off the payload struct alone sends Prague blocks to `newPayloadV3`,
//! which the execution layer rejects for a missing parameter — an error that
//! reads like a payload problem and is not one.
//!
//! Amsterdam (`ExecutionPayloadV4` / `newPayloadV5`) is deliberately refused
//! rather than guessed at. Its envelope and blobs bundle differ, and there is no
//! execution client to test the mapping against here; a wrong guess would fail
//! at the first Amsterdam block on a live chain instead of at startup.
//!
//! `forkchoiceUpdated` picks its version from the attributes, since each version
//! is defined by the fields it accepts: `parentBeaconBlockRoot` requires V3,
//! `withdrawals` requires V2. `getPayload` is asked newest-first, because each
//! of its versions answers for exactly one fork and refuses the rest.

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_consensus::constants::EIP4844_TX_TYPE_ID;
use alloy_consensus::{TxEnvelope, Typed2718};
use alloy_eips::eip2718::Decodable2718;
use alloy_eips::eip7685::{Requests, RequestsOrHash};
use alloy_primitives::B256;
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadInputV2,
    ExecutionPayloadSidecar, ExecutionPayloadV3, ExecutionPayloadV4, ForkchoiceState,
    ForkchoiceUpdated,
    PayloadAttributes, PayloadId, PayloadStatus, PraguePayloadFields,
};
use n42_h2_execution::{ChainBlock, BuiltBlock, ElError, ExecutionLayer, ResolveKind};
use serde_json::{json, Value};
use tracing::debug;

use crate::transport::{
    JsonRpcTransport, TransportError, INVALID_PAYLOAD_ATTRIBUTES, METHOD_NOT_FOUND,
    UNKNOWN_PAYLOAD, UNSUPPORTED_FORK,
};

/// How many in-flight builds to remember the beacon root for.
///
/// A node has one build in flight at a time in the normal case; the slack covers
/// builds that were superseded before anyone collected them. Old entries are
/// dropped rather than accumulating, since a build nobody collected is never
/// coming back.
const MAX_TRACKED_BUILDS: usize = 16;

/// An [`ExecutionLayer`] speaking the Engine API over `T`.
#[derive(Debug)]
pub struct EngineApiClient<T> {
    transport: T,
    /// Beacon roots for builds this client started, keyed by payload id, plus
    /// the order they were inserted in so the oldest can be evicted.
    ///
    /// The Engine API does not echo `parentBeaconBlockRoot` back from
    /// `getPayload`, but re-importing the built block through `newPayload`
    /// requires it, so a build's root has to survive from the request that
    /// started it to the response that collects it.
    builds: Mutex<(HashMap<PayloadId, B256>, Vec<PayloadId>)>,
    /// Where in [`FCU_WITH_ATTRS_METHODS`] the last accepted build-starting
    /// call was, so the ladder is climbed once per chain rather than once per
    /// build: a pre-Amsterdam chain refuses V4 on every leader build, and a
    /// refused round trip on the leader's path is a refused round trip on the
    /// fleet's cycle.
    fcu_rung: std::sync::atomic::AtomicUsize,
    /// Whether the execution layer answers `n42Engine_getPayloadRaw`. Assumed
    /// until it says "method not found" once; a stock execution layer is asked
    /// exactly one extra question in its life.
    raw_payloads: std::sync::atomic::AtomicBool,
    /// The loopback channel this repo's execution layer serves built blocks
    /// on as bytes (`payload_serve`), once its address has been asked for.
    raw_channel: tokio::sync::Mutex<RawChannel>,
    /// A second connection to the same channel for imports, so a build being
    /// collected never waits behind a block being executed.
    raw_import: tokio::sync::Mutex<RawChannel>,
}

/// State of the raw payload channel. See `payload_serve` in `bin/n42`.
#[derive(Debug, Default)]
struct RawChannel {
    /// `None` until asked; `Some(None)` for an execution layer without one.
    endpoint: Option<Option<std::net::SocketAddr>>,
    /// The connection, kept across builds. Dropped on any error and remade.
    stream: Option<tokio::net::TcpStream>,
}

impl<T: JsonRpcTransport> EngineApiClient<T> {
    /// Wraps a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            builds: Mutex::new((HashMap::new(), Vec::new())),
            fcu_rung: std::sync::atomic::AtomicUsize::new(0),
            raw_payloads: std::sync::atomic::AtomicBool::new(true),
            raw_channel: tokio::sync::Mutex::new(RawChannel::default()),
            raw_import: tokio::sync::Mutex::new(RawChannel::default()),
        }
    }

    /// Records the beacon root a build was started under.
    fn remember_build(&self, id: PayloadId, parent_beacon_block_root: B256) {
        let Ok(mut builds) = self.builds.lock() else {
            // A poisoned lock means another thread panicked mid-update. The map
            // is a cache, so losing it costs one failed collection, not
            // correctness — and taking the node down over it would be worse.
            return;
        };
        let (roots, order) = &mut *builds;
        if roots.insert(id, parent_beacon_block_root).is_none() {
            order.push(id);
        }
        while order.len() > MAX_TRACKED_BUILDS {
            let oldest = order.remove(0);
            roots.remove(&oldest);
        }
    }

    /// The beacon root a build was started under, if this client started it.
    fn recall_build(&self, id: PayloadId) -> Option<B256> {
        self.builds.lock().ok()?.0.get(&id).copied()
    }

    /// The transport, for callers that need to make a call this trait does not
    /// cover (`engine_exchangeCapabilities`, for instance).
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    async fn call<R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<R, TransportError> {
        let value = self.transport.call(method, params).await?;
        serde_json::from_value(value).map_err(|e| {
            TransportError::Transport(format!("{method} returned an unusable result: {e}"))
        })
    }
}

/// Builds the method name and parameters for a `newPayload` call.
///
/// Split out from the call so the mapping in the module docs is testable
/// without a transport — it is the part most likely to be wrong and least
/// likely to be noticed.
pub fn new_payload_call(data: &ExecutionData) -> Result<(&'static str, Vec<Value>), ElError> {
    let ExecutionData { payload, sidecar } = data;
    match payload {
        ExecutionPayload::V1(payload) => Ok(("engine_newPayloadV1", vec![json!(payload)])),
        ExecutionPayload::V2(payload) => {
            // V2 is not sent as `ExecutionPayloadV2`: the method takes a V1
            // payload with withdrawals flattened alongside it.
            let input = ExecutionPayloadInputV2 {
                execution_payload: payload.payload_inner.clone(),
                withdrawals: Some(payload.withdrawals.clone()),
            };
            Ok(("engine_newPayloadV2", vec![json!(input)]))
        }
        ExecutionPayload::V3(payload) => {
            // Cancun added both of these, and the method requires them, so an
            // absent one is a malformed payload rather than a default.
            let versioned_hashes = sidecar.versioned_hashes().cloned().ok_or_else(|| {
                ElError::new("a V3 payload needs versioned hashes; sidecar has none")
            })?;
            let parent_beacon_block_root = sidecar.parent_beacon_block_root().ok_or_else(|| {
                ElError::new("a V3 payload needs a parent beacon block root; sidecar has none")
            })?;
            let mut params = vec![
                json!(payload),
                json!(versioned_hashes),
                json!(parent_beacon_block_root),
            ];
            // Prague is a V3 payload with requests, sent to V4.
            Ok(match sidecar.requests() {
                Some(requests) => {
                    params.push(json!(requests));
                    ("engine_newPayloadV4", params)
                }
                None => ("engine_newPayloadV3", params),
            })
        }
        // Amsterdam: the same three arguments as V4 plus the requests, with the
        // access list riding inside the payload itself. Sending this block to
        // `newPayloadV4` is refused outright -- reth's version gate rejects
        // `(V4, Payload)` once Amsterdam is active -- and sending it without
        // the access list would be worse than refused: the block would import
        // serially and nothing would say why.
        ExecutionPayload::V4(payload) => {
            let versioned_hashes = sidecar.versioned_hashes().cloned().unwrap_or_default();
            let parent_beacon_block_root = sidecar.parent_beacon_block_root().ok_or_else(|| {
                ElError::new("a V4 payload needs a parent beacon block root; sidecar has none")
            })?;
            let requests = sidecar.requests().cloned().unwrap_or_default();
            Ok((
                "engine_newPayloadV5",
                vec![
                    json!(payload),
                    json!(versioned_hashes),
                    json!(parent_beacon_block_root),
                    json!(requests),
                ],
            ))
        }
    }
}

/// Picks the `forkchoiceUpdated` version for a set of attributes.
///
/// Each version is defined by the fields it accepts, so the attributes decide:
/// sending `parentBeaconBlockRoot` to V2 is rejected, and so is omitting it
/// from V3 on a Cancun chain.
pub const fn forkchoice_method(attrs: Option<&PayloadAttributes>) -> &'static str {
    match attrs {
        // Without attributes this is a plain head/finalise update. V3 accepts
        // that on every post-Cancun chain, which is every chain this runs on,
        // and Amsterdam's version gate only rejects V3 when it carries
        // attributes.
        None => "engine_forkchoiceUpdatedV3",
        Some(attrs) if attrs.parent_beacon_block_root.is_some() => FCU_WITH_ATTRS_NEWEST,
        Some(attrs) if attrs.withdrawals.is_some() => "engine_forkchoiceUpdatedV2",
        Some(_) => "engine_forkchoiceUpdatedV1",
    }
}

/// The `forkchoiceUpdated` version used to *start a build*, newest first.
///
/// Amsterdam rejects `(V3, PayloadAttributes)` outright — reth's
/// `validate_version_specific_fields` returns `UNSUPPORTED_FORK` — so a chain
/// with `amsterdamTime` set needs V4 to begin a payload at all. A chain without
/// it rejects V4 the same way, so the caller falls back; see
/// [`FCU_WITH_ATTRS_METHODS`].
const FCU_WITH_ATTRS_NEWEST: &str = "engine_forkchoiceUpdatedV4";

/// Every `forkchoiceUpdated`-with-attributes version, newest first, for the
/// fallback the fork schedule would otherwise have to be carried to decide.
pub const FCU_WITH_ATTRS_METHODS: [&str; 2] =
    ["engine_forkchoiceUpdatedV4", "engine_forkchoiceUpdatedV3"];

/// The `getPayload` versions, newest first.
///
/// Each version is bound to a fork: V5 answers only for Osaka builds, V4 only
/// for Prague, V3 only for Cancun, and the execution layer refuses the others
/// with [`UNSUPPORTED_FORK`]. This client does not carry the fork schedule, so
/// it asks newest-first and takes the first version that answers. The wrong
/// choice is not merely refused, either: a Prague build collected through V3
/// arrives without its execution requests, the block re-imported from it lacks
/// the requests hash its header carries, and the leader's own execution layer
/// rejects the block it just built with "block hash mismatch".
const GET_PAYLOAD_METHODS: [&str; 4] =
    ["engine_getPayloadV6", "engine_getPayloadV5", "engine_getPayloadV4", "engine_getPayloadV3"];

/// What every `getPayload` version has in common.
///
/// V3, V4 and V5 differ in what else they carry — V4 adds execution requests,
/// V5 changes the blobs bundle — but the block, its KZG commitments and the
/// requests are all that re-importing it needs, and all three spell those the
/// same way. Reading them through one shape is what lets the version be chosen
/// at runtime.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetPayloadEnvelope {
    execution_payload: PayloadMaybeWithBal,
    #[serde(default)]
    blobs_bundle: BlobCommitments,
    #[serde(default)]
    execution_requests: Option<Vec<alloy_primitives::Bytes>>,
}

/// A `getPayload` payload, keeping the access list if the version carries one.
///
/// The list is *inside* `executionPayload`, not beside it: Amsterdam's envelope
/// types the field as `ExecutionPayloadV4`, which is a V3 payload plus the list.
/// Reading the field at the envelope's top level finds nothing and finds it
/// silently, because serde ignores what it does not recognise -- so the payload
/// comes back as V3, the block imports serially where it can import at all, and
/// the first sign of it is `Unsupported fork` three hops away in a follower.
///
/// Worth carrying for one reason: reth executes a block in parallel when it has
/// one and serially when it does not
/// (`payload_validator.rs::bal_path_eligible`).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayloadMaybeWithBal {
    #[serde(flatten)]
    payload: ExecutionPayloadV3,
    #[serde(default)]
    block_access_list: Option<alloy_primitives::Bytes>,
}

#[derive(Default, serde::Deserialize)]
struct BlobCommitments {
    #[serde(default)]
    commitments: Vec<alloy_primitives::FixedBytes<48>>,
}

/// Turns a `getPayload` envelope into the node-neutral result.
///
/// `parent_beacon_block_root` is a parameter because the envelope does not carry
/// it: it was an input to the `forkchoiceUpdated` that started this build, and
/// the Engine API never echoes it back. It is nevertheless required to re-import
/// the block through `newPayload`, so the client remembers it per build — see
/// [`EngineApiClient::fork_choice_updated_with_attrs`].
pub fn built_block_from_envelope(
    value: Value,
    parent_beacon_block_root: B256,
) -> Result<BuiltBlock, ElError> {
    let envelope: GetPayloadEnvelope = serde_json::from_value(value)
        .map_err(|e| ElError::new(format!("unusable getPayload envelope: {e}")))?;

    let inner = &envelope.execution_payload.payload.payload_inner.payload_inner;
    let hash = inner.block_hash;
    let number = inner.block_number;
    let timestamp = inner.timestamp;
    let tx_count = inner.transactions.len();
    let blob_tx_hashes = blob_transaction_hashes(&inner.transactions);

    // From the bundle's KZG commitments, not from the transactions: this is the
    // list `newPayload` checks the block against, and the execution layer that
    // built it is the authority on it.
    let versioned_hashes = envelope
        .blobs_bundle
        .commitments
        .iter()
        .map(|c| alloy_eips::eip4844::kzg_to_versioned_hash(c.as_slice()))
        .collect();
    let cancun = CancunPayloadFields {
        parent_beacon_block_root,
        versioned_hashes,
    };
    let sidecar = match envelope.execution_requests {
        Some(requests) => ExecutionPayloadSidecar::v4(
            cancun,
            PraguePayloadFields {
                requests: RequestsOrHash::Requests(Requests::new(requests)),
            },
        ),
        None => ExecutionPayloadSidecar::v3(cancun),
    };

    // V4 when the build came back with an access list, V3 otherwise. The
    // variant is what carries the list to `newPayload`, and `newPayload` is
    // where reth decides between rayon workers and a `while` loop.
    let payload = match envelope.execution_payload.block_access_list {
        Some(block_access_list) => ExecutionPayload::V4(ExecutionPayloadV4 {
            payload_inner: envelope.execution_payload.payload,
            block_access_list,
            // EIP-7843's slot number is a consensus-layer concept and this
            // chain has no slots: HotStuff commits a block per view, so the
            // block's own number is the only monotonic index every member
            // agrees on without being told. It is what this node will send
            // back with the block, so leader and followers derive it the same
            // way from the same block.
            slot_number: number,
        }),
        None => ExecutionPayload::V3(envelope.execution_payload.payload),
    };

    Ok(BuiltBlock {
        hash,
        number,
        timestamp,
        tx_count,
        execution_data: ExecutionData::new(payload, sidecar),
        blob_tx_hashes,
        header: None,
    })
}

/// The hashes of the EIP-4844 transactions in a payload.
///
/// The consensus side broadcasts their sidecars separately, so blob
/// transactions that go unidentified produce a block its peers cannot validate.
///
/// A transaction that fails to decode is skipped rather than failing the block:
/// the execution layer built and accepted this payload, so a decode failure here
/// is this adapter's problem, and refusing the block over it would stall
/// consensus over a reporting detail.
fn blob_transaction_hashes(transactions: &[alloy_primitives::Bytes]) -> Vec<B256> {
    transactions
        .iter()
        .filter_map(|raw| {
            let mut slice = raw.as_ref();
            TxEnvelope::decode_2718(&mut slice).ok()
        })
        .filter(|tx| tx.ty() == EIP4844_TX_TYPE_ID)
        .map(|tx| *tx.tx_hash())
        .collect()
}

#[async_trait::async_trait]
impl<T: JsonRpcTransport> ExecutionLayer for EngineApiClient<T> {
    async fn latest_block_number(&self) -> Result<Option<u64>, ElError> {
        let hex: String = self
            .call("eth_blockNumber", vec![])
            .await
            .map_err(|e| ElError::new(e.to_string()))?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map(Some)
            .map_err(|e| ElError::new(format!("eth_blockNumber returned {hex}: {e}")))
    }

    async fn block_by_hash(&self, hash: B256) -> Result<Option<ChainBlock>, ElError> {
        let block: Option<alloy_rpc_types_eth::Block> = self
            .call("eth_getBlockByHash", vec![json!(hash), json!(true)])
            .await
            .map_err(|e| ElError::new(e.to_string()))?;
        Ok(block.map(block_parts))
    }

    async fn block_by_number(&self, number: u64) -> Result<Option<ChainBlock>, ElError> {
        // The Engine API's auth endpoint also serves the handful of `eth_`
        // methods the spec requires of it, this one among them, so no second
        // endpoint is needed to serve peers the chain.
        let block: Option<alloy_rpc_types_eth::Block> = self
            .call("eth_getBlockByNumber", vec![json!(format!("0x{number:x}")), json!(true)])
            .await
            .map_err(|e| ElError::new(e.to_string()))?;
        Ok(block.map(block_parts))
    }

    async fn send_raw_transaction(&self, raw: alloy_primitives::Bytes) -> Result<B256, ElError> {
        // The Engine API's auth endpoint serves this too: the spec requires
        // it of every execution client, for exactly this use.
        self.call("eth_sendRawTransaction", vec![json!(raw)])
            .await
            .map_err(|e| ElError::new(e.to_string()))
    }

    async fn send_raw_transactions(&self, raws: Vec<alloy_primitives::Bytes>) -> usize {
        // Chunked, because a batch is one HTTP body and the execution layer
        // caps how large that may be (reth's `--rpc.max-request-size`, 15 MB by
        // default). A hex-encoded transfer is a few hundred bytes of JSON, so
        // a thousand of them is comfortably inside any such limit while still
        // being a thousand round trips saved.
        const CHUNK: usize = 1000;
        let mut accepted = 0;
        for chunk in raws.chunks(CHUNK) {
            accepted += self
                .transport
                .call_many(
                    "eth_sendRawTransaction",
                    chunk.iter().map(|raw| vec![json!(raw)]).collect(),
                )
                .await;
        }
        accepted
    }

    async fn new_payload(&self, payload: ExecutionData) -> Result<PayloadStatus, ElError> {
        // The loopback channel first; any failure falls through to JSON.
        if let Some(status) = self.new_payload_over_channel(&payload).await {
            return Ok(status);
        }
        let (method, params) = new_payload_call(&payload)?;
        debug!(target: "n42.h2.el", method, "newPayload");
        self.call(method, params).await.map_err(ElError::new)
    }

    async fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, ElError> {
        let method = forkchoice_method(None);
        debug!(target: "n42.h2.el", method, "forkchoiceUpdated");
        self.call(method, vec![json!(state), Value::Null])
            .await
            .map_err(ElError::new)
    }

    async fn fork_choice_updated_with_attrs(
        &self,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> Result<ForkchoiceUpdated, ElError> {
        let beacon_root = attrs.parent_beacon_block_root;
        // Newest-first, like `getPayload`, and for the same reason: this client
        // does not carry the fork schedule, and each version is bound to a fork
        // in *both* directions. Amsterdam refuses V3-with-attributes and
        // requires EIP-7843's slot number; everything before Amsterdam refuses
        // V4 and refuses a slot number outright. Sending one shape to every
        // chain therefore breaks whichever chain it was not written for, which
        // is how a fix for an Amsterdam fleet stopped a Prague one.
        //
        // So the newest shape is tried and the older one answers for the older
        // chain. The fallback covers both refusals a wrong version produces:
        // `UNSUPPORTED_FORK` for the method and `INVALID_PAYLOAD_ATTRIBUTES`
        // for the field.
        // Only the post-Cancun shape has two candidate versions. Attributes
        // without a beacon root belong to an older fork and their version is
        // decided by the fields alone, with nothing to fall back to.
        let older = [forkchoice_method(Some(&attrs))];
        let ladder: &[&str] = if attrs.parent_beacon_block_root.is_some() {
            &FCU_WITH_ATTRS_METHODS
        } else {
            &older
        };
        let mut last: Option<ElError> = None;
        let mut updated: Option<ForkchoiceUpdated> = None;
        // Start from the rung that answered last time. The chain does not
        // change fork under a running client, so a version it refused once it
        // refuses every time, and paying that refusal per build was measured
        // as one more round trip on every leader path of a pre-Amsterdam fleet.
        let start = self.fcu_rung.load(std::sync::atomic::Ordering::Relaxed).min(ladder.len() - 1);
        for (rung, &method) in ladder.iter().enumerate().skip(start) {
            let mut attempt = attrs.clone();
            if method == "engine_forkchoiceUpdatedV3" {
                attempt.slot_number = None;
            }
            debug!(target: "n42.h2.el", method, "forkchoiceUpdated with attributes");
            match self.call(method, vec![json!(state), json!(attempt)]).await {
                Ok(value) => {
                    self.fcu_rung.store(rung, std::sync::atomic::Ordering::Relaxed);
                    updated = Some(value);
                    break;
                }
                Err(TransportError::Rpc(err))
                    if err.code == UNSUPPORTED_FORK || err.code == INVALID_PAYLOAD_ATTRIBUTES =>
                {
                    last = Some(ElError::new(err));
                }
                Err(err) => return Err(ElError::new(err)),
            }
        }
        let updated = updated.ok_or_else(|| {
            last.unwrap_or_else(|| ElError::new("no forkchoiceUpdated version accepted the attributes"))
        })?;

        // Remember what this build was started under, so collecting it can
        // rebuild a sidecar the block can be re-imported with.
        if let (Some(id), Some(root)) = (updated.payload_id, beacon_root) {
            self.remember_build(id, root);
        }
        Ok(updated)
    }

    async fn resolve_payload(
        &self,
        id: PayloadId,
        _kind: ResolveKind,
    ) -> Option<Result<BuiltBlock, ElError>> {
        // `ResolveKind::WaitForPending` has no Engine API equivalent: getPayload
        // returns the best payload available at the moment of the call and the
        // execution layer may stop building after serving it. The wait therefore
        // happens on the caller's side, in how long it lets the build run before
        // asking. Honouring the kind by polling here would be worse — each call
        // may terminate the build.
        //
        // A build this client did not start has no remembered root. Zero is the
        // honest stand-in — it is what a pre-Cancun chain uses — and the block
        // will fail its own `newPayload` check rather than being imported under
        // a root nobody agreed to.
        let beacon_root = self.recall_build(id).unwrap_or_default();
        // The loopback channel first: the block as bytes, nothing hex-encoded
        // or parsed. Any failure on it falls through to the JSON forms.
        if let Some(answer) = self.resolve_over_channel(id, beacon_root).await {
            return answer;
        }
        // This repo's execution layer answers with the block's RLP, which
        // skips a 24 MB JSON document each way and the decode the validator
        // then needed to find the header. Anything else falls through to the
        // Engine API's own shape below.
        if self.raw_payloads.load(std::sync::atomic::Ordering::Relaxed) {
            match self.transport.call("n42Engine_getPayloadRaw", vec![json!(id)]).await {
                Ok(Value::Null) => return None,
                Ok(value) => {
                    debug!(target: "n42.h2.el", "getPayloadRaw");
                    return Some(built_block_from_raw(value, beacon_root));
                }
                Err(TransportError::Rpc(err)) if err.code == METHOD_NOT_FOUND => {
                    debug!(target: "n42.h2.el", "execution layer has no n42Engine_getPayloadRaw; using getPayload");
                    self.raw_payloads.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                Err(TransportError::Rpc(err)) if err.code == UNKNOWN_PAYLOAD => return None,
                Err(err) => return Some(Err(ElError::new(err))),
            }
        }
        for method in GET_PAYLOAD_METHODS {
            match self.transport.call(method, vec![json!(id)]).await {
                Ok(value) => {
                    debug!(target: "n42.h2.el", method, "getPayload");
                    return Some(built_block_from_envelope(value, beacon_root));
                }
                // Wrong version for this build's fork: ask the next one down.
                Err(TransportError::Rpc(err)) if err.code == UNSUPPORTED_FORK => {}
                // A build the execution layer does not know about is an absent
                // result, not a failure: the driver retries or moves on.
                Err(TransportError::Rpc(err)) if err.code == UNKNOWN_PAYLOAD => return None,
                Err(err) => return Some(Err(ElError::new(err))),
            }
        }
        Some(Err(ElError::new(
            "no getPayload version accepted this build; the execution layer is on a fork this \
             adapter does not know",
        )))
    }
}

impl<T: JsonRpcTransport> EngineApiClient<T> {
    /// Learns the raw channel's address once, from `n42Engine_payloadEndpoint`.
    async fn raw_endpoint(&self, channel: &mut RawChannel) -> Option<std::net::SocketAddr> {
        if channel.endpoint.is_none() {
            let found = match self.transport.call("n42Engine_payloadEndpoint", vec![]).await {
                Ok(Value::String(addr)) => addr.parse::<std::net::SocketAddr>().ok(),
                Ok(_) => None,
                Err(TransportError::Rpc(err)) if err.code == METHOD_NOT_FOUND => None,
                Err(err) => {
                    debug!(target: "n42.h2.el", %err, "asking for the raw payload endpoint");
                    return None;
                }
            };
            debug!(target: "n42.h2.el", ?found, "raw payload endpoint");
            channel.endpoint = Some(found);
        }
        (*channel.endpoint.as_ref()?)
    }

    /// Hands a payload to the execution layer over the raw channel.
    ///
    /// `None` means "not this way" and the caller uses JSON.
    async fn new_payload_over_channel(&self, payload: &ExecutionData) -> Option<PayloadStatus> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut channel = self.raw_import.lock().await;
        let addr = self.raw_endpoint(&mut channel).await?;
        let started = std::time::Instant::now();
        let frame = n42_h2_execution::raw_engine::encode_execution_data(payload);
        let encoded = started.elapsed();
        let attempt: std::io::Result<PayloadStatus> = async {
            if channel.stream.is_none() {
                let stream = tokio::net::TcpStream::connect(addr).await?;
                stream.set_nodelay(true)?;
                channel.stream = Some(stream);
            }
            let stream = channel.stream.as_mut().expect("just connected");
            stream.write_u8(n42_h2_execution::raw_engine::request::NEW_PAYLOAD).await?;
            stream.write_u32_le(frame.len() as u32).await?;
            stream.write_all(&frame).await?;
            match stream.read_u8().await? {
                1 => {
                    let len = stream.read_u32_le().await? as usize;
                    let mut buf = vec![0u8; len];
                    stream.read_exact(&mut buf).await?;
                    n42_h2_execution::raw_engine::decode_payload_status(&buf)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                }
                2 => {
                    let len = stream.read_u32_le().await? as usize;
                    let mut message = vec![0u8; len];
                    stream.read_exact(&mut message).await?;
                    Err(std::io::Error::other(String::from_utf8_lossy(&message).into_owned()))
                }
                other => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("status {other}"))),
            }
        }
        .await;
        match attempt {
            Ok(status) => {
                if frame.len() > 1_000_000 {
                    debug!(
                        target: "n42.h2.el",
                        bytes = frame.len(),
                        encode_ms = encoded.as_millis() as u64,
                        round_trip_ms = started.elapsed().as_millis() as u64,
                        status = ?status.status,
                        "raw newPayload"
                    );
                }
                Some(status)
            }
            Err(err) => {
                debug!(target: "n42.h2.el", %err, "raw newPayload channel failed; using JSON for this block");
                channel.stream = None;
                None
            }
        }
    }

    /// Collects a build over the raw payload channel.
    ///
    /// `None` means "not this way": no channel, a channel that failed, or an
    /// execution layer that does not serve one — the caller then uses the
    /// JSON forms. `Some(None)` is the channel saying the build is unknown.
    async fn resolve_over_channel(
        &self,
        id: PayloadId,
        beacon_root: B256,
    ) -> Option<Option<Result<BuiltBlock, ElError>>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut channel = self.raw_channel.lock().await;
        let addr = self.raw_endpoint(&mut channel).await?;
        let started = std::time::Instant::now();
        let attempt: std::io::Result<Option<Result<BuiltBlock, ElError>>> = async {
            if channel.stream.is_none() {
                let stream = tokio::net::TcpStream::connect(addr).await?;
                stream.set_nodelay(true)?;
                channel.stream = Some(stream);
            }
            let stream = channel.stream.as_mut().expect("just connected");
            stream.write_u8(n42_h2_execution::raw_engine::request::GET_PAYLOAD).await?;
            stream.write_all(&id.0 .0).await?;
            match stream.read_u8().await? {
                0 => Ok(None),
                2 => {
                    let len = stream.read_u32_le().await? as usize;
                    let mut message = vec![0u8; len];
                    stream.read_exact(&mut message).await?;
                    Ok(Some(Err(ElError::new(String::from_utf8_lossy(&message).into_owned()))))
                }
                1 => {
                    let len = stream.read_u32_le().await? as usize;
                    let mut block = vec![0u8; len];
                    stream.read_exact(&mut block).await?;
                    let requests = if stream.read_u8().await? == 1 {
                        let n = stream.read_u32_le().await? as usize;
                        let mut requests = Vec::with_capacity(n);
                        for _ in 0..n {
                            let len = stream.read_u32_le().await? as usize;
                            let mut request = vec![0u8; len];
                            stream.read_exact(&mut request).await?;
                            requests.push(alloy_primitives::Bytes::from(request));
                        }
                        Some(requests)
                    } else {
                        None
                    };
                    let bal = if stream.read_u8().await? == 1 {
                        let len = stream.read_u32_le().await? as usize;
                        let mut bal = vec![0u8; len];
                        stream.read_exact(&mut bal).await?;
                        Some(alloy_primitives::Bytes::from(bal))
                    } else {
                        None
                    };
                    let received = started.elapsed();
                    let built = built_block_from_parts(block.into(), requests, bal, beacon_root);
                    if len > 1_000_000 {
                        debug!(
                            target: "n42.h2.el",
                            bytes = len,
                            channel_ms = received.as_millis() as u64,
                            split_ms = started.elapsed().saturating_sub(received).as_millis() as u64,
                            "raw payload collected"
                        );
                    }
                    Ok(Some(built))
                }
                other => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("status {other}"))),
            }
        }
        .await;
        match attempt {
            Ok(answer) => Some(answer),
            Err(err) => {
                debug!(target: "n42.h2.el", %err, "raw payload channel failed; using JSON for this build");
                channel.stream = None;
                None
            }
        }
    }
}

/// What `n42Engine_getPayloadRaw` answers with.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBuiltPayload {
    block: alloy_primitives::Bytes,
    #[serde(default)]
    requests: Option<Vec<alloy_primitives::Bytes>>,
    #[serde(default)]
    block_access_list: Option<alloy_primitives::Bytes>,
}

/// Splits a block's RLP into its header, its transactions as the EIP-2718
/// bytes the Engine API and gov5's wire both want, and its withdrawals.
///
/// The transactions are *not* decoded: each is either an RLP string wrapping
/// a typed transaction, whose contents are the bytes wanted, or an RLP list
/// that is a legacy transaction, whose whole encoding is. A 163,000-transaction
/// block is 163,000 slice operations here where decoding it is 50 ms and the
/// JSON it replaces was 150-200.
pub fn split_block_rlp(
    rlp: &[u8],
) -> Result<(alloy_consensus::Header, Vec<alloy_primitives::Bytes>, Vec<alloy_eips::eip4895::Withdrawal>), ElError> {
    use alloy_rlp::Decodable;
    let bad = |what: &str| ElError::new(format!("raw payload: {what}"));
    let mut buf = rlp;
    let outer = alloy_rlp::Header::decode(&mut buf).map_err(|e| bad(&e.to_string()))?;
    if !outer.list || buf.len() < outer.payload_length {
        return Err(bad("not a block list"));
    }
    let mut payload = &buf[..outer.payload_length];
    let header = alloy_consensus::Header::decode(&mut payload).map_err(|e| bad(&format!("header: {e}")))?;
    let txs_header = alloy_rlp::Header::decode(&mut payload).map_err(|e| bad(&e.to_string()))?;
    if !txs_header.list || payload.len() < txs_header.payload_length {
        return Err(bad("transactions are not a list"));
    }
    let (mut items, rest) = payload.split_at(txs_header.payload_length);
    payload = rest;
    let mut transactions = Vec::with_capacity(items.len() / 100);
    while !items.is_empty() {
        let whole = items;
        let item = alloy_rlp::Header::decode(&mut items).map_err(|e| bad(&e.to_string()))?;
        if items.len() < item.payload_length {
            return Err(bad("truncated transaction"));
        }
        let (body, after) = items.split_at(item.payload_length);
        transactions.push(if item.list {
            alloy_primitives::Bytes::copy_from_slice(&whole[..whole.len() - after.len()])
        } else {
            alloy_primitives::Bytes::copy_from_slice(body)
        });
        items = after;
    }
    let ommers = alloy_rlp::Header::decode(&mut payload).map_err(|e| bad(&e.to_string()))?;
    if payload.len() < ommers.payload_length {
        return Err(bad("truncated ommers"));
    }
    payload = &payload[ommers.payload_length..];
    let withdrawals = if payload.is_empty() {
        Vec::new()
    } else {
        Vec::<alloy_eips::eip4895::Withdrawal>::decode(&mut payload)
            .map_err(|e| bad(&format!("withdrawals: {e}")))?
    };
    Ok((header, transactions, withdrawals))
}

/// A [`BuiltBlock`] from `n42Engine_getPayloadRaw`'s answer.
///
/// The payload is assembled from the header's fields and the transactions'
/// bytes, which is exactly what the Engine API's envelope carries, without
/// anything having been decoded. The header rides along so the seal can be
/// applied to it directly.
pub fn built_block_from_raw(value: Value, parent_beacon_block_root: B256) -> Result<BuiltBlock, ElError> {
    let raw: RawBuiltPayload = serde_json::from_value(value)
        .map_err(|e| ElError::new(format!("unusable getPayloadRaw answer: {e}")))?;
    built_block_from_parts(raw.block, raw.requests, raw.block_access_list, parent_beacon_block_root)
}

/// [`built_block_from_raw`] from the parts, however they arrived.
pub fn built_block_from_parts(
    block: alloy_primitives::Bytes,
    requests: Option<Vec<alloy_primitives::Bytes>>,
    block_access_list: Option<alloy_primitives::Bytes>,
    parent_beacon_block_root: B256,
) -> Result<BuiltBlock, ElError> {
    use alloy_rpc_types_engine::{ExecutionPayloadV1, ExecutionPayloadV2};
    let (mut header, transactions, withdrawals) = split_block_rlp(&block)?;
    // Blob transactions need the blobs bundle, which this path does not carry.
    if transactions.iter().any(|tx| tx.first() == Some(&0x03)) {
        return Err(ElError::new("raw payload path cannot carry blob transactions"));
    }
    // A V4 payload carries EIP-7843's slot number and every importer writes it
    // into the header it rebuilds, so the header sealed here has to carry the
    // same value or no importer reproduces the hash. This chain has no slots
    // and its builder leaves the field empty; the block number stands in, as
    // it does on the JSON path.
    let slot_number = if block_access_list.is_some() {
        let slot = header.slot_number.unwrap_or(header.number);
        header.slot_number = Some(slot);
        slot
    } else {
        header.number
    };
    let hash = header.hash_slow();
    let v1 = ExecutionPayloadV1 {
        parent_hash: header.parent_hash,
        fee_recipient: header.beneficiary,
        state_root: header.state_root,
        receipts_root: header.receipts_root,
        logs_bloom: header.logs_bloom,
        prev_randao: header.mix_hash,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: header.extra_data.clone(),
        base_fee_per_gas: alloy_primitives::U256::from(header.base_fee_per_gas.unwrap_or_default()),
        block_hash: hash,
        transactions,
        // This repo's fork of the payload types carries APoS's two header
        // fields; the seal zeroes both a moment later.
        difficulty: header.difficulty,
        nonce: header.nonce,
    };
    let tx_count = v1.transactions.len();
    let payload = match (header.withdrawals_root.is_some(), header.blob_gas_used) {
        (false, _) => ExecutionPayload::V1(v1),
        (true, None) => ExecutionPayload::V2(ExecutionPayloadV2 { payload_inner: v1, withdrawals }),
        (true, Some(blob_gas_used)) => {
            let v3 = ExecutionPayloadV3 {
                payload_inner: ExecutionPayloadV2 { payload_inner: v1, withdrawals },
                blob_gas_used,
                excess_blob_gas: header.excess_blob_gas.unwrap_or_default(),
            };
            match block_access_list {
                Some(block_access_list) => ExecutionPayload::V4(ExecutionPayloadV4 {
                    payload_inner: v3,
                    block_access_list,
                    slot_number,
                }),
                None => ExecutionPayload::V3(v3),
            }
        }
    };
    let sidecar = match header.parent_beacon_block_root {
        None => ExecutionPayloadSidecar::none(),
        Some(_) => {
            let cancun = CancunPayloadFields { parent_beacon_block_root, versioned_hashes: Vec::new() };
            match (header.requests_hash.is_some(), requests) {
                (true, requests) => ExecutionPayloadSidecar::v4(
                    cancun,
                    PraguePayloadFields {
                        requests: RequestsOrHash::Requests(Requests::new(requests.unwrap_or_default())),
                    },
                ),
                (false, _) => ExecutionPayloadSidecar::v3(cancun),
            }
        }
    };
    Ok(BuiltBlock {
        hash,
        number: header.number,
        timestamp: header.timestamp,
        tx_count,
        execution_data: ExecutionData::new(payload, sidecar),
        blob_tx_hashes: Vec::new(),
        header: Some(header),
    })
}

/// The consensus header and transactions inside an `eth_getBlockByNumber`
/// answer, which is what gov5's block form is built from.
pub fn block_parts(block: alloy_rpc_types_eth::Block) -> ChainBlock {
    let header = block.header.inner;
    let transactions = block
        .transactions
        .into_transactions_vec()
        .into_iter()
        .map(|tx| tx.inner.into_inner())
        .collect();
    ChainBlock { header, transactions, withdrawals: block.withdrawals.map(|w| w.0) }
}


#[cfg(test)]
mod raw_payload_tests {
    use super::*;
    use alloy_consensus::{Block, BlockBody, Header, TxEip1559, TxEnvelope, TxLegacy};
    use alloy_eips::Encodable2718;
    use alloy_primitives::{Address, Signature, TxKind, U256};

    fn typed() -> TxEnvelope {
        let tx = TxEip1559 { chain_id: 1, nonce: 3, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(9), ..Default::default() };
        TxEnvelope::Eip1559(alloy_consensus::Signed::new_unchecked(tx, Signature::test_signature(), Default::default()))
    }
    fn legacy() -> TxEnvelope {
        let tx = TxLegacy { chain_id: Some(1), nonce: 4, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(1), ..Default::default() };
        TxEnvelope::Legacy(alloy_consensus::Signed::new_unchecked(tx, Signature::test_signature(), Default::default()))
    }

    /// An Amsterdam block over the raw path, sealed from its header, is a block
    /// a follower reconstructs: the payload's slot number and the sealed
    /// header's agree, and the access-list hash survives.
    #[test]
    fn an_amsterdam_raw_payload_seals_and_reconstructs() {
        let bal = alloy_primitives::Bytes::from(alloy_rlp::encode(&alloy_eip7928::BlockAccessList::default()));
        let decoded = <alloy_eip7928::BlockAccessList as alloy_rlp::Decodable>::decode(&mut bal.as_ref()).unwrap();
        let txs = vec![typed(), legacy()];
        let header = Header {
            number: 3,
            base_fee_per_gas: Some(7),
            // As an execution layer would hand it over: the real root, not a
            // default; a header that disagrees with its own body is not a
            // block any builder produces.
            transactions_root: alloy_consensus::proofs::calculate_transaction_root(&txs),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::repeat_byte(7)),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            block_access_list_hash: Some(alloy_eip7928::compute_block_access_list_hash(decoded.as_slice())),
            slot_number: None,
            ..Default::default()
        };
        let block = Block { header, body: BlockBody { transactions: txs, ommers: Vec::new(), withdrawals: Some(alloy_eips::eip4895::Withdrawals(Vec::new())) } };
        let rlp = alloy_rlp::encode(&block);
        let built = built_block_from_parts(rlp.into(), Some(Vec::new()), Some(bal), B256::repeat_byte(7)).expect("builds");
        let header = built.header.clone().expect("the raw path carries the header");
        let (sealed_data, sealed_header) =
            n42_h2_consensus::normalize_to_gov5_h2_from_header(header, &built.execution_data, 9, None).expect("seals");
        assert_eq!(sealed_data.block_hash(), sealed_header.hash_slow());
        let rebuilt = n42_h2_consensus::reconstruct_gov5_h2_block::<TxEnvelope>(&sealed_data)
            .expect("a follower reconstructs the sealed block");
        assert_eq!(rebuilt.header.hash_slow(), sealed_data.block_hash());
        assert_eq!(rebuilt.header, sealed_header);
    }

    /// The split hands back exactly the bytes `encoded_2718` would, for both a
    /// typed transaction (an RLP string on the block) and a legacy one (an
    /// RLP list that is its own encoding), plus the header and withdrawals.
    #[test]
    fn splitting_a_block_yields_its_2718_bytes() {
        // A well-formed post-Shanghai header: the trailing optional fields
        // encode positionally, so a withdrawals root without a base fee is an
        // encoding no real block has and alloy's own decoder rejects it.
        let header = Header { number: 5, base_fee_per_gas: Some(7), withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH), ..Default::default() };
        let withdrawals = vec![alloy_eips::eip4895::Withdrawal { index: 1, validator_index: 2, address: Address::repeat_byte(7), amount: 3 }];
        let block = Block { header: header.clone(), body: BlockBody { transactions: vec![typed(), legacy(), typed()], ommers: Vec::new(), withdrawals: Some(alloy_eips::eip4895::Withdrawals(withdrawals.clone())) } };
        let rlp = alloy_rlp::encode(&block);
        let (got_header, txs, got_withdrawals) = split_block_rlp(&rlp).expect("splits");
        assert_eq!(got_header, header);
        assert_eq!(got_withdrawals, withdrawals);
        let want: Vec<Vec<u8>> = block.body.transactions.iter().map(|tx| tx.encoded_2718()).collect();
        assert_eq!(txs.iter().map(|b| b.to_vec()).collect::<Vec<_>>(), want);
    }
}
