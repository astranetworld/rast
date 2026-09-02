// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The transactions this node's own pool admits, read from its public
//! JSON-RPC so they can be gossiped to the fleet.
//!
//! The Engine API's auth endpoint takes transactions but cannot list them,
//! so this polls the public endpoint: `eth_newPendingTransactionFilter` once,
//! `eth_getFilterChanges` every half second, `eth_getRawTransactionByHash`
//! for each new hash. A filter the node forgot (a restart) is made again.

use alloy_primitives::{Bytes, B256};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info};

const POLL: Duration = Duration::from_millis(500);

/// How many transactions go in one JSON-RPC batch.
///
/// A batch is one HTTP body and the execution layer caps how large that may
/// be (reth's `--rpc.max-request-size`, 15 MB by default). A hex-encoded
/// transfer is a few hundred bytes of JSON, so a thousand is comfortably
/// inside any such limit while still being a thousand round trips saved.
const FORWARD_CHUNK: usize = 1000;

/// Hands the fleet's gossiped transactions to this node's pool, off the
/// consensus loop.
///
/// Its own task for one reason, and it is the largest single result in this
/// fleet's history. Done inline, this is the only work in the service loop
/// whose size is set by the *fleet's* send rate rather than by the chain's:
/// the loop cannot poll its transport while it awaits, so a step that hands
/// over everything that arrived is a step during which the node is deaf to
/// proposals, votes and bodies. At 6,000 senders that was measured as one
/// member receiving nothing at all for 11.1 s, the view it should have led
/// expiring 31 ms before the body it was waiting for arrived, and every view
/// that member led costing the whole fleet a six-second timeout for the rest
/// of the round. Moving it here took the fleet from 13,714 TPS to 38,786 and
/// the block cycle from 1.667 s to 0.588 s.
///
/// Rationing it inline is not a substitute and was measured not to be: a
/// bounded batch every step is the same total work, spent in smaller pieces,
/// and it left the fleet at 12,190 TPS. The loop must not wait for the pool
/// at all.
pub async fn forward_transactions(rpc_url: url::Url, mut source: mpsc::Receiver<Vec<Bytes>>) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(client) => client,
        Err(err) => {
            debug!(target: "n42.h2.node", %err, "transaction forwarding: no HTTP client");
            return;
        }
    };
    while let Some(batch) = source.recv().await {
        for chunk in batch.chunks(FORWARD_CHUNK) {
            let body: Vec<Value> = chunk
                .iter()
                .enumerate()
                .map(|(id, raw)| {
                    json!({"jsonrpc": "2.0", "id": id, "method": "eth_sendRawTransaction", "params": [raw]})
                })
                .collect();
            // The reply is not read beyond its arrival. Every rejection here is
            // expected traffic -- a transaction the pool already holds, one
            // whose nonce has been mined, or a pool that is simply full -- and
            // there is nothing this node would do differently about any of
            // them.
            if let Err(err) = client.post(rpc_url.clone()).json(&body).send().await {
                debug!(target: "n42.h2.node", %err, count = chunk.len(), "could not hand transactions to the pool");
            }
        }
    }
}

/// Feeds every transaction the pool admits into `sink`, in batches, until
/// the receiver is dropped.
pub async fn poll_pending_transactions(rpc_url: url::Url, sink: mpsc::Sender<Vec<Bytes>>) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(client) => client,
        Err(err) => {
            debug!(target: "n42.h2.node", %err, "transaction source: no HTTP client");
            return;
        }
    };
    let call = |method: &'static str, params: Vec<Value>| {
        let client = client.clone();
        let url = rpc_url.clone();
        async move {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
            let response: Value = client.post(url).json(&body).send().await.ok()?.json().await.ok()?;
            response.get("result").cloned()
        }
    };
    let mut filter: Option<Value> = None;
    loop {
        tokio::time::sleep(POLL).await;
        if sink.is_closed() {
            return;
        }
        if filter.is_none() {
            filter = call("eth_newPendingTransactionFilter", vec![]).await.filter(|id| !id.is_null());
            if filter.is_none() {
                continue;
            }
        }
        let Some(changes) = call("eth_getFilterChanges", vec![filter.clone().expect("set above")]).await
        else {
            // The node forgot the filter, or is gone; start over.
            filter = None;
            continue;
        };
        if changes.is_null() {
            filter = None;
            continue;
        }
        let hashes: Vec<B256> = serde_json::from_value(changes).unwrap_or_default();
        let mut batch = Vec::with_capacity(hashes.len());
        for hash in hashes {
            if let Some(raw) = call("eth_getRawTransactionByHash", vec![json!(hash)]).await
                && let Ok(raw) = serde_json::from_value::<Bytes>(raw)
                && !raw.is_empty()
            {
                batch.push(raw);
            }
        }
        if !batch.is_empty() && sink.send(batch).await.is_err() {
            return;
        }
    }
}

/// Transactions per frame on the binary ingest. Its server takes up to 10,000;
/// a frame is also the unit one connection waits on, so smaller frames spread
/// a burst over the connections instead of queueing it behind one.
const INGEST_FRAME: usize = 1000;

/// Hands gossiped transactions to the execution layer over its binary ingest
/// (`N42_TX_INGEST`, the same socket the load generator uses) instead of
/// JSON-RPC.
///
/// The JSON path in [`forward_transactions`] tops out in the tens of
/// thousands a second: each transaction is hex in a JSON array that the RPC
/// server parses, decodes and recovers one at a time on its request path.
/// That was enough while a leader built one block in seven, because its pool
/// had seven cycles to refill from its own share of the load. A leader with a
/// tenure builds every block, so its pool has to refill at the chain's whole
/// rate -- 163,000 a second at the bench tier -- and six sevenths of that
/// arrives here, by gossip. The ingest server recovers senders on blocking
/// threads in parallel and admits a frame at a time, and it applies the
/// pool's high-water gate by delaying its reply, which is the backpressure
/// this task wants: a full pool stalls the forwarder, the loop's queue fills,
/// and the loop drops the excess gossip as it already does.
///
/// `connections` streams share the work round-robin; each waits for the reply
/// to its frame before sending the next, so the parallelism is the number of
/// connections. Connecting is lazy and retried per frame, because the
/// execution layer is usually still starting when the validator does.
pub async fn forward_transactions_over_ingest(
    addr: String,
    mut source: mpsc::Receiver<Vec<Bytes>>,
    connections: usize,
) {
    let connections = connections.max(1);
    let mut lanes: Vec<mpsc::Sender<Vec<Bytes>>> = Vec::with_capacity(connections);
    for lane in 0..connections {
        let (tx, rx) = mpsc::channel::<Vec<Bytes>>(4);
        tokio::spawn(ingest_lane(addr.clone(), lane, rx));
        lanes.push(tx);
    }
    let mut next = 0usize;
    while let Some(batch) = source.recv().await {
        for frame in batch.chunks(INGEST_FRAME) {
            let lane = &lanes[next % lanes.len()];
            next = next.wrapping_add(1);
            // Waits here, not `try_send`: the loop already bounded what it
            // hands over, and a lane that is behind is the ingest telling us
            // the pool is full. Dropping here would drop what the gate meant
            // to delay.
            if lane.send(frame.to_vec()).await.is_err() {
                return;
            }
        }
    }
}

/// One connection's worth of [`forward_transactions_over_ingest`].
async fn ingest_lane(addr: String, lane: usize, mut frames: mpsc::Receiver<Vec<Bytes>>) {
    let mut stream: Option<tokio::net::TcpStream> = None;
    let mut forwarded: u64 = 0;
    let mut accepted_total: u64 = 0;
    let mut last_report = std::time::Instant::now();
    while let Some(frame) = frames.recv().await {
        if stream.is_none() {
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    stream = Some(s);
                }
                Err(err) => {
                    debug!(target: "n42.h2.node", %err, %addr, lane, count = frame.len(), "ingest not reachable; transactions dropped");
                    continue;
                }
            }
        }
        let mut wire = Vec::with_capacity(4 + frame.iter().map(|raw| 4 + raw.len()).sum::<usize>());
        wire.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        for raw in &frame {
            wire.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            wire.extend_from_slice(raw);
        }
        let s = stream.as_mut().expect("connected above");
        let outcome = async {
            s.write_all(&wire).await?;
            let accepted = s.read_u32_le().await?;
            let pending = s.read_u32_le().await?;
            Ok::<(u32, u32), std::io::Error>((accepted, pending))
        }
        .await;
        match outcome {
            Ok((accepted, pending)) => {
                forwarded += frame.len() as u64;
                accepted_total += u64::from(accepted);
                if last_report.elapsed() >= Duration::from_secs(10) {
                    info!(target: "n42.h2.node", lane, forwarded, accepted = accepted_total, pool_pending = pending, "gossiped transactions handed to the ingest");
                    last_report = std::time::Instant::now();
                }
            }
            Err(err) => {
                debug!(target: "n42.h2.node", %err, %addr, lane, count = frame.len(), "ingest connection failed; reconnecting on the next frame");
                stream = None;
            }
        }
    }
}
