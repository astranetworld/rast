// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A binary TCP path into the transaction pool, for throughput rounds.
//!
//! `eth_sendRawTransaction` is the only ingress an execution layer offers, and
//! for a load generator it costs three things that have nothing to do with the
//! transaction: hex encoding, which doubles the bytes; JSON parsing of both
//! request and reply; and, above all, a request/response round trip the sender
//! has to wait out before it can send again. Measured on the seven-node fleet,
//! a generator with 64 blocking threads spent 0.9 of a core and delivered
//! ~22,000 transactions a second — about 290 ms per 100-transaction batch, with
//! the threads idle for essentially all of it.
//!
//! This is the same thing without those three. Frames are length-prefixed raw
//! EIP-2718 bytes, and a sender may put as many on the wire as it likes without
//! waiting: acknowledgements come back on the same connection, in order, and a
//! generator that does not care about them can ignore them entirely.
//!
//! # Wire
//!
//! ```text
//! frame   := u32 count, then `count` x (u32 len, len bytes of EIP-2718)
//! reply   := u32 accepted, u32 pool_pending      -- one per frame, in order
//! ```
//!
//! Little-endian, because both ends of this are the same machine or the same
//! LAN and nothing here is a consensus artefact.
//!
//! # Backpressure, which is the point of the reply
//!
//! A generator that is refused does not stop, it retries — and every retry
//! re-signs the transaction, so a full pool turns the generator's whole budget
//! into work neither side keeps. Every round measured here logged
//! `txpool is full` and then reported the generator's ceiling as the chain's.
//!
//! So this waits rather than refusing. A frame is not admitted while the pool
//! is at its high water mark; the connection simply does not answer until there
//! is room, and a client with a bounded window stops sending on its own. The
//! reply carries the pool's pending count so a client that wants to pace itself
//! can, without a second round trip to ask.
//!
//! Taken from N42-26's `crates/n42-node/src/ingest.rs`, which solved the same
//! problem in the same place — *not* from gov5, which is the Go client and has
//! no such path. What is *not* taken from it, yet, is the other half of their
//! design: their client sends a pre-recovered sender with each transaction and
//! the server trusts it, skipping ECDSA entirely. That removes ~50 us a transaction
//! and it is the right trade when recovery is the ceiling — but on this fleet
//! the machine is 94% idle at 22,000 TPS, so recovery is not the ceiling, and
//! trusting a client-supplied sender would change what the benchmark verifies
//! without changing what it measures. It is a switch worth adding the day CPU
//! becomes the limit, and not before.
//!
//! # What it is not
//!
//! Not a peer protocol and not authenticated. It hands transactions to the pool
//! exactly as `eth_sendRawTransaction` does — the pool validates every one, and
//! recovering the sender is the bulk of that — so it can admit nothing the RPC
//! could not. It is off unless `N42_TX_INGEST=<addr>` is set, and it should be
//! bound to loopback.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::Bytes;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// Largest frame this will read, in transactions.
///
/// A frame is read into memory before any of it is validated, so this bounds
/// what one connection can make the node allocate. Ten thousand transfers is
/// about 1.1 MB and comfortably more than one block of any tier here.
const MAX_FRAME_TXS: u32 = 10_000;

/// Frames one connection may have admitting in the background under
/// `N42_TX_INGEST_ASYNC`. At 100 transactions a frame and 64 connections
/// that is ~51,000 transactions buffered per node, about 300 ms of a full
/// block's demand: the length of the pool stall it is meant to cover.
const ASYNC_FRAMES_IN_FLIGHT: usize = 8;

/// Largest single transaction, in bytes.
const MAX_TX_BYTES: u32 = 1 << 20;

/// How long to wait between checks when the pool is at its high water mark.
const GATE_POLL: std::time::Duration = std::time::Duration::from_millis(2);

/// Pending transactions at which admission stops until the chain drains some.
///
/// From `N42_TX_INGEST_HIGH_WATER`, defaulting to a value that is only a
/// sensible default for a fleet whose pool holds far more: a gate above the
/// pool's own capacity never closes, and one far below it starves the builder.
/// Sized by the round, which knows its own pool depth.
fn high_water() -> usize {
    std::env::var("N42_TX_INGEST_HIGH_WATER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90_000)
}

/// Serves the ingest protocol on `addr` until the process ends.
///
/// One task per connection, and each connection is independent: a generator
/// gets its parallelism by opening several rather than by this doing anything
/// clever with one.
/// Prints the ingest's rate and time split every five seconds, once.
fn spawn_stats_reporter() {
    tokio::spawn(async move {
        let mut last = (std::time::Instant::now(), 0u64, 0u64, 0u64, 0u64);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let now = std::time::Instant::now();
            let (frames, txs, recover, pool) = (
                STATS.frames.load(Ordering::Relaxed),
                STATS.txs.load(Ordering::Relaxed),
                STATS.recover_ns.load(Ordering::Relaxed),
                STATS.pool_ns.load(Ordering::Relaxed),
            );
            let dframes = frames - last.1;
            if dframes > 0 {
                let dtxs = txs - last.2;
                let secs = now.duration_since(last.0).as_secs_f64();
                info!(
                    target: "n42.tx_ingest",
                    frames = dframes,
                    txs = dtxs,
                    rate = (dtxs as f64 / secs) as u64,
                    recover_ms_per_frame = (recover - last.3) / dframes / 1_000_000,
                    pool_ms_per_frame = (pool - last.4) / dframes / 1_000_000,
                    recover_us_per_tx = (recover - last.3) / dtxs.max(1) / 1_000,
                    pool_us_per_tx = (pool - last.4) / dtxs.max(1) / 1_000,
                    "ingest"
                );
            }
            last = (now, frames, txs, recover, pool);
        }
    });
}

/// Transactions a block holds at the tier the gate is sized for, from
/// `N42_TX_INGEST_BLOCK_TXS`; the allowance the gate grants per block the
/// pool has yet to hear of. Zero (the default) is the old gate.
fn block_txs_allowance() -> u64 {
    std::env::var("N42_TX_INGEST_BLOCK_TXS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

pub async fn serve<P>(
    addr: SocketAddr,
    pool: P,
    cache: Option<reth_evm::SenderRecoveryCache>,
    head: std::sync::Arc<AtomicU64>,
) -> std::io::Result<()>
where
    P: TransactionPool + Clone + 'static,
{
    spawn_stats_reporter();
    let listener = TcpListener::bind(addr).await?;
    info!(target: "n42.tx_ingest", %addr, "binary transaction ingest listening");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(target: "n42.tx_ingest", %err, "accept failed");
                continue;
            }
        };
        let pool = pool.clone();
        let cache = cache.clone();
        let head = std::sync::Arc::clone(&head);
        tokio::spawn(async move {
            if let Err(err) = serve_connection(stream, pool, cache, head).await {
                debug!(target: "n42.tx_ingest", %peer, %err, "ingest connection ended");
            }
        });
    }
}

async fn serve_connection<P>(
    mut stream: TcpStream,
    pool: P,
    cache: Option<reth_evm::SenderRecoveryCache>,
    head: std::sync::Arc<AtomicU64>,
) -> std::io::Result<()>
where
    P: TransactionPool + Clone + 'static,
    P::Transaction: 'static,
{
    let gate = high_water();
    let allowance = block_txs_allowance();
    // N42_TX_INGEST_ASYNC=1: answer a frame once it is past the gate and
    // admit it in the background, at most ASYNC_FRAMES_IN_FLIGHT frames at a
    // time per connection. The pool's write lock is taken for a block's
    // maintenance and the builder's snapshot, 200-300 ms at 163,000 a block,
    // and a generator whose every worker waits on this server's answer --
    // and, sending to all seven nodes, on the slowest of them -- stops for
    // that long at every block. Answered first, the frames in flight ride the
    // stall out. The answer's "accepted" is then the frame's size: what the
    // pool will not take (a gap, a fee, a full pool) is no longer reported,
    // which is right for a generator that only sends valid transactions and
    // wrong for anything else, so this is not the default.
    let asynchronous = std::env::var("N42_TX_INGEST_ASYNC").is_ok();
    let in_flight = std::sync::Arc::new(tokio::sync::Semaphore::new(ASYNC_FRAMES_IN_FLIGHT));
    // Nagle would batch the acknowledgements into the next read's latency, and
    // the point of this path is that nothing waits for a round trip.
    stream.set_nodelay(true)?;
    loop {
        let count = match stream.read_u32_le().await {
            Ok(count) => count,
            // A generator that has finished simply closes.
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        if count == 0 || count > MAX_FRAME_TXS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame of {count} transactions"),
            ));
        }
        let mut raws = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let len = stream.read_u32_le().await?;
            if len == 0 || len > MAX_TX_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("transaction of {len} bytes"),
                ));
            }
            let mut buf = vec![0u8; len as usize];
            stream.read_exact(&mut buf).await?;
            raws.push(Bytes::from(buf));
        }
        // The gate. Not a refusal and not a drop: the frame is held until the
        // chain has taken a block out of the pool, and the client hears nothing
        // until then, which is the whole difference between backpressure and a
        // generator burning its budget on retries.
        //
        // Read off the pool's size counters, not `pending_transactions()`:
        // that one takes the pool's read lock and clones every pending
        // transaction's `Arc` into a fresh `Vec`, which at a 100,000-deep pool
        // polled every 2 ms by 32 connections is a few hundred million refcount
        // touches a second under the same lock the pool admits through.
        // The gate, on what a builder could use rather than on `pending` as
        // the pool counts it: a block's transactions stay pending until the
        // pool hears the block is canonical, and a follower that has just
        // imported one holds 163,000 of them through its maintenance. Every
        // full-block round reported the deepest pool at the gate while the
        // leader's ran short -- the generator, answered by all seven nodes,
        // throttled by a follower's stale count. So for each block the chain
        // is ahead of the pool, the gate allows one block's worth more.
        loop {
            let lag = head
                .load(Ordering::Relaxed)
                .saturating_sub(pool.block_info().last_seen_block_number)
                .min(4);
            if u64::try_from(pool.pool_size().pending).unwrap_or(u64::MAX) < gate as u64 + lag * allowance {
                break;
            }
            tokio::time::sleep(GATE_POLL).await;
        }
        if asynchronous {
            let permit = std::sync::Arc::clone(&in_flight)
                .acquire_owned()
                .await
                .expect("the in-flight semaphore is never closed");
            let offered = u32::try_from(raws.len()).unwrap_or(u32::MAX);
            let pending = u32::try_from(pool.pool_size().pending).unwrap_or(u32::MAX);
            let (pool, cache) = (pool.clone(), cache.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let _ = admit(&pool, raws, cache).await;
            });
            stream.write_u32_le(offered).await?;
            stream.write_u32_le(pending).await?;
            continue;
        }
        let accepted = admit(&pool, raws, cache.clone()).await;
        let pending = u32::try_from(pool.pool_size().pending).unwrap_or(u32::MAX);
        stream.write_u32_le(accepted).await?;
        stream.write_u32_le(pending).await?;
    }
}

/// Hands a frame to the pool and counts what it took.
///
/// Decoding failures are counted as refusals rather than closing the
/// connection: one malformed transaction in a batch says nothing about the
/// next one, and a generator that sends one is not an attacker, it is a
/// generator with a bug.
/// Where the ingest's time goes, summed over every connection, and printed
/// every five seconds by [`serve`]: a generator whose workers wait 76% of
/// their time for this server's answer needs the server to say which half
/// of the answer -- recovering the senders, or the pool taking them -- it
/// was waiting for.
struct IngestStats {
    frames: AtomicU64,
    txs: AtomicU64,
    recover_ns: AtomicU64,
    pool_ns: AtomicU64,
}

static STATS: IngestStats = IngestStats {
    frames: AtomicU64::new(0),
    txs: AtomicU64::new(0),
    recover_ns: AtomicU64::new(0),
    pool_ns: AtomicU64::new(0),
};


async fn admit<P>(
    pool: &P,
    raws: Vec<Bytes>,
    cache: Option<reth_evm::SenderRecoveryCache>,
) -> u32
where
    P: TransactionPool + 'static,
    P::Transaction: 'static,
{
    // Decoding and sender recovery are CPU work -- ~50 us of secp256k1 per
    // transaction, so a 10,000-transaction frame is half a second -- and they
    // used to run on the runtime's worker thread, where every other connection
    // on that thread, and the pool's own futures, waited behind them. Blocking
    // threads are for exactly this.
    let started = std::time::Instant::now();
    let decoded = match tokio::task::spawn_blocking(move || decode_and_recover::<P>(raws, cache.as_ref())).await {
        Ok(decoded) => decoded,
        Err(err) => {
            warn!(target: "n42.tx_ingest", %err, "sender recovery task failed");
            return 0;
        }
    };
    if decoded.is_empty() {
        return 0;
    }
    // `External`, the same origin `eth_sendRawTransaction` uses for a
    // transaction that did not come from this node: it is validated, priced and
    // gossiped exactly as one that arrived over RPC.
    let recovered_at = started.elapsed();
    let count = decoded.len() as u64;
    let results = pool.add_transactions(TransactionOrigin::External, decoded).await;
    STATS.frames.fetch_add(1, Ordering::Relaxed);
    STATS.txs.fetch_add(count, Ordering::Relaxed);
    STATS.recover_ns.fetch_add(recovered_at.as_nanos() as u64, Ordering::Relaxed);
    STATS.pool_ns.fetch_add((started.elapsed() - recovered_at).as_nanos() as u64, Ordering::Relaxed);
    // Accepted, for a sender that advances its nonce on the answer: the pool
    // took it, or already had it, or the chain already mined it. The last two
    // arrive when the same frame reaches every node (`tx_flood --ingest-all`)
    // and one of them is ahead -- reporting them as refusals made the
    // generator re-send the same nonce to every node forever, and every pool
    // that had it refuse it again, until the sender gave up as stalled. What
    // is *not* accepted is what a re-send would still not fix: a gap, a fee,
    // a full pool.
    let accepted = results
        .iter()
        .filter(|outcome| match outcome {
            Ok(_) => true,
            Err(err) => {
                matches!(err.kind, reth_transaction_pool::error::PoolErrorKind::AlreadyImported)
                    || matches!(&err.kind, reth_transaction_pool::error::PoolErrorKind::InvalidTransaction(invalid) if invalid.is_nonce_too_low())
            }
        })
        .count();
    u32::try_from(accepted).unwrap_or(u32::MAX)
}

/// Decodes a frame's transactions and recovers their senders, on the calling
/// thread.
fn decode_and_recover<P>(
    raws: Vec<Bytes>,
    cache: Option<&reth_evm::SenderRecoveryCache>,
) -> Vec<P::Transaction>
where
    P: TransactionPool,
{
    let mut decoded = Vec::with_capacity(raws.len());
    for raw in raws {
        // Recover through the cache when there is one, so the sender this
        // costs ~50 us to compute is still there when the block carrying this
        // transaction is imported.
        //
        // Without it the work is simply done twice. reth's cache has exactly
        // two consumers -- devp2p transaction gossip and block import -- and
        // both recover-or-insert, so on a fleet that runs `--disable-tx-gossip`
        // and admits over RPC or over this path, nothing populates it before
        // import and it cannot hit by construction. That is what an A/B showing
        // no difference between having the cache and not having it looks like,
        // and it is not the same as the work being absent.
        type Pooled<P> = <<P as TransactionPool>::Transaction as PoolTransaction>::Pooled;
        let recovered = match <Pooled<P> as alloy_eips::Decodable2718>::decode_2718_exact(raw.as_ref()) {
            Ok(pooled) => match cache {
                Some(cache) => <P::Transaction as PoolTransaction>::try_recover_with_cache(pooled, cache)
                    .map_err(|_| "invalid signature".to_string()),
                None => <P::Transaction as PoolTransaction>::try_recover(pooled)
                    .map_err(|_| "invalid signature".to_string()),
            },
            Err(err) => Err(err.to_string()),
        };
        match recovered {
            Ok(tx) => decoded.push(tx),
            Err(err) => debug!(target: "n42.tx_ingest", %err, "undecodable transaction"),
        }
    }
    decoded
}
