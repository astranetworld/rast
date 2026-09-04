// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Load generator for the seven-node fleet: funds a derived sender set, then
//! floods it at the chain.
//!
//! ```text
//! tx_flood --rpc http://127.0.0.1:8700,http://127.0.0.1:8701 --chain-id 1143 \
//!          --senders 3000 --pertx 300 --offset 1 --conc 32 --rpcbatch 100
//! ```
//!
//! This is the Rust counterpart of gov5's `cmd/txflood`, and it derives its
//! senders the same way — `keccak256("n42-txflood-sender-v1" ‖ be64(offset+i+1))`
//! as the secret — so a round against either client draws on the identical set
//! of accounts. That matters for a comparison: the supply side is then provably
//! the same thing, not two harnesses that merely resemble each other.
//!
//! # Why one sender is not enough
//!
//! A key is a nonce sequence, so one key is one serial pipe: at 21,000-gas
//! transfers a single sender tops out around a hundred a second and the
//! measurement is of the harness. Thousands of senders in parallel is the only
//! way the chain becomes the limit — which is also how the chain's own limits
//! (pool depth, sender recovery, the gossip size cap) become visible at all.
//!
//! # `--offset` is not optional between rounds
//!
//! Derived accounts keep their nonces across runs. One transaction lost
//! anywhere in that history — rejected, or dropped from the pool before it was
//! mined — leaves a permanent hole: everything above it stays queued and can
//! never be promoted, because promotion needs the account's exact next nonce.
//! gov5 measured this as a pool holding 118,530 queued transactions with zero
//! pending and near-empty blocks, and it reads exactly like a node failure.
//! A fresh offset gives accounts whose nonces start at zero, which cannot have
//! a hole.
//!
//! # The gas price is a measurement decision
//!
//! The flood submits at a fixed price while the chain's base fee is chain state
//! that survives the round. A round started when the base fee sits above this
//! price does not merely run slow — it dies in its funding phase, and the
//! windows dutifully report an idle chain. Default 10 gwei against a 1 gwei
//! genesis floor leaves room for roughly twenty consecutive full blocks of
//! 12.5% climb; past that, let the chain idle or raise the price.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Signature, TxKind, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::{json, Value};

/// Where the flood's transfers go when `--recipients 1`.
///
/// Value lands somewhere that will never spend it again, so the senders'
/// balances are the only thing that moves.
const SINK: Address = Address::new([0x42; 20]);

/// Knuth's multiplicative constant, as N42-26's `n42-stress` uses it to spread
/// recipients. Kept identical so a block of this fleet's transfers touches the
/// same *number* of accounts, in the same scattered way, as a block of theirs.
const RECIPIENT_SPREAD: u32 = 2_654_435_761;

/// The recipient for one transfer.
///
/// One address for every transfer is the wrong shape and it took a comparison
/// to notice: a 163,000-transaction block that pays a single account writes one
/// account, where the same block with scattered recipients writes 163,000.
/// Five orders of magnitude of state, absent from every number this harness
/// produced before.
///
/// It also made one direction unmeasurable. Every transaction writing the same
/// account is a write-write conflict on every transaction, so a parallel
/// executor would serialise on it completely -- exactly the case N42-26's
/// roadmap excludes when it says the speedup shows only on contract-heavy
/// blocks.
fn recipient(spread: u32, index: u64) -> Address {
    if spread <= 1 {
        return SINK;
    }
    let slot = ((index as u32).wrapping_mul(RECIPIENT_SPREAD)) % spread;
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&slot.to_be_bytes());
    bytes[4] = 0x42;
    Address::new(bytes)
}
const TRANSFER_GAS: u64 = 21_000;
/// gov5 caps a batch here; beyond it the JSON body itself becomes the cost.
const MAX_RPC_BATCH: usize = 200;

struct Args {
    rpcs: Vec<String>,
    chain_id: u64,
    faucet: String,
    senders: usize,
    per_tx: u64,
    offset: u64,
    gas_price: u128,
    /// Gas limit on every transfer, funding included. 21,000 is a transfer
    /// everywhere before Amsterdam; on an Amsterdam chain EIP-8037 charges
    /// state creation up front, and a transfer that *creates* its recipient
    /// needs about 207,000 of limit or it runs out of gas -- mined, charged,
    /// and the value never moves. Measured here: a funding round that
    /// "mined through nonce 6000" and left every sender at 0 wei.
    gas: u64,
    conc: usize,
    rpc_batch: usize,
    shard_senders: bool,
    skip_funding: bool,
    /// How many distinct recipients the transfers are spread over. 1 keeps the
    /// old single-sink shape.
    recipients: u32,
    /// Binary ingest addresses, one per node, in place of JSON-RPC for the
    /// flood. Funding stays on RPC: it is six thousand transactions once, and
    /// it needs to read nonces back.
    ingest: Vec<String>,
    /// Every worker sends every transaction to every ingest, so no pool
    /// depends on gossip to hold what another pool holds. gov5 measures this
    /// way (their flood submits to all seven RPCs), and a leader with a
    /// tenure needs it: a transaction its pool never received leaves that
    /// sender's later nonces unbuildable for the whole tenure, and the fleet's
    /// other pools fill with them until the ingest gate stops the generator.
    ingest_all: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse()?;
    let client = Arc::new(
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(args.conc.max(1))
            .build()?,
    );

    let keys: Vec<PrivateKeySigner> = (0..args.senders).map(|i| derive(args.offset, i)).collect();
    println!(
        "senders      : {} derived at offset {} (first {})",
        keys.len(),
        args.offset,
        keys.first().map_or_else(|| "-".into(), |k| k.address().to_string())
    );

    if !args.skip_funding {
        fund(&client, &args, &keys)?;
    }

    let started = Instant::now();
    let sent = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    // A line every five seconds, because the round kills this process before
    // it could sum up, and a generator that cannot say its own rate leaves
    // "the chain was starved" and "the generator was slow" indistinguishable.
    // The three clocks say where a worker's time went: signing (CPU, this
    // process), sending (socket writes), waiting (the node's answer).
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (sent, rejected, stop) = (Arc::clone(&sent), Arc::clone(&rejected), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut last = (Instant::now(), 0u64);
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(5));
                let now = Instant::now();
                let total = sent.load(Ordering::Relaxed);
                let rate = (total - last.1) as f64 / now.duration_since(last.0).as_secs_f64();
                eprintln!(
                    "flood +{:>4}s: sent {} ({:.0}/s), rejected {}, sign {}s, send {}s, wait {}s, deepest pool {}",
                    started.elapsed().as_secs(),
                    total,
                    rate,
                    rejected.load(Ordering::Relaxed),
                    SIGN_NS.load(Ordering::Relaxed) / 1_000_000_000,
                    SEND_NS.load(Ordering::Relaxed) / 1_000_000_000,
                    WAIT_NS.load(Ordering::Relaxed) / 1_000_000_000,
                    DEEPEST.load(Ordering::Relaxed),
                );
                last = (now, total);
            }
        });
    }
    // One thread owns a disjoint set of senders, so a sender's nonces are
    // produced in order by one place. Sharing a sender across threads is how a
    // flood generates its own nonce holes.
    let chunk = args.senders.div_ceil(args.conc.max(1));
    std::thread::scope(|scope| {
        for (worker, part) in keys.chunks(chunk).enumerate() {
            let (client, sent, rejected, args) =
                (Arc::clone(&client), Arc::clone(&sent), Arc::clone(&rejected), &args);
            scope.spawn(move || {
                let mut batch: Vec<String> = Vec::with_capacity(args.rpc_batch);
                // Every sender this thread owns is in flight at once, a batch at
                // a time in rotation, rather than one sender being drained to
                // completion before the next one starts.
                //
                // Walking them sequentially puts exactly `--conc` nonce
                // sequences on the chain at any moment, and a single full block
                // of this tier can take more transactions than that offers. It
                // shows up as occupancy falling while the chain speeds up —
                // measured at 250 ms pacing as 68% occupancy with the chain
                // producing 51 blocks in a window — and it makes every sender
                // back off in lockstep when the pool fills, because they are all
                // at the same point in their own sequence.
                let mut nonce = vec![0u64; part.len()];
                let mut stalls = vec![0u32; part.len()];
                let mut live = part.len();
                // The binary path, when a round asked for one. A worker gets
                // one connection; its parallelism is the frames it keeps in
                // flight on that connection, not the number of connections.
                let mut ingest = if args.ingest.is_empty() {
                    None
                } else {
                    let addrs: Vec<&str> = if args.ingest_all {
                        args.ingest.iter().map(String::as_str).collect()
                    } else {
                        vec![args.ingest[worker % args.ingest.len()].as_str()]
                    };
                    match Ingest::connect(&addrs) {
                        Ok(conn) => Some(conn),
                        Err(err) => {
                            eprintln!("ingest {}: {err}", addrs.join(","));
                            return;
                        }
                    }
                };
                if let Some(conn) = ingest.as_mut() {
                    flood_over_ingest(conn, part, &mut nonce, &mut stalls, args, &sent, &rejected);
                    return;
                }
                while live > 0 {
                    live = 0;
                    for (index, key) in part.iter().enumerate() {
                        if nonce[index] >= args.per_tx {
                            continue;
                        }
                        live += 1;
                        // `--shard-senders` pins a sender to one node, so every
                        // proposer owns whole nonce sequences and the followers'
                        // pools stay cold: that measures the cold sender-recovery
                        // path. Spreading them warms every pool instead. Neither
                        // is wrong; a round has to say which it used.
                        let rpc = if args.shard_senders {
                            &args.rpcs[(worker * chunk + index) % args.rpcs.len()]
                        } else {
                            &args.rpcs[(worker + index) % args.rpcs.len()]
                        };
                        // Only advance a sender's nonce on acceptance. Under
                        // sustained oversupply the pool fills and starts
                        // refusing, and a flood that skipped the refused nonce
                        // would leave a hole: every later transaction from that
                        // sender stays queued forever, because promotion needs
                        // the account's exact next nonce. gov5 measured that as
                        // 118,530 queued with zero pending and near-empty
                        // blocks, which reads exactly like a node failure.
                        let from = nonce[index];
                        let upto = (from + args.rpc_batch as u64).min(args.per_tx);
                        batch.clear();
                        batch.extend(
                            (from..upto)
                                .map(|n| {
                                    let to = recipient(args.recipients, (worker * chunk + index) as u64 * args.per_tx + n);
                                    signed(key, n, args.chain_id, args.gas_price, args.gas, 1, to)
                                }),
                        );
                        let accepted = submit(&client, rpc, &batch, &sent, &rejected);
                        nonce[index] += accepted as u64;
                        if accepted < batch.len() {
                            stalls[index] += 1;
                            // A sender that has been refused this long is not
                            // coming back within the round; give up on it rather
                            // than spending the rest of the round on it.
                            if stalls[index] > 600 {
                                nonce[index] = args.per_tx;
                            }
                        } else {
                            stalls[index] = 0;
                        }
                    }
                    // One sleep per pass, not one per refused sender: the pass
                    // has already given the chain every other sender's work.
                    if live > 0 && stalls.iter().any(|s| *s > 0) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            });
        }
    });
    stop.store(true, Ordering::Relaxed);

    let elapsed = started.elapsed().as_secs_f64();
    let (sent, rejected) = (sent.load(Ordering::Relaxed), rejected.load(Ordering::Relaxed));
    println!(
        "flood        : {sent} accepted, {rejected} rejected, {elapsed:.1}s, {:.0}/s submitted",
        (sent + rejected) as f64 / elapsed
    );
    // A flood that could not give the chain more than the chain took has
    // measured itself. Saying so is the difference between a result and a
    // number.
    println!("note         : the submission rate above is this harness's ceiling, not the chain's");
    Ok(())
}

/// gov5 `deriveKey`: `keccak256("n42-txflood-sender-v1" ‖ be64(offset+i+1))`.
///
/// A hash that does not land on a valid secp256k1 scalar is hashed again rather
/// than skipped, so the set stays dense and the same index always names the
/// same account.
fn derive(offset: u64, index: usize) -> PrivateKeySigner {
    let mut seed = {
        let mut input = Vec::with_capacity(21 + 8);
        input.extend_from_slice(b"n42-txflood-sender-v1");
        input.extend_from_slice(&(offset + index as u64 + 1).to_be_bytes());
        keccak256(input)
    };
    loop {
        match PrivateKeySigner::from_bytes(&seed) {
            Ok(signer) => return signer,
            Err(_) => seed = keccak256(seed),
        }
    }
}

fn signed(key: &PrivateKeySigner, nonce: u64, chain_id: u64, gas_price: u128, gas: u64, value: u64, to: Address) -> String {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: gas,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price / 10,
        to: TxKind::Call(to),
        value: U256::from(value),
        ..Default::default()
    };
    let signature = key.sign_hash_sync(&tx.signature_hash()).expect("sign");
    let envelope: TxEnvelope = tx.into_signed(signature).into();
    alloy_primitives::hex::encode_prefixed(envelope.encoded_2718())
}

/// Time all workers spent signing, sending frames, and waiting for answers,
/// in nanoseconds; and the deepest pool any answer reported.
static SIGN_NS: AtomicU64 = AtomicU64::new(0);
static SEND_NS: AtomicU64 = AtomicU64::new(0);
static WAIT_NS: AtomicU64 = AtomicU64::new(0);
static DEEPEST: AtomicU64 = AtomicU64::new(0);

/// Floods one worker's senders over a binary ingest connection.
///
/// Round-robin across the senders, one frame in flight per sender, and a bound
/// on how many frames may be outstanding at once so a worker cannot outrun the
/// node's ability to answer. A sender whose frame is still unanswered is
/// skipped rather than waited on, which is what keeps every other sender
/// moving while one is being validated.
fn flood_over_ingest(
    conn: &mut Ingest,
    part: &[PrivateKeySigner],
    nonce: &mut [u64],
    stalls: &mut [u32],
    args: &Args,
    sent: &AtomicU64,
    rejected: &AtomicU64,
) {
    /// Frames a worker may have unanswered at once.
    ///
    /// Deep enough that the connection is never idle waiting for an answer,
    /// shallow enough that a worker cannot bury the node under work it has
    /// already refused: at 100 transactions a frame this is 3,200 in flight
    /// per worker.
    const WINDOW: usize = 32;

    let mut inflight = vec![false; part.len()];
    let mut done = vec![false; part.len()];
    // The deepest the pool was seen to be, so a round can tell a generator that
    // could not keep up from a chain that was full the whole time.
    let mut deepest = 0usize;
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(args.rpc_batch);
    loop {
        let mut wrote = false;
        for (index, key) in part.iter().enumerate() {
            if done[index] || inflight[index] || conn.inflight.len() >= WINDOW {
                continue;
            }
            let from = nonce[index];
            if from >= args.per_tx {
                done[index] = true;
                continue;
            }
            let upto = (from + args.rpc_batch as u64).min(args.per_tx);
            batch.clear();
            let at = Instant::now();
            batch.extend(
                (from..upto).map(|n| {
                    let to = recipient(args.recipients, index as u64 * args.per_tx + n);
                    signed_raw(key, n, args.chain_id, args.gas_price, args.gas, 1, to)
                }),
            );
            SIGN_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
            let at = Instant::now();
            if conn.send(index, &batch).is_err() {
                return;
            }
            SEND_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
            inflight[index] = true;
            wrote = true;
        }
        // Nothing left to write and nothing left to hear about.
        if !wrote && conn.inflight.is_empty() {
            if deepest > 0 {
                eprintln!("ingest       : deepest pool seen {deepest} pending");
            }
            return;
        }
        let at = Instant::now();
        let answer = conn.recv();
        WAIT_NS.fetch_add(at.elapsed().as_nanos() as u64, Ordering::Relaxed);
        match answer {
            Ok(Some((index, offered, accepted, pending))) => {
                deepest = deepest.max(pending);
                DEEPEST.fetch_max(pending as u64, Ordering::Relaxed);
                inflight[index] = false;
                sent.fetch_add(accepted as u64, Ordering::Relaxed);
                rejected.fetch_add((offered - accepted) as u64, Ordering::Relaxed);
                // Only accepted nonces advance, exactly as on the RPC path: a
                // skipped nonce leaves a hole and every later transaction from
                // that sender queues behind it forever.
                nonce[index] += accepted as u64;
                if accepted < offered {
                    stalls[index] += 1;
                    if stalls[index] > 600 {
                        done[index] = true;
                    }
                } else {
                    stalls[index] = 0;
                }
            }
            Ok(None) => {}
            Err(_) => return,
        }
    }
}

/// One connection to a node's binary transaction ingest.
///
/// Frames go out without waiting for the ones before them to be answered,
/// which is the whole reason this exists. Over JSON-RPC each batch was a
/// request the sender had to see answered before it could send again —
/// measured at about 290 ms per 100-transaction batch, with 64 threads idle
/// for essentially all of it and the generator using 0.9 of a core to deliver
/// ~22,000 transactions a second.
///
/// The window is per sender, not per transaction: a worker owns many senders
/// and puts one frame in flight for each, so a single sender's nonces are
/// still strictly serial — one frame, then its answer, then the next — while
/// the connection always has work on it.
struct Ingest {
    /// One node's ingest, or every node's at once (`--ingest-all`): a frame
    /// goes to each stream, and a reply is read from each in the same order.
    streams: Vec<std::net::TcpStream>,
    /// Senders with a frame in flight, in the order the frames were written.
    /// Replies come back in the same order, so this is what matches an answer
    /// to the sender it belongs to.
    inflight: std::collections::VecDeque<(usize, usize)>,
}

impl Ingest {
    fn connect(addrs: &[&str]) -> std::io::Result<Self> {
        let mut streams = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let stream = std::net::TcpStream::connect(addr)?;
            // Without this the kernel holds a frame back waiting for company,
            // and the pipelining above turns back into a round trip per batch.
            stream.set_nodelay(true)?;
            streams.push(stream);
        }
        Ok(Self { streams, inflight: std::collections::VecDeque::new() })
    }

    /// Writes one frame: `u32` count, then each transaction as `u32` length and
    /// its raw EIP-2718 bytes.
    fn send(&mut self, sender: usize, batch: &[Vec<u8>]) -> std::io::Result<()> {
        use std::io::Write;
        let mut frame = Vec::with_capacity(4 + batch.iter().map(|t| 4 + t.len()).sum::<usize>());
        frame.extend_from_slice(&(batch.len() as u32).to_le_bytes());
        for raw in batch {
            frame.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            frame.extend_from_slice(raw);
        }
        // One write for the whole frame: a frame split across writes is a
        // frame the server reads in two syscalls.
        for stream in &mut self.streams {
            stream.write_all(&frame)?;
        }
        self.inflight.push_back((sender, batch.len()));
        Ok(())
    }

    /// Reads the answer to the oldest frame still in flight.
    ///
    /// The answer arrives when the pool has room, not when the frame arrives:
    /// the server holds a frame at its high water mark rather than refusing it,
    /// so a full pool shows up here as a slow reply and not as a rejection to
    /// re-sign and resend. The pending count comes back with it, which is what
    /// makes the generator's own logs able to say whether it was the chain that
    /// was full or the generator that was slow.
    fn recv(&mut self) -> std::io::Result<Option<(usize, usize, usize, usize)>> {
        use std::io::Read;
        let Some((sender, offered)) = self.inflight.pop_front() else {
            return Ok(None);
        };
        // Across the streams: the fewest accepted, so a nonce never advances
        // past what every pool holds, and the deepest pool, which is the one
        // gating the generator.
        let mut accepted = usize::MAX;
        let mut pending = 0usize;
        for stream in &mut self.streams {
            let mut buf = [0u8; 8];
            stream.read_exact(&mut buf)?;
            accepted = accepted.min(u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes")) as usize);
            pending = pending.max(u32::from_le_bytes(buf[4..8].try_into().expect("4 bytes")) as usize);
        }
        Ok(Some((sender, offered, accepted, pending)))
    }
}

/// The same transaction as [`signed`], as bytes rather than as a hex string.
fn signed_raw(key: &PrivateKeySigner, nonce: u64, chain_id: u64, gas_price: u128, gas: u64, value: u64, to: Address) -> Vec<u8> {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: gas,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price / 10,
        to: TxKind::Call(to),
        value: U256::from(value),
        ..Default::default()
    };
    let signature = sign_hash(key, &tx.signature_hash());
    let envelope: TxEnvelope = tx.into_signed(signature).into();
    envelope.encoded_2718()
}

/// Signs a hash with libsecp256k1 rather than the signer's k256.
///
/// The signer's own `sign_hash_sync` is pure-Rust k256 and costs ~80 us a
/// transaction on this generator's SMT-shared cores -- 22 of its 64 workers
/// were signing at 269k/s with the other 42 waiting on answers, which put
/// the flood's own ceiling near 300k/s, below what the chain now consumes.
/// libsecp256k1 signs in a fraction of that, and the node recovers with the
/// same library, so the two sides agree on low-s normalisation. The
/// secret is re-derived from the signer's bytes each call; that is a scalar
/// check, ~1 us, nothing beside the signature. `TX_FLOOD_K256_SIGN=1`
/// restores the k256 path for an A-B.
fn sign_hash(key: &PrivateKeySigner, hash: &B256) -> Signature {
    static K256: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *K256.get_or_init(|| std::env::var_os("TX_FLOOD_K256_SIGN").is_some()) {
        return key.sign_hash_sync(hash).expect("sign");
    }
    let secret = secp256k1::SecretKey::from_slice(key.to_bytes().as_slice()).expect("a derived key is a valid scalar");
    let message = secp256k1::Message::from_digest(hash.0);
    let (recovery_id, compact) =
        secp256k1::SECP256K1.sign_ecdsa_recoverable(&message, &secret).serialize_compact();
    Signature::new(
        U256::from_be_slice(&compact[..32]),
        U256::from_be_slice(&compact[32..]),
        i32::from(recovery_id) != 0,
    )
}

/// Submits a batch as one JSON-RPC array. Counts each element's outcome, since
/// a batch is not atomic: some elements are accepted while others are refused,
/// and reporting the call rather than the elements hides a pool that is full.
/// Submits a batch and returns how many of its leading elements were accepted.
///
/// The prefix is what matters, not the total: the elements are one sender's
/// consecutive nonces, so the first refusal invalidates everything behind it
/// whatever the node said about those.
fn submit(
    client: &reqwest::blocking::Client,
    rpc: &str,
    batch: &[String],
    sent: &AtomicU64,
    rejected: &AtomicU64,
) -> usize {
    let body: Vec<Value> = batch
        .iter()
        .enumerate()
        .map(|(id, raw)| {
            json!({"jsonrpc": "2.0", "id": id, "method": "eth_sendRawTransaction", "params": [raw]})
        })
        .collect();
    match client.post(rpc).json(&body).send().and_then(reqwest::blocking::Response::json::<Value>) {
        Ok(Value::Array(results)) => {
            let bad = results.iter().filter(|r| r.get("error").is_some()).count() as u64;
            // Say why, once. A round that reports "2000 rejected" and nothing
            // else is a round spent guessing: the reasons are all different
            // problems — a base fee above the price, a nonce hole, a full pool,
            // a chain that is not moving — and they are all one line away.
            if bad > 0 {
                static SAID: std::sync::Once = std::sync::Once::new();
                SAID.call_once(|| {
                    if let Some(error) = results.iter().find_map(|r| r.get("error")) {
                        eprintln!("first rejection: {error}");
                    }
                });
            }
            rejected.fetch_add(bad, Ordering::Relaxed);
            sent.fetch_add(results.len() as u64 - bad, Ordering::Relaxed);
            // A batch response may come back out of order, so the prefix is
            // measured by id rather than by position.
            let failed: std::collections::HashSet<u64> = results
                .iter()
                .filter(|r| r.get("error").is_some())
                .filter_map(|r| r.get("id").and_then(Value::as_u64))
                .collect();
            (0..batch.len()).take_while(|id| !failed.contains(&(*id as u64))).count()
        }
        Ok(other) => {
            // A single object rather than an array is an error for the whole
            // batch — a method the node does not have, or a body it refused.
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| eprintln!("batch refused: {other}"));
            rejected.fetch_add(batch.len() as u64, Ordering::Relaxed);
            0
        }
        Err(err) => {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| eprintln!("submit failed: {err}"));
            rejected.fetch_add(batch.len() as u64, Ordering::Relaxed);
            0
        }
    }
}

/// One transfer per sender from the faucet, enough to cover every transaction
/// the flood will ask of it plus its own gas.
fn fund(
    client: &reqwest::blocking::Client,
    args: &Args,
    keys: &[PrivateKeySigner],
) -> Result<(), Box<dyn std::error::Error>> {
    let faucet: PrivateKeySigner = args.faucet.parse()?;
    let rpc = &args.rpcs[0];
    let call = |method: &str, params: Vec<Value>| -> Result<Value, Box<dyn std::error::Error>> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let response: Value = client.post(rpc).json(&body).send()?.json()?;
        if let Some(error) = response.get("error") {
            return Err(format!("{method}: {error}").into());
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    };

    // Per sender: everything the flood will spend, plus ten transfers of slack.
    let per_gas = args.gas_price * u128::from(args.gas);
    let fund_value = per_gas * u128::from(args.per_tx + 10);
    let total = (fund_value + per_gas) * args.senders as u128;

    // Check the faucet before submitting anything. A faucet that cannot cover
    // the round presents as mass rejection during the flood, not as an error,
    // and reads like a chain that fell over.
    let balance = call("eth_getBalance", vec![json!(faucet.address()), json!("latest")])?;
    let balance = U256::from_str_radix(balance.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
    println!(
        "faucet       : {} holds {} wei, round needs {total}",
        faucet.address(),
        balance
    );
    if balance < U256::from(total) {
        return Err(format!(
            "faucet holds {balance} wei but this round needs {total}; lower --senders/--pertx or wait for rewards"
        )
        .into());
    }

    let nonce = call("eth_getTransactionCount", vec![json!(faucet.address()), json!("latest")])?;
    let mut nonce = u64::from_str_radix(nonce.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
    let started = Instant::now();
    let (sent, rejected) = (AtomicU64::new(0), AtomicU64::new(0));
    let mut batch = Vec::with_capacity(args.rpc_batch);
    for key in keys {
        let tx = TxEip1559 {
            chain_id: args.chain_id,
            nonce,
            gas_limit: args.gas,
            max_fee_per_gas: args.gas_price,
            max_priority_fee_per_gas: args.gas_price / 10,
            to: TxKind::Call(key.address()),
            value: U256::from(fund_value),
            ..Default::default()
        };
        let signature = faucet.sign_hash_sync(&tx.signature_hash())?;
        let envelope: TxEnvelope = tx.into_signed(signature).into();
        batch.push(alloy_primitives::hex::encode_prefixed(envelope.encoded_2718()));
        nonce += 1;
        if batch.len() >= args.rpc_batch {
            // Funding is one nonce sequence from the faucet and it either goes
            // in or the round is over; the prefix count is for the flood.
            let _ = submit(client, rpc, &batch, &sent, &rejected);
            batch.clear();
        }
    }
    if !batch.is_empty() {
        let _ = submit(client, rpc, &batch, &sent, &rejected);
    }
    println!(
        "funding      : {} submitted, {} rejected, {:.1}s",
        sent.load(Ordering::Relaxed),
        rejected.load(Ordering::Relaxed),
        started.elapsed().as_secs_f64()
    );

    // Wait for the last funding transaction to be mined. Flooding before the
    // senders hold anything spends the whole round on rejections.
    let target = nonce;
    for _ in 0..120 {
        let mined = call("eth_getTransactionCount", vec![json!(faucet.address()), json!("latest")])?;
        let mined = u64::from_str_radix(mined.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
        if mined >= target {
            println!("funding      : mined through nonce {mined}");
            // Mined is not funded. A transfer whose gas limit is below what
            // this chain charges to create the recipient is mined, charged
            // and failed, and the faucet's nonce advances exactly as if it had
            // worked -- so the balance is what has to be read.
            let first = keys.first().ok_or("no senders to fund")?;
            let held = call("eth_getBalance", vec![json!(first.address()), json!("latest")])?;
            let held = U256::from_str_radix(held.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
            if held.is_zero() {
                return Err(format!(
                    "funding mined but {} holds 0 wei: the transfers failed in execution -- on an Amsterdam chain raise --gas (EIP-8037 charges account creation up front)",
                    first.address()
                )
                .into());
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err("funding did not mine within 120s; check the base fee against --gasprice".into())
}

fn parse() -> Result<Args, Box<dyn std::error::Error>> {
    let mut args = Args {
        rpcs: vec!["http://127.0.0.1:8700".into()],
        chain_id: 1143,
        // hardhat account 0, which this chain's genesis funds; tests/e2e.sh uses it too.
        faucet: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        senders: 0,
        per_tx: 300,
        offset: 0,
        gas_price: 10_000_000_000,
        gas: TRANSFER_GAS,
        conc: 32,
        rpc_batch: 100,
        shard_senders: false,
        skip_funding: false,
        ingest: Vec::new(),
        ingest_all: false,
        recipients: 1,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || it.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--rpc" => args.rpcs = next()?.split(',').map(str::to_owned).collect(),
            "--chain-id" => args.chain_id = next()?.parse()?,
            "--key" => args.faucet = next()?,
            "--senders" => args.senders = next()?.parse()?,
            "--pertx" => args.per_tx = next()?.parse()?,
            "--offset" => args.offset = next()?.parse()?,
            "--gasprice" => args.gas_price = next()?.parse()?,
            "--gas" => args.gas = next()?.parse()?,
            "--conc" => args.conc = next()?.parse()?,
            "--rpcbatch" => args.rpc_batch = next()?.parse::<usize>()?.clamp(1, MAX_RPC_BATCH),
            "--ingest" => args.ingest = next()?.split(',').map(str::to_owned).collect(),
            "--ingest-all" => args.ingest_all = true,
            "--recipients" => args.recipients = next()?.parse()?,
            "--shard-senders" => args.shard_senders = true,
            "--skip-funding" => args.skip_funding = true,
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}").into()),
        }
    }
    if args.senders == 0 {
        return Err(format!("--senders is required\n\n{USAGE}").into());
    }
    if args.rpcs.is_empty() {
        return Err("--rpc needs at least one URL".into());
    }
    Ok(args)
}

const USAGE: &str = "\
tx_flood — fund a derived sender set and flood the fleet with transfers

  --rpc <url[,url]>   nodes to submit to (default http://127.0.0.1:8700)
  --chain-id <u64>    the chain (default 1143)
  --key <hex>         faucet private key
  --senders <n>       how many accounts to derive and fund (required)
  --pertx <n>         transactions per sender (default 300)
  --offset <n>        shift the derived set; use a fresh one every round
  --gasprice <wei>    default 10 gwei; must stay above the chain's base fee
  --gas <limit>       gas limit per transfer (default 21000; ~210000 on Amsterdam,
                      where EIP-8037 makes creating the recipient cost more)
  --conc <n>          concurrent submitters (default 32)
  --rpcbatch <n>      transactions per JSON-RPC batch, 1-200 (default 100)
  --shard-senders     pin each sender to one node (cold-follower path)
  --skip-funding      the senders are already funded
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libsecp_signs_what_k256_signs() {
        for i in 0..8u64 {
            let key = PrivateKeySigner::from_bytes(&keccak256(i.to_be_bytes())).expect("key");
            let hash = keccak256((i * 7).to_be_bytes());
            let fast = sign_hash(&key, &hash);
            let slow = key.sign_hash_sync(&hash).expect("sign");
            assert_eq!(fast, slow, "sender {i}: libsecp256k1 and k256 disagree");
            assert_eq!(fast.recover_address_from_prehash(&hash).expect("recover"), key.address());
        }
    }
}
