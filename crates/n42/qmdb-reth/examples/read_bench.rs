// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Point reads of the same accounts from MDBX `HashedAccounts` (what the EVM reads today) and from the
//! QMDB entry file (what plan stage 6 would serve), on a stopped node's files.
//!
//! ```text
//! cargo run --release -p n42-qmdb-reth --example read_bench -- \
//!     <mdbx db dir> <qmdb dir> [recipients 2000000] [samples 1000000] [threads 1,16]
//! ```
//!
//! The accounts are the fleet flood's recipients (`tx_flood::recipient`: slot big-endian ‖ 0x42 ‖ zeros),
//! so both stores are asked for the same keys. MDBX is advised out of the page cache before its first
//! pass (cold), then read again (warm). QMDB in file mode reads its whole entry file when it opens, so
//! only its warm pass means anything. Values are decoded on both sides.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use alloy_primitives::{keccak256, Address, B256, U256};
use n42_qmdb_state::{ForestCheckpoint, ForestDelta};
use n42_twig_core::qmdb_compat::{gov5_account_key, QmdbCompatTree};
use reth_db::mdbx::DatabaseArguments;
use reth_db_api::{database::Database, tables, transaction::DbTx};

fn recipient(slot: u32) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&slot.to_be_bytes());
    bytes[4] = 0x42;
    Address::new(bytes)
}

/// gov5 `StateAccount.MarshalV2`: presence bitmap (nonce=1, balance=2, code=8), LEB128 nonce,
/// length-prefixed big-endian balance, 32-byte code hash.
fn decode_gov5_account(value: &[u8]) -> (u64, U256, Option<B256>) {
    let bitmap = value[0];
    let mut at = 1;
    let mut nonce = 0u64;
    if bitmap & 1 != 0 {
        let mut shift = 0;
        loop {
            let byte = value[at];
            at += 1;
            nonce |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
    }
    let mut balance = U256::ZERO;
    if bitmap & 2 != 0 {
        let len = value[at] as usize;
        at += 1;
        balance = U256::from_be_slice(&value[at..at + len]);
        at += len;
    }
    let code = (bitmap & 8 != 0).then(|| B256::from_slice(&value[at..at + 32]));
    (nonce, balance, code)
}

fn advise_out(path: &Path) {
    if let Ok(file) = std::fs::File::open(path) {
        unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    }
}

fn samples(recipients: u32, n: usize) -> Vec<Address> {
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            recipient((x % u64::from(recipients)) as u32)
        })
        .collect()
}

fn summary(label: &str, threads: usize, mut lat: Vec<Duration>, wall: Duration, found: usize) {
    lat.sort_unstable();
    let p = |q: f64| lat[((lat.len() as f64 - 1.0) * q) as usize].as_nanos();
    println!(
        "{label} threads={threads} reads={} found={found} p50_ns={} p99_ns={} p999_ns={} mean_ns={} reads_per_s={:.0}",
        lat.len(),
        p(0.5),
        p(0.99),
        p(0.999),
        lat.iter().map(|d| d.as_nanos()).sum::<u128>() / lat.len() as u128,
        lat.len() as f64 / wall.as_secs_f64()
    );
}

/// The checkpoint moved to the end of the delta log (the node's own framing: u64 length, 4 bytes of the
/// payload's keccak, bincode `ForestDelta`).
fn checkpoint(dir: &Path) -> ForestCheckpoint {
    let mut ckpt: ForestCheckpoint = bincode::deserialize(&std::fs::read(dir.join("forest.ckpt")).expect("ckpt")).expect("ckpt decodes");
    let bytes = std::fs::read(dir.join("forest.log")).unwrap_or_default();
    let mut at = 0usize;
    while at + 12 <= bytes.len() {
        let len = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8")) as usize;
        let start = at + 12;
        let Some(payload) = bytes.get(start..start + len) else { break };
        if keccak256(payload)[..4] != bytes[at + 8..start] {
            break;
        }
        let delta: ForestDelta = bincode::deserialize(payload).expect("delta decodes");
        at = start + len;
        if delta.base_next_slot != ckpt.next_slot && delta.head_number <= ckpt.head_number {
            continue;
        }
        ckpt.apply_delta(&delta).expect("delta applies");
    }
    ckpt
}

fn main() -> eyre::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mdbx_dir = PathBuf::from(&args[1]);
    let qmdb_dir = PathBuf::from(&args[2]);
    let recipients: u32 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(2_000_000);
    let n: usize = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
    let thread_list: Vec<usize> =
        args.get(5).map_or(vec![1, 16], |v| v.split(',').filter_map(|t| t.parse().ok()).collect());
    let addresses = samples(recipients, n);

    // MDBX, cold then warm.
    advise_out(&mdbx_dir.join("mdbx.dat"));
    let db = reth_db::open_db_read_only(&mdbx_dir, DatabaseArguments::default())?;
    let mdbx_pass = |label: &str, threads: usize| -> eyre::Result<Vec<Option<(u64, U256)>>> {
        let started = Instant::now();
        let chunk = addresses.len().div_ceil(threads);
        let results: Vec<(Vec<Duration>, Vec<Option<(u64, U256)>>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = addresses
                .chunks(chunk)
                .map(|part| {
                    let db = &db;
                    scope.spawn(move || {
                        let tx = db.tx().expect("read transaction");
                        let mut lat = Vec::with_capacity(part.len());
                        let mut out = Vec::with_capacity(part.len());
                        for address in part {
                            let t = Instant::now();
                            let hashed = keccak256(address);
                            let account = tx.get::<tables::HashedAccounts>(hashed).expect("mdbx get");
                            lat.push(t.elapsed());
                            out.push(account.map(|a| (a.nonce, a.balance)));
                        }
                        (lat, out)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("thread")).collect()
        });
        let wall = started.elapsed();
        let mut lat = Vec::new();
        let mut out = Vec::new();
        for (l, o) in results {
            lat.extend(l);
            out.extend(o);
        }
        let found = out.iter().filter(|a| a.is_some()).count();
        summary(label, threads, lat, wall, found);
        Ok(out)
    };
    let mdbx_values = mdbx_pass("mdbx-cold", 1)?;
    for &threads in &thread_list {
        mdbx_pass("mdbx-warm", threads)?;
    }

    // QMDB from the entry file, as a restart builds it.
    let ckpt = checkpoint(&qmdb_dir);
    let opened = Instant::now();
    let (tree, _) = QmdbCompatTree::from_entry_file(&qmdb_dir.join("entries.log"), ckpt.next_slot, &ckpt.active)
        .map_err(|e| eyre::eyre!("{e:?}"))?;
    println!("qmdb-open head={} slots={} open_ms={}", ckpt.head_number, ckpt.next_slot, opened.elapsed().as_millis());
    let mut qmdb_values = Vec::new();
    for &threads in &thread_list {
        let started = Instant::now();
        let chunk = addresses.len().div_ceil(threads);
        let tree = &tree;
        let results: Vec<(Vec<Duration>, Vec<Option<(u64, U256)>>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = addresses
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        let mut lat = Vec::with_capacity(part.len());
                        let mut out = Vec::with_capacity(part.len());
                        for address in part {
                            let t = Instant::now();
                            let key = gov5_account_key(&address.0 .0);
                            let account = tree.get(&key).map(decode_gov5_account);
                            lat.push(t.elapsed());
                            out.push(account.map(|(nonce, balance, _)| (nonce, balance)));
                        }
                        (lat, out)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("thread")).collect()
        });
        let wall = started.elapsed();
        let mut lat = Vec::new();
        let mut out = Vec::new();
        for (l, o) in results {
            lat.extend(l);
            out.extend(o);
        }
        let found = out.iter().filter(|a| a.is_some()).count();
        summary("qmdb-warm", threads, lat, wall, found);
        qmdb_values = out;
    }

    // Agreement: MDBX is persisted a few blocks behind QMDB's checkpoint, so accounts written in those
    // blocks differ; the count says how many.
    let (mut same, mut differ, mut only_mdbx, mut only_qmdb) = (0usize, 0usize, 0usize, 0usize);
    for (m, q) in mdbx_values.iter().zip(&qmdb_values) {
        match (m, q) {
            (Some(a), Some(b)) if a == b => same += 1,
            (Some(_), Some(_)) => differ += 1,
            (Some(_), None) => only_mdbx += 1,
            (None, Some(_)) => only_qmdb += 1,
            (None, None) => same += 1,
        }
    }
    println!("agreement same={same} differ={differ} only_mdbx={only_mdbx} only_qmdb={only_qmdb}");
    Ok(())
}
