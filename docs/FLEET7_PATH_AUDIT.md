# Fleet7 main-path audit: duplicated storage, duplicated work, structural waits (2026-09-13)

Scope: the 7-node HotStuff bench on the loop155 configuration (`docs/FLEET7_HANDOFF.md`: seal-first,
build-on-seal, deferred execution, parallel build and follower graft, QMDB entry file, retention 16), read
end to end in code: the leader's build and hand-off, a follower's check and import, reth's engine insert, and
persistence (`save_blocks`, RocksDB, static files, QMDB `on_canonical`). Per-phase costs are medians of the
loop155 A2 bench logs unless another loop is named. The fleet could not be run during the audit (a DATC build
held the box), so every fix below is either behaviour-neutral and proven by tests, or switched off by default
until a fleet leg measures it.

## 1. Is the QMDB tree's storage a duplicate of the plain state?

Reads: no. The EVM reads the latest state from MDBX `HashedAccounts`/`HashedStorages` (under storage v2 the
plain-state tables are not written at all); the QMDB computation reads only its own key index (the slot each
changed key held) and never a value.

Storage: yes. Every account and slot a block touches is written three times as a value:

| copy | holds | duplicate of | needed for |
| --- | --- | --- | --- |
| QMDB `entries.log` | every version of every leaf (blake3 key), live or dead | its live records = MDBX hashed tables; its dead records = the changesets' old values | the state root and proofs; restart |
| MDBX `HashedAccounts`/`HashedStorages` | the latest state (keccak keys) | QMDB's live records | every latest-state read, today |
| static-file account/storage changesets | the previous value per block (plain keys) | QMDB's dead records, but with block numbers and plain keys | historical state, unwinds; the full archive |
| RocksDB account/storage history | block numbers per key | derived from the changesets | fast history lookups |

The hashed tables are the one copy that can go without losing the archive, once the QMDB read view
(`docs/QMDB_UPGRADE_PLAN.md`, stage 6) answers every latest-state read on the fleet (6c). Until then each
touched key is also hashed twice per block (blake3 for QMDB, keccak for the hashed state).

## 2. Findings on the critical path

Follower (vote gate). A follower checks block N+1 only after block N's import has finished, ~200 ms: the
check waits for N's recorded execution fields and reads senders through `state_by_block_hash(N)`, which
needs N inserted in the engine. So N's carry fill (26 ms), hashed post-state (30), engine insert (52-61) and
the serial root/hashed pair sit in front of every vote, although the check needs only ~6,000 senders' nonces
and balances, all in N's bundle right after execution.

Leader (seal path, ~237 ms in window 1): the graft inserts ~147,000 accounts into one map serially (~70 ms);
the receipts loop commits 150,000 identical transfer receipts one at a time (45 ms); the body is deep-copied
four times per block; the provisional StateReady execution clones the whole bundle and all receipts only to
drop the receipts; the build-on-own start asks the forest for a parent's root while that parent's QMDB
computation holds the forest's lock, to get `None`; every transaction is encoded twice (tx root, wire frame).

Engine: reth converts the payload of a block its tree already holds and drops the result (a deep copy of the
body on the engine thread) and fills its execution cache over ~147,000 accounts, which nothing on this chain
reads.

Queue: `forget_mined` folded 163,000 nonces into a map before noticing the build stood on another parent; the
canonical pruner built a 163,000-entry SipHash set every block on every node for a closure that almost never
runs.

## 3. Findings in persistence (beside the path, same box)

- The plain-state reverts were converted four times per persisted block (two changeset writers, two history
  index writers).
- Account history read and rewrote each touched address's last shard serially (storage history already ran in
  parallel).
- Every pending RocksDB batch was committed with its own WAL fsync (three per save).
- QMDB fsynced `entries.log` every block but never the delta log that names those entries, nor the checkpoint
  it rewrites (`fs::write` + `rename`): after an OS crash the node could keep the entries, lose the delta and
  refuse to start.
- The QMDB delta per block largely repeats what the entry file and its active bits already hold (encoding and
  a keccak over ~1.3 MB a block); the checkpoint grows by a bit per slot ever written.

## 4. Fixed (behaviour-neutral; tests)

| fix | where | expected effect |
| --- | --- | --- |
| sender grouping in the follower's check with the address hasher | `bin/n42/src/follower_import.rs` `check_includable` | ~29 ms serial before the vote, per the measured SipHash cost |
| no carry fill after a parallel import (it read its accounts through its own providers) | `follower_import.rs` | 26 ms of the import |
| QMDB root and hashed post-state on the pool together by default (adopted in `FLEET7_STATUS.md`, never set) | `follower_import.rs` `root_hashed_parallel` | 94 -> 81 ms measured |
| build-on-own does not wait on the forest lock for a parent still behind its seal | `bin/n42/src/payload_serve.rs`, `built_executions::stage_of` | up to the parent's QMDB compute at the next build's start |
| `forget_mined` looks before folding, folds outside the lock | `crates/n42/tx-queue/src/lib.rs` | 5-15 ms and less queue-lock hold on the hand-off |
| canonical pruner builds its set only when an own block is held | `bin/n42/src/main.rs` | 10-20 ms per block on every node |
| plain-state reverts converted once per block, shared by both writers | `providers/database/provider.rs`, `static_file/manager.rs`, `rocksdb/provider.rs` | three conversions of ~147,000 accounts per persisted block |
| account history shards prepared on the worker pool | `rocksdb/provider.rs` | ~147,000 serial RocksDB reads per persisted block |
| one WAL sync per RocksDB commit | `rocksdb/provider.rs` `commit_batches` | two fsyncs per save |
| QMDB delta log and checkpoints durable | `crates/n42/qmdb-reth/src/node_state.rs` | correctness after an OS crash; one small fsync per block |
| no keccak before the QMDB reader answers | `providers/state/latest.rs` | one keccak per read in `N42_QMDB_READS=on` |
