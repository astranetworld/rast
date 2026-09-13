# Plan: port LayerZero QMDB's advantages into our QMDB (disk first), and serve state reads from it

## Context

We compared LayerZero's official `qmdb` (f14a2a09c) with our QMDB (gov5 format, `crates/n42/twig-core`,
`qmdb-state`, `qmdb-reth`) on the node's real state and on fleet7-shaped blocks
(`docs/QMDB_LAYERZERO_COMPARISON.md`, harness `/home/n42/src/n42/qmdb-compare`):

| | ours | LayerZero (no io_uring) |
| --- | --- | --- |
| block p50, 2M keys / 50M keys | 75 / 121 ms (p99 ~216) | 85 / 99 ms (p99 110) |
| memory, 2M / 50M keys | 4.1 / 10.7 GB | 1.1 / 2.5 GB |
| disk, same history | 2.0 / 2.6 GB | 7.0 / 15.1 GB |
| 1M creates a block | 318 ms | 608 ms |
| point read | none (EVM reads MDBX) | ~1 us |

User decisions (2026-09-13): the grouping rule, if a change-set grouping is ever needed, is **one change set
per block**; **disk footprint matters**; **do not switch to LayerZero's library** -- study its advantages and
design how to use them in ours; **include read performance against our MDBX**; **every node stays a full
archive** (no pruning of transactions, receipts, senders, changesets or history indices) -- disk work is
limited to what an archive can shed: QMDB's dead space, the hashed state tables that duplicate QMDB, and pure
overhead such as RocksDB's WAL (2.1 GB of node0's 4.1 GB).

Intended outcome: our store keeps its small disk and gov5-compatible root, gains LayerZero's memory and
large-keyspace latency, serves the node's state reads, and lets the node drop reth's hashed state tables.

## Findings that shape the design (so far)

Our store (file:line in `twig-core/src/qmdb_compat.rs` unless noted):
- Per-block costs that grow with total slots/twigs, not the block: `retire_twigs` zeroes an O(slots) bitmap
  and scans all twigs (904-953); `rehash_dirty` scans all twigs (1005-1020); `root()` rebuilds the whole upper
  tree serially every block and every proof (1720-1733); `trim_dead_twigs` scans all twigs (1862-1876).
- Leaf hashing uses scalar `blake3::Hasher` (lib.rs:36-42); the AVX2/512 kernels in `twig-core/src/simd.rs`
  are unused on this path.
- `KeyIndex` (1097-1194): 256 std HashMaps chosen by `key[0]`, hasher puts `key[0]` in the hash's low byte, so
  within a shard all keys start probing at 1/256 of the buckets (to confirm with a counter). ~47-94 B a key.
- Twig `nodes` (4096 hashes, 128 KiB) kept for every twig with a live slot (64 B/slot); `offsets` 8-16 B/slot;
  forest records ~33 MB/block x retain depth; `QmdbForest` behind one mutex for whole blocks
  (`qmdb-reth/src/node_state.rs:264`), no getter, tree may stand at a pending build.
- Restart walks and hashes every record in `entries.log` (`entry_store.rs:118-191`, `from_entry_file`
  1300-1335): dead byte ranges cannot be dropped until per-twig roots are persisted.
- Real leg (loop155 A2): 29.6M slots for 1.74M live keys, ~42 B a record, 1.16 GB.

gov5 (`../N42-gov5/lib/qmdb`), root-compatible tiers we can port: twig-leaf eviction with rehydration
(`twig_evict.go`, called after every block), incremental upper fold (`qmdb.go:605-683`), persisted twig
table for O(twigs) restart (`persist.go:280-299, 610-624`), dead-twig pruning (`compaction.go:markPruned`).
Root-changing and therefore fork-gated: live-entry compaction (`Compact`), sharded root (`sharded.go`).

Node disk (node0 `el/` after a 295-block leg, 32.6M Ed25519 transactions; `du`):

| component | size | needed to follow the chain? |
| --- | --- | --- |
| static files: transactions | 6.1 GB (+0.26 index) | no (serve blocks / RPC; unwind below the persisted head) |
| RocksDB (tx-hash index, account/storage history; WAL 2.1 GB of it) | 4.1 GB | no (RPC, historical state) |
| static files: senders / account changesets / receipts (+indices) | 0.9 / 0.9 / 0.5 GB | senders no; changesets only a reorg window; receipts no |
| QMDB (`entries.log` + ckpt/log) | 1.1 GB | yes |
| MDBX (`HashedAccounts`/`HashedStorages`, `Bytecodes`, body indices) | 241 MB | yes (hashed tables replaceable by QMDB) |

QMDB is ~8% of a node's disk; LayerZero's 3-6x layout would have doubled the node. The bench runs as an archive
(no `--prune.*`, `reth.toml` `[prune.segments]` empty); under storage v2 both history indices go to RocksDB
unconditionally (`crates/storage/provider/src/providers/rocksdb/provider.rs:1421-1422`).

Node read path: EVM → revm `State` → `CachedReads` carry → `StateProviderDatabase` → `MemoryOverlayStateProvider`
(linear scan of up to ~8 unpersisted blocks) → vendored `LatestStateProviderRef`
(`crates/storage/provider/src/providers/state/latest.rs:73-82` account: keccak + `mdbx_get` on `HashedAccounts` +
Compact decode; 300-320 storage: two keccaks + DupSort `get_both_range`). Measured 1.96 us a fetch warm
(`docs/NATIVE_FLEET7.md:5240`); cold fetches are single-page major faults (readahead off); 98% of the EL's major
faults are `mdbx_get` (349-356). No N42 `StateProvider` impl exists; the least-change plug point is the vendored
`LatestStateProviderRef` (it is what the engine, follower, builder and RPC all construct). The vendored
`HistoricalStateProviderRef` (`crates/storage/provider/src/providers/state/historical.rs:352-373`, storage
248-260) falls back to `HashedAccounts`/`HashedStorages` for a key's latest value, so an archive's historical
queries need the same QMDB branch before the hashed tables stop being written.

RocksDB WAL (`crates/storage/provider/src/providers/rocksdb/provider.rs:260-305`): 128 MB write buffer per
column family, WAL deleted only after every column family has flushed (`set_wal_ttl_seconds(0)`,
`set_wal_size_limit_mb(0)`), no `max_total_wal_size` -- a rarely written column family pins every WAL: node0
holds 32 WAL files, 2.72 GB, of a 4.1 GB RocksDB.

LayerZero mechanisms (`/home/n42/src/n42/qmdb-layerzero/crates`), all root-neutral to port:
- Index (`qmdb/src/indexer/memidx.rs`): 65,536 units by `kh[0..2]`, sorted 9-byte elements (3 key bytes + 6-byte
  pos/8) with a bucket offset table, overflow set for inserts, tombstones, background merge; candidates
  confirmed by reading the entry's key. ~11 B/key at 50M, lookup touches 1-2 cache lines.
- Twigs (`merkletree/tree.rs:784-802`, `twig.rs:123-172`): a full twig keeps 288 B + 256 B ActiveBits; a
  deactivation rehashes bitmap nodes only; leaves are needed only for proofs (twig file) -- ours can recompute
  them from the entry file.
- Upper tree (`tree.rs:318-371, 439-515`): only ancestors of touched twigs, ~D(1+log2(T/D)) hashes.
- Pipeline: per-block `EntryCache` fed by prefetch, pooled buffers, fsync off the timed path.
- Its disk (3-6x ours) is its record format (88-104 B for our values, ~200 B a create) plus never pruning below
  its compaction threshold: nothing to adopt for disk.

Two claims confirmed in code: (1) `KeyPrefixHasher` (`qmdb_compat.rs:1179-1194`) receives the `[u8;32]` length
prefix as a write, so a key's hash is `LE(key[0..8]) ^ 32`; shards are chosen by `key[0]` (1122), so every key in a
shard has the same low hash byte and probes start at 1/256 of the buckets. (2) `N42_HASHED_STATE=0` stops the chain
(`bin/n42/src/follower_import.rs:588-603`: the engine rejects an executed block, "gas used mismatch: got 0") -- the
hashed tables cannot be dropped until that dependency is found.

## Status

| stage | state | where the numbers are |
| --- | --- | --- |
| 0 | done | `docs/QMDB_LAYERZERO_COMPARISON.md` sections 6.1-6.5 |
| 1a | done: lookups 3-4x faster, warm reads +8%, block path -3%, roots unchanged | same doc, section 6.6 |
| 7 | code in (`max_total_wal_size` 256 MiB, `N42_ROCKSDB_MAX_WAL_MB`); fleet leg with WAL size still to record | -- |
| 2 | done: upper tree cached, refreshed along changed paths; `prove` reads it; roots unchanged, block p50 unchanged at 50M keys (the full fold was a few ms), no full rebuild per proof | `/data/blockchain/qmdb-compare/stage2` |
| 3a | done: retire and rehash proportional to the block, SIMD leaf and twig-level batches, coarse parallel units, restart hashes each bit set once and twigs in parallel. Real-state rebuild 4,541 -> 1,402 ms; S p50/p99 68.0/129.8 -> 60.2/106.5 ms; L 102.9/125.3 -> 95.5/107.6 ms; roots unchanged | `/data/blockchain/qmdb-compare/stage3a` |
| 3b | done: every full twig below the retention window drops its 128 KiB of leaf nodes, live or not; proofs and truncations rehash one from the entries (checked against its leaf root); restart keeps nodes only for the last twig. Real-state rebuild 1,402 -> 744 ms and RSS 5.38 -> 1.67 GB; L RSS 11.22 -> 7.09 GB; latency unchanged; roots unchanged | `/data/blockchain/qmdb-compare/stage3b` |
| 1b | done: 256 shards of `u64` buckets (24-bit seeded fingerprint, whose top bits are the home, and slot + 1), linear probing, load <= 3/4, growth without key reads, every match confirmed against the entry store. L RSS 7.09 -> 4.73 GB (prefill 6.30 -> 4.11), S 1.16 -> 1.01 GB; L block p50/p99 95.9/106.8 -> 98.9/112.5 ms (the confirm read); roots unchanged | `/data/blockchain/qmdb-compare/stage1b` |
| 4a | deferred: after 3a/3b the real state restarts in 0.74-0.94 s at 1.6 GB, which was 4a's latency motive; its other motive, dropping dead byte ranges (4b), has nothing to reclaim on this workload (section 6.2). Revisit when a larger state makes restart matter | -- |
| 5 | next: no clone of a block's operations (5a), then retention bounded by finality | -- |

## Recommended approach

Principle: every change is root-neutral (gov5 format byte-exact), each stage ships alone behind its own gate, and
LayerZero's library is used only as a reference. Order: **0 → 1a → 2 → 3 → 1b → 4a → 5 → 6a/6b → 6c → 4b**; 7 is
independent.

**Stage 0 -- measure (no behaviour change; harness `/home/n42/src/n42/qmdb-compare`, outside the repo).**
- Read benchmark on the loop155 A2 node0 state: MDBX `HashedAccounts`/`HashedStorages` get + Compact decode (reth
  db crates on a copy of `el/db`), our `QmdbCompatTree::get` after `from_entry_file`, LayerZero `read_entry` on the
  replayed store. Addresses and slots from the account/storage changeset static files. Warm and cold
  (`posix_fadvise(DONTNEED)`), 1 and 16 threads, p50/p99.
- `perf record` of our apply at 50M keys (workload L); phase split: index probe, upper rebuild, DIRTY_BITS vs
  DIRTY_LEAVES rehash counts, `note_move` BTreeSet, `ops.clone()`.
- Index probe-length histogram (feature `index-stats`), a `memory_report()` per component, disk accounting per
  `el/` component with RocksDB column-family and WAL sizes, and the QMDB bytes reclaimable in fully dead twigs.
- Results appended to `docs/QMDB_LAYERZERO_COMPARISON.md`; stages 3, 1b and 4b are sized from them.

**Stage 1a -- index hasher fix** (`twig-core/src/qmdb_compat.rs` `KeyPrefixHasher`): ignore the length-prefix write
and mix `key[8..16]` with a per-process seed (keys are grindable). One function.

**Stage 2 -- incremental upper tree** (new `twig-core/src/upper.rs`, used by `QmdbCompatTree`): dense per-level
`Vec<Hash>` over twig roots; `null_level` extended to 40 levels for the right edge; a sorted dirty-twig list maps to
parents level by level (`simd.rs` pair hashing, rayon on large levels); growth on new twigs, shrink on `apply_undo`
truncation. `root()` becomes O(1) and `prove` reads siblings from the levels. The old full fold stays as
`root_full()` under `cfg(test)` / a `root-check` feature and is asserted equal in debug builds.

**Stage 3 -- twig-node eviction and scan removal** (`qmdb_compat.rs`, `qmdb-state/src/forest.rs`):
- Drop `nodes` of every full twig whose last slot is below the hot cursor (tip − 4 blocks, including a pending
  build's `prev_next_slot`), live or not; a monotone pointer keeps it O(new twigs). Replaces `trim_dead_twigs`.
- `ensure_hydrated(twig)` (after gov5 `twig_evict.go:49-143`): hash the 2,048 records from the mmap with
  `simd::hash_leaves`, check `leaf_root` and `root`, refuse without mutating on mismatch. Called before
  `apply_undo` truncates into an old twig and by `prove` (scratch array).
- `apply_undo` revivals use `rehash_bits`, not a full `recompute`.
- `retire_twigs`, `rehash_dirty` work over sorted dirty lists, not O(slots) bitmaps or all twigs;
  `from_entry_file` sets bits directly, one `hash_bits` per twig, parallel recompute.

**Stage 1b -- compact index** (new `twig-core/src/index.rs`, trait `SlotIndex`): `TagIndex` -- 256 shards by
`key[0]`, open addressing over `u64` buckets `tag:24 | slot:40`, home from `key[4..12]` with a seed, linear probe,
backward-shift delete, load ≤ 0.75, prefetch (the `twig-core/src/flat.rs` pattern), and a mandatory confirm of
every tag match against the key read from the entry file. ~11-16 B a key against ~60. The current map stays as
`HashIndex` for differential tests; LayerZero's sorted units (`memidx.rs`) are the fallback if p99 shows resize
spikes.

**Stage 4a -- checkpoint v2 with a twig table** (`forest.rs` `ForestCheckpoint`/`ForestDelta`,
`qmdb-reth/src/node_state.rs` `initialize_file_mode`): per full twig `leaf_root` and base byte offset, carried by
deltas (`sealed_twigs`) and rewound with them; restart restores full twigs evicted and hashes only the youngest
twig -- O(twigs) instead of hashing 29.6M records -- then refuses to start unless the rebuilt root equals the head's
state root (or its `executed_fields` under deferred execution). v1 readers kept; `N42_QMDB_VERIFY_ON_START=1` runs
the full check in the background.

**Stage 5 -- finality-bounded retention** (`forest.rs`): records at or below the committed block keep
`{parent, number, root}`; ops and undo only for uncommitted blocks; `compute_operations` stops cloning ops;
`dirty_slots` and the delta's slot set become sorted `Vec`s; default retain depth 16; the hot cursor follows the
uncommitted depth.

**Stage 6 -- QMDB serves state reads.**
- 6a `qmdb-state/src/view.rs`: a versioned read view at the MDBX-persisted head N (the provider's anchor, 2-8 blocks
  behind the forest tip): index shards behind `RwLock`s, append-only offset pages, mmap chunks published through
  `ArcSwap`, file truncation deferred while views exist (no SIGBUS), a per-block key journal giving each view its
  `since` map, a generation check against reverts below N.
- 6b vendored `crates/storage/provider/src/providers/state/latest.rs` (`basic_account` 73-82, `storage` 300-320) and
  the `InPlainState` fallbacks in `historical.rs` (248-260, 352-373) branch on `N42_QMDB_READS=off|verify|on|only`;
  gov5 MarshalV2 decoded into reth's `Account`; bytecode stays in MDBX `Bytecodes`.
- 6c, only after the `N42_HASHED_STATE=0` failure is understood: stop `write_hashed_state` in `save_blocks`
  (`database/provider.rs:774-790`) and the hashed post-state passes (`follower_import.rs`,
  `engine-types/src/payload.rs`, `direct_build.rs`) behind an N42 storage flag. Archive history keeps coming from
  changesets and history indices.

**Stage 4b -- QMDB dead-space reclamation, opt-in (default off). Stage 0 result: 0 of 14,472 full twigs are fully dead on the real state, so punching dead twigs reclaims nothing here; QMDB history on disk only shrinks with live-entry compaction (root-changing, fork-gated). Kept only as an option for workloads with cold history.** `u32` offsets relative to the twig base;
`fallocate(PUNCH_HOLE|KEEP_SIZE)` over fully dead twigs below finality with a persisted punched set; `snapshot()`,
`entry_at` and portable export return an error on a punched twig. Off on archive and snapshot-serving nodes until
gov5's portable v2 hollow twigs are supported; enabled per node only after stage 0 shows the reclaimable size.

**Stage 7 -- archive-safe node disk** (`crates/storage/provider/src/providers/rocksdb/provider.rs` options): set
`max_total_wal_size` (~256 MB) and flush on persistence commit, so a rarely written column family no longer pins
2.7 GB of WAL. No pruning of any history (full-archive decision).

**Targets at 50M live keys** after stage 5: RSS ~1.5-2 GB (now 10.7), block p50 ≤ 100 ms and p99 < 130 ms (now 121 /
~216); after stage 6 a warm state read ≤ 1.5 us (MDBX measured 1.96); disk no larger than today.

**Fork-gated later, with gov5, not in this plan:** LayerZero's paged ActiveBits hashing, live-entry compaction, a
sharded root, NextKey entries for exclusion proofs; if a change-set grouping is ever needed, one change set per block.

## Verification

Every stage must pass, before the next starts:
- `cargo test -p n42-twig-core` (including `matches_gov5_cross_client_v1_vectors`), `cargo test -p n42-qmdb-state`,
  the `qmdb-reth` `node_state` restart tests.
- A new oracle proptest: random blocks, undo across power-of-two twig boundaries, siblings, eviction points and
  restarts, compared against the preserved legacy structures (`root_full`, `HashIndex`, never-evicting tree).
- Real state: rebuild `/data/blockchain/qmdb-compare/loop155A2-node0` to root `0xfd21f549…29b6ce6` (after 4a: in
  under a second, from the v2 checkpoint).
- Harness roots unchanged: 50-block fixed-order S `0xbf3fc24c…8b3e76`, L prefill `0x9e0588a3…`; latency, RSS and
  disk against the baseline table in `docs/QMDB_LAYERZERO_COMPARISON.md`.
- Stage 6: an n42-testing dev-chain run (persistence threshold 8, reorg at the tip) in `verify` with zero
  mismatches; a 16-reader stress test against a state-at-N oracle; a fleet7 leg in `verify`, then in `on`, with all
  nodes agreeing on roots.
- Stage 7: a fleet7 leg with RocksDB WAL size recorded and archive RPC history queries unchanged.
- All benchmarks on the shared box run in a 20 GB `systemd-run --user --scope` with the MemAvailable < 30 GB
  watchdog, never during a fleet leg or while DATC needs the memory.
