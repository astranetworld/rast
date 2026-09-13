# QMDB against its paper: direction, storage-layer defects, and the alternatives

*2026-09-13. A read of the code (`crates/n42/twig-core`, `qmdb-state`, `qmdb-reth`, the vendored
provider), gov5's `lib/qmdb` and `modules/state/commitment`, the QMDB paper (Zhang, Zarick, Wong,
Kim, LayerZero Labs, arXiv 2501.05262), and the public material on NOMT, Firewood, MonadDb,
AlDBaran and EIP-7864. No benchmark was run for this note; the numbers quoted as measured come
from `docs/NATIVE_FLEET7.md` and `docs/FLEET7_PLAN_V2.md`, the rest are labelled estimates.*

## 1. What is a binary tree in the node today

| Header field | Structure on the bench chain | Where |
| --- | --- | --- |
| State root | QMDB: 2048-leaf twigs, split twig commitment, upper binary tree, all Blake3. Under deferred execution the header carries the parent's root | `twig-core/src/qmdb_compat.rs`, `qmdb-reth/src/strategy.rs` |
| Transactions root | keccak Merkle-Patricia trie (parallel build). A Blake3 binary root exists only as a gov5 proposal | `engine-types/src/assembler.rs`; PHASE_D section 14 |
| Receipts root | flat keccak over the concatenated receipts (gov5's format) | `h2-consensus/src/header_profile.rs` |
| Withdrawals root | flat keccak (MPT form also accepted) | `header_profile.rs`, `hotstuff_consensus.rs` |

reth's MPT is off on QMDB chains: the engine strategy returns empty trie updates and the trie
tables are never written. `bmt-core` (a Blake3 sparse binary Merkle tree) is used only by
`mobile-verify`, not by the node. So the answer to "is it a binary tree" is yes for the state, no
for the other three roots.

Direction check: Ethereum's own EIP-7864 replaces the hexary keccak MPT with a unified binary tree,
its draft on BLAKE3 (final hash TBD: BLAKE3, keccak or Poseidon2). A Blake3 binary state
commitment is on the same road.

## 2. The paper in one page

- **Entry**: Id, Key, Value, NextKey, OldId, OldNextKeyId, Version. NextKey makes exclusion proofs
  (`E.Key < K < E.NextKey`); OldId/Version make historical proofs.
- **Twig**: 2048 entries. The youngest twig lives entirely in DRAM; a full twig keeps only its root
  (32 B) and its ActiveBits bitmap (256 B) in DRAM ("99.9% compression"); an inactive twig keeps
  its hash; a pruned twig's subtree is gone. Merkleization touches only the global root, shard
  roots, upper nodes and twig roots.
- **Updates**: append the new entry, flip the old entry's active bit. Read = 1 SSD read; update =
  1 read + 1 write; create = 1 read + 2 writes; delete = 2 reads + 1 write. Writes are batched
  (an SSD write every 2048 updates).
- **Indexer**: in-memory B-tree map, ~15.4 B of DRAM per key; a hybrid SSD indexer, ~2.3 B.
- **Compaction**: a worker re-appends old live entries so that the active ratio per shard stays
  above a threshold; old twigs become inactive and are pruned. Storage tracks live state, not
  history.
- **Sharding**: by the top bits of the key hash (16 shards in the example), roots folded above.
- **Blocks**: "N+1 serializability"; the chain is expected to keep a buffering layer and write
  only finalized data. Recovery replays to the last checkpoint.
- **It is the state database**: key-value and Merkle storage in one structure, replacing a
  RocksDB-backed MPT. Table 3: 614,948 / 346,843 / 294,349 updates per second at 4M / 256M / 4096M
  keys against NOMT's 162,190 / 42,277 / 37,057; ~6x over RocksDB; up to 2.28M updates per second
  with io_uring on larger hardware; 15 billion entries on one server.

## 3. Side by side

| Aspect | Paper | gov5 (`lib/qmdb`) | This node |
| --- | --- | --- | --- |
| Hash | not named in the text | Blake3, domain bytes | Blake3, same bytes (cross-client fixtures) |
| Twig root | subtree hash + ActiveBits | `hashNode(leafRoot, Blake3(0x03‖bits))` | same (matches) |
| Entry fields | Key, Value, NextKey, OldId, OldNextKeyId, Version | key, value; death stamps for history | key, value only |
| Proofs | inclusion, exclusion, historical | inclusion; historical bits via `history.go` | inclusion at the head only |
| Full twig in DRAM | 32 B root + 256 B bits | nodes evicted (`EvictTwigsThrough`, live path) and rehydrated on demand | 4096-hash array (131 KB, ~64 B a slot) until every bit is 0 |
| Upper tree | incremental, dirty paths | incremental with dirty marks | rebuilt from zero, serially, on every `root()` and every `prove` |
| Index | 15.4 B / 2.3 B per key | flat open-addressing index; MDBX-backed persistent index injected by the engine | 256 `HashMap<Hash,u64>` shards, ~60 B per live key, rebuilt at restart |
| Compaction | yes, by active ratio | implemented (`Compact`), not on the live path; moving live entries changes the root | none |
| Sharding | yes | `ShardedTree` (opt-in, new chains: its root differs) | one tree |
| Non-final blocks | not in the database: write finalized only | undo records, revert | forest: records 16-64 deep, undo, `move_to`, rename, pending build |
| Role | the state database; reads served from it | commitment beside Erigon PlainState; `N42_STATE_READ_QMDB=off/verify/on` | commitment beside MDBX; EVM reads never touch it |

## 4. Direction problems

**4.1 QMDB is a side structure, not the state database (the largest one).** The paper's whole cost
argument is that one append-only structure serves both reads and the commitment. Here the EVM reads
reth's state provider: in-memory blocks, then MDBX `HashedAccounts`/`HashedStorages` keyed by
keccak (storage v2). Every block therefore pays for the state three times:

1. the QMDB forest and entry file (Blake3 keys, the root);
2. the hashed post-state pass (keccak of every touched address and slot; measured 26 ms of a
   438 ms follower import, and the same on the build) and its persistence into MDBX
   (loop147: the persistence thread writing ~150,000 accounts a block; loop148: 1.3 s per
   persistence cycle, 109 cycles a leg);
3. changesets in static files and history indices in RocksDB, plus ~15 MB a block of bundle and
   hashed state held in memory for up to eight unpersisted blocks.

Four storage engines (QMDB files, MDBX, RocksDB, static files) compete for the same 16 cores and
page cache the execution needs. `N42_HASHED_STATE=0` stops the chain (loop106) because on v2 the
hashed tables *are* the read state. gov5 has the same shape by default and the switch to leave it
(`QMDBReadMode` off → verify → on) already written.

**4.2 The forest carries non-final state the paper keeps out of the database.** HotStuff-2 finalizes
in two views, and under deferred execution at most the head and one or two pending blocks are
uncommitted. The forest still keeps block records 16-64 deep with undo records, re-applies across
branches, renames builds and replays deltas. That machinery is where loop147-152's defects lived
(the sibling's empty body, the forest's `DeltaBase` refusal, the aborted execution's receipts, the
outdated insert). The paper's model is a buffering layer above the database and finalized-only
writes; reth already keeps unpersisted blocks in memory, which is that layer.

**4.3 The entry format cannot prove absence or history.** Without NextKey there is no exclusion
proof (a light client cannot prove an account does not exist); without OldId/Version there is no
historical proof. The format is frozen by the gov5 fixtures, so this is a fork-gated, cross-client
change, not a local one.

## 5. Storage-layer defects (implementation, most local)

1. **Twig nodes of live twigs stay in DRAM.** 131 KB per twig (~64 B a slot) until every one of the
   twig's 2048 slots is dead. One long-lived account pins a twig forever. The paper keeps 288 B per
   full twig; gov5 evicts the node arrays on its live path and rebuilds a twig's leaf tree from the
   entry file when a proof needs it. The bench hides this: its 2M recipients and 6,000 senders are
   overwritten constantly, so old twigs die. A real chain's account distribution does not.
2. **No compaction.** The entry file and the per-slot bitmap grow with every modification (973 MB
   a node for one leg). Without compaction, footprint tracks history, not live state, and point 1
   has no way out. Compaction that moves live entries changes the root (gov5 `compaction.go`), so
   its trigger and order are a consensus rule to agree with gov5.
3. **The upper tree is rebuilt from zero on every root and every proof**, serially:
   `next_power_of_two(twigs) - 1` hashes a call. ~8,000 hashes at a leg's end (milliseconds). As an
   estimate, at 1M TPS (~2M slots a second) a day of history is ~86M twigs and ~134M hashes a root.
   It must become incremental (dirty twig roots only), as in the paper and gov5.
4. **The key index costs ~60 B a live key and is rebuilt at restart by scanning the file.** The
   paper: 15.4 B in memory or 2.3 B hybrid; gov5: a flat open-addressing index and a persistent
   MDBX-backed one.
5. **Restart is serial and history-sized.** Replay sets each active bit one at a time, rehashing the
   256-byte bitmap per active slot, then recomputes every twig serially; the checkpoint holds
   per-slot bits and no twig or leaf roots, so every leaf is hashed again.
6. **One unsharded tree.** Leaf hashing, retire and index inserts use rayon, but there is no
   partition with independent roots. A sharded root is a different root (new chains only, as gov5's
   `ShardedTree` notes).
7. **Defaults and drift.** `N42_QMDB_ENTRY_FILE` defaults to off in code (the bench sets it);
   `N42_QMDB_RETAIN_DEPTH` defaults to 64. Stale comments: `qmdb_compat.rs` calls the keys keccak
   (they are Blake3); `node_state.rs` describes a restart from the checkpoint the file mode no
   longer does; `QMDB_ENTRY_LOG.md` says "not implemented yet" above its own done list.

What is right and should stay: the split twig commitment (deactivation touches 256 B, never the
leaf tree), Blake3, append-only slots, fsync of the entry file before the delta, the file-backed
entries with a small checkpoint, dead-twig trimming.

## 6. Alternatives

| Candidate | What it is | Fit here |
| --- | --- | --- |
| **QMDB as the state DB** (the paper's own model) | reads from the index and the entry file; drop the hashed tables | Best fit: local (not consensus), keeps the gov5 root, removes a full copy of state. Recommended |
| LayerZero `qmdb` crate (Rust, MIT, active through 2026-05) | the paper's implementation: HPFile, hybrid indexer, compaction, io_uring | Its entry and hash layout are not gov5's frozen format, so swapping it in changes the root. Borrow its indexer, compaction and file layer; do not swap |
| NOMT (Thrum) | binary Merkle trie on disk: Beatree key-value store + Bitbox page-aligned node table, io_uring | A canonical (key-set) root, but a different commitment, and the paper measures it 8x slower than QMDB at 4B keys. No |
| Firewood (Ava Labs) | trie nodes stored directly on disk, revisions, free lists, no compaction | Beta, Ecosystem License, 16-ary trie. No |
| MonadDb | Patricia trie natively on SSD, io_uring, can bypass the filesystem | Part of Monad's C++ client, MPT-shaped; take the lessons (async IO, raw device), not the code |
| AlDBaran (2025) | in-memory, thread-sharded sparse binary Merkle tree; asynchronous snapshots and journal | Claims 10-30x QMDB, on 96 cores and 1.5 TB of DRAM with state in memory. gov5's `ShardedTree` already borrows its sharding. The idea to keep for the hot path: no disk IO while updating |
| Tuning MDBX / RocksDB | | Treats the symptom: the cost is duplication, not the engine |

## 7. Recommendation, in order

1. **Serve state reads from QMDB and stop the hashed tables** (local, no consensus change; plan v2
   section 1.5, plan v3 phase C). A reth `StateProvider` over `QmdbNodeState`
   (`account_leaf`/`storage_leaf` exist, no hot-path caller yet) with bytecode by hash from
   `Bytecodes`; a verify mode first (both reads, compare, as gov5's `QMDBReadVerify`), then a
   persistence path in the vendored provider that skips `write_hashed_state` and the hashed
   post-state pass. What it removes, measured: the 26 ms hashed pass on each side, the persistence
   thread's ~150,000 account writes a block, the keccak per read. What it needs: RPC and proofs
   served from QMDB (reth's `eth_getProof` is already wrong on these chains), changesets only where
   an archive wants them.
2. **Finalized-only writes**: apply to the forest on commit; the pending build reads an in-memory
   overlay (reth's `MemoryOverlayStateProvider` already does this for build-on-own). Retain depth 2,
   and most of the forest's branch code can go.
3. **Local memory and time fixes**: evict node arrays of full twigs and rebuild on proof demand
   (gov5's `EvictTwigsThrough`/`ensureHydrated`); an incremental upper tree; a flat persistent key
   index; a checkpoint that carries twig leaf roots and bits; a parallel restart; entry file and a
   small retain depth as the defaults.
4. **With gov5, fork-gated**: a deterministic compaction schedule; a sharded root for new chains;
   NextKey and Version in the entry for exclusion and historical proofs; the Blake3 binary
   transactions and receipts roots already proposed.

Expected effect on the bench, as an estimate: item 1 is worth tens of milliseconds a block on each
chain plus the background IO and page cache that windows 2-3 lose today; it does not lift the
current wall, which is transaction supply (Ed25519 verification on every node). Items 3-4 matter for
running days rather than 90-second windows, and for 1M TPS, where the state changes ~200 MB a second
a node.
