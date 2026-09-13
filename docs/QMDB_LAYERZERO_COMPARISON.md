# LayerZero's QMDB against our QMDB (gov5 format): data and performance comparison

*2026-09-13. Measured on the fleet7 box beside a DATC run (each run in a 20 GB memory scope,
swap off, stopped if the box's MemAvailable fell under 30 GB). LayerZero `qmdb` at commit
`f14a2a09c` (2026-05-29, MIT); ours at `b1af5f213`. The harness is
`/home/n42/src/n42/qmdb-compare` (outside this repository: it depends on both code bases by path).
Performance sections are filled in from the runs; this section is written from the code.*

## 1. Format and semantics, side by side

| | Ours (gov5 format, `twig-core::qmdb_compat`) | LayerZero `qmdb` |
| --- | --- | --- |
| Entry | key, value | key, value, next_key_hash, version (i64), serial number, list of serial numbers it deactivates |
| Entry bytes | `[key 32][len u32 LE][value]` | `[u32 LE (value_len<<8 | key_len)][dsn_count u8] key value next_key_hash version sn dsn* pad-to-8` |
| Leaf hash | `Blake3(0x01 ‖ key ‖ value)` | Blake2b-512 of the payload, truncated to 32 bytes |
| Internal node | `Blake3(left ‖ right)` | keyed Blake3, the key the Blake3 IV with the children's level xored into byte 0 |
| Twig | 2048 leaves; root = `node(leaf_root, Blake3(0x03 ‖ bits))` | 2048 leaves; root = `H_11(left_root, L3)`, L3 a 3-level Merkle tree over the bitmap's 8 pages |
| Key placement | the key itself is Blake3(address) or Blake3(address ‖ slot) | Blake3(key) chooses the shard (top 4 bits) and the next-key order |
| Shards | one tree | 16 shard roots; no global root defined, no per-height root stored |
| Create | append the entry | append the entry and rewrite its predecessor (next-key link) |
| Update | append, clear the old bit | append with DSN of the old entry |
| Delete | clear the bit | rewrite the predecessor with DSNs of both; no tombstone |
| Empty value | a deletion | rejected (an empty value marks a sentry) |
| Sentries | none | 4,096 per shard at 16-bit prefixes |
| Compaction | none | inside the write path, per shard, when live ≤ 70% of the serial range and the shard holds ≥ `compact_thres` (default 20M) live entries; changes the root |
| Proofs | inclusion at the head | inclusion (`SingleProof`, not activeness) for twigs in the twig file; exclusion by next key in principle; no historical reads |
| Twig file | none (nodes in memory) | optional (`with_twig_file`, default off; without it proofs work only for the youngest twig) |
| Index | in-memory sharded HashMap, ~60 B a live key | in-memory, 65,536 sorted units, ~9-10 B a key; hybrid SSD index optional; rebuilt at start |
| Non-final blocks | forest: records, undo, branch moves | none: at most 2 blocks in flight, no rollback |
| Durability | fsync of the entry file before the delta | entry segments `sync_all`; the meta file written without fsync |

**What the root depends on, beyond the key-value set, in LayerZero's format.** The append history
(as in ours); the compaction parameters and schedule; and the entry's `version`, which is
`(height << 24) + index of the change set within the block` -- so the way a block's operations are
grouped into change sets is part of the root. A consensus rule on this format has to pin all three,
plus a fold of the 16 shard roots into one header root, which the library does not define.

**What changing formats means for the chain.** Every root changes: the chain's state commitment is
a different function. Both clients switch at a fork (or on a new chain), and gov5 has to implement
the same bytes: Blake2b leaves, level-keyed Blake3 nodes, the paged ActiveBits tree, sentries, DSN
lists, next-key maintenance on create and delete, compaction with pinned parameters, the change-set
grouping, and the shard fold. gov5's production fleet runs the current format, so the switch needs a
migration (re-inserting the live state into the new structure at the fork height, whose cost is
measured below as the prefill).

## 2. Data confirmation (real state)

Input: the end state of the fleet7 leg loop155 A2, node0 (the node's own `entries.log`,
`forest.ckpt` and `forest.log`, copied): the checkpoint moved through the log's 4 deltas to block
295, 29,639,064 appended slots, 1,738,215 live keys, no deletions (live keys = distinct keys ever
written). Our root rebuilt from those files by the node's restart path:
`0xfd21f549...29b6ce6`.

The 29,639,064 records were replayed into LayerZero's QMDB in slot order, a block cut wherever a key
repeats (the node's own blocks never repeat a key), each record a create on its key's first
appearance and an update after: 296 blocks. Then every live key was read back from LayerZero's
store and compared with our live value byte for byte:

    live keys   equal       differ   missing
    1,738,215   1,738,215   0        0

The key-value state is the same data in both stores. The roots are different functions of it, as
expected (LayerZero's 16 shard roots folded locally: `0xfaadb452...29cfd1c`).

    store                      operation                               wall     peak RSS   disk
    ours                       rebuild from the entry file (restart)   5.8 s    4.27 GB    1.16 GB entries + 6 MB ckpt/log
    LayerZero (no io_uring)    replay of all 29.6M records, 296 blocks 21.9 s   3.60 GB    4.14 GB
    LayerZero (io_uring 16x48) the same                                23.1 s   3.67 GB    4.14 GB

Both LayerZero I/O paths pass the same check (1,738,215 equal, 0 differ, 0 missing) and produce the
same folded root, so the root does not depend on the I/O path. The io_uring path runs with 16 rings
of 48 registered 8 KB buffers (~6 MB): this user's locked-memory limit is 8 MB and the library's
default (16 rings of 256, ~33 MB) fails to register, which kills the prefetcher threads and hangs
`flush` -- a deployment needs `LimitMEMLOCK` raised.

(LayerZero's peak includes the harness holding the live set and the 1.16 GB entry file in memory for
the check. Its disk is 3.6x ours for the same history: 53+ bytes of fixed fields an entry, the twig
file, and no compaction below 20M live entries a shard.)

## 3. Performance

Workload S: the fleet7 bench's block shape (6,000 senders in runs, 163,000 transfers a block over
2,000,000 recipients, gov5 account values), 300 blocks, 50,646,600 operations (~168,800 a block,
creates early and updates after). Both stores fed the same operation bytes; both on jemalloc; each
run alone in a 20 GB scope. Ours runs as the node runs it: entry file on, retain depth 2, a block
computed, filed, made canonical and the entry file fsynced. LayerZero: 32 change sets a block,
`flush` until the block's meta info is back (its entry segments are `sync_all`ed; its meta file is
not fsynced); the time includes building and sorting the change sets.

    store / configuration                   block ms p50   p99    mean   peak RSS   disk     random read p50   CPU
    ours                                    75.1           107    75.5   4.09 GB    2.00 GB  (no read path)     1770%
    LayerZero, no io_uring, twig file       84.7           100.9  85.4   1.08 GB    6.98 GB  0.9 us             709%
    LayerZero, no io_uring, no twig file    81.8           99.3   82.7   1.13 GB    5.09 GB  0.9 us             727%
    LayerZero, compaction at 50,000/shard   101.2          607.5  179.8  1.07 GB    10.29 GB 0.9 us             786%
    LayerZero, io_uring 16x48               117.1          135.9  116.6  1.22 GB    6.98 GB  0.9 us             576%

(Ours: compute 70.5 + file 2.3 + sync 2.3 ms at p50. Every LayerZero run read 200,000 random
recipients back and matched the generator's state 200,000 times.)

What S says:
- **Write path: within ~10%.** Ours is ~10% faster at p50 and ~6% slower at p99 than LayerZero's
  default layout; ours uses 2.5x the CPU for it (rayon over leaf hashing and twig rehash).
- **Memory: LayerZero ~4x lower.** 1.1 GB against 4.1 GB at 2M live keys: its full twigs keep 288 B,
  ours keep every live twig's node array, and its index is ~10 B a key against ~60.
- **Disk: ours 2.5-3.5x lower** for the same history (entries of 36 B + value against 53 B + value +
  DSNs + padding, plus the twig file). Compaction as configured here does not pay back inside 300
  blocks: LayerZero deletes old segments only every 500 blocks, so moved entries are written twice
  and the tail latency (p99 607 ms) is the compaction running inside the write path.
- **io_uring under an 8 MB lock limit is slower**, not faster: 48 in-flight reads a ring and O_DIRECT
  reads that cannot use the page cache. Its intended configuration (256 a ring, ~33 MB locked) could
  not be measured on this box without root.
- **Reads: LayerZero serves a point read in ~1 us** (index + one entry read). Ours has no read path
  in the node (the EVM reads MDBX), which is the direction problem of `docs/QMDB_PAPER_REVIEW.md`.

**The roots of the S runs differ between LayerZero configurations for a reason in the harness, and
it is itself a result.** The generator emitted a block's recipients in `HashMap` order, which varies
per process; the block is then split into 32 change sets, and LayerZero's entry `version` is the
change set's index, so a different grouping of the same operations is a different root. Ours sorts a
block's operations before applying them and is insensitive to their order. See section 3.3.

### 3.2 Workload L: 50 million accounts

50,000,000 accounts created in blocks of 1,000,000, then 100 blocks of the S shape spread over the
50M (16,882,200 operations).

    phase / store                           block ms p50   p99     mean    peak RSS   disk      random read p50
    prefill: ours (compute+file+sync)       318            ~1,350  367     9.01 GB    1.95 GB
    prefill: LayerZero, no io_uring         608.3          647.8   608.2   2.54 GB    12.81 GB
    blocks: ours (compute+file+sync)        121            ~216    ~121    10.65 GB   2.62 GB   (no read path)
    blocks: LayerZero, no io_uring          98.8           110.4   99.1    2.54 GB    15.05 GB  1.1 us (200,000 of 200,000 matched)
    blocks: LayerZero, io_uring 16x48       275.4          323.4   277.7   2.81 GB    15.05 GB  1.1 us

(Ours at p50: prefill compute 234.2 + file 12.2 + sync 72.5 ms; blocks compute 106.3 + file 3.0 +
sync 11.8 ms. The p99 figures for ours sum the phases' p99s and overstate the joint tail; the file
phase records no mean, so ours' means use its p50.)

What L adds to S:
- **At 50M keys LayerZero is faster on the block path**: 99 ms against ours 121 at p50, and a flat
  tail (110 against ~216). Ours grows with the key count (75 → 121 ms from 2M to 50M; the index and
  the upper-tree rebuild); LayerZero's barely moves (85 → 99).
- **Creates cost LayerZero double**: every create rewrites its predecessor's next-key link, so a
  block of 1M creates takes 608 ms against ours 318. The fleet workload is mostly updates, a chain's
  first weeks are mostly creates.
- **Memory 4.2x lower** (2.5 GB against 10.7 GB at 50M live keys) and **disk 5.7x higher** (15 GB
  against 2.6 GB), without compaction in either.
- **io_uring at 16x48 is 2.6-2.8x slower than the fallback at this scale** (prefill 1,600 ms against
  608; blocks 275 against 99), so the throttled configuration says nothing about the library's
  intended io_uring performance, only that it needs its locked-memory budget.
- **The prefill's roots are identical on both I/O paths** (`0xc3d4ab69...`): its operations come in a
  fixed order, while the blocks' order varied per process (section 3.3). The I/O path does not enter
  the root; the grouping does.

### 3.3 Determinism and grouping

50 blocks of workload S with the generator's order fixed (recipients sorted), each run in a fresh
directory:

    run                                     root
    ours, run a                             0xbf3fc24c...8b3e76
    ours, run b                             0xbf3fc24c...8b3e76   (and the same with the order varying per process, matrix 2)
    LayerZero, 32 change sets a block, a    0x7907fd42...dd22ac
    LayerZero, 32 change sets a block, b    0x7907fd42...dd22ac
    LayerZero, 64 change sets a block       0xa6864899...50f2e1
    LayerZero, 32, order varying (matrix 2) 0x981c5e61... and 0x3f0d81bc... on two runs

LayerZero's root is deterministic for a fixed order and grouping, and changes with either: the same
operations split into 64 change sets instead of 32 are a different root. Ours sorts a block's
operations and is insensitive to both. A consensus rule on LayerZero's format has to fix how a
block's operations are grouped into change sets.

## 4. Maturity of the library for a consensus-critical path

- No global root and no per-height root history (`root_hash_by_height` is never written).
- Errors are panics; no rollback or shutdown API; endless detached threads.
- The meta file is not fsynced; recovery panics on a root mismatch.
- Hash golden tests are `#[ignore]`d; updater tests marked WIP; no end-to-end root vector.
- A possible disagreement between the stored root and the proof root when a block ends exactly on a
  twig boundary (`get_max_level` subtracts one for an empty youngest twig, `sync_upper_nodes` does not).

## 5. Verdict

**Data: passes.** The node's real state, replayed into LayerZero's QMDB, reads back identical key for
key (1,738,215 of 1,738,215). With a fixed operation order the root is the same on both I/O paths.

**Performance: favourable where it matters for scale, not a free win.**

| | ours | LayerZero (no io_uring) |
| --- | --- | --- |
| block p50, 2M keys | 75 ms | 85 ms |
| block p50 / p99, 50M keys | 121 / ~216 ms | 99 / 110 ms |
| 1M creates a block | 318 ms | 608 ms |
| memory, 2M / 50M keys | 4.1 / 10.7 GB | 1.1 / 2.5 GB |
| disk, same history | 2.0 / 2.6 GB | 7.0 / 15.1 GB |
| point read | none in the node | ~1 us |

**Not yet "no problem": what must be solved before implementing on it.**

1. *No chain root.* The library keeps 16 shard roots and never stores a root per height. A header
   root needs a defined fold, stored per block, in our fork of the crate.
2. *The root depends on how a block is grouped* (the entry version is the change-set index) *and on
   the compaction parameters and schedule.* Both become consensus rules: one fixed grouping (for
   example one change set per transaction, in block order) and pinned compaction settings, written
   down for gov5.
3. *Durability and failure handling on a consensus path.* The meta file is written without fsync;
   recovery panics on a root mismatch; errors are panics throughout; no rollback (acceptable with
   finalized-only writes, which the node would need anyway).
4. *Disk and compaction.* 3-6x the disk for the same history; compaction runs inside the write path
   (p99 607 ms as configured) and old segments are deleted only every 500 blocks.
5. *Creates cost 2x* (next-key maintenance, the price of exclusion proofs).
6. *io_uring needs `LimitMEMLOCK` raised* (~33 MB at the defaults); under this box's 8 MB it is
   slower than the fallback, so its intended performance is still unmeasured here.
7. *Proof APIs.* `SingleProof` proves inclusion, not activeness; the multiproof that does is not
   exposed; no exclusion or historical proof API.
8. *Test coverage.* No end-to-end root vector, hash golden tests ignored, updater tests WIP, and a
   possible stored-root/proof-root disagreement at a twig boundary to test.
9. *Cross-client cost.* gov5 has to implement the same bytes (Blake2b leaves, level-keyed Blake3
   nodes, paged ActiveBits, sentries, DSN lists, next-key maintenance, compaction, grouping, fold),
   and gov5's production chain needs a migration at the fork.

**The path, if adopted.** (a) Fork the crate into this repository with items 1-3 fixed and our own
root vectors (item 8); (b) write the format specification for gov5 (items 2 and 9) and have gov5
implement it against those vectors; (c) run it as the state database -- reads served from it,
reth's hashed tables dropped, as `docs/QMDB_PAPER_REVIEW.md` recommends -- behind a fork flag on a
new devnet first; (d) measure io_uring with the lock limit raised, and compaction over a long run.
Items 1-3 and the gov5 specification are the gate: the implementation should not start before
there is a decision on the grouping and compaction rules, because every root depends on them.
