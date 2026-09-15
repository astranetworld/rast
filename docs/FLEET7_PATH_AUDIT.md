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

## 5. Behind a switch, off until a fleet leg measures it

| change | switch | expected effect |
| --- | --- | --- |
| a follower's check of block N+1 reads its senders from block N's execution output, published by N's import as soon as N's QMDB root is filed, instead of waiting for N to land in the engine; untouched senders are read at N's parent, which is in the engine; N+1's execution still waits for N's insert | `N42_CHECK_ON_PARENT_OUTPUT=1` (`bin/n42/src/follower_import.rs`) | N's engine insert and hand-off bookkeeping (~60-80 ms) off every vote's path |

## 6. Found, not changed yet: each needs a larger change or a fleet leg

| finding | cost | why not now |
| --- | --- | --- |
| the leader's graft inserts ~147,000 accounts into one `BundleState` map serially | ~70 ms on the seal path | a sharded bundle kept through the roots and the overlay, merged only behind the seal: a representation change across builder, overlay and roots |
| the leader's receipts loop commits 150,000 transfer results one at a time (receipt build, a Cancun check and an empty state commit each) | 45 ms on the seal path | the executor's receipts and gas counters are private to alloy-evm's `EthBlockExecutor`; a bulk append needs an executor of our own, and the receipts root is consensus data |
| the body is deep-copied four times per block (build-on-own, hand-off, `remember_sealed`, the engine's conversion of a block it already holds) | ~40 ms and allocator churn | `Arc<SealedBlock>` in every store; the engine's conversion is reth's |
| every transaction is encoded twice (tx root, wire frame) | ~15-25 ms (estimate) | the assembler's encodings would have to travel with the payload |
| the hand-off waits for the hashed post-state, and followers build it before the engine insert | 28-40 ms | reth's `LazyHashedPostState` would have to be handed over pending |
| reth fills its execution cache over ~147,000 accounts on the engine thread for blocks nothing re-executes | ~20 ms (estimate) | needs a wrapper around `BasicEngineValidator`, and the engine's own fallback execution uses the cache |
| `HashedAccounts`/`HashedStorages` duplicate QMDB's live state | ~150,000 MDBX upserts and a keccak per touched key per block | stage 6c: after `N42_QMDB_READS` holds on the fleet in `verify`, then `on` |
| the QMDB delta per block repeats what the entry file and its active bits hold; the checkpoint grows a bit per slot ever written | encode + keccak over ~1.3 MB a block; periodic full rewrites | a log format change with a migration |
| ~14 static-file fsyncs per save (two per segment) | device-dependent | reth's static-file writer; one sync per commit needs a change there |

## 7. Fixed after the audit: the APoS beneficiary

The QMDB read view's verify mode (stage 6b) showed the database and the QMDB forest disagreeing about one account
on the APoS dev chain. The payload builder credits a block's fees to its signer (its coinbase), but the engine's
execution credited the header's beneficiary, which on APoS is a signer-vote target (zero, or the proposed signer),
and `validate_block[_operations]` returns an already-filed block's root without recomputing, so the forest kept the
builder's execution while the database kept the engine's. An N42 fix for this (`b6c61af56`, recovering the signer
in `evm_env_for_payload`) had been lost when the vendored EVM crate was unforked.

`N42EvmConfig` (`crates/n42/engine-types/src/n42_evm.rs`) now credits the signer recovered from the Clique seal in
`evm_env` and `evm_env_for_payload` on any chain whose genesis is not a HotStuff chain (checked once), falling back
to the header's beneficiary when no seal recovers. HotStuff chains, the fleet included, are unchanged: their
beneficiary is the leader's fee recipient on both sides. This is gov5's rule: `NewEVMBlockContext` (`N42-gov5/internal/evm.go`
36-47) credits `engine.Author(header)`, which for APoS is the seal's `ecrecover` (`internal/consensus/apos/apos.go`
245), and falls back to `header.Coinbase` only when that yields the zero address. The Rust node had drifted from it.
The deferred-execution vectors (`crates/n42/n42-testing/testdata/deferred_execution_vectors.json`, Rust-only) change
accordingly: the state roots of the blocks that carry a transfer, and the hashes and seals that follow from them. The end-to-end verify test now runs with tips: the signer
is credited 21,000 gwei a block in the database, and 38 reads check with 0 mismatches.

## 8. The fleet legs (loop156, 2026-09-14)

Eight legs on the loop155 configuration, in this order: W (warm-up) A1 B1 C1 V1 A2 B2 C2. A is the loop155
build (kept as `rust-fleet7-bin/pre-audit-loop155`, built 2026-09-12 08:36); B is b94012c27 (QMDB stages 1-6b,
the fixes of section 4, the APoS fix of section 7); C is B with `N42_CHECK_ON_PARENT_OUTPUT=1`; V is B with
`N42_QMDB_READS=verify`. WAL and RocksDB are the largest of the seven nodes at the end of the round; the pool is
the huge-page pool `hugeprep` left before the leg (a leg under ~30 GB is not comparable).

| leg | win1 | win2 | win3 | round (M tx) | check p50 (ms) | WAL files / GiB | RocksDB GiB | pool GB | reading |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| W (B) | 304,038 | 200,904 | 184,627 | 20.70 | 160 | 4 / 0.20 | 1.86 | 36 | warm-up |
| A1 | 276,855 | 222,410 | 86,887 | 17.60 | 261 | 33 / 2.51 | 3.96 | 37 | |
| B1 | 293,202 | 152,108 | - | 13.37 | 207 | 4 / 0.25 | 1.23 | 19 | void: pool |
| C1 | - | - | - | 0 | - | - | - | 39 | the funding never mined: defect 1 |
| V1 | 303,339 | 217,259 | 173,821 | 20.84 | 159 | 4 / 0.23 | 1.75 | 41 | the view invalidated mid-round: defect 2 |
| A2 | 255,356 | - | - | 7.66 | 224 | 8 / 0.56 | 0.91 | 43 | an invalid block, 10 TCs: defect 3 |
| B2 | 336,397 | 140,483 | - | 14.32 | 199 | 4 / 0.24 | 1.33 | 22 | void: pool (1 stall, 5 TCs, 4 watchdog lines) |
| C2 | - | - | - | 0 | - | - | - | 39 | as C1 |

What the legs settle:

- **Stage 7 (RocksDB `max_total_wal_size`).** On full rounds the WAL is 1-4 files and at most 0.20-0.23 GiB a node
  against A1's 28-33 files and 2.25-2.51 GiB, and a node's RocksDB is 1.75-1.86 GiB against 3.81-3.96, with the
  round carrying 18% more transactions. Adopted.
- **The follower's check** (section 4, without the switch): p50 159-160 ms on W and V1 against 257-261 on A1 and
  both loop155 legs.
- **Throughput is not settled.** The two valid B-binary legs (W, V1) read 303-304k on window 1 and 20.7-20.8M
  transactions a round against A1's 277k and 17.6M, but W is a warm-up, A2 broke down and B1/B2 are void. Both
  void legs followed an A leg (pools 19 and 22 GB; every other leg 36-43 GB). loop157 repeats B, C and V without
  the A binary.
- **Major faults** are not a difference between the binaries: the runner's per-leg sample counts the execution
  layers only under `target/*/release`, so the A legs counted validators alone; `fleet7-windows.py` gives the
  new binary's rate as loop155's (1.6-2.2M per 30 s).

### Defect 1: the check on the parent's output waited for outputs nothing publishes (fixed)

With `N42_CHECK_ON_PARENT_OUTPUT=1`, a block's check waited up to `PARENT_WAIT` (3 s) for its parent's published
execution output. Only the follower's direct import publishes one; a parent this node built (every block of its
own tenure) or one the engine imported by its own path never appears. node0's first foreign block after its tenure
(block 63 in C1) waited the whole three seconds; blocks queued behind it; the next import missed its parent's
landing, went by the engine's path, published nothing, and its child waited three seconds in turn. At a 350 ms
cycle the chain never caught up: 87 failed direct imports on the two nodes past their tenures, empty blocks, and a
funding transaction set that never mined in 120 s. `wait_for_parent_output` now also asks whether the parent is in
the engine the ordinary way (the header known, the execution result recorded) and returns at once when it is;
`a_parent_in_the_engine_without_an_output_ends_the_wait_at_once` covers it. The 3-second parent timeouts on node0
in the switch-off legs (A1 50, B1 79, loop155 A2 47) predate the switch and recover.

### Defect 2: the read view lost the next block's changes behind a database 17 blocks back (fixed)

In V1 the read view answered on all seven nodes and verified at least 1,048,576 reads against the hashed tables
with 0 mismatches and 0 declines, then was invalidated on every node ("a persisted block's changes are not on the
tree's path") at view heads 128-146. At every invalidation the chain's tip was 17-18 blocks past the view's next
block: under load the database persists that far behind, and `set_canonical` had pruned the forest's records to
the retention depth (16) before the database reached them. The forest now keeps the records of blocks from the
view's next block up (`QmdbForest::set_keep_from`, advanced by `on_persisted`), up to `READER_KEEP_CAP` = 64
blocks below the head -- the depth the fleet ran with before it was lowered to 16 -- and releases the keep when the
view is invalid. `a_readers_keep_holds_records_past_the_retention_depth` and
`the_read_view_follows_a_database_behind_the_retention_depth` cover it (40 blocks behind stays valid, 110 behind
invalidates).

### Defect 3: an invalid block after a hang, a TC and a reorg (open)

On the A binary in A2, node2's own-block hand-off of block 128 stalled 10 s in the engine (the orchestrator branch
idle 10,047 ms; the watchdog named the hand-off at `new-payload`). The view timed out, node2 re-proposed a sibling
of block 129, and the chain committed a third block 129. The queue then handed back the same transactions three
times: the own block at that height that was not committed (158,616), the reorg's reverted block (163,000), and
the build on the same parent that was not committed (216,020). node2's next build of block 130 executed all
163,000 transfers on the parallel path (`par_skipped=0`, `stale=0`) and the other nodes refused it: "nonce 0,
0xe469... is at 1500" and "nonce 500 too low, expected 1500". The fast transfer path refuses a nonce that differs
from the account's, so the build's state held those senders at nonces a whole round old, or the transactions came
in from a source the analysis has not found (the queue's gap lookup reads reth's pool by nonce from the state the
builder reported). loop154 A1 showed one such block; loop155 A1/A2, loop156 A1 and the four B legs none. Not
fixed: loop157's `rej` column says whether HEAD reproduces it, and the builder's state source for a build after a
reorg is the next thing to trace.

## 9. The confirmation legs (loop157, 2026-09-14)

The working tree with the fixes of defects 1 and 2 (committed as cdb074fa2), six legs on one binary in the
order W C3 V3 B3 C4 V4. Invalid blocks counts the execution layers' "Encountered invalid block" lines; the first
is the lowest block refused and how many nodes refused it.

| leg | win1 | win2 | win3 | round (M tx) | check p50 (ms) | WAL files / GiB | RocksDB GiB | pool GB | invalid blocks | reading |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| W | 276,572 | - | - | 8.30 | 183 | 5 / 0.23 | 0.66 | 40 | 1 (184, one node) | warm-up; defect 4 |
| C3 | 298,725 | 206,223 | 168,868 | 20.23 | 140 | 4 / 0.24 | 1.57 | 42 | 0 | defect 1 fixed |
| V3 | 315,402 | 238,941 | - | 16.64 | 215 | 3 / 0.22 | 1.56 | 35 | 36 (258, six nodes) | defect 2 fixed; defect 5 |
| B3 | 325,872 | 200,856 | 168,397 | 20.86 | 162 | 3 / 0.18 | 1.85 | 41 | 0 | clean |
| C4 | 331,204 | 249,745 | - | 17.44 | 188 | 4 / 0.28 | 1.61 | 37 | 42 (257, six nodes) | defect 5 |
| V4 | 255,990 | - | - | 7.68 | 195 | 4 / 0.26 | 0.62 | 35 | 54 (130, six nodes) | defect 5 |

What the legs settle:

- **Defect 1 is fixed.** Both C legs mined their funding and ran; C3, a clean full round, checked at a p50 of
  140 ms against B3's 162 without the switch (one leg each).
- **Defect 2 is fixed.** The read view stayed valid on all seven nodes through V3 and V4 (no invalidation), each
  verifying at least 1,048,576 reads with 0 mismatches and 0 declines.
- **Stage 7** holds: every leg's WAL is at most 0.28 GiB a node.
- **Throughput** is still not an A/B: B3, the clean full round of this binary, read 325,872 on window 1 and 20.86M
  transactions; C3 298,725 and 20.23M. Three of the other four legs broke down on defect 5, which is now the
  first thing between the fleet and a readable comparison.

### Defect 4: a follower filed a sibling's execution under the other block's hash (fixed)

W's single refusal: node4, 44 s behind and catching up, had built its own empty block 183 ahead of leading, on
the same parent as node2's empty block 183 that the chain had committed. The own-block reuse found a kept build by
the payload's parent, number and -- under deferred execution -- the parent's result, all of which a sibling on the
same parent shares, and the sealed header takes the payload's beneficiary, timestamp, randao, gas limit and base
fee, so the pairing hashed correctly: node4 handed node2's block to its engine as its own build, filed its own
build's state root under node2's hash, and refused block 184, whose header carried node2's. `reuse_own_build` now
also requires the build to execute as the sealed block (`build_executes_as_sealed`: beneficiary, timestamp, randao,
gas limit, base fee, beacon root, transactions root and rewards equal). The seal changes only the view in the extra
data, so this node's own blocks always pass; `a_sibling_on_the_same_parent_is_not_executed_as_the_build` covers it.

### Defect 5: mined transactions in a new leader's block after a stalled handover (fixed in e5d859d82)

V3 (block 258), C4 (257) and V4 (130) broke down the same way, at a leader handover. All six followers' engines
idle about eight seconds on `executed_insert` at the same millisecond; the view times out; the incoming leader
(node4 in V3 and C4) proposes a second block at the height; the chain commits the other one. In V3 node4's engine
committed its own sibling (5a5707dd) for a moment before the chain's block (9be33925), and the queue's settle path
gave the chain's block's 175,672 transactions back to the lanes; the hand-off's `forget_mined` did not forget
them, because the queue's last build stood on the other sibling; and node4's next block carried nonces its parent
had already mined (nonce 4032 against 4992). Six nodes refuse it, and every header node4 builds after it carries a
parent result they reject (36-54 refusals a leg). This is also the mechanism of defect 3 on the A binary. Two
changes are due: the eight-second `executed_insert` stall at a handover, which is the trigger, and the queue's
bookkeeping across two siblings at one height, which is the consequence -- a mined-nonce floor per sender that no
give-back may go under would close the second whatever the order of the engine's notifications.

**Root cause (read in reth v2.5.1 and the node, 2026-09-14).** The mechanism above is the consequence; the cause
is one step earlier. reth's tree skips an `InsertExecutedBlock` whose number is at or below its canonical block
number ("outdated block that can be skipped", `engine/tree/src/tree/mod.rs`). The header-only own-block import
checks the engine's head before the hand-off and moves it to the block's parent when they differ, but a
forkchoice to the sibling that lands between that check and the tree processing the insert makes the sibling
canonical first, and the insert of the chain's block at the same height is dropped silently. The header-only
`newPayload` that follows is then executed by the engine: `convert_payload_to_block` returns the sealed block
kept for it (163,000 transactions), but `N42EvmConfig::tx_iterator_for_payload` iterates the payload's own
transaction list, which a header-only payload leaves empty. The block executes as empty -- "Receipt root task
received incomplete receipts", receipts 0, gas 0 -- and the post-execution guard of loop151 accepted the result,
so the tree holds the block with none of its state changes. Every block the leader builds on it reads its
senders at the previous block's nonces (V3: 4032 against the chain's 4992). In all three breakdown legs the
leader logged that incomplete execution for its own just-proposed block 0.3-2.2 s before the first refusal
(V3 9be33925 at 257, C4 97115779 at 256, V4 f6990cd4 at 129). The queue's missing prune and full re-offer at the
reorg follow from the same empty execution.

**Fix, not yet compiled or tested** (local branch `wip/header-only-payload-fix`, e2c8f77c1): the iterator takes the
kept sealed block's transactions when the payload carries none (`n42_evm::executable_transactions`, with a unit
test), so a dropped insert costs an engine execution and nothing else; the guard names the real cause and logs at
error. Still to do: compile and test it, then legs that reach a handover (the loop158 runner in the session
scratchpad: W V5 C5 B5 V6 C6 with a per-leg count of the fallback's warning and of invalid blocks). Worth adding
after that: re-check the engine's head after the hand-off and redo the head move and the insert when a sibling
became canonical meanwhile, so the fallback execution is rare.

**The trigger, not yet explained.** In V3, C4 and V4 the incoming leader's execution layer stops answering its
validator for 5-7 s right after its first on-seal builds of the tenure (the validator's forkchoice request fails
with a transport error), the own block's header-only import takes 8.4-9.3 s of which the hand-off is 37-45 ms, and
the engine loop is idle, not busy, for the whole stall; the followers then idle on `executed_insert` for the same
eight seconds and the view times out. Something on the execution layer's request path, not the engine tree, holds
for those seconds; the build-on-seal path's waits (`built_executions` waits up to 3 s per lookup) are the first
place to look.

**The first fix was not enough (loop158).** The iterator change above ran the kept block's transactions, and V5 and
C5 still broke down (54 and 55 refused blocks): the fallback fired once in each, and the execution still came
back with receipts 0 and gas 0. reth's `execute_block` takes `transaction_count = input.transaction_count()`,
which for a payload is the payload's own list, and executes that many, whatever block the conversion returned
and whatever the iterator can yield. That change was withdrawn.

**The fix (e5d859d82).** The header-only own-block `newPayload` lists the block's transactions (encoded on the
worker pool). When the executed insert landed, the engine answers from its tree without executing; when it was
dropped, the execution is complete. The post-execution guard for an incomplete result names this cause and logs at
error. One more consequence of the old path, now also gone: an incomplete result never recorded the block's
receipts, so `executed_fields::get` stayed empty for it and its children's direct imports waited out their parent.

**Confirmed on the fleet (loop159, six legs W V7 C7 B7 V8 C8).**

| leg | win1 | round (M tx) | TC | refused blocks | incomplete executions |
| --- | --- | --- | --- | --- | --- |
| W | 303,920 | 9.13 | 6 | 0 | 0 |
| V7 | 279,566 | 9.70 | 4 | 0 | 0 |
| C7 | 271,535 | 19.40 | 4 | 0 | 0 |
| B7 | 284,125 | 19.44 | 2 | 0 | 0 |
| V8 | 287,715 | 13.68 | 1 | 0 | 0 |
| C8 | 293,266 | 18.39 | 2 | 0 | 0 |

In C8 the case that broke V5 and C5 happened: node4 re-proposed a sibling at block 257, its executed insert was
dropped, and the engine executed the block itself (a fork-chain insert of 537 ms against 4 ms for an insert that
lands) -- completely this time, with no refused block after it. The read view held through V7 and V8 (2,097,152
and 1,048,576 reads verified, 0 mismatches). The own-block import did not get slower (14-31 ms).

**Still open: the handover stall that starts it.** Every leg still has TCs at leader handovers, and W and V7 lost
windows to them. What the logs show so far, on loop158 W's node4 (the node that lagged):

- A commit's forkchoice never reached the execution layer for 6.5 s. Block 188's Decide came before its import;
  the driver deferred the forkchoice to the import's landing (52.76 s), but the engine logged no forkchoice at all
  until 59.30 s, for block 189. Meanwhile block 189's direct import waited for 188 to be canonical, gave up after
  3 s, and went the engine's way (5.2 s), as did 190 (5.8 s): the node fell behind from there.
- The driver's loop itself stood still: blocks whose bodies arrived at 55.5 s started importing at 59.3 s.
- Catching up, the node started a build ahead for every block it imported (26 payload jobs in 3 s on node4, 27 on
  B5's node5, 12 on V6's node4). The driver aborts the previous build's task, not the execution layer's job, and
  every one of those builds stands on a parent the queue has already pruned past, so the parallel path refuses
  nearly every transaction on its nonce and the serial loop does the rest (1.2-1.4 s each).
- `--builder.interval 60` is read by reth as 60 seconds, so a job builds once and does not rebuild; the abandoned
  jobs cost one build each, not a stream of them.

The next step is the transport under the driver's calls (`h2-el-rpc` `EngineApiClient`: the forkchoice over
JSON-RPC, the builds and imports over three mutex-guarded raw channels) and the driver loop's awaits, to find what
held the forkchoice; then not starting builds ahead while the node is behind the committed chain.

### Defect 6: the handover stall -- a given-up build ahead froze reth's tree (fixed in 2ce2f60e5)

**Found (loop160-161, 2026-09-15).** loop160 added the commit forkchoice's timing and loop161 an engine message
trace (`N42_ENGINE_MESSAGE_TRACE=1`) and a per-second thread sampler. In loop161 W node3's commit forkchoice for block
190 and its own block 191 were taken off the engine's stream within 40 ms of being sent and answered 11.1 s later;
node4 did the same at block 256 (9.7 s). The tree thread slept in a futex the whole time, persistence was idle on
node4, and every follower idled because nothing new arrived; the view timed out and a TC followed. It is not the
transport, the driver loop or the box: reth v2.5.1's tree, on a completed persistence, defers the in-memory
hand-off while any payload job holds a build lease (`PayloadBuildTracker`, one lease per forkchoice with
attributes), and while that hand-off is pending `wait_for_event` waits only for "payload build finished" and takes
no engine message. The driver aborted a build ahead it gave up (a mismatched proposal, a newer parent, a refused
build on the sealed block): that drops its own task, not the execution layer's job, which then lives to its
deadline -- `--builder.deadline` 3 s plus up to three times that while the chain's whole-second timestamps run ahead
of the wall clock, 12 s in all. Both freezes ended 11.8-12.2 s after the abandoned job was created.
(`--engine.persistence-backpressure-threshold 1024` rules out reth's other stop, the persistence back-pressure.)

**Fix.** A build ahead that a forkchoice started is told it was given up instead of aborted: it skips its
forkchoice if it has not sent it, or resolves its job -- resolving always removes a job -- and drops the block. A
build on the sealed block starts no job and is still aborted. Test: a mock resolve gate holds the build between its
forkchoice and its resolve; the old code never resolves.

### Defect 7: a follower that fell behind never caught up -- early Decides were dropped (fixed in 2ce2f60e5)

loop160 V10 node1 (94 failed direct imports), C10 node5 (39) and loop161 W node0 (39), B11 node1 (44) fell behind and
stayed there. The service dropped a Decide for a block that was neither imported nor importing yet ("not finalised
here"), so the block was imported but never canonical, and each child's direct import waited out its parent
(`header known: false, execution fields known: true`) and went the engine's slower way. On a node already behind
most Decides arrive before the import starts (C10 node5: 187 of 318; V10 node1: 96; W node0: 42; healthy nodes 0-1),
so the cascade fed itself. The driver now keeps such a commit (`commit_when_imported`) and runs its forkchoice when
the import lands, as it already did for a commit that ran before its body. A parent wait that times out now says
which half was missing. (A longer wait for a parent whose direct import was still running, tried in loop161, never
triggered and was removed.)

**Confirmed (loop162, six legs, against loop160-161 on the same configuration).**

| leg | win1 | round (M tx) | TC | handover stalls | failed direct imports | undelivered FCU answers | given-up jobs resolved |
| --- | --- | --- | --- | --- | --- | --- | --- |
| W | 288,214 | 20.06 | 1 | 0 | 0 | 0 | 3 |
| V12 | 308,809 | 20.85 | 1 | 0 | 0 | 0 | 3 |
| C12 | 304,149 | 21.19 | 1 | 0 | 0 | 0 | 4 |
| B12 | 321,753 | 22.04 | 1 | 0 | 0 | 0 | 4 |
| V13 | 293,268 | 20.21 | 1 | 0 | 0 | 0 | 3 |
| C13 | 325,304 | 21.84 | 2 | 0 | 0 | 0 | 4 |

loop160-161's ten legs had 1-5 TCs each, up to 9 engine idles over 5 s, up to 2 undelivered forkchoice answers and
a node with 39-94 failed direct imports in five of them, at 8.5-20.7M transactions a round. Every TC left in loop162
is the start-up view 1, except C13's view 276 (defect 8). Window 3 no longer collapses (163-191k against 49-223k).

### Defect 8: a leader lost a view while its own parent was still importing (fix in test, loop163)

loop162 C13 node4, in the middle of its tenure: its own block 275 took 970 ms to reach the engine, the build on the
sealed block was refused (no QMDB tree for 275 yet), the fallback forkchoice was answered SYNCING, and the service
gave up the view ("could not build a block to propose") -- it asks again only when `driver.is_importing(head)`, which
counts follower imports, not the leader's own import on its task. The driver now tracks its own imports in flight
(`is_importing_own_block`), and the proposal retries on either. It is kept out of `is_importing` on purpose: a commit
for a block counted there waits for a follower import's report, which an own import never sends.

### Defect 9: a follower's import deadlocked on the QMDB forest inside the worker pool (fixed in bdb8a802e)

loop164 O17 and T17 stopped the chain at a new leader's tenure (node3 at view 192, node4 at view 256): the leader's
import of its parent stuck at the "hashed-state" stage and its build ahead at "finishing" for the rest of the leg,
the watchdog repeating every 6 s, every rayon and engine thread asleep in the sampler, and the leader asking again
for a parent that never landed until the round ended (9.6M transactions instead of ~22M). The import ran its QMDB root
and hashed post-state with `rayon::join`, so the root job was a rayon job holding the forest's mutex while the forest's
hashing waited on the pool; a worker that waits steals other jobs, and with two imports in flight (or a build's
assembly beside one) the other root job, which needs the same mutex, landed on a thread that could never get it. The
assembler's root has run on a thread of its own for exactly this since loop113. The import's root now does the same,
with the hashed post-state on the calling thread. loop165, six legs: no import stuck, one TC a leg (start-up).

### Stage 6c on the fleet: the hashed tables off (loop164-165)

`N42_HASHED_TABLES=off` (96b52c19a) ran on all seven nodes in four legs with 0 unanswered reads, 0 gas-used
mismatches and 0 invalid blocks; the QMDB reader answered at least 4,194,304 reads a node with 0 declines. Against
`on` legs with the tables written, alternated in the same loop:

| pair | round (M tx) on / off | win1 on / off | win2 on / off | win3 on / off |
| --- | --- | --- | --- | --- |
| loop164 O16 / T16 | 21.82 / 22.82 | 314,076 / 325,919 | 227,747 / 249,753 | 184,634 / 184,653 |
| loop165 O18 / T18 | 21.20 / 23.31 | 310,061 / 336,733 | 222,651 / 249,832 | 173,679 / 190,122 |
| loop165 O19 / T19 | 21.40 / 22.65 | 321,120 / 320,244 | 206,002 / 222,658 | 184,602 / 211,806 |
| loop165 O20 / T20 | 21.66 / 22.49 | 319,689 / 304,163 | 222,681 / 233,526 | 179,222 / 211,807 |

Every pair's round is larger with the tables off (loop165 mean +6.5%), the gain sitting in windows 2 and 3 (+8%, +14%)
while window 1 is unchanged within its noise. The follower's root phase fell from 45-48 to 32-36 ms (the hashed
pass beside it is gone), persistence saved more often at a lower cost each, and the follower's execution was 0-15 ms
slower. Before a node can run with it outside a bench leg, an unwind and a restart must stop invalidating or
emptying the read view (`docs/QMDB_UPGRADE_PLAN.md`, stage 6c).

### What binds the round after 6c (loop166-169)

With defects 5-9 fixed and the tables off, the round sits at ~22.8M transactions and window 1 at ~320-325k. Three
rounds went into finding what holds it there.

**The leader's profile (loop166-167).** loop166's seven concurrent `perf record` sessions all wrote 0 bytes: on 256
CPUs each session's ring buffers need more than the 8 MB memlock limit, so profiles run one process at a time. loop167
profiled the leader (node2) alone. Ed25519 verification with its SHA-512 took 39% of the node's samples and keccak 9%,
both on tokio runtime threads (the ingest of the flood). The build and import threads were a small share. Frame-pointer
call graphs on this build attribute inclusive time wrongly, so only self samples and the code's own phase timers are
used.

**Supply-side verification (43c4b1c83, loop168).** The flood's ingest frames are runs of 500 nonces from one sender. A
batch equation that sums each key's A terms keeps dalek's transcript, the order of its z coefficients and its verdict,
and takes one-sender batches from 11.4 to 7.7 µs a signature; mixed batches are unchanged (`N42_ED25519_MERGE=0` goes
back to dalek's equation). loop168 ran it against the unmerged equation in three pairs (reads on, tables off). It cut
the ingest's recover time from 23 to 17 µs and its busy time from 21 to 13-14 µs a transaction, and the follower
check's p50 from 169-201 to 162-167 ms. The round did not move: 22.78M / 319k unmerged, 22.64M / 325k merged, the
means of three legs each. The merge stays on, but verification CPU is not the constraint.

**The follower's check before the vote (loop169).** `N42_CHECK_ON_PARENT_OUTPUT=1` cut the check's p50 from 152-196 to
140-147 ms with 0 invalid blocks. The round went from 22.84 to 22.99M and window 1 from 325.2k to 325.5k, both noise.
The vote does not bind either.

**What remains is the leader's serial chain.** The leader seals at ~293 ms. Its fold then takes 123-139 ms (median):
the receipts loop is ~53 ms and the graft of the per-sender bundles onto the block state is ~70 ms. The next build
waits for that grafted post-state. Moving the whole fold behind the seal buys nothing for that reason. The two cuts
worth measuring:

- Build the receipts in parallel from the batches' results instead of through `commit_transaction`
  (`N42_DIRECT_RECEIPTS=1`, uncommitted, waiting for a quiet box).
- Make the graft cheaper: senders never repeat across batches, while recipients and the beneficiary do.

**CI's Test step (7328976f9).** Test died at exit 143 because the integration tests never shut their nodes down. Each
node allocates reth's fixed-capacity cross-block cache (4 GB by default) at start, so the ninth test ran out of a
runner's 16 GB. The harness now caps the cache at 64 MB and the whole suite peaks at 4.7 GB locally. CI shows it once
the branch reaches main.

## 10. Where the work stopped (2026-09-15)

- Defects 5-9 are fixed and confirmed on the fleet (e5d859d82, 2ce2f60e5, b902caff1, bdb8a802e; loop159, loop162,
  loop163, loop165). Stage 6c's hashed-tables-off experiment holds and adds 6.5% a round (above). Neither supply-side
  verification (loop168) nor the follower's check before the vote (loop169) binds the round. Next on the path to
  1M: the leader's fold (123-139 ms median: the receipts loop ~53 ms and the graft ~70 ms), then the production
  prerequisites of the tables off. Also seen, not yet chased: 3-12 commit forkchoices a leg answered Valid after
  500 ms or more, without a stall. Defect 3 (an invalid block after a hang, a TC and a reorg) has not recurred since
  defect 5's fix; the C9 one-off (node6's state root for an empty block 79) is not explained.
- History from 2026-09-01 was rewritten twice to take assistant attribution out of commit messages and then to
  point eight messages at the rewritten hashes; the pre-rewrite refs are kept under `refs/backup/` and in bundles
  under `/data/blockchain/git-backup/`.
- CI: Clippy passes. Test's exit 143 was the test nodes' 4 GB cross-block caches, not the build (fixed in 7328976f9,
  above); CI confirms it once the branch is merged to main.
