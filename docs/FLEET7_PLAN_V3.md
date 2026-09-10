# Fleet7 plan v3 -- two chains and one box

*2026-09-09 evening. Written after re-reading plan v2, the A1/A2 commit
(bae77e3e0), the loop110 launcher, and loop108 R16b's logs split into 30 s
windows on both sides. Supersedes the round order in `FLEET7_PLAN_V2.md`
section 4; sections 1-3 of v2 (the leader's chain, the plumbing, the
storage-v2 finding) still stand and are not repeated here.*

## 1. What the review found

### 1.1 The state of the in-flight work

- **A1/A2 is built and unmeasured.** `target/release/{n42,examples/h2_validator}`
  were built at 18:05 EDT from the tree that became bae77e3e0 at 18:06 (the
  lock-file commit after it changes no code). `run-loop110.sh` is the S-B-S-B
  round (S = `N42_BUILD_ON_SEAL=1`, B = without), pacing 450, grace 600, rayon 16.
- **The launcher would hang.** Its first gate is
  `until grep -q ALLDONE run-loop109.out`, and loop109 never ran: there is no
  `run-loop109.out`. The waiter (`wait-for-gov5-110.sh`, still running) would
  start loop110 the moment gov5's claim clears, and loop110 would then sleep
  forever without a message. Fixed in this pass: the line now waits for any
  running `fleet7-bench.sh` to finish instead.
- **The box is not in a measurable state tonight.** MemTotal is 143 GB, not
  256; gov5's seven `n42-r35` nodes hold 105 GB; swap is 7.2 of 8 GB used
  again (it was emptied by the user on 2026-09-05); `/tmp` (tmpfs) holds 19 GB
  of Shmem that never leaves RAM. The launcher's gate (80 GB available, load
  under 8, no fleet) will pass once gov5 is down, and the legs will then run
  with a full swap and 19 GB of tmpfs pinned. Both are recorded in the
  `good regime` line now, neither blocks the gate: swap needs root, and a
  full-but-idle swap does not hurt a leg by itself.

### 1.2 The A1/A2 code holds up to a static read

Checked against the risks the design has:

- The sealed-block build and the own-block import use **separate raw
  connections** (`raw_build` and `raw_import` in `h2-el-rpc/engine.rs`), so
  the 62 ms import cannot queue the build behind it or vice versa.
- **The queue's hold is idempotent.** `BUILD_ON_OWN` forgets the parent's
  mined transactions and holds them under the sealed hash; the import's
  hand-off then finds nothing to remove and `hold_own_block` returns early on
  an empty set instead of replacing the held block.
- **Attributes are deterministic**, so the build prepared at seal time is the
  build the proposal asks for: timestamp = parent + period (never the clock),
  slot = parent number + 1, beacon root from the committee pool, and pacing is
  skipped for a preparing build (`period_ms` 0). The import's later request
  for a build ahead finds the same parent and attributes and returns at once.
- **The registry holds two builds** (`built_executions::KEEP = 2`): the sealed
  parent and the block being built on it. The parent is taken by its own
  import (62 ms) long before a third build could push it out.
- `matches_build` finds the parent by parent hash, number, roots and gas,
  not by the sealed hash, which is what makes the re-keying under the sealed
  header work. `QmdbForest::rename` tolerates the second ask.
- **Not covered by any test.** Nothing exercises `DirectBuilder::build_on_own`
  offline: a wrong overlay (a nonce read from the grandparent's state instead
  of the parent's bundle) would surface as 163,000 refused transactions in the
  first on-seal block of the round, and the round would be lost. Section 3,
  phase 0.

### 1.3 Windows 2-3 are both chains, not the leader's

Plan v2 read the window-2/3 collapse off the leader's build (396 -> 680) and
put it under A4. loop108 R16b's logs, split into the same 30 s windows on the
followers' side:

    window   leader build (node0)          follower import engine_ms (node1/2/3)
             exec  fold  finish  total
    1        40    83    107     334       305 / 308 / 312
    2        --    --    --      --        425 / 455 / 458
    3        187   138   135     695       465 / 504 / 466
    4        313   151   139     768       579 / 499 / 528

The follower's import grows 1.5-1.9x across the leg, the leader's build
2.0-2.3x. Both chains lengthen together, so a leader-side fix cannot restore
windows 2-3; after A1 the cycle in window 3 would still be the followers'
~500 ms import plus the fixed ~100, about 0.6 s, against 0.97 s today and
0.62 s in window 1.

The box's counters over the same leg (`mem-loop108R16b.txt`, one execution
layer's RSS, 5 s samples): the fleet's major faults go 1.4M -> 4.5M -> 6.9M
-> 9.5M at the window boundaries (2.5-3M per 30 s, all of it MDBX refaults
in the execution layers, as diagnosed in round 43), MemAvailable 108 -> 42 ->
38 -> 30 GB, AnonPages 8.5 -> 74 -> 78 -> 86 GB, one execution layer's RSS
0.8 -> 9.3 -> 10.1 -> 11.3 GB. The queue is flat (368k-389k transactions),
so it is not the pool. Seven execution layers at 11 GB plus seven validators
plus the flood is ~90 GB of anonymous memory on a 143 GB box with 19.6 GB of
tmpfs pinned: the page cache the ELs' MDBX reads live in is what gets
evicted, and the import slows with the fault rate.

**The round total is three windows.** loop104 A2, the best round, is
248,906 / 190,086 / 173,806: windows 2-3 lose 24-30% to this. Holding them at
window 1's rate would be worth ~4M transactions a round (18.4M -> 22.4M),
more than any single pass removal on either chain. Memory is a phase of its
own in this plan, not a sub-item of the leader's.

### 1.4 What the current protocol can reach

With every follower executing the block before it votes, the cycle cannot go
below

    cycle >= fixed + max(leader build per tx, follower import per tx) x N

where fixed is the part that does not scale with the block: push ~27, body
to import start ~2, EL to vote ~48, quorum ~10, propose ~13 -- about 100 ms
today -- and N is 163,000. At the bench's block shape:

| after | leader build | follower import | cycle | blocks / 30 s | window 1 |
| --- | --- | --- | --- | --- | --- |
| today (loop108) | 396 + 134 plumbing | 450 | 570 | 48-49 | 260k |
| A1/A2 | ~365 | 450 | ~550 (followers + fixed) | 54-55 | ~295k |
| + B1-B3 (followers ~410) | ~365 | ~410 | ~510 | 58-59 | ~315k |
| + A3 (leader ~300) + C (both ~300) | ~300 | ~300 | ~400 | 75 | ~400k |

Every row is one block shape and one box; the third row is where the two
chains cross and per-pass work starts paying on both sides again. Beyond the
last row the fixed ~100 ms and the vote-after-execute coupling are the wall,
and only a protocol change moves it (section 3, phase D).

## 2. The rule set (unchanged from v2, one addition)

- Cut the longer chain; judge the cut by that chain's own metric
  (`fleet7-leader.py` `waited` and `build` for the leader, the followers'
  `engine_ms` for the import), and expect TPS to move only when the chains
  cross.
- Window 1 resolves in whole blocks (5,433 TPS); the round total is the
  metric for anything smaller.
- **Addition: read every leg per window on both sides** -- leader build,
  follower import, fleet major faults, MemAvailable, one EL's RSS -- before
  reading TPS. A change that lifts window 1 and leaves windows 2-3 is a
  leader-chain change; one that lifts windows 2-3 alone is a memory change.
  The two are not interchangeable and must not be compared by the round
  total alone.
- Bench discipline carries over: hugeprep + dropcache before every leg, never
  compile between legs, one warm-up leg, `fleet7-repeat.sh` before a claim,
  bookend everything, and a leg whose `memory :` header shows a pool under
  30 GB is void.

## 3. The plan

### Phase 0 -- before the next round (no box time)

*Status 2026-09-09 21:00 EDT: all five done. 0a the launcher; 0b
`direct_build::tests::the_parent_state_is_its_bundle_over_the_grandparent_under_the_sealed_hash`
(the registry finds the build by the fields a seal cannot change, the overlay
reads the parent's nonces and created accounts over the grandparent, an
untouched account reads through, `BLOCKHASH` answers the sealed hash);
0c `scripts/fleet7-windows.py` (the table in 1.3 is its output); 0d the
tmpfs 20 -> 8.4 GB (8,401 stale Erigon sort buffers, 684 reth-test dirs, 46
Go link dirs, all older than a day and held by no process; the 2.1 GB
`tmp.*` dirs of unknown origin were left); 0e swap emptied and re-enabled
by the user (8 GB, 0 used).*

0a. **Launcher**: done -- loop110 no longer waits on a round that never ran,
    and its `good regime` line records swap and Shmem beside datc and
    available memory.
0b. **An offline test for the direct build.** In `n42-engine-types`: build
    block N through `default_n42_payload` on a dev chain, re-seal its header
    under a different hash (a changed nonce or extra data, as the view seal
    does), then call `DirectBuilder::build_on_own` with the sealed header and
    N's `BuiltExecution`, and assert that N+1's transactions from the same
    senders are accepted (their nonces read from N's bundle, not the
    grandparent's state), that N+1's parent hash is the sealed hash, and that
    `BLOCKHASH(N)` inside N+1 answers the sealed hash. The test is the guard
    against losing a round to a wrong overlay.
0c. **A per-window reader**: `scripts/fleet7-windows.py <bench dir>` printing,
    per 30 s window from the first full body, the leader's build phases from
    `builds-node0.log`, the followers' `engine_ms` from `builds-node{1..6}.log`,
    and the box's counters from the launcher's `mem-<tag>.txt` (major
    faults per window, MemAvailable, EL RSS). The table in section 1.3 was
    made by hand; every leg should print it.
0d. **Free the tmpfs.** `/tmp` holds 19 GB of Shmem that can never be
    evicted. Old fleet datadirs under it belong to nobody now
    (`fleet-tmpfs-cleanup` in memory); confirm the owner of what remains
    before deleting. This is 19 GB of page cache back for every leg.
0e. **Ask the user for a swapoff/swapon** (root) before the memory phase's
    rounds; record `SwapFree` in every `good regime` line meanwhile.

### Phase A -- the leader's chain (window 1) -- A1/A2 DONE 2026-09-10

*Status 2026-09-09 23:00 EDT -- A1/A2 measured (loop110-113, `docs/NATIVE_FLEET7.md`
"loop110-111" and "loop113"): the plumbing leaves the chain as designed (`fcu` 0,
`waited` 0) but the S legs read 244k against 271-276k baselines (four B legs agree to
four figures; 275,839 is the best window 1), because the build of N+1 and the
hand-off/persistence of N now overlap on the QMDB forest's single mutex (direct build
435 vs 384 ms in window 1, 756-820 vs 444-590 later; rename p90 172-357, hand-off p90
193-376, assembly root p90 152-167 vs 41), and one S leg in two hung: a rayon worker
holding the forest lock stole the other assembly's root job (stack dump, loop113).
Fixed so far: taken builds stay findable (`find_kept`), a refused on-seal build is
replaced by the import's forkchoice build, on-seal only for own blocks, the QMDB root
job on its own thread. loop114 (2026-09-10 01:06) measured them: no hang, 0 refusals, 0
critical-path builds, and the S legs still 233,620 / 244,491 against B legs 266,225 /
266,222 -- the contention alone is 6-7 blocks a window. That contention was the
forest moving its one tree for persistence (`set_canonical`/`delta_since` stood the tree
at the head, reverting the next block's build for the next computation to replay);
e7b60c513 captures each block's delta at compute time and persistence consumes it without
moving the tree. loop115 (06:38): S 266,216 / 260,744 against B 260,789 / 265,985 on
window 1 -- parity -- and S2's windows 2-3 the best of the campaign (217k / 185k, round
19,884,000, the best round yet); one S leg's windows 2-3 collapsed on the supply side
(flood replies 2 s, builds waiting 618 ms for the queue), unexplained. loop116 repeats
the round: loop116 S1 248,774 / 211,787 / 206,361 = 20,007,660 (the best round), B1/B2 19.5M /
18.9M, and S2 collapsed -- a stale build-ahead request after a slow hand-off became a reorg
(NATIVE_FLEET7 loop116); the guard (35e5ba4b4) went into loop117, which read S 266,223 / 211,839 / 200,977 =
20,371,170 and 266,222 / 211,842 / 190,086 against B 19.39M / 19.23M with no collapse.
**A1/A2 done and adopted** (`N42_BUILD_ON_SEAL=1` in the record configuration). Window
1 now reads 49 blocks on both arms: the cycle is the followers' chain, so phase B is next
as written; on the leader's side the checkpoint's clone under the forest lock and the
delta capture's cost remain; the capture's own cost
(the assembler's root phase 76-105 ms against ~60) is the next cut -- a lazy appended
range.*

A1/A2. **Measure build-on-seal** with loop110 as written (S-B-S-B, pacing
    450, grace 600, rayon 16). Pass criteria, in order: on-seal builds appear
    as `fcu_ms=0 on_seal=true` in `leader.txt`; `waited` falls from ~77
    toward 0 on the S legs; `commit->body` falls from ~188 toward ~40;
    window 1 gains 5-6 blocks (~295k). If `waited` stays positive, the
    on-seal build is slower than the forkchoice build and the direct path
    has a cost the static read missed -- read `find_ms`, `queue_ms`,
    `rename_ms`, `build_ms` on the `built ahead on the sealed own block`
    line before touching anything.
A3. **Build phases** (361 ms; fold 89, finish 107, assemble 49): as in v2 --
    the graft emitted sharded by QMDB key, the hashed post-state computed
    after publication, assembly as a copy of the pool's RLP. Each is a whole
    pass and worth ~one block; each is judged by `build` in `leader.txt`,
    and none of them shows on TPS until the chains cross (phase B).
A5. **The zero-code round** from v2 (`N42_PARALLEL_BUILD_THREADS=32` under
    rayon 16) is folded into A1's follow-up, not run on its own.

### Phase M -- the box's memory (windows 2-3; new)

M1. **Attribute the growth.** One profiling leg with `fleet7-profile.sh
    --alloc` on the leader *and* one follower during window 2, plus
    `AnonHugePages` and RSS per process per window from `fleet7-windows.py`.
    Candidates, in the order the numbers point: reth's in-memory chain
    (`ExecutedBlock`s held until persistence -- at 147,000 accounts a block
    each carries a bundle, receipts, hashed state and trie updates;
    `--engine.persistence-threshold` and `--engine.memory-block-buffer-target`
    are the knobs), the `thp:always` heap's own retention (jemalloc keeps
    2 MB extents it cannot return under `defrag=defer`), the sender cache
    (4M entries), the queue's held blocks (16 x 163,000 transactions).
M2. **Cap what M1 names**, one knob per leg, judged by the fleet's major
    faults per window and by window 3 / window 1 (target >= 0.9; today
    0.65-0.70). The persistence knobs and freeing the tmpfs are the first
    two legs because they need no code.
M3. **Then the heap policy A/B again on the new footprint**: `thp:always`
    for the execution layer only, the validators and flood on 4 KB pages;
    the earlier A/B (loop77) predates the pinning and the flood fix.

M1-M2 are worth ~4M transactions a round if they hold windows 2-3 at
window 1's rate, and they are independent of phases A and B: schedule them
in the same round order, alternating, so neither waits on the other.

### Phase B -- the followers' chain (once `waited` reads ~0)

*Status 2026-09-10 16:45 EDT -- started, with the tail first. `waited` read 0 on loop117's S
legs, so this phase opened; but before cutting the import, `scripts/fleet7-cycles.py` (new)
showed window 1's blocks are lost to a tail, not to the median: median cycle 537-550, mean
601-608, ~3.3 blocks a window in cycles of 0.7-1.1 s -- the QMDB checkpoint (the tree cloned
under the forest lock, four or five stalls a window) and the three tenure changes (the
incoming leader's forkchoice + build after its import, ~950 ms). loop118 took the checkpoint
off the lock (a background compaction from the files; NATIVE_FLEET7 loop118): same-leader
stalls 6-7 -> 2-3 a window, one block a window on both bookended pairs, 277,001 the best
window 1 and 20,701,000 the best round; adopted. Its background cost shows on the median
(followers' import +15 ms): nice 10 and a checkpoint ratio > 1 are the next zero-risk cuts.
B0 (new): the tenure change -- measured next with `F7_LEADER_TENURE=64` (the T leg, void in
loop118 because the funding reached only node0; fixed in the flood), then the incoming leader
building on its own imported post-state without the forkchoice. B1 has a cause: the Ed25519
sender cache is direct-mapped (`fixed-cache` evicts on collision), 4M entries, and the queue
holds ~360k transactions ahead of the chain, so ~13% of a block's senders are evicted before
the follower imports it (22k batch-verified again, senders 37 ms instead of ~5); the
predicted eviction 1 - exp(-520k/4M) = 12% matches. loop119 ran 16M entries (~1 GB a node)
against 4M: the senders phase 37 -> 17 ms as computed (157k of 163k cached), and the fleet
lost a block a window and 0.5-1M a round to the memory (EL RSS +1.5 GB, major faults 3.5-4.8x
in window 1, six same-leader stalls against two). Kept at 4M; the 20 ms needs a form that
costs no memory (a shallower queue, a 16-byte tag, or a set-associative table) and is worth
a block only once the tail is gone. loop120 (armed): the compaction at nice 10 and
`N42_QMDB_CHECKPOINT_RATIO=4`, and the tenure-64 legs.*

B1. **Converged pools**: make `F7_INGEST_ALL=1` actually converge so a
    follower's senders phase is a lookup (38 -> ~3 ms) and its mined-removal
    is real; judged by `cache_hits` on the followers before TPS.
B2. **Body by reference** (hashes instead of 24.8 MB of bodies; fetch the
    missing ones by hash, gov5's `block_by_hash` already exists): removes
    the follower's decode (42), the validator's (14), most of the push.
B3. **The graft** (68) through A3's sharded output.

Expected: follower import ~410, and with the leader at ~365 the chains cross
at ~58-59 blocks (~315k). From here per-pass work on either side pays 1:1.

### Phase C -- per-pass work on both chains

Plain-state storage mode (v2 section 1.5: on `--storage.v2` the hashed
tables are the state; a plain-state mode is a flag, then a persistence
change in the vendored provider), the QMDB root (54-107 ms: incremental
leaves per execution batch instead of one pass at the end), the carry
cache. Each removes a pass from both chains at once. Target ~300 ms a side,
~75 blocks, ~400k at this shape.

### Phase D -- the protocol (a decision, not a round)

Everything above keeps "a follower executes the block before it votes". The
fixed ~100 ms and the execute-then-vote coupling are then the wall: at
~300 ms a side the cycle is ~400, not 300. The known way past it is
**deferred execution**: the header of N carries the post-state root of N-1
(what Ethereum's EIP-7862 proposes), so a follower votes on N after checking
its structure, signatures and availability, and executes N while N+1 is
being proposed; the leader builds N+1 on its own post-state of N as it
already does. The cycle becomes max(leader build, follower import, network)
with the fixed part overlapped, and phase C's ~300 ms a side would read
~100 blocks a window (~540k) instead of 75.

It is a header-profile change, therefore a cross-client rule (gov5's
`VerifyHeader`, the committee evidence's `parentBeaconRoot` link, the
mobile receipts that read `state_root`). Not for this campaign to decide
alone: write it up with the numbers from phases A-C as a proposal to the
gov5 side, and go/no-go after phase B has crossed the chains. Nothing in
phases A-C is wasted if D is refused, and nothing in them assumes it.

## 4. Rounds, in order

1. **loop110** (A1/A2, S-B-S-B) -- after 0a, 0b and 0d, on a box gov5 has
   released; read `leader.txt` and `fleet7-windows.py` per leg.
2. **M1** -- the allocation profile of leader and follower in window 2, one
   leg, profiling build. Can run the same night as loop110 if the box
   allows; the profile leg's TPS is not read.
3. **M2** -- persistence knobs and the tmpfs, two legs each, judged by
   window 3 / window 1 and by faults per window.
4. **B1** -- pool convergence, `cache_hits` first.
5. **A3 / B2 / B3 / M3** as code lands, each bookended, alternating leader,
   follower and memory so a round always has one item from each.
6. **C** after the chains have crossed; **D** as a written proposal at the
   same time.

## 5. What not to do

- Do not read loop110's windows 2-3 as a verdict on build-on-seal; they are
  the box's memory. Read window 1 and `waited`.
- Do not run any leg with the tmpfs at 19 GB or swap at 7 GB without writing
  both numbers into the leg's header; a leg without them cannot be compared
  to one with them later.
- Do not start phase B before `waited` reads ~0 on most blocks (v2's rule).
- Do not skip the hashed post-state on the v2 storage layout (v2, 1.5).
- Do not attribute a window-2/3 change to a chain-side cut, or a window-1
  change to a memory knob, without the per-window table on both sides.
- Do not compile between legs, and check `pgrep -f 'fleet7-benc[h].sh'`
  before building: the launcher's legs run `target/release` from a claim
  taken minutes earlier.
