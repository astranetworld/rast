# Fleet7 plan v2 -- the leader's chain is the cycle

*2026-09-09. Written after a review of rounds 95-108, with the R16b logs of
loop108 re-read end to end. Supersedes the "pass removal" list at the end of
`docs/FLEET7_STATUS.md`; that list is not wrong, it is aimed at the wrong
process.*

## 1. What the review found

### 1.1 The critical path is the leader's build, not the followers' import

Every round since loop95 was designed around the follower's import (445-507
ms of a 570-625 ms cycle) and read its result on window 1. Cuts of 17-53 ms
in that import were "real in the import, invisible on the fleet", shrinking
the builder's pool (loop107) made the import *faster* and the round *slower*,
and the cost model concluded the chain costs 4.0 us per transaction with the
EVM under 11% of it.

The leader's side of the same blocks was never measured. `scripts/fleet7-leader.py`
(new) reads it from the validator logs. loop108 R16b, full blocks, 30 s
windows from the first full body:

    win  bodies  own_rt  fcu  build  waited  commit->body  cycle
    1    49      62      72   396    77      188           570
    2    35      60      98   595    182     285           815
    3    33      56      102  642    190     269           852
    4    32      61      109  680    174     285           907

- `own_rt`: the leader imports its own block by sealed header, 62 ms round
  trip, and only then asks for the next build.
- `fcu`: the engine's forkchoiceUpdated that starts the build ahead, 72 ms.
- `build`: reth's payload job, 396 ms, of which our builder's own phases are
  361 (window 1: fold 89, finish 107, assemble 49, exec 42, pull 15, other
  ~60); the rest is the payload service around it.
- `waited`: **after the leader already holds the parent's quorum, it waits
  77 ms for its own build -- on 48 of 49 blocks in window 1.** In windows 2-4
  it waits 174-190 ms on every block.

Read as a chain: 62 + 72 + 396 + ~13 (propose) + ~27 (push) = 570 ms, which
is the window-1 cycle to the millisecond. The followers' chain (body received
-> import -> vote -> quorum) is ~493 ms and has ~77 ms of slack. Every
follower-side cut of the last two weeks landed in that slack, which is why
none of them showed. loop107 is the same story: a 4-thread builder pool
slowed the build and the round followed it exactly.

**Windows 2-4 are the same chain getting longer**: the build goes 396 -> 595 ->
642 -> 680 and the wait grows with it. From the builder's own phase log,
what grows is the parallel execution (42 -> 148 -> 187 ms), the fold
(89 -> 127 -> 144) and the finish (107 -> 148 -> 157) -- everything the
builder does, roughly together, which points at memory (the leader's heap
grows with its pool; the huge-page pool is spent by then) rather than at any
one algorithm. That is the window-2/3 collapse, and it was always on the
leader.

### 1.2 Thirty percent of the leader's chain builds nothing

Of the 570 ms, about 170 ms is plumbing between the leader and its own
execution layer:

| step | ms | what it is |
| --- | --- | --- |
| own-block import round trip | 62 | header-only import of a block the builder just executed, awaited before the next build may start |
| forkchoiceUpdated to start the build ahead | 72 | canonicalising that block in reth's tree and creating a payload job |
| payload service around our builder | ~35 | job creation, resolve with `WaitForPending` |

The builder holds the parent's post-state in memory when it finishes a block
(`built_executions`). The next build could start from it the instant the
block is sealed, with the engine's import and forkchoice running beside it
instead of ahead of it. That is the single largest item in this plan and it
is entirely in our own code (`payload_serve`, the driver, the payload
builder).

### 1.3 The thread finding of loop108 was misattributed

loop108's numbers stand (16 rayon threads: 260,485 / 259,233 at 48 blocks,
against 253k at the default and 248k at 32) but the explanation written the
same morning -- "1,792 rayon threads on 256 cores, the fleet is
oversubscribed" -- was wrong. **Every node is pinned to 16 physical cores
with their SMT siblings (`F7_PIN=1`, `F7_CORES_PER_NODE=32`, 32 logical
CPUs); the flood has the last 16 cores.** rayon's default is
`available_parallelism()`, which honours the affinity, so the default was 32
per node, 224 across the fleet, not 1,792. What loop108 measured is that
*within a node's 32 logical CPUs* one rayon thread per physical core (16) is
better than one per logical CPU, because the node's other threads -- the
builder's 16, tokio's 8, the ingest's 20, the validator's 4 -- share them.
The "offline versus fleet" gap (conversion 26 vs 48 ms, execution 145 vs
197) is the offline bench's 128 cores against a node's 16, not contention
between nodes. The honest hardware statement is therefore stronger, not
weaker: **260k TPS with seven 16-core nodes on one box.** The "a node per
machine would read 325k" sentence in the loop107 write-up is retracted.

### 1.4 The bench gives followers cold caches, and pools do not converge

On every follower, every full block: `cache_hits=0/163000`. The follower
verifies all 163,000 Ed25519 signatures (36-39 ms) and decodes the 24.8 MB
body (40-44 ms) on its import path, although `F7_INGEST_ALL=1` sends every
transaction to every node's ingest and the ingest writes every verified
sender into the shared cache. The frame counts differ per node (1021 / 792 /
711 / 682 in one leg), the followers' mined-removal takes 3 ms (a pool that
held the block's transactions would take ~260), and `gate_us_per_frame` is
210-240 ms on three nodes against 29 on the fourth: the followers' pools are
full of *other* transactions, their gates are shut, and the leader's block
is built from transactions they never admitted. In a real network the
followers would have seen and verified those transactions before the block
arrived. The bench's supply model puts ~80 ms of per-transaction work on the
follower's critical path that a deployment would not have -- but it only
matters once the follower's chain is the cycle (section 3, phase B).

### 1.5 Why the hashed post-state cannot be skipped (loop106, explained)

`--storage.v2` defaults to true and `use_hashed_state()` is `storage_v2`:
**on this chain the database's canonical account and storage tables are
`HashedAccounts`/`HashedStorages`, keyed by keccak, and persistence fills them
from each executed block's `hashed_state`.** An empty hashed state persists
an empty change for the block; the next block's senders read pre-block
nonces from the database once persistence has run, every transaction fails,
and the block executes with no receipts -- exactly loop106's
`gas spent by each transaction: []`. The pass is not a trie side-product
here, it is the write path of the state. Removing it means a plain-state
storage mode (`--storage.v2=false`, then no hashed writes at all since the
Merkle-Patricia trie is unused on a QMDB chain): a flag first, then a
persistence change in the vendored provider. Worth ~26 ms of the build's
finish and the follower's import each, plus two fewer tables to write; it is
phase C material, after the chain has been re-balanced.

## 2. The cycle, as it actually is (window 1, 16 rayon threads)

    leader    own import 62 | fcu 72 | build 396 (builder 361: fold 89, finish 107, assemble 49, exec 42, pull 15) | propose 13 | push 27   = 570
    follower  body -> import start 2 | import 450 (convert 42, senders 38, exec 211, root 54, hashed 26, carry 24, misc) | EL->vote ~48 | quorum 10 | = ~493, slack 77

Both chains scale with the block (loop105: doubling the gas ceiling doubled
the cycle). "4.0 us per transaction" is the leader's chain per transaction;
the followers' is ~3.5.

## 3. The plan

The rule that replaces "remove a whole pass": **cut the longer chain, and
judge the cut by the chain's own metric, not by TPS, until the two chains
cross.** A leader-side cut of up to 77 ms will show as at most one block on
window 1; it shows in `waited_for_ahead` going to zero. A follower-side cut
shows nothing at all until the leader's chain is shorter than the
follower's.

### Phase A -- the leader's chain, plumbing first (target: 570 -> ~400)

A1. **Build the next block on the builder's own post-state, immediately.**
    When the builder seals block N it already has N's bundle and QMDB
    state; start building N+1 on it in the same breath, and let the
    engine's header import of N and its forkchoice run concurrently. Removes
    own_rt 62 + fcu 72 from the chain (the engine still does the work,
    beside the chain instead of in it). Where: `payload_serve` (the
    OWN_BLOCK request path), `h2-execution/driver.rs` (`prepare_build_on` is
    the request), `engine-types/payload.rs` + `built_executions.rs` (the
    builder must accept a parent that is not yet in the tree). Judge by
    `own_rt`/`fcu` leaving the chain and `waited` falling by ~130.
A2. **Drive our builder directly for the build ahead**, not through reth's
    payload service: the ~35 ms between `build_ms` and the builder's own
    `total_ms`. Falls out of A1 if the ahead build is a direct call.
A3. **Build phases** (361 ms; each is a pass over the block): fold 89 (the
    graft of per-sender bundles -- emit the parallel results already sharded
    by the QMDB key so the merge is a per-shard append; the same change
    serves the follower's 68 ms graft), finish 107 (QMDB leaves + root are
    mandatory for the header; the hashed post-state's 26 ms can be computed
    after the block is published, before persistence needs it), assemble 49
    (the RLP of every transaction is already in the pool object; assembly
    should be a copy, and the transactions root can be built per batch as
    execution finishes).
A4. **Window 2-4 growth.** The builder's exec goes 42 -> 187 ms across a leg
    with nothing but the pool changing. Take an allocation profile
    (`fleet7-profile.sh --alloc`) of the *leader* during window 2, and read
    the leader's THP fallback (`AnonHugePages` of the leader's PID per
    window). This is the whole of the window-2/3 story and is worth as much
    as A1 to a round's total.

Expected after A1-A2: the leader's chain ~430, the followers' 493 becomes the
cycle: **window 1 ~60 blocks, ~300-330k**, and the follower work below starts
to count.

### Phase B -- the followers' chain, once it is the cycle (target: 493 -> ~410)

B1. **Warm caches / converged pools.** Make the ingest-all supply actually
    converge (the flood advances a nonce only when all seven accepted; find
    why frames still differ per node -- the gate's high-water refusals are
    the suspect) so the follower's sender phase is a lookup (38 -> ~3 ms)
    and mined-removal is real. This is bench realism, and in a deployment it
    is transaction gossip; the engineering version is a binary batched
    gossip between execution layers into the same ingest.
B2. **Body by reference.** With converged pools the proposal can carry
    transaction hashes (5.2 MB) instead of bodies (24.8 MB): removes the
    follower's decode (42 ms), the validator's decode (14), most of the
    push, and the validator->EL copy. Fallback: fetch missing transactions
    by hash from the leader (gov5 already has `block_by_hash`).
B3. The graft (68 ms) via A3's sharded output; the second decode in
    `convert` (0.29 us) disappears with B2.

Expected after B1-B3: ~410 ms follower chain against a ~400 leader chain --
the two cross, **~70 blocks, ~360-390k**, and only then do the per-pass
items on both sides pay 1:1 again.

### Phase C -- per-pass work on both chains

Plain-state storage mode (section 1.5), the QMDB root (54-107 ms) and the
remaining passes, in whichever chain is longer at the time. Nothing here
before phases A and B have crossed the chains.

## 3a. Status

- **A1/A2 built** (2026-09-09 afternoon, `N42_BUILD_ON_SEAL=1`): the
  validator asks for the next build the moment it seals a block; the
  execution layer builds it directly on the sealed parent's own post-state
  (`crates/n42/engine-types/src/direct_build.rs`, `payload_serve.rs`
  `BUILD_ON_OWN`, `driver.rs` `prepare_build_on_sealed`). Falls back to the
  forkchoice path when refused. Round: `run-loop110.sh`, not yet run.

## 4. Rounds, in order

1. **Zero code:** `N42_PARALLEL_BUILD_THREADS=32` under `RAYON_NUM_THREADS=16`
   (the builder's pool on all 32 logical CPUs while the global pool sleeps;
   loop107 only ever tested 4 against 16, and under the old default). Judge
   by `build` and `waited` in `fleet7-leader.py`; a win shows as ~one block.
2. **A1 + A2** behind a knob, A-B-A-B at pacing 450 / grace 600 / rayon 16;
   `waited` must go to ~0 and `commit->body` to ~40; TPS follows only to the
   follower's chain.
3. **A4's profile round** (profiling build, one leg, leader-focused).
4. **B1** (flood/ingest convergence) -- read `cache_hits` and `mined_ms` on
   the followers before reading TPS.
5. Then A3 / B2 / B3 as code lands, each bookended.

Bench discipline carries over unchanged: hugeprep + dropcache before every
leg, never compile between legs, one warm-up leg, `fleet7-repeat.sh` before
any claim, window 1 in whole blocks (5,433 TPS each), and now
`fleet7-leader.py` and `fleet7-phases.py` read together at the end of every
leg so the round says which chain it moved.

## 5. What not to do

- Do not spend a round on a follower-side cut while `waited_for_ahead` is
  positive on most blocks; it cannot show.
- Do not read TPS as the verdict on a leader-side cut; read `waited` and
  `cycle` on the leader first.
- Do not skip the hashed post-state on the v2 storage layout (section 1.5).
- Do not attribute the offline-vs-fleet gap to cross-node contention again;
  the nodes are pinned, the gap is 128 cores against 16.
