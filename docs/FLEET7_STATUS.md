# Fleet7 status (living note; last updated 2026-09-09 14:30 EDT)

The one-page state of the native seven-node fleet work: what is true now, how
it is measured, what has been cut, what is in flight and what is next. The
measurements behind every claim are in `docs/NATIVE_FLEET7.md` (rounds 40-43,
the loop82-99 sections), `docs/BLOCK_SHAPE_SURVEY.md` and
`docs/ROADMAP_ED25519_TX.md` section 0c.

## The goal

Push the all-Rust seven-node fleet (`scripts/fleet7-bench.sh`, gov5's flagship
shape: seven independent members, each its own execution layer and validator,
static full mesh) as high as it honestly goes on the native chain, at a block
shape a real chain would produce, and record what the ceiling is made of.

## What is true now

- **Shape.** The bench's blocks carry 163,000 plain transfers and touch
  ~147,000 accounts, since the flood fix (ab3c79240). Every number before
  round 43 was measured on ~13,000-account blocks and does not transfer.
  Every round prints a `shape` line (senders, distinct recipients, run
  lengths). `docs/BLOCK_SHAPE_SURVEY.md` places that shape against Ethereum
  (88k accounts per 163k transactions), BNB (46k), Polygon (11k) and Tron
  (173k): ours is conservative, close to Tron's.
- **Throughput at that shape.** 244-253k TPS on window 1 at a 0.64-0.67 s
  cycle; 16.8-18.2M transactions per round. **Best window 1: loop111 B2,
  275,839 at 51 blocks** (2026-09-09 night, the round-43 configuration with
  `RAYON_NUM_THREADS=16`; four baseline legs of loop110-111 read 271,634 /
  271,655 / 271,645 / 275,839, so the number is the box's state that night,
  not a fluke); before it loop108 R16a, 260,485 at 48 blocks; **best round: loop116 S1,
  248,774 / 211,787 / 206,361 = 20,007,660** (build-on-seal; loop115 S2 19,884,000 before it) (build-on-seal on the forest that no longer
  moves for persistence, e7b60c513; one round, loop116 repeats it; B2 of the same round
  19,706,000; the previous best 18,388,500, loop104 A2); best round: loop104 A2 --
  248,906 / 190,086 / 173,806 and 18,388,500, with the highest third window
  yet; loop98 S1's 252,518 is still the highest single window. The cycle is linear in accounts touched:
  0.40 s + 2.8 us per account (loop80 sweep).
- **Window 1 has a resolution of one block: 5,433 TPS, 2.2%** (loop101). Every
  block is full at the gas ceiling (163,000 transfers), so a 30 s window reads
  `blocks x 163,000 / 30` -- 244,500 for 45 blocks, 249,933 for 46. Changes
  worth less than a block are invisible there; use the round total and the
  import's own milliseconds.
- **Neither the import nor the pacing sets the cycle alone.** The import is
  429-446 ms with the round-43 cuts (506 without) and the quorum's fifth vote
  ~500 ms, but a leg with the worst barrier of its round still read 0.653 s,
  and pacing 350/400/450 are equal (loop101). What the cuts did move is the
  **tail**: p90 of the view cycle 3,781/2,935 ms before, 1,439/1,854 after.
  The fleet is balanced -- the slowest validator votes ~19 ms after the fifth
  -- so the way up is a shorter *common* import, and it must be ~150 ms
  shorter to buy one block.
- **Where the cycle goes.** `cycle ~= publish->recv 30 + import barrier +
  vote->decide 20 + decide->publish 80 ms`, and the pacing (450 ms) sets a
  floor under all of it. The barrier is a validator's wait for its execution
  layer's answer; inside it, at 163,000 transfers with the round-43 cuts in:
  execution 180-192 (partition 30, groups 55-62, merge 59), QMDB root 63-65,
  conversion 48-50, hashed state 26, senders 35, engine 39, checks 5; total
  429-446 ms. Without the cuts each of root, hashed and conversion is
  ~1.6x larger and the total is 506.
- **A follower's CPU** (loop94 profile): 61% tokio threads doing the ingest
  (Ed25519 batch verification ~36% of all samples, keccak ~5%), 14% rayon
  threads doing the import, 6% persistence. Every validator verifies every
  transaction it votes on, so at ~400k offered per node the verification
  alone is ~10 of 32 cores. **The import bounds the cycle by latency; the
  ingest bounds the fleet by cores.**
- **Window 1 is bimodal by the box's memory state, not by the code**
  (loop86-98): 239-253k when the fleet's `MALLOC_CONF=thp:always` heaps get
  2 MB pages at the flood's start, 177-196k when they fall back to 4 KB
  pages. The seven heaps grow 9 -> 40 GB in ~15 s and take every free
  order-9 block; from the first fallback `defrag=defer` has kswapd evicting
  7-11 GB of page cache every 5 s for the rest of the leg, and the fleet's
  own MDBX pages are what goes (40-50k major faults per execution layer per
  5 s). A leg after a build, a profile, a datc run, a 33 GB file read or
  five minutes of idling was the slow kind; a leg started right after
  another leg's fleet was killed was the fast kind. loop94's 179k and
  loop95's first leg were this, not regressions.
- **Ed25519 batch width is null** (loop95: 128 vs 256 vs the 256 cap,
  239-243k either way). The ingest's 27 us a transaction is ~16 us curve,
  ~2 keccak, ~9 decode and cache.

## Method (how a number becomes a fact here)

1. **Never conclude from one round.** Window 1 and the round total are the
   metrics; over three runs the total varies 5% and window 1 by 4%, window 2
   by 17% and window 3 by 89%. A difference under ~10% between single rounds
   is invisible. Bookend everything (S-B-S or S-B-R-S-B-R).
2. **Never read a first leg.** Since loop98 the bench runs
   `scripts/dropcache.py` (evicts stale file pages, no root) and
   `scripts/hugeprep.py 30 2 <target> 4` before every leg, and prints a
   `memory :` header line. hugeprep writes every page of a 30 GB working set
   -- which also evicts a neighbour's page cache, and which the earlier
   sparse version did not do at all -- collapses it with `MADV_COLLAPSE` in
   256 MB chunks, frees it, and repeats until the free huge-page pool reaches
   `F7_HUGEPREP` GB (default 40; ~2 s a round once the pool is healthy, and
   ~42 GB is this box's ceiling while the tmpfs holds 21 GB). A leg whose
   pool was under ~30 GB at the start is not comparable.
   `F7_DROP_CACHE=0` / `F7_HUGEPREP=0` turn them off.
3. **A leg is void** if `datc`, a gov5 fleet, or a foreign flood was on the
   box. The launcher gates on `pgrep -fc 'n4[2] node'`, `n42-dat[c]` and
   `txfloo[d]` being zero, three times 30 s apart, then claims the box per
   `/data/blockchain/wr-logs/BOX-CLAIM-PROTOCOL.md`.
4. **Measure offline first.** Ignored benches at the bench's block shape make
   a 12 ms cut visible where the fleet cannot see it:
   `bench_follower_import` (parallel_transfer), `bench_convert_payload`
   (engine_validator), `where_apply_sorted_ops_goes` (twig-core),
   `where_the_root_phase_goes` (qmdb-reth), `bench_parallel_trie_root`
   (assembler), `bench_build_run` (parallel_transfer). Then bookend on the
   fleet: the fleet decides, the bench only aims.
5. **The instruments.** `scripts/fleet7-measure.py` (TPS with occupancy and
   full-block share), `scripts/fleet7-phases.py` (where a block's cycle
   goes; run at the END of a round, compare whole rounds),
   `scripts/fleet7-shape.py`, `scripts/fleet7-profile.sh` (perf between
   windows, needs `--profile profiling`), and for memory
   `~/.claude/jobs/2127e0ae/tmp/vmsample.sh` + `vmdelta.py` (5 s deltas of
   THP, compaction, reclaim and `/proc/buddyinfo`).

## Cut so far (round 43)

| change | offline | on the fleet |
| --- | --- | --- |
| Parallel builder (`N42_PARALLEL_BUILD=1`) + follower graft (`N42_FOLLOWER_GRAFT=1`) | build 1054 -> 365 ms | +14-17% win1, adopted into the record env |
| Parallel state commit (default on) | root 190 -> 104 ms | 223-228k against 189-201k |
| Stragglers' grace (`F7_STRAGGLER_GRACE_MS=600`) + progress votes | -- | no stall in six legs; 244k where plain 450 ms collapsed |
| Own-block ledger (held until the height settles) | queue test | no loss after an uncommitted own block |
| dropcache + hugeprep before every leg | pool 24 -> 80 GB | every leg 243-253k from any start; best total 18.17M |
| `TxEnv`s on rayon, graft base swap, parallel revert sort | partition 41 -> 30, merge 75 -> 59 | **null** (barrier 535 -> 528) |
| Sharded twig index, bitmap retirements, chunked undo entries | apply 52 -> 22-28 ms (15-18 at 32 threads) | import 506 -> 429-446 ms, barrier -85 ms; win1 +2.5%, total +2.0% |
| Conversion's `Result<Vec>` collect off rayon's short-circuit path | 40 -> 26 ms | (the same legs) |
| Follower sender lookups, same fix; hashed state folded once | hashed 43 -> 26 ms on the fleet | (the same legs) |
| `RAYON_NUM_THREADS` (each node is pinned to 16 physical cores + siblings, 32 logical) | every parallel phase 1.5-2x at 32 | **16 is the value**: 260,485 / 259,233 at 48 blocks against 253k at the default (= 32 under the pin) and 248k at explicit 32 (loop108). The gain is outside the followers' import -- 16's barrier is *worse*, 507 ms against 482, and its cycle shorter anyway, because the leader's chain, which is the cycle, gets the cores (`docs/FLEET7_PLAN_V2.md`) |
| QMDB root and hashed post-state joined (`N42_ROOT_HASHED_PARALLEL`) | the pair 94 -> 81 ms | import 445 -> 428 with the offload; **null** on win1 (17 ms is a ninth of a block). Adopted anyway: no risk |
| Queue and pool bookkeeping off the vote path (`N42_QUEUE_WORK_OFFLOAD`) | its worker reports 12 ms | null on win1; zero stale transactions in 63 builds, but stays opt-in |
| The carry cache filled after the answer (`N42_CARRY_ASYNC`) | 24 ms off the path | with the other two: import 456 -> 403 ms, window 1 a tie, and the round's spread widens (17.44M and 18.39M against 18.03M and 18.06M). Opt-in |
| Fast answer v1 (`N42_DIRECT_FAST_ANSWER=1`, answer before the engine's pass, no remembered block) | -35 ms on the path | **a loss**: 239k against 244.5k, because the engine's pass went 35 -> 102 ms (it decodes the payload again) |
| Fast answer v2 (remembers the block from the executed block's `Arc` on a worker thread) | the engine's pass 102 -> 62 ms | loop103: a tie on window 1 (249.1k vs 249.8k) with the totals confounded by different pools. Not a loss any more; needs a clean pair |

Null knobs, measured and left off: follower sender grouping, Ed25519 batch
width, 32-thread build pool, builder graft without cache inserts, MDBX
readahead (a loss), jemalloc background purge (+3%, no cure), recovery-thread
pinning. Never `dirty_decay_ms:-1` on this box (OOM-killed an execution layer).

## Record environment

`N42_PARALLEL_BUILD=1 N42_FOLLOWER_GRAFT=1` (both off by default),
`N42_PARALLEL_STATE_COMMIT` (on by default), `F7_BLOCK_INTERVAL_MS=450` and
`F7_STRAGGLER_GRACE_MS=600` (bench defaults), `MALLOC_CONF=thp:always`,
`N42_TX_INGEST_RECOVER_PARALLEL=20`, `N42_TX_QUEUE_RUN=64`,
`TOKIO_WORKER_THREADS=8`, **`RAYON_NUM_THREADS=16`** (loop108: 16 beats the default by
3% and 32 by 5%; one thread per physical core of the node's pinned 16; the
value must be set by the launcher -- loop100-107 silently ran at the default), `F7_FLOOD_ALG=ed25519`,
`N42_ALTSIG_SENDER_CACHE=4194304`, `N42_ED25519_BATCH=128`, `--pertx 10000`.

## In flight

**loop105** (running): a doubled gas ceiling, because the block is the other
lever -- see the round log. **loop104** (done): the two plumbing cuts together
(`N42_ROOT_HASHED_PARALLEL=1` and `N42_QUEUE_WORK_OFFLOAD=1`), A-B-A-B.
**loop103** (queued, builds): the fast answer's second attempt, and the first
round to log `carry_ms`.

The bench reproduces to four figures when the box is in the same state:
loop100's two B legs read 244,488 and 244,489 with identical totals, matching
loop99's B legs. A first leg after another driver has held the box for hours
is still not comparable (loop100 F1: 217k).

**loop99** (done, see the cut table) (launcher `~/.claude/jobs/2127e0ae/tmp/run-loop99.sh`, waiting at
its gate for eight foreign `txflood-r34` processes from another session to
exit): the S-B-R bookend of the import cuts in b83371904 -- S = the loop95
binary (`target/profiling`, HEAD 42f1cc5eb), B = `target/release` built by the
launcher, R = B with `RAYON_NUM_THREADS=32`. Six legs, dropcache and hugeprep
before each. What it decides: whether the offline cuts (root, conversion,
senders, hashed state; ~60 ms of a 470 ms import) move the barrier, and
whether the node's rayon pool should be sized to 32 rather than the box's 256
logical CPUs (every parallel phase ran 1.5-2x faster at 32 offline).

## What the chain costs (loop105, the number that now governs everything)

`cycle = 4.0 us per transaction`, with no fixed part: doubling the gas ceiling
doubled the cycle exactly, so 250k TPS is 1/4 us and no arrangement of blocks,
pacing or consensus timing changes it. Per transfer, at 163,000 transfers and
147,000 accounts a block:

| where | us per transfer |
| --- | --- |
| the follower's import | 2.80 |
| &nbsp;&nbsp;execution: the EVM itself | 0.43 |
| &nbsp;&nbsp;execution: the merge (graft) | 0.42 |
| &nbsp;&nbsp;execution: the partition | 0.18 |
| &nbsp;&nbsp;QMDB root | 0.43 |
| &nbsp;&nbsp;payload conversion | 0.29 |
| &nbsp;&nbsp;senders | 0.21 |
| &nbsp;&nbsp;hashed post-state | 0.16 |
| &nbsp;&nbsp;carry cache | 0.15 |
| &nbsp;&nbsp;header, checks, parent state, dispatch | ~0.35 |
| publish, vote, decide, the engine | ~1.20 |

**The EVM is under 11% of the chain.** Everything else is the same 147,000
accounts moved through a hash map (the graft), grouped (the partition), turned
into trie leaves (the root), hashed again (the hashed state), copied for the
next block (the carry) and decoded twice (the conversion). A change that does
not remove one of those passes cannot matter, and one that removes a whole
pass is worth ~0.2-0.4 us, or 5-10%.

## Next (rewritten 2026-09-09 afternoon -- read `docs/FLEET7_PLAN_V2.md`)

*2026-09-09 evening: `docs/FLEET7_PLAN_V3.md` supersedes the round order below.
loop108 split per window shows the followers' import grows with the leader's
build (305 -> 579 ms across a leg) while the fleet's major faults climb 2.5-3M
per 30 s: windows 2-3 are the box's memory, a phase of their own (M), and
build-on-seal (A1/A2) can only move window 1.*

The pass-removal list that stood here was aimed at the followers' import.
Re-reading loop108's logs from the leader's side (`scripts/fleet7-leader.py`)
shows **the leader's chain is the cycle**: own-block import 62 ms + forkchoice
72 + build 396 + propose + push = 570, and the leader waits 77 ms for its own
build after holding the quorum on 48 of 49 window-1 blocks; in windows 2-4 the
build grows to 595-680 and the wait to 174-190, which is the window-2/3
collapse. The followers' chain is ~493 with 77 ms of slack -- every follower
cut of rounds 95-106 landed in that slack.

Order of work (details, numbers and the judging metric per step in the plan):

1. Zero code: `N42_PARALLEL_BUILD_THREADS=32` under rayon 16 -- judge by
   `build`/`waited` in `fleet7-leader.py`.
2. **A1/A2: start the next build on the builder's own post-state the moment a
   block is sealed**, engine import and forkchoice beside the chain, our
   builder called directly: removes ~170 ms of plumbing from the leader's
   chain. **Built** (`N42_BUILD_ON_SEAL=1`, `direct_build.rs`, request
   `BUILD_ON_OWN`); `run-loop110.sh` is the S-B-S-B round, not yet run.
   `waited` must go to ~0. TPS follows only down to the followers' chain
   (~300-330k).
3. A4: allocation profile of the *leader* in window 2 (exec 42 -> 187 ms).
4. B1/B2: converged pools (followers' `cache_hits` is 0/163000 today) and body
   by reference -- the followers' per-transaction work off their path.
5. A3/B3: the graft on both sides via sharded output; the hashed post-state
   only via a plain-state storage mode (loop106's mechanism: on `--storage.v2`
   the hashed tables *are* the state).

Rule: cut the longer chain, judge by that chain's metric, and expect TPS to
move only when the two chains cross.
