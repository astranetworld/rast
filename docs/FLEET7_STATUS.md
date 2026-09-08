# Fleet7 status (living note; last updated 2026-09-08 22:35)

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
  cycle; 16.8-18.2M transactions per round. Best round: loop98 S1, 252,518 /
  184,684 / 168,379 and 18.17M. The cycle is linear in accounts touched:
  0.40 s + 2.8 us per account (loop80 sweep).
- **The import is no longer the pole** (loop99). With the round-43 cuts it is
  429-446 ms (506 without them) and the barrier 474-492 (556-577), but four
  legs in six read a 0.652-0.667 s cycle either way: at 450 ms pacing the
  floor is the pacing plus the ~200 ms that does not overlap it. The next
  gain is a tighter pacing, not a faster import -- loop101 sweeps it.
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
| `RAYON_NUM_THREADS=32` (the box has 256 logical CPUs) | every parallel phase 1.5-2x | 250k twice, the round's two best legs; adopted |

Null knobs, measured and left off: follower sender grouping, Ed25519 batch
width, 32-thread build pool, builder graft without cache inserts, MDBX
readahead (a loss), jemalloc background purge (+3%, no cure), recovery-thread
pinning. Never `dirty_decay_ms:-1` on this box (OOM-killed an execution layer).

## Record environment

`N42_PARALLEL_BUILD=1 N42_FOLLOWER_GRAFT=1` (both off by default),
`N42_PARALLEL_STATE_COMMIT` (on by default), `F7_BLOCK_INTERVAL_MS=450` and
`F7_STRAGGLER_GRACE_MS=600` (bench defaults), `MALLOC_CONF=thp:always`,
`N42_TX_INGEST_RECOVER_PARALLEL=20`, `N42_TX_QUEUE_RUN=64`,
`TOKIO_WORKER_THREADS=8`, `RAYON_NUM_THREADS=32`, `F7_FLOOD_ALG=ed25519`,
`N42_ALTSIG_SENDER_CACHE=4194304`, `N42_ED25519_BATCH=128`, `--pertx 10000`.

## In flight

**loop100** (running): the fast answer, F-B-F-B. **loop101** (queued): the
pacing sweep P450/P400/P350 with the grace, now that the import is 70 ms
faster than when 300 ms pacing made every tenure handover stall.

**loop99** (done, see the cut table) (launcher `~/.claude/jobs/2127e0ae/tmp/run-loop99.sh`, waiting at
its gate for eight foreign `txflood-r34` processes from another session to
exit): the S-B-R bookend of the import cuts in b83371904 -- S = the loop95
binary (`target/profiling`, HEAD 42f1cc5eb), B = `target/release` built by the
launcher, R = B with `RAYON_NUM_THREADS=32`. Six legs, dropcache and hugeprep
before each. What it decides: whether the offline cuts (root, conversion,
senders, hashed state; ~60 ms of a 470 ms import) move the barrier, and
whether the node's rayon pool should be sized to 32 rather than the box's 256
logical CPUs (every parallel phase ran 1.5-2x faster at 32 offline).

## Next

1. **Read loop99.** If the barrier moves, the import is worth more cuts; if
   not, the barrier is not the import's own latency and the next thing to
   instrument is what the validator does between the answer and its vote.
2. **The graft's 42 ms** is 129,000 `BundleAccount`s inserted into one
   `HashMap` on one thread. No grouping avoids it (component and sender
   groups are within 5 ms at this shape); it needs a different bundle
   representation -- a sharded or pre-sized map the batches write into
   directly.
3. **The supply side**, once the chain passes ~330k: the ingest is ~400k/s
   per node and every node verifies every transaction (7x redundant). The
   cheap half is fewer verifications per node; the expensive half is a
   de-duplicated ingest, which is a design, not a patch.
4. **1,000k TPS** needs a sharded state commit and that de-duplicated
   ingest. Separate design work, not a knob.

## Open defects and hazards

- Queue desync after a reorg is fixed (b6413c5af, 7c6b8ce11) but has not been
  exercised by a real reorg on the fleet; watch for "own block at this height
  was not the one committed ... offered again" in future logs.
- Launcher hygiene: gate on `pgrep -fc 'n4[2] node'` (any target dir), chain
  launchers by ALLDONE, an `F7_BIN` dir needs `examples/h2_keygen` and
  `send_tx` too. `pkill -f` with a self-matching pattern kills the shell.
  **Never edit a script while a leg is running** -- bash reads it
  incrementally and the running copy hits garbage at the edit offset
  (loop95E512a lost its end-of-round section this way).
- `/tmp` is a 69 GB tmpfs and holds 20-34 GB of other sessions' leftovers;
  that memory is not available to the fleet and is not reclaimable.
