# Fleet7 status (living note; last updated 2026-09-08 14:05)

The one-page state of the native seven-node fleet work: what is true now, what
is in flight, what is decided and what is not. The measurements behind it are
in `docs/NATIVE_FLEET7.md` (rounds 40-43 and the loop82-87 sections),
`docs/BLOCK_SHAPE_SURVEY.md` and `docs/ROADMAP_ED25519_TX.md` section 0c.

## What is true now

- **Shape.** The bench's blocks touch ~147,000 accounts per 163,000 transfers
  since the flood fix (ab3c79240). Every number before round 43 was measured
  on ~13,000-account blocks and does not transfer. Every round now prints a
  `shape` line (senders, distinct recipients, run lengths).
- **Throughput at that shape.** 239-247k TPS on window 1 at a 0.65-0.68 s
  cycle; 17.4-17.7M transactions per 90 s round without a stall (loop87
  P450). The cycle is linear in accounts touched: 0.40 s + 2.8 us/account.
- **Where the cycle goes.** Leader build 362-387 ms (no longer the pole);
  follower import 410-470 ms (execution ~190: partition 39, groups 62, graft
  73; root 86-104; convert 50; hashed 29-38; senders 36; engine 31).
- **Window 1 is bimodal by the box's memory state, not the code** (loop86-96):
  239-247k when the leg starts a minute after another leg's fleet was killed,
  177-196k after a build, a profile, a datc run, a 33 GB file read or five
  minutes of idling. The seven `thp:always` heaps take every free order-9
  block in the flood's first seconds; a heap that got 2 MB pages then is
  fast, one that fell back to 4 KB pages is the slow mode (the 4 KB-heap
  legs read the same 184k), and from the first fallback `defrag=defer` has
  kswapd evicting 7-11 GB/5 s of page cache -- the fleet's MDBX pages --
  for the rest of the leg. loop94's 179k and loop95's first leg were this.
  **Never read a first leg; compare legs that follow legs.** Every
  round.txt now has a `memory :` header line (free, cached, order-9 pool).
  **Adopted (loop97-98): `fleet7-bench.sh` runs `scripts/dropcache.py`
  (stale file pages, no root) and `scripts/hugeprep.py 60` (MADV_COLLAPSE,
  an ~80 GB pool in 5 s) before every leg; from any starting state the legs
  read 243-253k, and loop98 S1's 18.17M is the campaign's best total.** A
  leg whose pool was under ~30 GB at the start is not comparable.
- **Ed25519 batch width is null** (loop95: 128 vs 256, 240-243k either way).
- **The stall** at blocks ~190-225 is the leader outrunning the followers
  outside the quorum (5 of 7 votes make a QC; followers vote after importing,
  so two slow importers fall a block behind per view; the next leader, if one
  of them, must catch up and the views time out). 450 ms pacing removes it in
  practice; memory pressure (thp:always heaps vs page cache) widens it.

## Decided since 08:30

- **Stragglers' grace adopted** (loop92): `F7_STRAGGLER_GRACE_MS=600` with 450 ms
  pacing -- 244k on window 1, no stall in four grace legs, best totals of the
  day (17.1M); it needs the progress votes and the leader's own vote in the
  ledger (b713b113d). At 300 ms it paces to the slowest follower (slower here).
- **Follower sender grouping is null** (loop91): stays off.
- **Own-block transactions are held until the height settles** (7c6b8ce11):
  a block consensus never committed used to lose them and leave every
  affected sender's lane above the chain's nonce (P450a). loop93 validates.

## Defaults and knobs (record environment)

`N42_PARALLEL_BUILD=1 N42_FOLLOWER_GRAFT=1` (off by default, in the record
env), `N42_PARALLEL_STATE_COMMIT` (on by default), `F7_BLOCK_INTERVAL_MS=450`
(bench default), `MALLOC_CONF=thp:always`, 20 recovery slots,
`N42_TX_QUEUE_RUN=64`, `TOKIO_WORKER_THREADS=8`, Ed25519 flood, sender cache
2^22, batch 128, pertx 10000. Null knobs (measured): 32-thread build pool,
builder graft without cache inserts, MDBX readahead (a loss), jemalloc
background purge (+3% win1, no cure), decay off (OOM). 4 KB heap: -24% win1,
perfectly steady.

## In flight (launchers in `~/.claude/jobs/2127e0ae/tmp/`, chained by ALLDONE)

1. (done) **loop89/91** -- follower grouping by sender: null.
1. (done) **loop92** -- grace: adopted.
1. (done) **loop93** -- no stall occurred in any of its four legs (box recovered: 239-240k win1), so the held own-block ledger is validated by its queue test only; watch for "own block at this height was not the one committed" in future logs.
1. (old) **loop89** -- follower grouping by sender (`N42_FOLLOWER_SENDER_GROUPS=1`,
   7dbb2cc21) vs connected components, S-B-S-B. Ran under a 17-31 GB `datc`
   neighbour (flood starved: 13 s replies); its numbers are suspect.
2. **loop90** -- the stragglers' grace *with progress votes* (ed417f695 +
   858f31994): `F7_STRAGGLER_GRACE_MS=600` at 300 ms pacing vs 450 ms pacing
   vs both. loop88's first leg (grace without progress votes) read 125k at a
   1.25 s cycle: the ledger never saw the late voters, so every block waited
   the whole grace -- hence the progress votes.
3. **loop91** -- loop89 again on a box without datc.

Decision rules: window 1 and the round total, bookended; a leg is void if
`datc` or another fleet was on the box; the shape line must read ~145k
distinct recipients.

## Decided, pending data

- Grace: adopt into the record env if G300 matches/exceeds P450's totals with
  no stall; if G450 is the steadiest, both.
- Sender grouping on the follower: adopt if S beats B on import time and
  totals on the clean rerun (loop91).

## Where a follower's CPU goes (loop94 profile)

61% in the tokio threads doing the ingest (Ed25519 batch verification ~36% of
all samples, keccak ~5%), 14% in the rayon threads doing the import, 6%
persistence. Each validator verifies every transaction it votes on; at ~400k
offered per node that is ~10 of 32 cores. The import bounds the cycle by
latency; the ingest by cores.

## Next after these

loop98 (S-B-S: old binary against the first follower cuts -- `TxEnv`s on the
worker pool, the graft taking the largest bundle as the block's bundle,
reverts sorted in parallel; the "66 ms prune" was the canonical pruner's
log line, not the vote path, and `prune_pool` is unset in the queue
configuration) read null on the fleet: the import fell 482 -> 470 ms on the
same node in the same mode (partition 41 -> 30, merge 75 -> 59) and the
import barrier did not move (535 / 528 ms), so the cycle did not either
(S1 252.5k, B1 244.9k, S2 244.5k). The barrier is the cycle's largest part
(cycle ~= publish->recv 30 + barrier 530 + vote->decide 20 + decide->publish
80 ms), so the import is still the pole, but it needs a cut of 100 ms, not
12. Next: measure offline (`bench_follower_import`, ignored test) and take
groups (55-62 ms, the giant component executing serially), merge (59: graft
/ take / reverts now timed apart), root (100), convert (54), hashed (40),
senders (36); then the supply side (ingest ~400k/s per
node, 7x redundant verification) once the chain passes ~330k. 1,000k needs a
sharded state commit and de-duplicated ingest -- a separate design.

## Open defects and hazards

- Queue desync after a reorg is fixed (b6413c5af) but not yet exercised by a
  real reorg on the fleet.
- Launcher hygiene: gate on `pgrep -fc 'n4[2] node'` (any target dir), chain
  launchers by ALLDONE, an `F7_BIN` dir needs `examples/h2_keygen` and
  `send_tx` too. `pkill -f` with a self-matching pattern kills the shell.
- Never `dirty_decay_ms:-1` on this box (OOM-killed an execution layer).
