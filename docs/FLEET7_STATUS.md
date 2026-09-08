# Fleet7 status (living note; last updated 2026-09-08 12:00)

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

Follower import 470 -> ~300 ms: graft sharding, convert (50 ms) profile,
twig structural writes sharded; then the supply side (ingest ~400k/s per
node, 7x redundant verification) once the chain passes ~330k. 1,000k needs a
sharded state commit and de-duplicated ingest -- a separate design.

## Open defects and hazards

- Queue desync after a reorg is fixed (b6413c5af) but not yet exercised by a
  real reorg on the fleet.
- Launcher hygiene: gate on `pgrep -fc 'n4[2] node'` (any target dir), chain
  launchers by ALLDONE, an `F7_BIN` dir needs `examples/h2_keygen` and
  `send_tx` too. `pkill -f` with a self-matching pattern kills the shell.
- Never `dirty_decay_ms:-1` on this box (OOM-killed an execution layer).
