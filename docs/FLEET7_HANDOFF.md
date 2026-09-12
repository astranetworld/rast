# Fleet7 handoff (2026-09-12 08:55 EDT)

The state of the seven-node fleet campaign at a pause: the box was handed to a DATC run, nothing
of the fleet is running and nothing is queued. This note is the entry point for the next session;
the measurements behind every line are in `docs/NATIVE_FLEET7.md` (loop131-155) and the design
and defect record in `docs/PHASE_D_DEFERRED_EXECUTION.md` (sections 10-16).

## 0. Resuming in five minutes

1. **The box.** Read `/data/blockchain/wr-logs/BOX-CLAIM-PROTOCOL.md`. At the pause
   `/data/blockchain/.box-claim-datc` was held. Do not start a fleet, a flood or a release build
   while another claim is live; a launcher's `good()` gate plus claim file does this for you.
2. **The code.** `main` == `feat/native-fleet7` at `92b2cb76a` plus this note. Tree clean.
3. **The binary.** Legs run `target/deferred/release` (built with
   `cargo build -j16 --release --target-dir target/deferred -p n42 --bin n42 -p n42-h2-node
   --example h2_validator --example tx_flood --example h2_keygen --example send_tx`).
   `target/release` is left for old launchers. Profiled or stack-dumped legs need
   `--profile profiling` and `F7_BIN=target/profiling`.
4. **A leg.** Copy the newest launcher, `~/.claude/jobs/2127e0ae/tmp/run-loop155.sh`: it waits for
   the previous launcher's `ALLDONE`, builds, waits for a quiet box, claims it, runs legs, copies
   every node's `el.log` and `v.log` into the bench directory, writes `phases.txt`, `leader.txt`,
   `viewcycle.txt`, `windows.txt`, `cycles.txt`, and releases the claim. Change the three
   `loopNNN` references and the header comment. Results land in
   `/data/blockchain/rust-fleet7-bench/bench-loopNNN<tag>/round.txt`.
5. **The adopted configuration** (what every leg since loop141 runs):

       fleet7-bench.sh --gasceil 3423000000 --senders 6000 --pertx 10000 --conc 64 --rpcbatch 500
       exports  F7_LEADER_TENURE=16 F7_INGEST=1 F7_INGEST_ALL=1 F7_NO_TX_GOSSIP=1 N42_TX_INGEST_ASYNC=1
                F7_DIRECT_PUSH=1 F7_SKIP_STALE_CHECK=1 F7_METRICS_BASE=19300 N42_TX_QUEUE=1
                N42_TX_INGEST_RECOVER_NICE=10 N42_TX_INGEST_DIRECT=1
       leg      F7_EL_EXTRA="--builder.interval 60 --builder.deadline 3" N42_FAST_TRANSFER=1
                N42_FOLLOWER_DIRECT_IMPORT=1 F7_SENDER_CACHE_MULT=4 N42_TX_QUEUE_BATCH=1024
                N42_TX_QUEUE_DRAINER=1 F7_FLOOD_WINDOW=6 N42_TX_INGEST_RECOVER_PARALLEL=20
                F7_BLOCK_INTERVAL_MS=350
       C        N42_BUILDER_PULLER=1024 N42_TX_QUEUE_RUN=64 MALLOC_CONF=thp:always N42_FOLLOWER_PARALLEL=1
                TOKIO_WORKER_THREADS=8 F7_FLOOD_ALG=ed25519 N42_ALTSIG_SENDER_CACHE=4194304 N42_ED25519_BATCH=128
       R        N42_PARALLEL_BUILD=1 N42_FOLLOWER_GRAFT=1 F7_STRAGGLER_GRACE_MS=600 RAYON_NUM_THREADS=16
                N42_BUILD_ON_SEAL=1 F7_LEADER_TENURE=64 N42_QMDB_RETAIN_DEPTH=16 N42_QMDB_ENTRY_FILE=1

   Defaults that need no flag: the bench genesis `n42_fleet7_bench.json` gates deferred execution
   at time 0; the leader seals before it finishes (`N42_SEAL_FIRST=0` turns it off); the Ed25519
   key cache is on; `fleet7-env.sh` passes `--engine.persistence-backpressure-threshold 1024`.

## 1. The goal and the ruler

The standing target is 1,000,000 TPS at the bench's block shape (163,000 transfers touching
~147,000 accounts a block). `docs/FLEET7_PLAN_V3.md` section 5 is the cost model: 1M is a 163 ms
cycle, which needs deferred execution (done), a ~4x cut of per-transaction work on both chains,
and the state off the heap; on this shared box the current protocol tops out near 400k, so 1M is a
seven-machine number.

How to read a leg: **window 1 and the round total are the metrics**; windows 2 and 3 vary 17% and
89% between identical runs. Window 1 resolves one block (163,000 / 30 s = 5,433 TPS). A leg whose
huge-page pool was under ~30 GB at start (`memory :` header) is not comparable.

**Records**: window 1 **333,416** (loop141 P350a), round **22,518,476** (loop141 P350b).
Best since the fixes below: loop154 A2, 322,920 / 228,051 / 173,727 = 21.76M.

## 2. What this stretch shipped (e5110ed5b..92b2cb76a)

| commit | what | evidence |
| --- | --- | --- |
| `9f0244b5f` `590a7cf30` `a2f924705` | The audit's fixes and their regressions: rejected-block evidence withdrawn, SYNCING retries, two imports in flight, a queued block counts as importing, a queued block's commit waits, a refused forkchoice is not a rejection | PHASE_D 14/16/16.1; loop143-145 |
| `5e52dcd64` | tx-queue: a build cut short mid-run kept its sender out of the rotation; a leader stranded one sender a block and built empty blocks late in its tenure (since 2026-09-02) | loop144 A2, loop146: every block full through the tenures |
| `acba105e5` | Watchdog tracks the own-block hand-off stage | loop147 stack dump |
| `9932c9353` | The node launcher's engine service loop: branches timed, a 250 ms tick, a late-tick detector; the backpressure flag | loop148-149 |
| `7a469e2f5` `7cfa757ab` `4e57e8823` | A follower's commit that runs before the block arrives is repeated when the import lands (three forms) | loop149, 152, 154; PHASE_D 16.3 |
| `0a8dfc2e2` `8e513160b` `5e7e50669` | The sibling a leader re-proposes after a TC: sealed block found not taken + header-only guard; forest delta rewinds on a shorter sibling; an incomplete execution records no receipts; the engine head moved to the parent before a forking hand-off (reth drops a same-height executed insert) | loop147-154; PHASE_D 16.2 |

## 3. The legs, loop141-155

`stall` = nodes whose validator logged `transport: error sending` (the leader's 8 s engine timeout);
`rej` = followers' `execution layer rejected`; `pwait` = `direct import failed ... not imported within 3s`.

    leg        win1     win2     win3    round  stall  TC  rej  pwait
    141P350a  333,416  226,815  132,927  20.80    1    2    0    -
    141P350b  328,018  220,073  202,273  22.52    0    1    0    -
    143A1     284,806  119,557  225,656  18.91    1    5   19    1
    143A2     300,210  142,924   28,041  14.14    1    5    0    1
    144A1     300,245        0        0   9.01    0    1    0    0
    144A2     316,429    5,468        0   9.68    0    1    0    0
    145A1     296,666  211,481  193,739  21.07    0    2    0    0
    145A2     242,516  224,726  203,987  20.14    1    2    0    1
    146A1     244,159  244,034  160,391  19.46    2    3    0    6
    146A2     327,484  238,126  178,687  22.33    0    1    0   34
    147A1     304,070   86,250        0  11.72    1    8   42   36
    147A2     257,116        0        0   7.72    1    9   48   48
    148A1     266,149  244,270  217,128  21.84    1    2    0    0
    148A2     270,089        0        0   8.10    0   10   54   48
    149A1     314,813   11,433        0   9.80    0    4    0   33
    149A2     304,042  157,113  244,428  21.18    0    2    0    7
    150A1     255,247        0        0   7.66    1   10   54   48
    150A2     308,477  135,756  195,534  19.20    2    7   30   36
    151A1     260,743        0        0   7.82    1   10   54   48
    151A2     282,260  189,717  151,940  18.73    1    3    0    8
    152A1     307,250   21,383        0   9.87    0    1    0   96
    152A2     282,402   92,323        0  11.25    1    8   36   36
    154A1     298,713  146,632  113,253  16.77    1    5    1   32
    154A2     322,920  228,051  173,727  21.76    0    1    0    0
    155A1     298,718  228,056  183,903  21.35    1    6    0    0
    155A2     314,915  233,487  152,065  21.03    0    1    0   47

loop147 ran the profiling build; loop153 was cancelled before its legs. From loop147 to loop152 one
leg in two died after its first stall; from loop154 on no leg did.

## 4. How the defects were found (the method worth keeping)

After every leg, before the next one overwrites `node*/el.log`, grep the bench directory for:

    transport: error sending      the leader's stall (8 s engine timeout on a commit forkchoice)
    has not progressed            watchdog: import / build / own-block hand-off stuck >= 6 s (stage named)
    TC formed                     a view lost
    execution layer rejected      a follower refused a header (deferred fields mismatch) -- the chain is dying
    fork chain / reorg:           a sibling was inserted / the canonical chain switched
    could not follow              QMDB forest could not persist the canonical head
    incomplete execution result   an aborted execution's receipts were refused (8e513160b firing)
    forks from the engine         the head was moved to a sibling's parent (5e7e50669 firing)
    direct import failed          a follower waited 3 s for a parent: a lost commit
    engine service loop:          a slow branch, a long idle, or a late tick in the launcher's engine loop
    pruned from the queue ... queued=   a node's queue depth (the ingest gate closes at 407,500)

Then follow one block hash through the leader's and one follower's `v.log` and `el.log` side by
side (`received Decide`, `block body received`, `import starting`, `checked`, `imported`,
`Block added to canonical chain`, `Canonical chain committed`). Every defect of this stretch was a
difference in the *order* of those lines between a good block and a bad one. For a hang, build
`--profile profiling` and export `N42_WATCHDOG_STACKS=1`: the watchdog dumps every thread's stack
into `el.log` six seconds into a stuck stage.

## 5. Open

1. **The leader's stall** (PHASE_D 16.4). 7-10 s before the leader's own-block `newPayload` is
   answered, about once a leg at a tenure change; a TC follows. Survivable now; it costs ~10 s, a
   few percent of a round. Ruled out: persistence backpressure (metric count 0 on every node), a
   slow branch of the launcher's engine loop (`took_ms=0`), the loop unpolled (the tick never came
   late). In the loop147 dump the tree thread idled in `wait_for_event` and every tokio worker was
   parked, which suggests the request had not reached the tree's channel. Next probe: a timestamped log on both
   sides of `ConsensusEngineHandle::new_payload`'s send in `own_block_by_header`
   (`bin/n42/src/payload_serve.rs`) and on the tree side when `BeaconEngineMessage::NewPayload` is
   received (reth's `EngineApiTreeHandler` is upstream: patch the checkout under
   `~/.cargo/git/checkouts/reth-*/6dec1b9` for a diagnostic build, or vendor `crates/engine/tree`).
   Then run until a stall and read the two timestamps.
2. **A residual lost commit on an empty block** (loop155 A2, node0, 12:46:31-34). Block 288 had no
   transactions; its Decide came 1 ms before its body; the engine inserted it at 31.424, but no
   forkchoice made it canonical until block 289's commit at 34.525; the engine's service loop saw
   no message for 3.09 s in between, and the validator logged neither a SYNCING wait nor a refusal.
   So the repeat of 4e57e8823 either ran before the executed insert reached the tree or did not run.
   Blocks under 10,000 transactions log nothing on the import path (`txs >= 10_000` guards in
   `crates/n42/h2-execution/src/driver.rs`), which is why the order cannot be read. Next: log
   every commit (hash, cause: direct / pending / ahead-repeat, answer) and every `ImportReport::Done`
   regardless of size, then look at the flood's tail where empty blocks alternate with full ones.
3. **The proposal retry spins.** "the parent is still importing; proposing once it lands" repeats
   every ~13 ms until the parent lands at a tenure change (`crates/n42/h2-node/src/service.rs`). Harmless
   but noisy; wait on the import's landing instead.
4. **Windows 2-3.** With every block full, they now fall off by cycle time (0.70-0.81 s against
   0.52-0.55 s in window 1) and in window 3 by the flood's tail. `windows.txt` has the per-window
   memory table; the late-window memory phase of phase M is the usual suspect.
5. **Cross-client.** gov5 has not implemented deferred execution
   (`/data/blockchain/wr-logs/NOTE-deferred-execution-for-gov5.md`); `n42_fleet7.json` and the
   devnet stay ungated. Known gaps of the check (PHASE_D 14): state-dependent gas (EIP-8037), a
   recipient spending in-block received value, the provisional bundle clone per block.

## 6. Where the next TPS is (the thinking)

- **Supply is the wall on this box.** Each of the seven nodes verifies every Ed25519 transaction at
  ~20 µs on its 16 cores beside its execution; the ingest reads 250-300k tx/s. The batch size does
  not move it (loop142): what is left per signature is R's decompression, not batchable. The one
  local lever is one keccak a transaction in the ingest; past that, a box per node.
- **The chain holds 350 ms pacing, not 300.** At 300 the leader outruns the stragglers (loop141).
  The follower's post-check import (~265 ms) is what would let 300 hold.
- **Reliability is worth more than a cut now.** The stall costs ~10 s a leg, a lost commit on a
  follower can cost a whole window (the flood waits for every node's answer), and until this
  stretch a TC could cost the leg. Items 5.1 and 5.2 above come before any performance round.
- **Recommended order**: (1) instrument and fix the stall; (2) the empty-block lost commit;
  (3) three legs of the adopted configuration to set a clean baseline and, if they hold, retry the
  records; (4) one keccak per transaction in the ingest; (5) the follower's post-check import at
  pacing 300.

## 7. Hazards

- Never compile while a leg runs; use `target/deferred` so a running launcher's binary is not
  replaced.
- `pgrep -f <launcher name>` or `pkill -f` inside a shell command matches that shell itself and kills
  it (exit 144, hit twice on 2026-09-12). Use a character class: `pgrep -f 'run-loop15[5].sh'`.
- `node*/el.log` and `node*/v.log` are overwritten by the next leg's `up --fresh`; the launchers
  copy them into the bench directory, but a leg analysed mid-run must be copied first.
- The box is shared (gov5 fleet, DATC, eth-el runs): check claims and foreign processes before a
  leg; the huge-page pool at leg start decides whether window 1 is comparable.
