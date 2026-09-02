# The all-Rust seven-node fleet on the native chain

gov5 runs the flagship native chain, `mainnet_qmdb_staggered` (chain 94), on
seven HotStuff nodes. This is the same fleet shape built entirely from this
repo: seven independent members, each an `n42` execution layer driven by its own
`h2_validator` over the Engine API, wired into a static full mesh with no
discovery and no devp2p.

`scripts/fleet7.sh` runs it; `scripts/fleet7-env.sh` holds every launch argument
and is the only place any of them is written down. That separation is gov5's
lesson, already paid for once in `scripts/qs/qs-env.sh`: their Windows fleet
declared its environment inside the deploy script, a rolling restart driven by a
*different* script silently dropped one lever, and the whole transaction index
went with it.

```bash
cargo build --release -p n42 -p n42-h2-node --bins --examples
scripts/fleet7.sh up --fresh     # seven nodes from genesis
scripts/fleet7.sh status         # heights and head hashes, and whether they agree
scripts/fleet7.sh watch 300      # a measured window: blocks, memory, disk, loopback
scripts/fleet7.sh roll 3         # stop and restart one node; check it rejoins
scripts/fleet7.sh down           # SIGTERM, and wait
```

Data lives under `/data/blockchain/rust-fleet7` — deliberately not `/tmp`, which
on this host is a 69 GB tmpfs, where a datadir *is* resident memory.

## What the chain is

`crates/chainspec/res/genesis/n42_fleet7.json`: seven validators whose BLS keys
are derived from the seed `n42-fleet7-validator`, and chain 94's consensus
parameters — 3 s period, 6 s base timeout rising to 30 s, `epochLength` 200,
`fastPropose`, and gov5's own committee pool (seed `0x03c75de6…`, 200,000 slots,
512 signers per block, ramping over 1,000,000 blocks). The libp2p network keys
are gov5's fleet keys, so the seven peer ids are byte-identical to `QS_PEERIDS`
in `scripts/qs/qs-env.sh`.

What is deliberately *not* copied from chain 94 is its fork schedule. Chain 94
began at timestamp 1678174066 — 7 March 2023 — and its forks are staggered
across its life: Shanghai at **block 305,000**, Cancun at **block 3,935,000**,
then Pectra, Osaka/EOF/Fusaka, mobileAnchor and Glamsterdam by timestamp. A
fresh chain cannot replay that. It also must not try: gov5 pays its block reward
**as withdrawals**, and withdrawals do not exist before Shanghai, so a fresh
fleet carrying `shanghaiBlock: 305000` would run its first three hundred
thousand blocks unable to pay anyone. The fleet genesis activates everything at
block 0, as the devnet genesis it descends from does.

Chain 94's real schedule, for when the fleet is pointed at it
(`crates/chainspec/res/genesis/gov5/mainnet_qmdb_staggered.json`, genesis hash
`0xa2d2ff5d…`):

| fork | activation |
| --- | --- |
| homestead … arrowGlacier, beijing | block 0 |
| shanghai | block 305,000 |
| cancun | block 3,935,000 |
| pectra | 1746612311 (2025-05-07) |
| osaka, eof, fusaka | 1765238400 (2025-12-09) |
| mobileAnchor | 1784372000 (2026-07-18) |
| glamsterdam | 1798761600 (2027-01-01) |

Note that changing the `hotstuff` block does **not** change the genesis hash —
it lives in `config`, which the header does not cover. Two chains with different
committee pools would therefore share a fork digest and meet on the wire, and
diverge only when one rejected the other's `parentBeaconRoot`.

## What was wrong, and what it cost

Three defects surfaced only at seven nodes. None of them was visible on the
four-node fleet in `scripts/devnet-fleet.sh`, and the third was invisible even
here in the sense that the chain kept producing blocks throughout.

### The validator drew a new identity at every start

`H2V4Transport::new` generates a fresh ed25519 keypair. A fleet wired with
static multiaddrs naming a peer id cannot survive that: a restarted node comes
back as a stranger and its peers' dial entries point at an identity that no
longer exists. `h2_validator` now takes `--node-key`, and without it keeps a hex
secp256k1 secret in `<datadir>/network-key` — gov5's `network-keys`, in gov5's
format, so `h2_keygen --libp2p-peer-id` reads either.

### A block cost the size of the world state to persist

`on_canonical` serialised the **entire QMDB forest** with bincode and wrote it,
on every head move. On this devnet that is twenty kilobytes a block and looks
like nothing. On chain 94 it is tens of gigabytes every three seconds, which is
not a slow node but an impossible one — and it was the hard blocker under "then
climb to chain 94".

`forest.bin` is now a checkpoint and `forest.log` holds the deltas since it.
QMDB only ever appends at a cursor and deactivates slots below it, so a block's
whole effect is a contiguous run of new slots plus the few older ones it
touched; `QmdbForest::delta_since` reports exactly that. The checkpoint is
rewritten only once the log has grown past it, which bounds the log at twice the
state and leaves the amortised per-block cost at the size of the block.

Measured on the fleet: `forest.bin` frozen at 1,432 bytes while `forest.log`
grew about **990 bytes per block**. Under the old scheme the same file had
reached 19,707 bytes by block 35 — and was rewritten in full every block.

The subtle part is the revert. Reverting a block rewinds the append cursor, and
the block applied in its place appends over the very slots the reverted one
held. Those slots are never *deactivated*; they are abandoned and reused, so
nothing names them but the cursor's low-water mark. The first version of the
delta tracked only deactivations and produced a tree that differed from the
snapshot at exactly one slot after a branch switch — which
`a_delta_taken_after_a_branch_switch_carries_the_revert` now pins.

### One missed body spun the fleet

A member that misses a proposal's body asks every connected peer for it. The
answer comes back, executing the block still fails — what is missing is the
block's *parent*, not the block — and the hash leaves the awaiting set, so the
very next pass asks all six peers again. Nothing paced it and nothing gave up.

On a seven-node fleet, where the mesh is still forming during the first views,
one member hit this at view 2 and stayed there. Over six minutes it:

- re-imported **one block 2,531 times** into its execution layer,
- wrote **1.36 GB of log** (636 MB from the execution layer, 727 MB from the
  validator), where the same node after the fix wrote 84 KB and 108 KB in four
  minutes,
- and filled every peer's inbound request-response streams to capacity
  (`libp2p_request_response: Dropping inbound stream because we are at
  capacity`).

Meanwhile the fleet produced blocks at the target rate and all seven agreed on
every head hash. That is what made it worth finding rather than obvious, and it
is why `scripts/fleet7.sh watch` reports bytes written and loopback traffic and
not only block rate: a fleet can be wrong in every way the brief cares about
while looking perfectly healthy.

`BODY_REQUEST_INTERVAL` now paces the broadcast, and the `PayloadMissing` event
goes out on the same schedule — a caller that logs every pass is how the spin
was found, and a gigabyte of log is not a better signal than one line.

## What it measures

`scripts/fleet7.sh watch 300`, on an otherwise quiet 256-core, 136 GB host,
seven nodes from genesis, each pinned to eight cores. Both columns run the same
reth arguments; "before" is that fleet as it stood before the three fixes above
and the allocator tuning below, so the difference is those four things and
nothing else.

| | before | after |
| --- | ---: | ---: |
| resident memory, seven nodes | 3,044 MB | **1,235 MB** |
| — per execution layer | 370 MB | 155 MB |
| — per validator | 66 MB | 22 MB |
| threads | 623 | 651 |
| written to disk | 0.63 MB/block | **0.45 MB/block** |
| loopback traffic | — | 0.25 MB/block |
| logs written in five minutes | 1.36 GB (one stuck node) | 3.0 MB (whole fleet) |
| block rate | 0.330 /s | 0.330 /s (target 0.333) |
| agreement | seven heads, one hash | seven heads, one hash |

The genesis then took gov5's real committee pool in place of the devnet's —
200,000 slots and 512 signers a block instead of 4,096 and 64, a forty-nine-fold
increase. It is the only thing that changed between these two runs:

| | 4,096 slots / 64 signers | 200,000 / 512 |
| --- | ---: | ---: |
| resident memory, seven nodes | 1,235 MB | 1,367 MB |
| per execution layer | 155 MB | 167 MB |
| per validator | 22 MB | 28 MB |
| block rate, disk, loopback | unchanged | unchanged |

About 19 MB a node, which is what the pool is: `SimulatedCommitteePool` keeps
the slots as a `Vec<U256>` of scalars — 6.4 MB at 200,000 — and derives BLS keys
from them on demand, in both the execution layer and the validator. Building it
costs 200,000 EIP-2333 derivations at startup, parallel across the node's cores;
the execution layer still had its auth port open a hundred milliseconds after
its first log line.

And the arguments themselves, against seven nodes started with nothing but the
chain, the ports, and devp2p off — reth's defaults, jemalloc's defaults, no CPU
binding:

| | stock | tuned |
| --- | ---: | ---: |
| resident memory, seven nodes | **29,610 MB** | **1,367 MB** |
| per node | 4,230 MB | 195 MB |
| threads | 11,060 | 651 |
| written to disk | 0.45 MB/block | 0.45 MB/block |
| loopback traffic | 0.25 MB/block | 0.25 MB/block |
| block rate | 0.330 /s | 0.330 /s |
| agreement | seven heads, one hash | seven heads, one hash |

Twenty-two times the memory and seventeen times the threads, for a fleet that
produced exactly the same chain at exactly the same rate. The two middle rows
are the honest part: disk and loopback did *not* move, because those savings
came from the three fixes above and not from any argument. Levers and defects
are separate accounts, and mixing them is how a tuning guide ends up taking
credit for a bug fix.

### Under load

Everything above is empty blocks, which measures the fleet's floor and none of
the costs that scale with transactions — and on gov5's fleet that is where the
dominant cost lived. `F7_TXGEN_RATE` offers the fleet a sustained rate from one
sender per funded account, each pointed at a different member's RPC.

| | empty | 200 tx/s offered |
| --- | ---: | ---: |
| transactions sealed | 0 | **59,036** of 60,004 offered, **0 rejected** |
| throughput | — | **196.8 tps**, 602.4 a block |
| block rate | 0.330 /s | 0.327 /s |
| resident memory, seven nodes | 1,367 MB | 1,703 MB |
| written to disk | 0.45 MB/block | 1.28 MB/block |
| loopback traffic | 0.25 MB/block | 11.26 MB/block |
| agreement | seven heads, one hash | seven heads, one hash |

That is an offered rate, not a ceiling: the fleet took all of it, refused none
of it, and held its block interval. The costs it does show are the ones that
should scale — about 48 MB a node for the pool and the execution, 1.4 KB of disk
across seven nodes per transaction, and a block body that now has six hundred
transactions in it to gossip. The QMDB root of a 602-transaction block still
took 53 µs, which is the binary tree earning its place: the work is the append,
not a trie walk over everything the block touched.

The thread count going *up* is jemalloc's `background_thread:true` earning its
place: the purge that returns dirty pages to the operating system runs on its
own thread rather than in the allocating one, which is most of why the row above
it halved.

The block rate is the point of the last two rows: none of this cost the fleet
anything. Ninety-nine blocks in three hundred seconds is the 3 s period, and all
seven members carry the same head hash at every height.

## What the levers are, and what they are worth

Everything below is per node, and there are seven of them. The figures come from
`scripts/fleet7.sh watch 300` on an otherwise quiet 256-core, 136 GB host.

### CPU affinity is the one lever that resizes every pool at once

tokio, rayon and reth all size their thread pools from `available_parallelism`,
which on Linux reads the CPU affinity mask. Pinning a node to eight cores caps
its tokio workers, its rayon pool, and reth's prewarming and proof workers
together, with no flag for any of them. Unpinned on this host a single execution
layer asks for hundreds of threads and seven ask for thousands.

### reth's defaults are sized for one archive node on a dedicated host

The expensive ones, all per node: `--engine.cross-block-cache-size` defaults to
**4096 MB**; `--engine.prewarming-threads` to one per core; `--engine.storage-
worker-count` and `--engine.account-worker-count` to twice that; the four
transaction sub-pools to 20 MB each; the RPC state cache to 5,000 blocks. None
of it is serving anything on a fleet whose members talk only to their own
validator.

`--log.file.max-files 0` is worth calling out separately: reth writes a
debug-level log file by default, 200 MB × 5 per node, and at seven nodes that
was the largest single writer on the box with none of it chain data.

### jemalloc's defaults are sized the same way

The execution layer's resident set was 288 MB of anonymous memory of which
**258 MB was transparent huge pages**: an arena per few cores, each with its own
cache of dirty pages, every one rounded up to two megabytes. `MALLOC_CONF` in
`fleet7-env.sh` cuts that to two arenas, decays dirty pages in two seconds, and
turns huge pages off.

`abort_conf:true` is in that string on purpose, and earned its place
immediately: the obvious name for the variable, `_RJEM_MALLOC_CONF`, is the one
tikv-jemallocator uses when it keeps its prefix, and this build does not. Set
under that name it changed nothing and said nothing.

### devp2p is off, not merely undiscovered

Every block a node will ever see arrives over the Engine API from its own
validator, which got it from the consensus gossip. A devp2p mesh between the
seven would carry the same blocks a second time and, worse, offer reth a
backfill path — and backfill computes Merkle-Patricia roots in its own stage,
which on a QMDB chain rejects every header. The execution layers run with
`peers=0`.

### What is *not* a lever

The GossipSub parameters. `crates/n42/h2-net/src/config.rs` matches gov5's
router value for value — mesh degree, heartbeat, message-cache history, and a
30 s `seenMessagesTTL` rather than libp2p's two minutes — and asserts it in
tests, because a mixed fleet whose members disagree about them behaves
inconsistently under load. Communication is saved by not sending things twice,
not by retuning the mesh.

## Restarting one member

`scripts/fleet7.sh roll <i>` stops a node and starts it again on its own
datadirs. It is the only path that exercises what a restart depends on — the
consensus vote log, the libp2p identity, and the delta log replaying onto its
checkpoint — and a fleet whose members cannot be restarted one at a time cannot
be upgraded, moved, or repaired without stopping the chain.

The forest comes back from the checkpoint plus the log, at the block the
database is at, and the member rejoins:

```
node 3: at height 123, stopping
restored the QMDB forest block=123 head_hash=0x7817adf0… log_bytes=121111
QMDB state ready block=123 head_hash=0x7817adf0…
node 3: height 125 (fleet 125), commits since restart 1
node 3: 0 error lines in the execution layer log
```

A hundred and twenty-one kilobytes is the whole of what persisting a hundred and
twenty-three blocks cost — 985 bytes a block, against a full serialisation of
the tree each time.

The first roll attempted here failed, and instructively. The node restarted
cleanly, restored its forest, connected to all six peers, and then rejected
every block from 136 on with `parent beacon root … is not the parent's committee
evidence`, retrying one block forever behind reth's invalid-header cache. The
cause was not in the node: the genesis file had been edited between `up` and
`roll`, so the restarted member was computing committee evidence from a
different pool than its peers. It is a correct rejection — and a demonstration
of the hazard noted above, that two chains differing only in `config` share a
genesis hash and meet on the wire. `fleet7.sh` now records the genesis at `up`
and refuses to roll against a changed one, with that explanation.

## Is it stable

Ten hours eleven minutes unattended, from genesis to block 12,059, seven members
the whole way:

| | |
| --- | --- |
| agreement | one head hash across all seven, at every check |
| execution layers | **0 ERROR, 0 WARN** lines, in ten hours |
| consensus | 12,060 commits a node; **1–2 view timeouts**, 0.016% of views |
| epochs | 60 boundaries crossed at `epochLength` 200 |
| QMDB checkpoint rotation | happened independently on all seven |
| block rate | 0.3287 /s against a 0.3333 target, 98.6% |
| spread | seven nodes within 1 MB of resident memory of each other |

The checkpoint rotation is worth naming: `forest.bin` went from 1,432 bytes to
5.98 MB and the log started again, on every node, which until then had only ever
happened in a unit test.

**Memory plateaus rather than climbing.** It grew from 167 MB an execution layer
to 269 MB over those ten hours, which looked like a leak until it was broken
down: 236 MB of it is anonymous heap and 8 MB file-backed, so it is not mapped
database pages, and `AnonHugePages` is 0, so `thp:never` held. The size is what
`--engine.cross-block-cache-size 128` and the RPC caches come to when they fill,
and sampling every two minutes afterwards shows 268–271 MB across eighty blocks
— flat, inside 3 MB. Bounded, not growing.

### Losing members

HotStuff-2 with seven tolerates two. Taking exactly two away is the boundary,
not a comfortable margin, so that is what was taken:

| | five members | seven again |
| --- | ---: | ---: |
| block rate | 0.033 /s | 0.280 /s and rising |
| agreement | one hash across the five | one hash across the seven |
| forks | none | none |

It survives correctly and it costs a lot: **about thirty seconds a block**, which
is `maxTimeout`. Two of every seven views are led by a member that is not there,
and those views can only end by timing out; the timeout backs off toward its
maximum and stays there while the absences continue. It decays again once they
return — the recovery to 0.280 /s and climbing is that decay — so this is a
liveness cost, not a wedge. But it is worth knowing that two members down slows
a fleet tenfold rather than by two sevenths.

### An ungraceful kill

`SIGKILL` to both processes of one node, no warning, mid-block. The convention
in `fleet7-env.sh` is never to do this — it is how MDBX spills get truncated —
which is precisely why it is worth knowing what happens when something else
does it.

```
before: fleet 12125, node 4 12125
node 4 SIGKILLed (validator and execution layer, no warning)
restored the QMDB forest block=12120 head_hash=0x20a49e3e… log_bytes=1358974
fleet 12164, node 4 12164, one hash across all seven, 0 errors
```

The database came back at 12120, five blocks behind where the node was killed,
because those five were still in reth's in-memory buffer. The delta log ran
*past* that point and the replay stopped at the database's head rather than at
the log's end — the one branch in `replay_delta_log` that exists for exactly
this, proving itself under a real crash rather than a truncated file in a test.
The node then pulled the forty-four blocks it had missed and rejoined on its
own.

### What is still untested

The longest run under transaction load is five minutes, not ten hours. No member
has been away for hours and come back on this fleet (the four-node fleet has
that measurement, `docs/N42_26_PORT.md`). And the memory plateau rests on eighty
blocks of flat sampling after a ten-hour climb, which is good evidence and not
proof.

## Throughput

`scripts/fleet7-bench.sh` runs a round; `scripts/fleet7-measure.py` measures a
window; `examples/tx_flood` supplies it; `scripts/fleet7-profile.sh` profiles a
node between windows. The structure and most of the rules come from gov5's
`docs/QS_TPS_BENCHMARK.md`, which paid for each of them with a wasted round —
a fresh sender offset every round, fresh datadirs, base-fee decay before the
flood, every window reported, occupancy read beside TPS, window 1 treated as
the measurement, and profiles pulled only between windows.

The bench chain is its own: `n42_fleet7_bench.json` differs from the fleet
genesis in two things that cannot be passed as flags, because they are chain
parameters — a one-second period rather than three, and a 480M genesis gas
limit. One second is this client's floor. The proposer's pacing and the Engine
API timestamp are both whole seconds, so gov5's 0.496 s cycle is not reachable
here without a millisecond path.

`tx_flood` derives its senders exactly as gov5's `cmd/txflood` does —
`keccak256("n42-txflood-sender-v1" ‖ be64(offset+i+1))` — so a round against
either client draws on the identical accounts, and the supply side of a
comparison is provably the same thing rather than two harnesses that resemble
each other.

### Four things the harness found before it produced a number

**The gossip size cap was hardcoded.** `MAX_GOSSIP_SIZE` was `1 << 20` with a
comment noting that gov5 overrides it with `N42_MAX_GOSSIP_MB` — and no way to.
It is a block-size cap that presents as a gas cap: at ~107 bytes a transfer it
holds a block to about 8,500 transactions whatever the gas ceiling says, and a
full 480M block needs about 2.44 MB. Worse, there was no producer-side packing
budget at all, only a receiver-side check, so raising the gas limit past the cap
would have built blocks the fleet could not carry. It now reads gov5's variable,
by gov5's name — which matters beyond throughput: two clients on one chain that
disagree about this do not merely differ in speed, the one with the smaller cap
refuses the other's blocks and drops out.

**A pidfile named the wrong process.** `setsid cmd & echo $!` records setsid's
pid when setsid forks and the node's when it execs, and which one you get
depends on the shell that called it. One node's pidfile was off by one, so
`f7_stop` looked up a pid that no longer existed, concluded the node was not
running, and `down` reported "fleet stopped" with a node still holding its
ports. Three validators survived that way and then dialled the *next* fleet from
a different chain: "peer is on a different chain; it will disconnect", and a
chain stuck at view 1 with nothing in the new fleet's own logs to explain it.
Nodes are now started through `f7_spawn`, where the shell writes its own pid and
then execs, and `down` verifies against every port the fleet binds rather than
against the pidfiles it just used.

**reth refuses a transaction whose fee exceeds 1 ETH.** `--rpc.txfeecap`
defaults to 1.0, and this tier's price has to be high enough that the base fee
cannot climb past it inside a window — 21,000 gas at 100,000 gwei is 2.1 ETH.
The whole round was refused during funding, and what that looks like from the
outside is a chain that will not accept transactions. It is on the list of
things gov5 warns present as mass rejection rather than as an error, and it took
one line of diagnostics to see: the flood now reports the first rejection
message rather than only counting rejections.

**Release binaries carry no symbols.** `[profile.release]` sets
`strip = "symbols"`, so `perf report` against a release node spends minutes
producing an empty file. Profiled rounds build with the `profiling` profile,
which exists for exactly this.

### Round 1

| window | tps | txs | blocks | cycle | occupancy | full(>=95%) |
|---|---:|---:|---:|---:|---:|---:|
| win1 | **13,100** | 393,007 | 22 | 1.364 s | 78.2% | 14/22 |

**This round measured the harness, not the chain.** The supply was 2,000 senders
x 200 transactions = 400,000, and window 1 sealed 393,007 of them in thirty
seconds — 98% of everything the flood had, against a theoretical ceiling of
13,333. gov5 hit the same wall at ~28k TPS on their rig and said so; the number
above is a floor for this fleet and nothing more.

It also exposed a defect in the flood worth more than the number: under
sustained oversupply the pool fills and starts refusing, and the first version
skipped the refused nonce and carried on — which leaves a permanent hole,
because promotion needs an account's exact next nonce. gov5 measured that as
118,530 queued with zero pending and near-empty blocks. The flood now retries in
place and only advances a nonce on acceptance, which has the second virtue of
pacing itself to whatever the chain is actually taking, with no rate to guess.

### Rounds 2 and 3

Supply raised to 6,000 senders x 500 transactions — three million, so the flood
is no longer the limit:

| round | window | tps | txs | blocks | cycle | occupancy | full(>=95%) |
|---|---|---:|---:|---:|---:|---:|---:|
| 2 | win1 | **15,999** | 479,997 | 21 | 1.429 s | **100.0%** | **21/21** |
| 3 | win1 | **15,999** | 479,997 | 21 | 1.429 s | **100.0%** | **21/21** |
| 3 | win2 | 10,916 | 327,476 | 24 | 1.250 s | 59.7% | 12/24 |

Window 1 reproduced to the transaction across two rounds on two binaries, which
is worth more than either number alone: on gov5's rig the within-binary spread
is wider than the between-binary difference, and a benchmark that cannot repeat
itself cannot attribute anything.

Window 2 is a supply shortfall, not the fee oscillation it superficially
resembles — `full ~= blocks/2` is that signature, but the base fee here reached
1.5 gwei against a 100,000 gwei cap, nowhere near binding. It is the flood:
each of its 64 threads walks its senders *sequentially*, so only 64 nonce
sequences are ever in flight and one full block can drain what they have
offered. Interleaving the senders within a thread is the fix; until then, and
per gov5's rule, window 1 is the measurement.

Twenty-one blocks, every one full, 22,857 transactions each — which is exactly
480,000,000 / 21,000. The chain is at its gas ceiling and nothing else: not the
pool, not the supply, not the fee market. Against gov5 at the same tier —
22,089 TPS, 22,857 transactions a block, 0.98 s — the block contents are
identical and the entire difference is the cycle: **1.429 s against 0.98 s**.

(Round 2's later windows were lost to a defect in the harness rather than the
chain: `fleet7-profile.sh` ran `perf report` inline between windows, and against
a 2.3 GB binary with full DWARF that takes minutes, so it delayed the very
windows it was meant not to disturb. Recording and reporting are now separate —
`--report` reads a recording afterwards. The cycle analysis below does not
depend on those windows.)

### Where a block's second goes

The round's logs answer more than its TPS did. Node 0's execution layer, over
the whole run, split by how full the block was:

| block | commit -> next payload | payload -> added to canonical |
| --- | ---: | ---: |
| full (>400M gas, ~22,000 transfers) | 1,295 ms | **82.7 ms** |
| partial | 1,164 ms | 37.9 ms |
| empty | 1,014 ms | 0.8 ms |

A follower executes a full 480M-gas block, computes its state root and files it
in **83 milliseconds** — 3.8 µs a transfer. The canonical commit that follows is
another 12 ms. So the execution layer accounts for about 95 ms of a 1.36 s
cycle, and the pacing wait accounts for 1.0 s of it by construction.

What is left is the interesting part: a full block's cycle runs **281 ms longer**
than an empty one's, and only 82 ms of that is this node's own import. The rest
happens somewhere outside it — the leader building the same 22,000 transactions,
the consensus round, and a ~2.5 MB block body crossing the gossip mesh. Round 2
profiles a node under sustained load to say which.

Round 3 instrumented both ends of the block body — `published block body` on the
leader, `block body received` on each follower, timestamped — so the last term
stopped being a residual. It was worth doing, because the residual was wrong:

| | estimated by subtraction | measured |
| --- | ---: | ---: |
| body reaching the followers | ~173 ms | **27.8 ms** (median, 1.71 MB body; p90 32.4 ms) |

With that measured, the leader's whole interval measures too, and the account
closes:

| phase (full block) | measured |
| --- | ---: |
| leader: its own commit -> the next body on the wire | **1,260 ms** |
| body on the wire -> follower has it | **27.8 ms** |
| follower: proposal seen -> vote sent | **111.3 ms** (p90) |
| vote -> Decide | **23.2 ms** (p90) |
| **total** | **1,422 ms** |

against a measured cycle of **1,429 ms** — accounted to within 7 ms, with
nothing left over. The same leader interval on an *empty* block is 1,013 ms, so
**~1,013 ms of a full block's cycle is the one-second pacing floor and ~247 ms
is the work of building and sealing it** (of which the payload build itself is
122 ms).

### Two transports that are not the problem

A block crosses the wire twice per hop on this fleet: once as the gossip body
between validators, and once as JSON over the Engine API between each validator
and its own execution layer. Both are obvious candidates for "make the transport
faster" — UDP instead of TCP, shared memory instead of HTTP — and both were
measured before being believed (`examples/gossip_cost`, on a real
22,857-transaction block):

| | size | cost |
| --- | ---: | ---: |
| gossip wire form (RLP + snappy, encode and decode) | 1.71 MB | **4.03 ms** |
| Engine API (JSON, transactions hex-encoded) | **5.32 MB** — twice the RLP | **4.33 ms** |

The JSON really does double the block, and it really is paid twice per block per
node. It is also four milliseconds. Fusing the validator into the execution
layer to share memory would save that; replacing gossipsub's TCP with UDP would
save some part of the 27.8 ms the body takes to arrive, most of which is
propagation rather than encoding. Neither is a lever against a cycle where the
pacing floor alone is a thousand.

What the 122 ms build and the 83 ms import are, then, is execution: 22,857
transfers at 3.6 µs each, signature recovery included. That is the EVM doing the
work, not a serialiser.

### Round 4: not respecting the block interval

The point of a throughput round is the ceiling, not a block interval, so the
bench tier now paces in milliseconds and overrides the chain's period —
`--block-interval-ms`, which is what gov5 calls the same knob. Their production
chainspecs say `period: 3` exactly as this fleet's does; the millisecond flag is
how they benchmark at 1000 ms and now 500.

Under a second the meaning of a timestamp changes, so it is gated and it warns.
A header's timestamp is a whole second that must strictly exceed its parent's,
so more than one block a second cannot be stamped from the wall clock at all;
the block takes `parent + 1` instead and the chain's clock runs ahead of real
time. That is fine while measuring throughput and wrong for anything else — the
stamps stop describing when blocks happened, and gov5 drops a gossiped block
whose timestamp is ahead of its own clock, so such a fleet cannot be mixed with
one.

| pacing | tps | blocks | cycle | occupancy | full(>=95%) |
|---|---:|---:|---:|---:|---:|
| 1000 ms | 15,999 | 21 | 1.429 s | 100.0% | 21/21 |
| **250 ms** | **26,551** | 51 | **0.588 s** | 68.3% | 32/51 |

**+66%**, and it lands where the analysis said it would: the pacing floor was
the limit, and removing it moved the number by two thirds while nothing else
changed. gov5's 32,381 TPS at 0.496 s is now 22% away rather than a factor of
two.

Occupancy falling to 68% is the next limit announcing itself, and it is the
harness again. The chain now asks for a full block every 588 ms and the flood
cannot fill one: each of its threads walked its senders *sequentially*, so only
`--conc` nonce sequences were ever in flight, and one full block of this tier
takes more transactions than 64 senders offer. Window 2 of the same round went
to zero — 72 empty blocks — with `txpool is full` in the flood's log, which is
the same defect from the other side: every sender in a thread is at the same
point in its own sequence, so they fill the pool together and then back off
together. The flood now rotates through all of a thread's senders a batch at a
time.

### Round 5: the fix that made it worse, and what that found

Interleaving the flood's senders fixed the supply — occupancy went from 68% to
95–100%, blocks filled again — and the throughput fell by more than half:

| round | supply shape | tps | cycle | occupancy |
|---|---|---:|---:|---:|
| 4 | 64 senders in flight | 26,551 | 0.588 s | 68.3% |
| 5 | 6,000 senders in flight | **10,165** | **2.143 s** | 95.3% |
| 5 (win2) | — | 7,619 | 3.000 s | 100.0% |

The obvious reading is that many distinct senders make a block expensive — more
accounts to touch, more signatures the recovery cache misses. The logs said no:

| | round 3 (64 senders) | round 5 (6,000 senders) |
| --- | ---: | ---: |
| follower import, full block | 82.7 ms | **66.8 ms** |
| leader build, full block | 122.5 ms | **126.8 ms** |

Execution did not move at all, and the import got slightly *faster*. So the
extra 1.8 seconds a block was not in the block. Measuring the phases again found
it in their tails:

| phase | median | p90 | p99 |
| --- | ---: | ---: | ---: |
| leader: commit -> body published | 518 ms | **6,262 ms** | — |
| body publish -> follower has it | 31.9 ms | **2,746 ms** | **14,619 ms** |
| import barrier | 1.3 ms | 92.8 ms | — |
| vote -> Decide | 9.5 ms | 185.8 ms | — |

Every median is healthy. The tails are seconds — one body took 19 — and a mean
cycle is made of tails. Something was stopping the node for whole seconds at a
time, which is the signature of the consensus loop being blocked rather than of
any per-block cost.

It was: `forward_inbound_transactions` handed each gossiped transaction to the
execution layer as its own `eth_sendRawTransaction` round trip, sequentially,
inside the service loop — and that loop polls the libp2p swarm exactly once per
iteration. A gossip batch carries up to 256 transactions and several can arrive
per step, so a few thousand sequential round trips is a few seconds during which
no consensus message and no block body is read at all. Round 4 escaped it
because 64 senders in lockstep produced far fewer distinct transactions to
forward; the defect was there the whole time and the supply fix is what exposed
it.

`ExecutionLayer::send_raw_transactions` now takes the batch, and the JSON-RPC
client sends it as one request. The trait's default implementation is still the
sequential loop, so an execution layer with nothing better is unaffected.

This is worth stating plainly as a method: the first explanation was wrong, and
it was wrong in the direction of blaming the chain for a defect in the harness's
own neighbour. Two measurements — execution unchanged, tails enormous — cost
ten minutes and pointed at the actual line of code.

### Rounds 6 and 7: one fix that did nothing, one that did

Both changes came out of round 5's tails, both are mechanically confirmed, and
only one of them moved throughput. Same tier, same 6,000-sender supply, same
250 ms pacing throughout.

**Round 6 — the batched forwarding.** `send_raw_transactions` in one JSON-RPC
request instead of one round trip each:

| | round 5 | round 6 |
| --- | ---: | ---: |
| win1 / win2 / win3 tps | 10,165 / 7,619 / 7,609 | 10,123 / 7,619 / 7,278 |
| body arrival p90 | 2,746 ms | **1,526 ms** |
| body arrival p99 | 14,619 ms | **8,441 ms** |

Throughput did not move — the three windows match window for window. Claimed as
a latency result only, which is the third time in this document that a
confirmed cost came out and TPS stayed where it was, and the same pattern gov5
reports across three of their own rounds.

**Round 7 — draining the transport.** The service loop took exactly one
transport event per iteration while spending a hundred milliseconds or more per
iteration awaiting the execution layer, so a node read its mesh at the rate of
its own block cycle and block bodies queued behind transaction gossip. It now
handles everything already queued, bounded at 256:

| | round 6 | round 7 |
| --- | ---: | ---: |
| win1 tps | 10,123 (94.9%) | **11,428** (100.0%, 15/15 full) |
| win2 tps | 7,619 (100.0%) | **13,714** (100.0%, 18/18 full) |
| win3 tps | 7,278 (95.5%) | 4,680 (25.6%, supply gone) |
| **transactions sealed, all three windows** | **750,622** | **894,681** |
| body arrival median (sampled after win1) | 379.8 ms | **41.5 ms** |
| body arrival p90 (same sample) | 1,526 ms | **481.7 ms** |
| body arrival p99 (same sample) | 8,441 ms | **1,911 ms** |

Nine times better at the median body arrival, four times at the p99, and 19%
more transactions through the chain in the same ninety seconds against the same
supply — which is the comparison to read, since it does not depend on choosing
a window.

The three latency rows are both sampled at the same point, after window 1, and
that has to be said rather than assumed: taken over round 7 *entire* the same
measurement reads median 27.8 ms, p90 571 ms, **p99 9,757 ms** — a better median
and a much worse tail, because window 3 is the fleet running out of supply with
the base fee climbing, and those blocks are in the sample. Round 6's logs cannot
be re-measured the same way to match: `up --fresh` deletes a node's directory,
so the rotation that would have kept them never happens on a fresh round. That
is a gap in the harness, not a result: a round should keep its own evidence.

The shape changed as much as the numbers. Rounds 5 and 6 *degraded* across their
windows (10,165 → 7,619 → 7,609) and round 7 *improved* (11,428 → 13,714): the
starvation compounded, because a loop that reads one event per block cycle falls
further behind the longer it runs. Round 7's third window is the fleet running
out of supply, not slowing down — it had already sealed 120,000 more
transactions than round 6 by then.

A note on a number that was not a finding. Windows reporting a cycle of
"3.000 s" twice in two rounds looked exactly like a fixed timer, and there is a
three-second constant in the file (`CATCH_UP_RETRY`). It was arithmetic: ten
blocks in a thirty-second window. The fleet's catch-up counters were zero
throughout — no pulls, no `BEHIND`, one view timeout across three nodes — so
nothing was retrying anything.

### Round 8: a quantised block interval, and two more harness defects

Supply doubled to 12,000 senders x 500 = six million, so a window could not run
dry. The round produced no windows at all — the measurement died — but its phase
decomposition is the most useful data of the series. Measured at 250 ms pacing
with all the fixes above in place:

| phase (full block) | median | p90 |
| --- | ---: | ---: |
| **leader: commit -> body published** | **871.8 ms** | 4,555 ms |
| leader: payload build | 149.8 ms | 710.6 ms |
| body: published -> received | 35.3 ms | 900 ms |
| follower: import barrier | 1.3 ms | 89.9 ms |
| follower: payload -> canonical | 62.8 ms | 75.6 ms |
| vote -> Decide | 10.6 ms | 552 ms |

The leader's 872 ms is the term to explain: the pacing floor is 250, the build
is 150, importing its own block is 63 and encoding it is 4 — about 470,
leaving 400 unaccounted inside one node.

It was `PROPOSE_RETRY`, a 200 ms constant. When the pacing deadline has not
passed the attributes builder answers `None`, and the loop waits this long
before asking again — so the achieved interval is the pacing **rounded up to a
multiple of the retry**. At gov5's three-second pacing (their
`minProposeDelayMs`, which this matches deliberately) that is invisible. At a
250 ms benchmark pacing it is up to 200 ms on a 250 ms target. The re-ask is now
sized from the pacing — an eighth of it, floored at 10 ms and capped at the old
200 ms — so production settings are unchanged and a benchmark polls at 31 ms.

Two harness defects surfaced with it, both of which cost this round:

**The measurement killed the round it was measuring.** Under a flood the nodes
answer surplus connections with HTTP 429, `fleet7-measure.py` raised on it, and
the round ended after funding with a Python traceback where its windows should
have been. A sample that aborts an expensive round has its priorities backwards;
it now retries with backoff and the bench tier raises `--rpc.max-connections`
from the lean fleet's 32 — a value sized for a fleet whose only client is its
own validator — to 512.

**The round aborted on the word "error".** The funding wait grepped the flood's
log for `error`, which matches the flood's own per-batch diagnostics
("submit failed: error decoding response body" is one refused batch of
thousands). It now matches only a fatal `^Error:`.

### Round 9: two changes at once, and a number that cannot be attributed

Round 9 ran the re-ask fix at 12,000 senders. It should not have: round 8's
windows were lost to the harness defects above, so there is no 12,000-sender
baseline to compare against, and the round therefore changed *two* things at
once against round 7 — the supply doubled and the re-ask changed. What it
produced cannot be attributed to either.

| | round 7 (6,000 senders) | round 9 (12,000, re-ask fixed) |
|---|---:|---:|
| win1 / win2 | 11,428 / 13,714 | 7,586 / 7,619 |
| occupancy | 100% / 100% | 99.6% / 100% |
| cycle | 2.000 s / 1.667 s | 3.000 s / 3.000 s |
| leader: commit -> published (median) | — | 532.6 ms (round 8: 871.8) |
| body arrival p99 | 9,757 ms | **36,958 ms** |

The leader's interval did fall by 339 ms, which is about what removing a 200 ms
quantisation plus noise looks like, and the p90 import barrier fell from 89.9 ms
to 7.0 ms. Those are the shapes the change predicted. They are still not
claimable from this round, because the supply moved too. Round 10 repeats it at
round 7's 6,000 senders, changing one thing.

The other half is a finding in its own right and does not depend on the
confound: **doubling the distinct senders made the fleet slower at full
occupancy**. Every block was full and the cycle went from 1.7-2.0 s to 3.0 s,
with the body's p99 arrival nearly four times worse. Whatever costs scale with
the number of accounts in flight — pool bookkeeping, gossip volume, the sender
cache — they bite between six and twelve thousand, and none of them is
execution: `payload -> canonical` stayed at 67.7 ms.

### Round 10: the change that did nothing, and the reason none of them could

Round 10 repeated round 9's change at round 7's supply, so exactly one thing
differed from a measured baseline. The result is as clean as this rig gets:

| | round 7 | round 10 (re-ask sized from the pacing) |
|---|---:|---:|
| win1 | 11,428 tps, 342,855 txs | **11,428 tps, 342,855 txs** |
| win2 | 13,714 tps, 411,426 txs | **13,714 tps, 411,426 txs** |

Identical to the transaction. The re-ask quantisation is real and the fix is
right in principle, and at this operating point it is **worth nothing**: the
cycle is 1.7–2.0 s against a 250 ms pacing floor, so the leader is never waiting
on the pacing when it becomes ready — the deadline passed long before. A
quantisation of the pacing only bites when the pacing binds.

Two windows reproducing to the transaction across two rounds is itself worth
recording. gov5 notes that on their rig the within-binary spread is wider than
the between-binary difference, which makes single-round attribution impossible;
this one is deterministic enough that a change producing identical output is
information rather than noise.

### The medians were never the number

Round 10's full-block phases, and the cycle they are supposed to add up to:

| phase | median |
| --- | ---: |
| leader: commit -> body published | 396.5 ms |
| body: published -> received | 34.2 ms |
| follower: import barrier | 1.2 ms |
| vote -> Decide | 10.0 ms |
| **sum of medians** | **442 ms** |
| **measured cycle** | **2,000 ms** |

The typical path accounts for a fifth of the cycle. The rest is in the tails,
and a cycle is an arithmetic mean, so the tails *are* the number.

That first reading of the tail was wrong, and the way it was wrong is worth more
than the number. A p90 body arrival of **56,975 ms** looked like the whole
answer. It was an artefact of the instrument: some bodies are delivered to a
node **twice**, about fifty-eight seconds apart — 56 of 1,259 (node, block)
pairs in that round — and counting the second copy as an arrival latency put a
minute on a path that carries 65% of its traffic in under a tenth of a second.
Every body is published exactly once, so the duplicates are deliveries and not
re-publishes. Counting only each node's *first* receipt:

| body arrival | counting every receipt | counting the first |
| --- | ---: | ---: |
| median | 34.2 ms | 30.2 ms |
| p90 | **56,975 ms** | **1,107.7 ms** |
| p99 | 58,857 ms | 57,845 ms |

A factor of fifty-one on the p90. The conclusion above survives it — the sum of
medians is 438 ms against a 2,000 ms cycle either way — but "the body takes a
minute" does not, and it was one paragraph away from being written down as a
finding about gossip.

What remains after the correction is smaller and sharper: 10% of bodies take
over a second, about 1% take fifty-eight, and the *same* fifty-eight seconds
separates the duplicate deliveries. One mechanism plausibly produces both — a
node that stops for a minute and then works through everything queued, arriving
late for what it had not seen and again for what it had. Even empty-block bodies
show it (p99 6,994 ms against a 0.1 ms median). What stalls a node for
fifty-eight seconds is the question the next round asks.

That explains every result above that looked like a paradox. Batching the
transaction forwarding cut the p99 body arrival from 14.6 s to 8.4 s and moved
throughput not at all. Draining the transport cut the median from 380 ms to
41.5 ms — nine times — and moved throughput by a fifth, which is what a change
that also happened to help the tail looks like. Sizing the re-ask improved a
median that was already 1.2 ms and moved nothing.

**Optimising the median path cannot move this fleet's throughput.** Whatever
makes one block body take a minute to cross a loopback mesh that carries the
median one in 34 ms is the whole remaining problem, and it is not a cost that
shows up in any per-block measurement — including, per gov5's finding 3, a CPU
profile. That is the next round's question, and it is a different kind of
question from the nine before it.

### Round 11: what a single missed body costs

The corrected tail left one question — what stops a node for fifty-eight
seconds — and the logs answered it directly. Six of the seven nodes' largest
gaps between log lines are all exactly **6.0 s**, which is `baseTimeout`: views
that ended in a timeout rather than a commit. Node 4's largest gap is **43.0 s**,
at 23:58:51, which is where the late and duplicate deliveries cluster.

Its execution layer says what happened:

```
gap  7.6s after: Received new payload  number=116
gap 35.6s after: Status connected_peers=0 latest_block=114
gap 15.0s after: Received new payload  number=117
gap 23.9s after: Received new payload  number=117
```

Block 116 arrived and no state root, no canonical add, nothing followed it, and
`latest_block` sat at 114. The node had missed **one** body — 115 — so 116 was
an orphan; reth parks an orphan payload and reaches for its parent by backfill;
this fleet's execution layers run with `peers=0` by design, so there is no
backfill to complete, and the block stays parked with every later `newPayload`
behind it. The node comes back only when the consensus layer pulls the gap by
range, which retries every three seconds.

So the six-second gaps on the other six nodes are the second half of the same
event: while node 4 was stuck, every view *it* led could only end by timing out.
One member missing one body costs the whole fleet a six-second view every seven
blocks — which is the arithmetic that turns a 438 ms median cycle into a 2 s
mean.

`FAR_AHEAD_BLOCKS` already held a block **32** past the tip for exactly this
reason. Thirty-two is reth's `MIN_BLOCKS_FOR_PIPELINE_RUN` and it is the wrong
distance: reth parks an orphan whatever the gap, so the guard needs to be at
**one**, which is the distance that actually happens.

The first attempt judged it by hash — is this block's parent one we have
imported — and that was wrong in a way worth keeping in the file. It fails
*closed*: when the node's bookkeeping does not agree with the execution layer's
about what has been imported, every block is held forever. The four-node fleet
test is exactly that case (a driver whose head is a genesis constant the mock's
blocks do not descend from) and it caught it immediately — four tests, no
commits at all. Judging by block number instead uses `imported_height`, which is
`None` until the first import, so the guard is simply inert until it can be
right. The same test then went from timing out at 60 s to passing in 21 s.

On the fleet it stopped the chain outright: round 11's funding never mined, and
the fleet produced a handful of blocks in three minutes. A threshold of one has
no slack for the hop between the execution layer importing a block and this
service noticing — `imported_height` is set when the `BlockImported` event is
drained, one step later — so the *next* block, arriving legitimately, looks two
past a tip that has already moved and is held. At 32 that hop was invisible.

The tip has to be as fresh as the threshold is tight. `ExecutionDriver::head`
advances synchronously with the import, so the height of the header it names is
the truthful answer; `imported_height` stays as the fallback for a head this
node never saw a header for, which keeps the mock-driver case inert as before.

### Round 12: the stall is gone and the throughput is not

With the tip taken from the driver's synchronously-advanced head, the guard at a
distance of one works, and it does what it was built to do:

| | round 10 (guard at 32) | round 12 (guard at 1) |
| --- | ---: | ---: |
| body arrival p99 | 57,845 ms | **39,772 ms** |
| body arrival max | 58,857 ms | **48,316 ms** |
| import barrier p90 | 98.0 ms | 104.2 ms |
| leader: commit -> published p90 | 5,608 ms | 6,273 ms |
| win1 | 11,428 tps (15 blocks) | 10,012 tps (14 blocks) |
| win2 | **13,714 tps, 411,426 txs** | **13,714 tps, 411,426 txs** |
| win3 | 3,683 tps (20.1% occupancy) | 4,284 tps (23.4%) |

Window 2 reproduces to the transaction for the third round running. Window 1
differs by one block in a thirty-second window, which is this measurement's
granularity rather than a regression. The body tail improves by about a third.

That last number was nearly reported as a factor of twenty-one, and the reason
is worth more than the number — **for the second time in this file, a comparison
was drawn between a full round and a partial one.** Sampled after window 2,
round 12's body p99 is 2,708 ms; sampled over the whole round it is 39,772,
because window 3 is the supply-exhaustion window and the stalls return in it.
Round 10's figure was always a full round. The like-for-like improvement is 31%,
not 2,000%. The same mistake was caught once already, between rounds 6 and 7,
and caught again only because the round's own end-of-run numbers arrived after
the paragraph was written. A phase sample has to say what it covers, and two
samples that do not cover the same thing cannot be put in one table.

So: a modest latency result, and no throughput result. **That is the fourth time
in this document.** Batching the transaction forwarding, sizing the re-ask,
draining the transport, and now removing the orphan stall — four separately
confirmed costs, three of them large, and the number the fleet produces has not
moved outside a block per window. gov5 reached the same place after three of
their own rounds and wrote it down as the finding rather than as a failure: at
this pacing and this supply the fleet is not limited by any of these.

What is left, and what the next round should take, is the one term that has not
improved across any of the twelve: the leader's own interval from committing to
publishing, whose p90 is still six seconds against a median of 392 ms — the same
shape it had in round 8, before four separate fixes. Its median is a quarter of
a second of real work. Something makes one leader in ten take twenty times that,
and nothing measured so far touches it.

### Round 13: the timeout was 24 times the block interval

The leader's six-second p90 was never the leader being slow. Six seconds is
`baseTimeout`, so that p90 is a view *before* it that ended in a timeout rather
than a commit — the leader's interval simply contains the dead view.

Which exposed a configuration mistake in the bench tier, not a defect in the
node. gov5's chains pair a 3,000 ms period with a 6,000 ms `baseTimeout`: the
timeout is **twice** the interval. Overriding the pacing to 250 ms and leaving
the timeout at the genesis value made it **twenty-four times** the interval, so
one view where a leader did not propose cost twenty-four block-times. Round 12
had 61 timeouts across seven nodes in 164 blocks, each six seconds.

Round 13 scaled it: `--timeout-ms` at four times the pacing, floored at a
second.

| | round 12 (6,000 ms timeout) | round 13 (1,000 ms) |
|---|---:|---:|
| win1 | 10,012 tps | 7,412 tps |
| win2 | 13,714 tps | **19,596 tps** |
| win3 | 4,284 tps | 1,925 tps |
| all three windows | 840,330 txs | 868,123 txs |
| view timeouts / block | 0.37 | 1.53 |
| leader: commit -> published median | 392 ms | 1,251 ms |
| body arrival p99 | 39,772 ms | **2,901 ms** |

19,596 is the best window this fleet has produced at 6,000 senders — 43% above
a figure that had reproduced to the transaction in three consecutive rounds. It
is also not a result. Window 1, which is the measurement by gov5's rule, fell
26%; the three-window total moved 3.3%; and the spread across the round is now
far wider than anything a single round can attribute. **Claimed as a lever, not
as a throughput result.**

What *is* mechanical: timeouts became four times more frequent per block and six
times cheaper each, which is what tightening a timeout does, and the body
arrival p99 fell by an order of magnitude. A tighter timeout trips on a leader
that is merely slow, and recovers from one that is stuck; four times the pacing
is one point on that curve and gov5 runs at two. Finding the right ratio needs
several rounds at several values, compared window-for-window — which is the
shape of the next session's work, not a paragraph in this one.

### What actually limited this fleet

Seventy percent of the cycle was a clock, not a cost.

`hotstuff.period` is seconds, the proposer's pacing compared `as_secs()`, and
the Engine API timestamp is a whole second that must strictly exceed its
parent's. One second was therefore a floor, and at the 480M tier it was 1,013 of
the 1,429 ms. Every execution cost in the table — building
122 ms, importing 83 ms, rooting 0.06 ms, the wire 28 ms — together comes to
less than a third of it.

That reframes the gap against gov5 entirely. At the same tier, with the same
22,857 transactions in every block, they run a 0.98 s cycle and now a 0.496 s
one; the difference is not that their execution is faster, it is that their
blocks are not pinned to a whole second.

Round 4 confirmed it by removing the floor — `--block-interval-ms`, with the
timestamp taken from the parent rather than the clock below a second: 26,551 TPS
at 250 ms pacing against 15,999 at 1,000 ms, with nothing else changed. Every
round after it runs at 250 ms, so the sentences above are the fleet as it was
before round 4 and not as it is.

Note what this does *not* say. The fleet's production shape is 3 s, the same as
every one of gov5's chainspecs and four times faster than Ethereum's 12 s slots;
one second was never a product limit, only a benchmark one. What the round
bought is the ability to measure the chain rather than its clock.

Round 2's logs close the account exactly. Every phase of a full block, measured
across all seven nodes:

| phase | full block | empty block |
| --- | ---: | ---: |
| pacing wait (the chain's one-second floor) | ~1,000 ms | ~1,000 ms |
| leader builds the block (22,857 transactions) | **122.5 ms** | 0.9 ms |
| block body reaching the followers (1.71 MB on the wire) | **27.8 ms** (measured, round 3) | — |
| follower executes, roots and files it | 82.7 ms | 0.8 ms |
| import barrier: proposal seen -> vote sent | 111.3 ms (p90) | 1.5 ms |
| quorum and Decide | 23.2 ms (p90) | 9.1 ms |
| canonical commit | 12.0 ms | 12.0 ms |

Everything above except the body was measured directly, which left the body as a
residual — 1,429 ms of cycle, less 1,000 of pacing, less 122 of building, less
111 of importing, less 23 of quorum, leaves ~173 ms. A residual is the weakest
number in any table, because it collects every error in the terms above it, and
this one turned out to be wrong by a factor of six: round 3 timestamped both
ends of the body path and measured **27.8 ms**.

Two things were done to find that out. The first was `examples/gossip_cost`,
which measures the parts that are computation rather than propagation, on a real
22,857-transaction block:

```
rlp          : 2,651,333 bytes (2.65 MB)
compressed   : 1,719,894 bytes (1.72 MB, 64.9% of raw)
encode  rlp  :  2.38 ms      compress:  1.27 ms      decompress: 0.32 ms
leader side  :  3.66 ms  (encode + compress, once per block)
```

**Four milliseconds.** Putting a full block on the wire and taking it off again
is 4 ms, and six copies of 1.72 MB across loopback is about another one — so
whatever the residual was, the wire format was not it. That ruled out a cause
but did not find one, which is exactly the limit of measuring a residual's
parts: the second thing was to stop subtracting and timestamp the body itself,
and the answer was that the body was never slow. The ~145 ms the residual had
wrongly attributed to it belongs to the leader, whose own commit-to-publish
interval measures 1,260 ms rather than the 1,122 ms the subtraction assumed.

The same benchmark turned the gossip cap from an inference into a demonstration.
Run without `N42_MAX_GOSSIP_MB`, it does not produce a slow block — it fails
outright:

```
decompress: Snappy("expands past the gossip size limit")
```

A full 480M-gas block is 2.65 MB decompressed against a 1 MiB default. Every
receiver on the chain would refuse it.

One structural redundancy is worth recording even though it is not the cost it
looked like. The flood submits to all seven members in turn, so a follower's
pool already holds most of the
transactions in the block it is being sent — and the body ships all 2.5 MB of
them again. gov5 reaches the same conclusion from the other end: after removing
three separately-confirmed costs with no movement in TPS, they name their
remaining levers as "the block-interval cap, the load generator, and the import
barrier inside the vote path" (`docs/QS_TPS_BENCHMARK.md`, finding 3). Two of
those three — the interval cap and the import barrier — are the two largest
terms measured here, from a client with a different implementation of both.

Their finding 3 carries a warning worth repeating here, because it applies to
this fleet's next round and not only to theirs: the cost they found — a pool
lock held across two MDBX read-transaction opens per validated transaction —
"never showed in a CPU profile, because the work is cgo and allocation rather
than Go CPU; the mutex and allocation profiles both pointed straight at it."
A `perf record` of this fleet is subject to the same blindness in its own
dialect. Lock contention and allocation need their own instruments.

The QMDB root is not in the running for that gap. Measured across every block of
the round, including the full ones: **median 56 µs, p90 285 µs, slowest
4.06 ms**. A block with twenty-two thousand transfers in it commits its state in
four milliseconds, which is the binary tree's whole argument — the work is an
append at a cursor, not a trie walk over everything the block touched.

### Round 14 and the repeats: a sweep that reversed itself

Three values of the view timeout against the same 250 ms pacing, same supply,
same binary — the only thing that differs between these rounds is one number:

| timeout | ratio | win1 | win2 | win3 | **all three windows** | timeouts/block |
|---|---|---:|---:|---:|---:|---:|
| 6,000 ms (genesis) | 24x | 10,012 | 13,714 | 4,284 | 840,330 | 0.37 |
| 1,000 ms | 4x | 7,412 | 19,596 | 1,925 | 868,123 | 1.53 |
| 500 ms (gov5's) | 2x | 11,013 | 13,714 | 9,434 | **1,024,853** | 2.09 |
| 500 ms, repeated | 2x | 9,904 | **8,381** | 11,517 | **894,094** | — |

The first three rows say 22% more transactions at gov5's ratio than at the
genesis value, monotonic as the ratio tightens. The fourth row is the same
configuration as the third and says 894,094 — so a repeat was run, and then
three runs of each, which reversed the conclusion completely:

| timeout | runs | median transactions | spread | range |
|---|---:|---:|---:|---|
| 6,000 ms (genesis, 24x) | 3 | **858,658** | 5% | 820,892 – 862,339 |
| 500 ms (gov5's ratio, 2x) | 3 | **685,710** | 11% | 639,996 – 718,162 |

**Tightening the timeout to twice the pacing is 20% slower, and the two ranges
do not overlap.** Round 14's 1,024,853 was an outlier at the top of a wide
distribution, and the "+22%" drawn from it pointed the wrong way. The default it
was written into has been reverted.

The mistake was in the invariant, not the arithmetic. gov5 pairs a 3,000 ms
period with a 6,000 ms timeout, and reading that as "the timeout should be twice
the interval" is reading a ratio where there is a threshold: **a view timeout has
to exceed the cycle a block actually takes.** This fleet's cycle at the 480M tier
is 1.4–2.5 s no matter how fast the pacing asks for blocks, so a 500 ms timeout
fires in the middle of ordinary operation and discards views that were about to
succeed — timeouts per block went from 0.37 to 2.09 while throughput fell. Six
seconds is longer than gov5's block *and* longer than this fleet's, which is why
the genesis value works for both and their ratio does not transfer.

What survives from the sweep is the observation that started it: the leader's
six-second p90 is a timed-out view sitting inside the interval, not the leader
being slow. That remains true. The conclusion drawn from it — that the timeout
was misconfigured — did not.

## Which window is the measurement, and how wide the spread is

Window 2 came back as exactly 13,714 in rounds 7, 10 and 12, so it looked like
the reproducible one and this section previously said so. Three runs of the same
configuration, measured properly with `scripts/fleet7-repeat.sh`, say otherwise:

| | median | spread across three runs |
|---|---:|---:|
| win1 tps | 11,428 | **4%** |
| win2 tps | 13,714 | **17%** |
| win3 tps | 2,220 | 89% |
| **transactions, all three windows** | **858,658** | **5%** |

Those three exact repeats were coincidence. Window 2 varies by 17% run to run;
window 1 varies by 4%; the round's total varies by 5%. So gov5's rule — window 1
is the measurement — holds here after all, and the total is as good. Window 3 is
supply exhaustion and carries no information at all.

**A configuration is a distribution.** With a 4–5% spread on the reliable
metrics, a difference of less than about 10% between two single rounds is not
visible, and most of the comparisons earlier in this document are single rounds.
They should be read as directions. `fleet7-repeat.sh` exists so that the ones
that follow do not have to be.

### Two levers measured properly, and what that changed

With `fleet7-repeat.sh` in place, a configuration is three runs and a spread
rather than one number. Two levers went through it:

| configuration | runs | median transactions | spread | range |
|---|---:|---:|---:|---|
| baseline (genesis timeout, 250 ms pacing) | 3 | **858,658** | 5% | 820,892 – 862,339 |
| view timeout 500 ms (gov5's 2x ratio) | 3 | 685,710 | 11% | 639,996 – 718,162 |
| `--engine.suppress-persistence-during-build` | 3 | 832,900 | 5% | 811,599 – 851,572 |
| leader direct block push | 3 | 861,093 | 7% | 842,119 – 902,826 |

The timeout is **20% worse** and its range does not touch the baseline's: a real
effect, in the opposite direction to the one a single round had suggested.
Suppressing persistence during the build is **3% lower with the ranges
overlapping**, which at a 5% spread is no effect at all — and reth's own note
for that flag ("useful on chains with short block times where persistence I/O
can interfere with block building latency") describes this tier exactly, so a
plausible mechanism and a measured nothing.

Direct push is **+0.3% with the ranges overlapping almost entirely** — no
throughput effect either, which is the fifth confirmed mechanism in this
document to move nothing. It was built because the measurement pointed at it:
bodies arrive in 30 ms at the median and 1.1 s at the p90, and the p90 is the
mesh queueing rather than the bytes. The mechanism does what it was built to do
— body arrival p90 495.8 ms and p99 6.7 s against 1,107.7 ms and 39.8 s in the
single rounds before it — but those baselines are one round each, so that is a
direction and not a magnitude, and the number the fleet produces did not move.
N42-26 measure the same design at +6.95%, which is inside this rig's spread; if
it is worth that here, three runs cannot see it.

It is kept, off by default. A latency improvement with no throughput result is
still a latency improvement, and the protocol is additive — gov5 members do not
speak it and take the body from the topic exactly as before.

The change worth keeping is not either result. It is that both statements are
now the kind that can be wrong in only one way: three runs, a stated spread, and
ranges that either overlap or do not. Every comparison earlier in this document
rests on one round each side, and at a 5% spread on the reliable metric that
means anything under roughly 10% in those sections is invisible — including two
of the four "no effect" conclusions, which were right but not for a reason the
evidence could carry.

## The three clients' numbers, and what each of them measures

Both sibling clients publish throughput figures far above this fleet's, and the
gap is mostly in what is being measured. Their own documents say so; this is a
summary of what they say, not a re-measurement.

| client | figure | what it measures |
| --- | ---: | --- |
| this fleet | ~13,700–16,000 tps | 7 nodes, full signature recovery, QMDB root computed per block, bodies over GossipSub, 480M gas, 250 ms pacing |
| gov5 | 22,089 @ 0.98 s | 7 nodes, same 480M tier, full path (`docs/QS_TPS_BENCHMARK.md`) |
| gov5 | 32,381 @ 0.496 s | as above at half the block interval |
| N42-26 | **13,858** | "2s slot, all optimizations" — the row their own records call *more production-like* |
| N42-26 | 47,527 | TCP inject + fast propose |
| N42-26 | 90,949 | cache-hit fast path peak |
| N42-26 | **156,500** | `N42_SKIP_TX_VERIFY=1`, deferred state root, trusted TCP ingest, `N42_BLOCK_DIRECT_ONLY=1`, binary-v1 + zstd |

N42-26's `docs/performance-records.md` separates those two groups itself, and
says why: "so future readers do not compare incompatible numbers." The 156,500
row belongs to a section headed *Controlled 7-Node Binary Payload A/B*, described
there as "controlled codec and network comparisons, **not production-chain
records**". Its first flag disables transaction verification. Every round in this
document recovers every sender and computes a real state commitment.

Against the row N42-26 itself labels production-like — 13,858 at a 2 s slot —
this fleet's 13,714–16,000 is the same order, at a quarter of the block
interval, and at 1.4–2.0 GB of resident memory against the 39.1 GiB their round
38 records for seven nodes.

What is worth taking from their work is not the number but two of the levers
behind it. The first is already here: their round 42 "partitions the 256 logical
CPUs across the seven local validators, prevents the transaction validation
runtime from creating a second host-sized Rayon set" — the same problem the CPU
pinning above solves, found independently. The second is not: **direct push**.
Their leader unicasts the block body to all six peers over QUIC instead of
publishing it to the mesh, keeps GossipSub as the fallback when the fanout does
not fully resolve, and de-duplicates on receipt; they measure it at +6.95%. This
fleet's body arrival is 30 ms at the median and 1.1 s at the p90, and the p90 is
mesh queueing — so it is the right shape of fix for the right measured problem,
and it is a feature rather than a flag.

## Where it stands

Seven all-Rust members produce the native chain at its 3 s period, agree on
every head hash, restart one at a time without losing their place, sustain 200
transactions a second without refusing one, and cost between 1.37 and 1.70 GB
between them depending on load. What is measured here is a chain from genesis; the
flagship chain is thirteen million blocks and thirty-five gigabytes of state,
and three things stand between this and it.

The first is the forest itself: the tree is held whole in memory, which the
delta log makes cheap to *persist* but not cheap to *hold*. Thirty-five
gigabytes of state is thirty-five gigabytes resident, per node, and it is now
the largest single item. The other two are the header field
`MobileRegistryRoot`, which reth's `Header` cannot carry, and gov5's EOF, which
revm 42 does not implement — both recorded in `docs/N42_26_PORT.md`.

## Round 16: the consensus loop was handing transactions to the pool

Fifteen rounds had moved throughput once. Five mechanisms had been confirmed to
work and shown to change nothing, and the record's own summary of why was that
the cycle is made of tails rather than of medians. That was true and it was not
yet a cause.

Two things arrived together to give one.

### gov5's own fleet, on this host, at this tier

gov5 ran a seven-node round on this machine at settings that happen to match
this fleet's bench tier exactly — 250 ms pacing, a 480M gas ceiling, seven
miners — so for the price of reading their RPC there was a same-machine
comparison with every variable except the client held still:

| | this fleet | gov5, same host, same hour |
|---|---:|---:|
| cycle | 1,430–1,667 ms | 256–323 ms |
| transactions per block | 22,857 | ~12,300 |
| occupancy | ~100% | 53% |
| TPS | ~15,000 | 45,700–48,000 |

The first thing that settles is a direction this file was about to take. Their
blocks are *half* the size and their cycle is five times shorter, so more gas
per block is not what they are doing, and the round that had been prepared to
test a 960M tier was not run. (`--gasceil` was built for it and is kept, since
the reason it was needed is real: a block's gas limit moves by 1/1024 of its
parent's per block, so a chain born at 480M needs ~710 blocks to reach a 960M
ceiling, and a round pointed at a ceiling it has not climbed to measures the
chain it was born as.)

The second thing it settles is where the gap is *not*. Per transaction this
fleet's median path is 19 µs, against 22 µs per transaction of gov5's entire
cycle. The median path is not behind. 22,857 transactions in the 442 ms the
medians actually sum to would be 51,700 TPS — better than gov5's peak. The
whole difference is the ~1,060 ms of cycle that no median accounts for.

### Naming the timeouts instead of subtracting them

Three previous attempts on that gap worked by subtracting medians from the
cycle, and two of them were wrong. So the timeout was made to say its own
cause: a view that expires has two shapes needing opposite fixes — the leader
never proposed, or it proposed and the votes did not arrive — and only the
leader knows which, only at the moment it decided. The reason is now recorded
where the decision is made and quoted when the view expires, at warn, because
at 0.37 a block this is the fleet's dominant cost and not an exceptional event.

A round at the baseline settings, which reproduced it to the transaction
(win1 10,666, win2 13,714 — the same figures as the three t6000 runs):

| | |
|---|---:|
| timed-out views, fleet-wide | 88 |
| of which "not this node's view to lead" | 83 (94%) |
| commits, six of the nodes | 192 |
| commits, node 3 | **111** |
| nodes that ever logged BEHIND | **node 3, and no other** |

Every node's timeouts were at views ≡ 3 (mod 7) — the views node 3 leads. One
member out of seven was sick, never recovered, and paid its 1-in-7 leader slot
at the full six-second `baseTimeout` about fourteen times. Fourteen views ×
6 s is 84 s of dead time in a 90 s measurement: **the round was mostly node 3's
timeouts.**

Node 3's own log says how it got sick, and it is not what a stalled node usually
looks like:

```
06:39:46.658  view 112 committed
      …       11.08 s in which this node logs nothing at all
06:39:57.742  view 113 times out
06:39:57.773  view 113's body arrives — 31 ms after the view it belonged to expired
```

Not slow: silent. No bodies, no proposals, no votes, and its execution layer
idle beside it. Something stopped the service loop for eleven seconds, and
while it was stopped the node was deaf to the mesh.

### What the loop was doing

`forward_inbound_transactions` — handing the transactions the fleet gossiped to
this node's own pool. The call site already carried a comment saying this loop
cannot poll its transport while it awaits, and the fix that comment describes
was to send the batch as one request instead of one per transaction. That was
done, and it was not enough, because the batch itself has no bound: it is
everything that arrived since the last step, the adapter chunks it into
JSON-RPC batches of a thousand, and each chunk is a round trip the loop waits
out. At 6,000 senders that is tens of thousands of transactions, tens of
sequential round trips, against a pool already answering `txpool is full` — and
every one of those validations is paid before the rejection.

It is the only work in that loop whose size is set by the *fleet's* send rate
rather than by the chain's. Everything else scales with one block.

### What it costs

A diagnostic round with the forwarding switched off entirely
(`F7_NO_TX_GOSSIP=1`, which is sound only as a diagnostic: the flood submits to
all seven RPCs, so in a bench round the gossip carries nothing the pools do not
already have):

| | baseline | forwarding off |
|---|---:|---:|
| win1 | 10,666 TPS, 2.143 s cycle | **34,284 TPS, 0.667 s** |
| win2 | 13,714 TPS, 1.667 s cycle | **38,786 TPS, 0.588 s** |
| transactions, whole round | 858,658 | **2,270,887** |
| timed-out views | 88 | **5** |
| commits, worst node / best node | 111 / 192 | **360 / 360** |

Not one node fell behind. Occupancy stayed at 100%, so this is 22,857
transactions a block at a 0.588 s cycle — twice gov5's block at rather more
than gov5's rate, on the same machine.

The 2.64× is the size of what one unbounded `await` in a consensus loop was
costing, and every one of the five confirmed-but-inert mechanisms before it was
inert for the same reason: they improved a median while the fleet was spending
its time somewhere no median could see.

**And 38,786 TPS is a floor, not a ceiling.** Window 3 collapses to 3.3%
occupancy, which the first reading of this round put down to the base fee
reaching 186 Ggwei and the chain pricing its own flood out. That reading is
wrong, and the round's own numbers say so: window 3's base fee *starts* at 320,
so the blocks before it were empty, and empty blocks are not what a chain that
has priced its supply out looks like — they are what a chain with no supply
looks like. `tx_flood` runs `while live > 0` and exits when every sender has
sent its `--pertx`; at 6,000 x 500 that is 3,000,000 transactions and this round
consumed 2,270,887 of them, so the generator was finishing while window 3 was
being measured.

Which means the chain was never shown to be saturated. Windows 1 and 2 took
2.19M transactions in 60 s — about 36,500 a second offered against 36,535
achieved — so the fleet kept up with everything it was given and its ceiling is
somewhere above. The next round has to outsupply it before any of these figures
can be called a maximum.

Credit for that correction goes to the gov5 session working on the same host,
which had just been caught by the same thing from the other side: their load
generator's rate limit was a no-op under batching, so it dumped 12M transactions
in 80 s and exited, and three of their four windows were measuring a draining
pool while reporting it as the chain slowing down. Two harnesses, the same
failure, found once. They also corrected the comparison figure taken from their
RPC above: 45,700-48,000 TPS was an instantaneous sample, their own measured
windows peak at ~41,500, and they have since established that their fleet
saturates near 40,000 — raising offered load from 40k to 80k tx/s *lowered*
their peak window to 36,190. So the target to size against is ~41,500, not
48,000.

### The fix that ships, and what it is worth

Switching the forwarding off is a diagnostic. What ships is the forwarding
moved off the loop entirely: its own task, its own HTTP client on the same
public RPC, fed by a four-deep channel, and the loop hands over with `try_send`
and never waits for an answer.

An intermediate attempt is worth recording because it failed and the reason is
the whole point. Rationing the forwarding inline — at most one JSON-RPC batch
per step, so the stall is bounded rather than unbounded — measured **12,190
TPS**, which is the baseline. The same total work spent in smaller pieces is the
same total work, and a loop that waits for the pool at all is a loop that is
deaf while it waits. Bounding the stall was never the fix; removing it was.

Three rounds each, against the three-round baseline:

| | baseline | forwarding off the loop |
|---|---:|---:|
| win1 TPS, median | 11,428 (10,999–11,428) | **22,290 (19,047–24,380)** |
| whole round, median | 858,658 (5% spread) | **1,411,294 (10% spread)** |
| ratio | — | **1.95x on win1, 1.64x on the round** |

Neither pair of ranges overlaps, which after this file's history is the only
form in which a result counts.

The 1.64x understates it, and the reason matters more than the number: all
three off-loop rounds report **zero** transactions in window 3, where the
baseline still had 2,220 TPS of supply left to chew on. The faster fleet
exhausts a 3,000,000-transaction round before the round is over, so the totals
are comparing a fleet that ran out against one that did not.

Window 2 says the same thing more precisely. Across the three rounds it runs at
a **0.370–0.536 s cycle at 32.7–66.1% occupancy** — the fleet taking a 480M-gas
block every 0.4 s and finding it half empty. At 22,857 transfers per full block
that is a demonstrated appetite of roughly **54,800 transactions a second**
against a generator supplying 22,662. So:

**This fleet has never been saturated, and no number in this file is its
maximum.** The next measurement has to outsupply it before any of them can be.

### The ceiling probe went the wrong way, and said where to look

Supply was raised five-fold — 6,000 senders x 2,500 transactions, 15,000,000
against a fleet that had just demonstrated an appetite of about 54,800 a second
— on the assumption that the previous rounds were supply-limited and the number
would rise.

It fell:

| | 3,000,000 supply | 15,000,000 supply |
|---|---:|---:|
| win1 | 22,290 TPS, 1.000 s | 22,094 TPS, 1.035 s |
| win2 | 22,662 TPS, 0.536 s | **8,633 TPS, 1.667 s** |
| win3 | 0 (supply gone) | 12,319 TPS, 1.250 s |
| nodes behind | none | **node 4: 123 commits against 170** |
| timed-out views | 5 | 53 |

More load made it slower, and the one-member-falls-behind pathology came back
with it. gov5 had already reported the same shape from the other side — raising
their generator from 40k to 80k offered tx/s lowered their peak window from
41,495 to 36,190 — so this is a property of the regime rather than of either
client.

It also falsifies the framing of the previous section. "Supply-limited" was the
right reading of window 2's 32-66% occupancy, but "therefore more supply gives a
bigger number" did not follow, and the probe was worth running precisely because
that step was an assumption rather than a measurement.

What it points at is a defect of exactly the same family as the forwarding one,
one layer along: **work whose size the fleet sets, done where consensus has to
wait for it.** `publish_transactions` filtered the pool's outgoing transactions
against a `VecDeque` of 4,096 remembered hashes using `contains`, which is a
linear scan, once per transaction published. At 22,000 TPS that is around 90
million 32-byte comparisons a second on the consensus event loop, and it grows
linearly with the transaction rate — so raising supply raises the cost of
carrying it, which is the mechanism by which more load produces fewer blocks.

The deque is kept for eviction order and a `HashSet` added beside it for
membership. Both structures hold the same hashes; only the lookup changes.

### The scan was replaced, and the replacement was not a result

Three rounds of the set-based dedup against three of the off-loop build:

| | median round | spread | range |
|---|---:|---:|---|
| forwarding off the loop | 1,411,294 | 10% | 1,274,724 – 1,417,110 |
| + set-based dedup | 1,244,697 | 23% | 1,043,100 – 1,325,706 |

The ranges overlap, the medians differ by 12% inside spreads of 10% and 23%, and
window 1's spread went from 4% to 65%. **That is not a result in either
direction**, and the mechanism argued for it in the previous section — 90
million comparisons a second — is arithmetic on an assumption, not a
measurement. `publish_transactions` is fed by a filter polled every 500 ms, and
how many transactions per second actually reach it was never measured.

There is also a method error in it, and it is the more useful half. The change
was not the data-structure change it was described as. The original pushed every
heard hash into the deque **including duplicates**, so 4,096 entries held fewer
than 4,096 distinct hashes; a `HashSet` holds 4,096 distinct ones and therefore
remembers a longer window and filters more of this node's own publishing. So two
things changed at once — how the window is searched, and what the window
remembers — and the round measured the pair. Whatever it measured, it was not
"O(n) versus O(1)".

It was redone as a counting multiset — exactly the original semantics, only the
lookup differs — and re-measured:

| | median round | spread | range |
|---|---:|---:|---|
| the scan (unchanged) | 1,411,294 | 10% | 1,274,724 – 1,417,110 |
| counting multiset, O(1) | 1,372,147 | 69% | 1,119,860 – 2,060,892 |

**No effect.** Three percent on the median, with the ranges overlapping across
almost their whole length. The scan cost nothing measurable, and the 90-million
figure was arithmetic on a publish rate that was never measured — the outbound
side is fed by a filter polled every 500 ms, and how many transactions actually
come through it per second is still unknown.

The index has been taken back out. It is not carried for a benefit that does not
exist, and this fleet is meant to be frugal; what stays is the note above the
field saying it was tried and what it measured.

That makes six confirmed-but-inert mechanisms in this file, and this is the
first where the mechanism was written down as a finding before it was checked.
The rule that follows is narrower than "measure everything": **a cost argued
from a rate is not a cost until the rate is measured.** Both halves of
`90e6 = 22,000 x 4,096` were assumptions; only the 4,096 was ever read off the
code.

### A commit that carried something it did not mention

`eddc3a9fb` was made with `git add -A` and swept in an unrelated, unmeasured
change to `crates/node/builder`: sizing reth's sender-recovery cache from the
transaction pool rather than taking upstream's `1 << 17` default. The reasoning
is gov5's and it is sound — the cache is direct-mapped, the whole pool churns
through it, and at a 360,000-slot pool a block's senders are overwritten between
the pool recovering them and the block arriving — but it is a change to a
vendored reth crate that every node compiles, and it went in inside a commit
about transaction forwarding.

It did not contaminate anything: `target/release/n42` was last built on
2026-08-31 and the patch is from 2026-09-01, so no round in this file ran with
it. It is measured on its own, after the dedup question is settled, and the
sequencing matters — the validator binary and the execution-layer binary have to
move one at a time or neither result means anything.

## Round 17: the generator stops being the answer

Two changes to the leader's path and one to the load generator, measured
separately, with one of the three turning out to be a fourfold regression.

### What the leader's path is actually made of

The leader's build was timed in four parts rather than guessed at, because the
two candidate fixes are opposites and this file has picked wrong before. At the
480M tier, on full blocks:

| stage | | |
|---|---:|---|
| `fcu_ms` | 0 ms | telling the execution layer to start |
| `build_ms` | **95 ms** | waiting for it to fill the block |
| `seal_ms` | 17 ms | stamping the view into the header |
| `import_ms` | **80 ms** | executing the block this node just built |
| total | 195 ms | |

`import_ms` is the striking one. `getPayload` builds a block without inserting
it; sealing the view changes the hash, so reth cannot recognise the block as
the one it assembled and runs every transaction a second time. reth does
short-circuit a block already in its tree — a block from `getPayload` is not in
it.

### Moving the import behind the proposal

The import has to happen: the leader never receives its own proposal back over
gossip, so nothing else ever imports it, and the block would be committed by
consensus and then rejected by the leader's own execution layer. But it does not
have to happen *first*. Publishing the body and the proposal before importing
takes 80 ms off the leader's path and gives every follower the block 80 ms
earlier, to execute in parallel with the leader's own import.

Leader path after: **110 ms** (`build 89`, `seal 17`).

### The binary ingest path

The generator was the other half. Measured during a flood, the whole fleet used
**13.8 cores of the 224 pinned — 6%** — and the generator itself used 0.9 of a
core to deliver ~22,000 transactions a second. Sixty-four threads, each blocked
about 290 ms per 100-transaction batch on a JSON-RPC round trip.

`crates/n42/tx-ingest` is the same submission without the three costs that have
nothing to do with the transaction: hex encoding, JSON, and above all a round
trip the sender waits out. Frames are length-prefixed raw EIP-2718; a client
pipelines across its senders, one frame in flight per sender, so a single
sender's nonces stay strictly serial while the connection always has work on it.

The other half is gov5's, and it is the half that mattered: **the server waits
rather than refusing.** A frame is not admitted while the pool is at its high
water mark, and the reply carries the pool's pending count. Every round in this
file until now logged `txpool is full`, and a refused generator retries — which
means re-signing, so a full pool turned the generator's whole budget into work
neither side kept.

| | JSON-RPC | binary ingest with the gate |
|---|---:|---:|
| submitted | ~22,000/s | **51,719/s** |
| rejected | every round | **0** |
| win1 | 22,290 TPS | **43,426** |
| win2 | 22,662 TPS | **44,189** |
| cycle | 1.000 s | **0.517 s** |
| occupancy | 100% | 100% |

Supply is no longer the binding constraint: the generator delivers faster than
the chain consumes, the gate holds the pool at ~100,800, and occupancy stays at
100%. What sets the rate now is the chain.

One thing deliberately not taken from gov5's design: their client sends a
pre-recovered sender with each transaction and their server trusts it, skipping
ECDSA entirely. That is the right trade when recovery is the ceiling. Here the
machine is 94% idle, so it is not the ceiling, and trusting a client-supplied
sender would change what the benchmark verifies without changing what it
measures. `recover_raw_transaction` — the same entry point
`eth_sendRawTransaction` uses — stays.

### Building ahead is a fourfold regression

The remaining 89 ms is the leader waiting for a build it could have started a
consensus round earlier: the parent of a leader's block is the block committed
in the previous view, and a node knows that block when it *imports* it, before
the votes are in.

The first attempt never fired — `ahead=false` on all 59 proposals in a round —
because the prepared build ran the proposal's pacing gate, and a build prepared
the instant a block is imported always has `head_seen.elapsed() ≈ 0`. Pacing
decides when to propose, not when to start building; the fix was a `preparing`
flag on the context.

With it firing, three consecutive rounds reported **~11,400 TPS against 43,426**,
and the switch flipped back reproduces 43,427 — the same figure to one
transaction. So it is not noise and not the environment.

**Off by default, behind `N42_BUILD_AHEAD`.** The arithmetic is sound and the
measurement says the arithmetic is not the whole story: asking the execution
layer for a payload on a block the fleet has not committed costs far more than
the 89 ms wait it saves. The untested hypothesis is that the prepared
forkchoice moves the execution layer's head to an uncommitted block and the
commit that follows has to undo it, but that is a guess, and this file's rule is
that a mechanism is not a cost until it is measured.

### Three harness defects, all of the same shape

Each of these produced a wrong number rather than an error, which is the
expensive kind:

1. **`fleet7-repeat.sh` divided a spread by a zero median** when a window
   reported no transactions, killing the summary after the windows that had one
   — no `total txs` line, no `runs` line, and a caller waiting on either waited
   forever. Cost: eighty minutes.
2. **The staleness guard, added earlier in this session, fired twice on files
   that do not go into the binary** (a test, and a different example), refusing
   valid rounds. It also fired once correctly. Now narrowed to exactly the
   compilation inputs of the binary it checks, and `fleet7-repeat.sh` pins a
   snapshot of the binaries for the whole repeat so editing source mid-run is
   harmless.
3. **The base-fee decay was a fixed thirty seconds.** A fresh chain starts at
   875,000,000 wei and loses 12.5% per empty block, so reaching the floor takes
   about 120 blocks — and whether thirty seconds contains 120 blocks depends on
   how fast the fleet came up. Two rounds of the same build started at 7,887 wei
   and 31,060,570 wei. It now waits on the number rather than the clock; the
   round that found this needed **80 seconds**, and the next needed 30.

The first diagnosis of (3) was "the datadirs were not wiped", and a guard was
written for it before the chain itself was read. It was wrong — the chain was
fresh both times — and reading `baseFeePerGas` from blocks 1, 20 and 65 settled
it in one command.

## Round 18: catching up with N42-26's tier

N42-26's record is 156,499 TPS at **163,000 transactions a block**. Reading their
devlogs settled what to copy and what not to, and then measuring settled it
again — differently, twice.

### The comparison was not what it looked like

Earlier rounds said "my cycle is faster, the difference is block size". That was
an artefact of comparing at *different* block sizes. Run at their tier:

| | N42-26 | this fleet |
|---|---:|---:|
| transactions a block | 163,000 | 163,000 |
| cycle | 1.15 s | 3.33 s |
| TPS | 156,499 | 48,898 |

At the same block size they are **2.9x faster per block**. The honest gap is
theirs, not the tier's.

Bigger blocks alone bought almost nothing: 7.1x the transactions cost 6.4x the
cycle, so 44,189 TPS became 48,898 — 11%. Per-block cost is close to linear in
block size, which is the thing a gas tier cannot get around.

### Sizing the tier is three numbers, not one

A 163,000-transaction block needs a pool that can hold one. The bench tier's
120,000-slot pending pool is five blocks at 480M and **less than one** at 3.42G,
and a builder that cannot fill a block does not say so — it produces short
blocks and the round reports them as the chain's rate. The pool and the ingest
gate are now derived from the gas ceiling the way the gossip cap already was:
three blocks of pool, a gate at five sixths of it.

### Two redundant decodes of the leader's own block

Tracing one full cycle through the leader's log found 648 ms between the block
being finished and its body being published, on a path where sealing is 150 ms.

The whole of it was `built.execution_data.clone().try_into_block::<TxEnvelope>()`
— a clone of twelve megabytes and a full decode of 163,000 transactions into
typed envelopes, **to read one header**. And the header had just been built:
`normalize_to_gov5_h2` constructs it to hash it, then drops it. The same payload
was decoded twice in a row for the same object.

Returning the sealed header instead: **48,898 -> 54,331 TPS**, 648 ms -> 425 ms.

At 22,857 transactions the same defect is about 90 ms and invisible. It took the
tier to make it show.

### What the remaining 418 ms is, and what it is not

| | |
|---|---:|
| `encode_ms` | **346–401 ms** |
| `compress_ms` | 9–10 ms |
| `push_ms` | 2–4 ms |

Snappy on nineteen megabytes is ten milliseconds. Encoding the block into gov5's
RLP is thirty-five times that, and it is a third full decode: `encode_block_rlp`
reconstructs the block from raw bytes, recomputes the transaction root as a trie
over 163,000 transactions, and re-encodes every transaction back to the bytes it
started from.

### Sharing the pushed block: confirmed, and inert

`push_block_to_all` copied the block once per peer — six copies of twelve
megabytes per block, on the consensus loop. Changed to a shared `Bytes`, which
is what N42-26 did with an `Arc<Vec<u8>>`.

**No measurable difference**: 425 ms -> 418 ms, and the round's windows land in
the same places. The instrumentation then said why: `push_ms` is 2–4 ms. Seventy
megabytes of memcpy is about ten milliseconds at this machine's bandwidth, and
the "six copies of twelve megabytes" arithmetic that motivated the change never
had a rate under it.

That is the eighth confirmed-but-inert mechanism in this file and the third time
this session that a cost was argued from a quantity without measuring the rate.
The change stays — it is strictly less copying with no downside — but it is not
a result.

### What was studied and deliberately not taken

N42-26's `payload_cache` (402-line reth patch): the payload builder stores its
execution output keyed by block hash, and `newPayload` takes it and skips the
EVM entirely, forcing a synchronous state root because the StateRootTask would
otherwise wait for execution updates that never come. It exactly matches a cost
measured here — the leader re-executing its own block, 710 ms at this tier.

Not adopted, for two reasons and one caveat:

* The phase analysis says the leader's own import is **not on the serial chain**.
  Every node executes every block as a follower (621 ms); the leader merely does
  one extra execution per seven blocks. Removing it saves EL work, not cycle.
* It needs three more reth crates in the patch table (`crates/evm/evm`,
  `crates/ethereum/payload`, `crates/engine/tree`).
* And it would miss anyway without a change: sealing the view alters the block
  hash, so a cache keyed by the built hash never matches the imported one.
  Re-keying after the seal would work — the seal touches only extra data,
  ommers hash and difficulty, none of which change the execution output.

Three other things from their devlogs, checked and not applicable: their zstd is
on their own payload format, while this fleet's block topic is gov5's
`ssz_snappy` wire contract; their `connection_limits` ordering bug needs a
`connection_limits` behaviour, which this transport does not have; and their
UDP receive-buffer ceiling is a QUIC problem, while this transport is TCP.

### A note on how this file is kept

N42-26 keeps 152 numbered devlogs under an index. This file is one document with
rounds appended, now past 1,500 lines. The convention that matters is the same
one either way: **every attempt is recorded, including the ones that did
nothing** — eight of the mechanisms in this file are confirmed and inert, and
they are the reason the ones that worked can be believed.

### Eager import: the half that was missing

N42-26's `devlog-22-consensus-exec-pipeline.md` carries the timing diagram that
says what was still wrong here:

```
before:  Build N -> broadcast -> vote -> await import (710 ms) -> ...
after:   Build N -> broadcast -> vote -> Build N+1
                        |
                        +-- eager import, spawned, parallel with the vote
```

Moving the import behind the proposal was half of it, and this file recorded
that half as done. Awaited, it still holds the consensus loop for the length of
the import — 710 ms at this tier — and during that time the leader cannot read
the votes for the block it has just proposed.

Handed to a task instead:

| | win2 | cycle |
|---|---:|---:|
| import awaited | 54,331 TPS | 3.000 s |
| import spawned | **59,764 TPS** | **2.727 s** |

Window 2 and window 3 both report 1,793,000 transactions in 11 blocks, which is
as reproducible as this rig gets.

Nothing has to come back from the task. The consensus engine asks for the block
to be executed like any other, and that request finds it in the execution
layer's tree; if the task has not finished, the request executes it and the only
cost is the saving not happening — N42-26 call these the two cases and fall back
the same way. Their devlog also answers the obvious worry: reth serialises engine
requests through one channel, so the eager `newPayload` and the commit's
forkchoice cannot race.

At the 163,000-transaction tier this fleet has now gone **48,898 -> 54,331 ->
59,764 TPS**, and both steps came from reading their devlogs rather than from
tuning.

### The leader took its own block apart three times

The same root cause showed up in three places, and it is the most useful pattern
this tier exposed: **a leader repeatedly decoding a block it had just built.**

| where | what it did | cost |
|---|---|---:|
| sealing | `try_into_block` to construct the header, hashes it, drops it | 150 ms (needed) |
| remembering the header | `try_into_block` again, for the header just dropped | 648 -> 425 ms |
| encoding for the wire | `try_into_block` a third time, plus a transaction-root trie rebuilt over 163,000 transactions to check its own block, then every transaction encoded back into the bytes it came from | **346-401 -> 6 ms** |

The block's transactions are EIP-2718 bytes in the payload the whole time, which
is exactly what gov5's block RLP wants. Compressing nineteen megabytes is 10 ms;
encoding them was 360. The ratio is what gives the game away — thirty-five times
the cost of touching every byte, spent on taking the block apart and putting it
back together.

| | win2 | cycle |
|---|---:|---:|
| general encode path | 59,764 TPS | 2.727 s |
| raw bytes, sealed header | **65,177 TPS** | **2.501 s** |

The general path stays for blocks this node did not build, where the decode is
the point.

Running total at the 163,000-transaction tier: **48,898 -> 54,331 -> 59,764 ->
65,177 TPS**, a third more than the tier started at, from four changes of which
none were tuning and three came from reading N42-26's devlogs.

### Building ahead, measured again: a 4x regression became an 8% gain

The same change, the same switch, re-measured after the leader's path had been
cleared of the three redundant decodes and the awaited import:

| | win2 | cycle | prepared builds used |
|---|---:|---:|---|
| `N42_BUILD_AHEAD` off | 65,177 TPS | 2.501 s | — |
| `N42_BUILD_AHEAD` on | **70,615 TPS** | **2.308 s** | 17 of 19 |

It had measured **four times slower** at the 480M tier, across three rounds,
with the switch flipped back reproducing the baseline to the transaction. That
measurement was not wrong. It was a measurement of the code as it stood: a
leader whose loop was held for 710 ms by an awaited import and whose path
carried three full decodes of its own block had no room to use a payload
prepared early, and the prepared forkchoice competed with an execution layer
that was already busy.

The lesson is not "measure twice". It is that **a negative result is about the
system it was measured in, not about the idea**, and when the system changes
enough the result has to be re-earned. Nothing in this file's method catches
that automatically; what caught it was noticing that the leader's build had
become the largest item on the serial chain and asking what would remove it.

Running total at the 163,000-transaction tier: 48,898 -> 54,331 -> 59,764 ->
65,177 -> **70,615 TPS**, cycle 3.33 s -> 2.31 s.

### The workload is not the same workload

Then a comparison problem, found by reading N42-26's stress generator rather
than their devlogs:

| | recipients |
|---|---|
| this fleet's `tx_flood` | **one** — every transfer goes to `0x4242…42` |
| N42-26's `n42-stress` | up to **2,000,000 distinct**, hash-derived |

Their 163,000-transaction block touches up to 163,000 recipient accounts. This
fleet's touches one. That is five orders of magnitude of difference in state
writes per block, and it runs against this fleet in the comparison: **their
blocks do more work than these and are still 2.2x faster**, so the gap measured
here is if anything understated.

It also makes one direction untestable. Every transaction in these blocks writes
the same account, so a Block-STM parallel executor would find a write-write
conflict on every one and serialise — which is why N42-26's own roadmap says the
speedup "shows only on contract-heavy blocks". Parallel execution cannot be
evaluated on this workload at all.

The generator has to change before any of these numbers can be called a
comparison. Fixing it will lower them.

### The comparable number, and it is half

With N42-26's recipient spread — 2,000,000 hash-derived accounts instead of one
sink — at the 163,000-transaction tier, everything else identical:

| recipients | win1 | win2 | win3 |
|---|---:|---:|---:|
| one | 72,243 | 70,615 | 65,167 |
| **2,000,000** | **35,112** | **38,032** | **54,331** |

So the honest figure against their 156,499 TPS is **38,032–54,331**, and the gap
is 2.9–4.1x rather than the 2.2x this file had been claiming. Every number in
this file before this point was measured on a workload that wrote one account
per block.

The shape inside the round is the interesting part. Window 3 is 55% faster than
window 1 on the same chain with the same supply, and the reason is account
creation: 15,000,000 transfers over 2,000,000 recipients means the first two
million transfers each create an account and write new trie nodes, and the rest
update accounts that already exist. A round that starts on an empty recipient
set measures creation; one that runs long enough measures updates. Both are real
and they are not the same number — which is a thing to state whenever one of
these figures is quoted.

N42-26's generator clamps recipients to two million the same way, and their
sixty-second round moves 9.39M transfers, so they are in the same regime.

### The propagation tail, found by a ratio and diagnosed wrongly twice

Applying the byte floor to what was left of the serial chain. A 12.2 MB body
touched once is about 1.2 ms of work at this machine's memory bandwidth:

| step | measured | vs the floor |
|---|---:|---:|
| snappy compress | 10 ms | 8x |
| encode from raw bytes | 6 ms | 5x |
| direct push, sender side | 4 ms | 3x |
| **published -> received** | **302 ms** | **248x** |

Everything on the leader's path sits at 3-8x. Propagation sits at 248x, which is
40 MB/s across loopback. Small bodies cross in 0.1 ms, which rules out a stalled
event loop and leaves flow control.

libp2p's yamux receive window is the specification's 256 KiB, so a 12.2 MB body
is about forty-eight window round trips. Raising it to 16 MiB:

| yamux | win2, two rounds each |
|---|---:|
| libp2p default | 38,032 / 38,032 TPS |
| **fixed 16 MiB window** | **59,762 / 65,197 TPS** |

**+57% to +71%**, with the two pairs not overlapping and one of them reproducing
to the transaction.

Two things about that were wrong on the way, and they are the useful part.

**The 256 KiB was a constant read from the wrong version.** libp2p-yamux 0.47
defaults to yamux **0.13**, whose flow control tunes itself; the 256 KiB default
is yamux 0.12's. `set_receive_window_size` does not raise a window — it switches
the connection back to 0.12 and a fixed one. The change is a trade of
auto-tuning for a constant, and it happens to win here. Reading a default and
assuming it is in force is the same error that produced the sender-cache sizing
earlier in this file, which gov5 then measured at exactly 0% hit rate because
their import path never consults that cache at all.

**And the median was never the problem.** The ratio pointed at propagation and
propagation was right, but the fix did not move the median — 302 ms to 285 ms.
It moved the tail:

| | median | p90 | p99 |
|---|---:|---:|---:|
| libp2p default | 311 ms | 757 ms | **1,599 ms** |
| fixed 16 MiB | 285 ms | 374 ms | **633 ms** |

A cycle is a mean and a mean is made of its tail — this file's oldest lesson,
arrived at again from a different direction. The byte-floor ratio found the
right subsystem for the wrong reason, which is still worth more than not finding
it.

**And a two-variable round, which is my error and not the rig's.** The first
window round also carried a rebuilt execution layer with the sender-cache sizing
backed out, and its 80% was credited to yamux before either was isolated. Three
rounds in a 2x2 settled it: the cache changes nothing (38,032 either way) and the
window is the whole effect. Same mistake as the dedup index earlier — two changes
measured as one.

Comparable standing at the 163,000-transaction tier with 2,000,000 recipients:
**65,197 TPS** against N42-26's 156,499.

### Two clients, and I confused them

A correction that matters for every attribution in round 18. There are two
sibling clients here and they are not interchangeable:

* **`../N42-gov5`** — the Go client. MDBX, HotStuff, QMDB. Measured peak on this
  box **41,495 TPS** at 0.496 s blocks, 22,857-transaction blocks.
* **`../N42-26`** — the Rust client. reth-based, so it shares
  `crates/ethereum/payload/src/lib.rs` with this repo. Record **156,499 TPS** at
  163,000-transaction blocks.

The 156,499 this file has been chasing is N42-26's and is recorded correctly
above. What was wrong: the binary ingest server's pool gate is credited in its
own source to "gov5's sibling client" when it came from N42-26's
`crates/n42-node/src/ingest.rs`, and in a message to the gov5 session I
attributed N42-26's roadmap and their 156,499 to them. Their reply: no reth in
their repo, no such file, and 156,499 appears nowhere in their records. Fixed in
the source; recorded here.

### The comparison that came out of it, which is worth more than the mistake

Their per-block decomposition against this fleet's, on the same box:

| | this fleet | gov5 |
|---|---:|---:|
| block | 163,000 tx | 22,857 tx |
| import total | 676 ms | 148.2 ms |
| **execution per transaction** | **3.586 µs** | **3.403 µs** (3.033 broadcast) |
| non-execution per transaction | **0.56 µs** | **3.08 µs** |

**Per-transaction execution is the same within 15%.** Two clients, two
languages, two state backends, and the EVM costs the same per transfer — which
says the throughput difference between this fleet and gov5 is not execution
speed at all. It is that a 163,000-transaction block amortises fixed per-block
cost over seven times as many transactions: 0.56 µs against 3.08.

That cuts against a target this file has been circling. The follower's 584.6 ms
of execution is 86% of its import and it looked like the obvious thing to
attack — but at 3.586 µs a transfer it is already at the same cost as another
client's, so parallel execution is an improvement to make, not a gap to close.
The gap this fleet still has is against N42-26, who run the same serial
`payload/src/lib.rs` at the same block size, and that one cannot be explained by
amortisation.

### reth's sender-recovery cache does nothing here either

| | import median | p90 | win2 / win3 |
|---|---:|---:|---:|
| `--engine.sender-recovery-cache` | 676 ms | 763 ms | 65,197 / 65,190 TPS |
| without it | **669 ms** | **737 ms** | **65,140 / 65,197 TPS** |

Windows 2 and 3 reproduce to the transaction across the pair. The cache is
inert on this import path.

gov5 reached the same conclusion on a Go client with a different pool, a
different state backend and a different cache, by tracing hit rates rather than
by A/B: theirs is consulted zero times because the sender is already on the
pooled transaction object when the hint pass asks. Two independent clients, two
methods, same answer — which is worth more than either measurement alone, and is
the strongest evidence in this file for anything.

Tenth confirmed-but-inert mechanism. It also retires the sizing change twice
over: gov5 withdrew the finding it was based on, and this A/B says the cache's
existence changes nothing to size.

### The second sender recovery is real, and free

Two rounds settle a question that took three attempts to ask properly.

**First attempt.** Switching reth's `--engine.sender-recovery-cache` off changed
nothing (676 → 669 ms, windows reproducing to the transaction), and that was read
as "the sender is not recovered twice". It does not follow: a cache that never
hits is indistinguishable from no cache.

**Then the source, rather than the inference.** reth consults the cache once per
transaction on the import path (`tx_iterator_for_payload`), so the null had only
one reading left — asked, and missing. And the reason is structural rather than a
matter of size: the cache has exactly two consumers, devp2p transaction gossip
and block import, and both recover-or-insert. This fleet runs
`--disable-tx-gossip` and admits over the binary ingest and RPC, so **nothing
populates it before import** and it cannot hit by construction.

**So the ingest was made to populate it** (`try_recover_with_cache`, the entry
devp2p uses), with the cache sized at four times the pool — 8,388,608 slots,
fifty-one times a block, hits guaranteed:

| | import median | p90 | win3 |
|---|---:|---:|---:|
| cache never populated | 676 ms | 763 ms | 65,197 TPS |
| populated, 8.4M slots | **661 ms** | **743 ms** | **65,197 TPS** |

**Nothing.** 2.2% on the median, window 3 identical to the transaction.

And this null says something the first one could not. The cache is populated and
must hit, so the second recovery **is** happening and removing it **does not
help**. reth recovers senders in parallel ahead of the execution loop — the loop
waits on an already-recovered iterator, which is what its `transaction_wait`
metric measures — so the ~50 µs a transaction is paid on cores that are idle
anyway. This fleet uses 6% of its machine. Work removed from an idle core is not
time saved.

Eleventh confirmed-but-inert mechanism, and the most carefully established one:
the mechanism is real, the duplication is real, and the saving is zero because
the resource it saves is not scarce here.

The sizing goes back to upstream's `1 << 17`. Four times the pool is about
440 MB a node for a 2.2% that this rig cannot distinguish from noise, and this
fleet's first requirement is memory. `N42_SENDER_CACHE_MULT` keeps the sweep
available. The ingest keeps populating the cache: it costs one insert per
transaction on a path that already had the sender in hand, and it is the wiring
that should have been there.

## Round 19: the gas tier is exhausted, and what that leaves

Doubling the tier, everything else held:

| tier | tx a block | cycle | TPS |
|---|---:|---:|---:|
| 3.42 G | 163,000 | 2.500 s | **65,197** |
| 6.84 G | 326,000 | 5.000 s | **65,197** |

Identical to the transaction. Twice the block, twice the cycle: per-block fixed
cost is already negligible against per-transaction cost, and **bigger blocks are
finished as a lever**. The +11% that 480M → 3.42G bought was the last of the
amortisation, not the start of a trend.

That reduces the problem to one line. The serial chain is 12.5 µs a transaction:

| | per transaction |
|---|---:|
| propagate | 1.9 µs |
| **import (execution)** | **4.2 µs** |
| **build (execution + selection)** | **5.5 µs** |
| seal | 0.9 µs |

Execution appears twice — the leader executes to build, every node executes to
validate — and is 9.7 of the 12.5. 160,000 TPS needs 6.25 µs, and no combination
of the other three reaches it: removing propagation entirely leaves 10.6.

**So parallel execution is necessary, and at N42-26's stated 6.5x for simple
transfers it is also sufficient** — 1.9 + 0.9 + 1.5 + 0.9 = 5.2 µs, about
192,000 TPS. Everything else measured in this file is a rounding error against
it.

### The two routes to it, priced

reth already implements parallel execution, gated on the block carrying an
EIP-7928 block access list (`payload_validator.rs`: `has_block_access_list()` →
`bal::execute_block`). N42-26's roadmap says it never fires for them because
they are on Cancun. This chain declares `osakaTime = 0`, so the fork is not the
obstacle here — the transport is:

* `getPayloadV5` (Osaka) returns an envelope with **no** BAL.
* The BAL rides in `ExecutionPayloadV4`, carried by `newPayloadV5` (Amsterdam).
* This repo's Engine API adapter tops out at `newPayloadV4` and **explicitly
  refuses V5**.

So the work is plumbing, not algorithms: Amsterdam in the chainspec, V4 payload
and V5 methods in the adapter, and the BAL carried through the seal and the
block gossip encoding. reth's half is already written.

The alternative is writing a parallel block executor, which is N42-26's plan B
and which their own roadmap stages over four phases. The plumbing is cheaper.

## Round 20: reth already has a parallel executor, and nine gates to reach it

The arithmetic in round 19 left one route to the target, and this round
established that the executor for it is already written — in reth, behind a gate
this fleet had never opened.

### It is real, and it is gated on one field

`payload_validator.rs::bal_path_eligible` chooses between a serial `while` loop
and `payload_processor::bal::execute_block`, and the choice is `bal.is_some()` —
the fork check next to it is still a TODO. The parallel side is not scaffolding:
`rayon::Scope`, one worker per pool thread, speculative execution in parallel,
and a commit loop that only applies state diffs in order.

N42-26's roadmap says it never fires for them because they are on Cancun, and
lists a parallel executor as P0 work staged over four phases. **This chain
declares `osakaTime = 0`, so the fork was never the obstacle here.** The
transport was.

### Nine gates, eight passed

Each was found by reth's own error, and the error moved one step per round:

| | symptom | cause |
|---|---|---|
| 1 | `-38005 Unsupported fork` | the adapter stopped at V4; Amsterdam refuses `(V3, attrs)`, `(V4, payload)`, `(V5, getPayload)` |
| 2 | `-38003 Invalid payload attributes` | EIP-7843's slot number, required post-Amsterdam and refused before it |
| 3 | `no payload build for id` | symptom of 4 |
| 4 | `could not transform version=V6` | `MissingBlockAccessList` |
| 5 | — | **this repo's `default_n42_payload` lacks upstream's `with_bal_builder_if`** |
| 6 | still `MissingBlockAccessList` | **the built list was then dropped: `EthBuiltPayload::new(.., None)`** |
| 7 | `-38005` on the *import* side | followers rebuild from gossip, which carried no list |
| 8 | still `-38005` | **`blockAccessList` is nested inside `executionPayload`, and serde ignored it silently** |
| 9 | `no gov5 header variant hashes to the payload's block hash` | the header's `block_access_list_hash` — open |

Gates 5, 6 and 7 are one root cause seen three times: **forking a file does not
fork what upstream adds to it later.** One upstream line corresponds to two
holes here, and the third has no upstream counterpart at all because gov5's
block format is ours.

Gate 8 is the subtlest thing found today. `blockAccessList` lives *inside*
`executionPayload` — Amsterdam types that field as `ExecutionPayloadV4`, a V3
payload plus the list — and serde ignores fields it does not recognise. Read at
the envelope's top level it is always absent, silently, and the first sign is
`Unsupported fork` three hops away in a follower. What located it was a wire
round-trip test *passing*: with the encoding proved good, the fault had to be
upstream of it.

Gate 9 is a different shape again: the information is **not in the protocol**.
The Engine API carries the access *list*; the header carries its *hash*, which
the execution layer derives. A header rebuilt from a payload therefore cannot
have it. gov5's `withdrawals_root` and `requests_hash` have the same problem and
the reconstruction already solves it by trying both candidate values and letting
the block hash decide — the access-list hash was added as a fifth dimension, and
does not yet match.

### And a regression that nearly shipped

Making `forkchoiceUpdated`-with-attributes always use V4 with a slot number is
required on Amsterdam and **refused on every fork before it**. Seven consecutive
rounds ran the Amsterdam genesis, so the fleet's normal configuration was broken
and silent for all of them. A regression round on the default genesis is what
found it; without that the tree would have been green, well-committed and unable
to start a chain.

Fixed with the newest-first fallback whose constant had already been written and
never used. The narrower lesson: **a change should be scoped as tightly as the
reason for it.** The reason was "Amsterdam needs V4"; the code said "every call
with attributes uses V4".

Baseline re-verified after the fix: windows 2 and 3 both **65,197 TPS** at a
2.500 s cycle, identical to before.

### Where this leaves the target

Not reached. The comparable figure is 65,197 TPS at 163,000 transactions a block
with 2,000,000 recipients, against a target above 160,000. The route to it is
established, the executor exists, eight of nine gates are open, and the ninth is
characterised precisely rather than guessed at.

### Gate 9, isolated into a test rather than a fleet

The ninth gate is now a unit test instead of a four-minute round, which is the
trick gov5 took from gate 8 applied to itself: `reconstruct_gov5_h2_block` is
handed a normalized Amsterdam payload and asked to reproduce the sealed hash.

Two things fell out of it immediately, neither visible from the fleet:

**A finding recorded here an hour ago was wrong, and the way it was wrong is the
point.** It said the access-list hash has two schemes and the payload conversion
used the wrong one, so the normalizer was changed to recompute it before
sealing. That reading came from a malformed test object: the test header left
the blob-gas fields unset, so `execution_data_for_block` built a *pre-Cancun*
payload, which the test then wrapped in a V4 variant — an object no execution
layer would produce. Give the test header its Cancun fields and the conversion
computes the hash correctly. The "fix" was overwriting a right answer with
`None`, and it has been removed.

Two malformed-input conclusions in one session, both written down before being
checked against a well-formed case. The first was `22,000 x 4,096`; this one is
a header built by hand that no producer would emit. **A test fixture is an input
like any other, and a conclusion drawn from one that could not occur is not a
finding about the system.**

**What the test did earn is the field-by-field comparison**, which "no variant
matched" never gives. Against a well-formed Cancun header the differences are:

| field | sealed | rebuilt from payload | already a candidate |
|---|---|---|---|
| `ommers_hash` | zero | empty-ommer root | yes |
| `withdrawals_root` | gov5's nil | empty trie root | yes |
| `block_access_list_hash` | one value | **another** | yes, and still not matching |

The first two are the variants this reconstruction was already built to try. The
third is open: both the sealed value and the payload's are present in the
candidate set and the hash still does not reproduce, so the remaining difference
is either a fourth field or the candidate set is being applied wrongly. The test
stays in the tree, `#[ignore]`d, because it answers this in zero seconds where a
fleet round takes four minutes and a base-fee decay.

### The staleness guard has a blind spot

Gate 9 also cost two rounds to a stale binary for the third time today. The
reconstruction runs in the *node* — `engine-types/src/engine_validator.rs` calls
it while validating `newPayload` — and the fix was compiled into
`h2_validator` but not into `n42`.

The guard added earlier checks the validator binary against its sources and says
nothing about the node's. Its first two failures were false positives (a test
file, a different example); this one is a false negative, which is the more
expensive direction.

## Round 21: gate 9 was on the leader, and the parallel executor is a net loss here

### Gate 9, found by the unit test and verified on the fleet

The reconstruction was never the problem. alloy's `from_block_unchecked`
produces a **V4** payload for any header carrying `block_access_list_hash`, and
fills the list field with the 32-byte hash as a placeholder. This repo's
`execution_data_for_block_with_bal` handled `V3 => V4` and passed anything else
through unchanged — so the leader sealed and gossiped a payload whose "access
list" was a hash. Every importer then hashed the placeholder and no header
variant could match. The fix is one arm: replace the placeholder with the list
when the payload is already V4. The `#[ignore]`d test passes and is no longer
ignored; the field-by-field print now shows only the two fields the candidate
set already covers.

Two harness defects fell with it, both of the "wrong number rather than error"
kind: `tx_flood` treated a mined funding transaction as a funded sender, and the
ingest server took the pool's read lock and cloned every pending `Arc` on each
2 ms gate poll. The second is why the generator's ceiling was 51,719/s:

| | before | after |
|---|---:|---:|
| ingest submission rate | 51,719 tx/s | **127,240 tx/s** |

(`pool_size().pending` instead of `pending_transactions().len()`, and sender
recovery moved to a blocking thread.) The `forkchoiceUpdated` ladder also now
remembers the rung the chain accepted, so a pre-Amsterdam chain no longer pays
a refused V4 round trip on every leader build.

### The Amsterdam chain charges 205,000 gas to create an account

The first Amsterdam round reported an idle chain with a full generator. revm 43's
`AMSTERDAM` carries **EIP-8037** (state-creation gas, the reservoir model) along
with EIP-8038 and EIP-2780. Measured on this chain:

| transfer | gas needed | gas used |
|---|---:|---:|
| to an existing account | 21,000 | 21,000 |
| to a fresh account, value 0 | 21,000 | 21,000 |
| **to a fresh account, value > 0** | **~207,000** | **204,600** (183,600 at block level) |

A 21,000-gas creating transfer is mined *failed*: charged, nonce advanced, value
never moves — which is why "funding mined through nonce 6000" left every sender
at 0 wei. N42-26 measures on Cancun, where a creation costs the same 21,000 as an
update, so the comparable measurement on Amsterdam is updates only:
`F7_AMSTERDAM=1` now sets `--gas 210000` and runs a precreate flood (6,000 x 500
= 3,000,000 transfers cover 99.9% of the 2,000,000 recipient slots; 77 s to
mine) before the windows. Whether EIP-8037 belongs on this chain at all is a
chain-rules decision, not a benchmark one; it is recorded here, not made.

### reth's BAL executor, measured: 65,197 -> 40,809

Round `ams-bal6`, the 163,000-transaction tier with 2,000,000 recipients,
recipients precreated, every block through `execute_block_bal` (291 of 291):

| | Osaka, serial (`yamux2`) | Amsterdam, BAL parallel (`ams-bal6`) |
|---|---:|---:|
| win2 / win3 | 65,197 / 65,190 TPS | **40,809 / 40,923** |
| cycle | 2.500 s | **3.750 s** |
| block execution (follower) | 584.6 ms serial | **521–745 ms** parallel |
| follower payload -> canonical | 676 ms | **1,189 ms** |
| leader build | ~740 ms | **1,430–1,728 ms** |
| body on the wire | 12.2 MB | **24–25 MB** (16 MB compressed) |

The parallel path executes 163,000 transfers no faster than the serial loop
did, and everything around it got more expensive: the builder now constructs
the access list (+0.8 s on the leader), the importer verifies it after
executing (+0.5 s between "executed" and "state root finished"), and the list
doubles the body. Nothing here is a tuning problem: the executor is at parity,
and the costs are the EIP's.

So the arithmetic of round 19 — "parallel execution is necessary and at 6.5x
sufficient" — was right about necessary and wrong about where the 6.5x would
come from. reth's implementation is not it for this workload.

### What the serial chain now says

At the 163,000 tier the chain is build ~0.9 s + propagate ~0.3 s + import
~0.68 s = 1.9 s, measured against a 2.5 s cycle; the 0.6 s difference is vote
gating, step latency and pacing. 160,000 TPS at this block size is a cycle of
1.0 s, so **build and import each have to roughly halve, and propagation with
them** — which is what N42-26's 1.15 s cycle on the same serial builder says is
possible. The next rounds mine their devlogs for the execution-side changes
this fleet has not adopted, rather than continuing with the access list.

### Control: the Osaka chain with the same binaries

One round (`osaka-ctl1`), everything as `yamux2` except the binaries carrying
this round's fixes:

| | `yamux2` | `osaka-ctl1` |
|---|---:|---:|
| win2 / win3 | 65,197 / 65,190 TPS | **70,632 / 70,631** |
| cycle | 2.500 s | **2.308 s** |

Windows 2 and 3 reproduce to the transaction, as they did before. One round is
not a result by this file's rule; the candidate mechanism is the ingest gate no
longer taking the pool's read lock 500 times a second per connection — the
builder drains the same pool under the same lock — and it is measured properly
with `fleet7-repeat.sh` before it is claimed.

## Round 22: the leader's build, taken apart

### What the builder actually spends

The payload builder now logs its phases per block. At the 163,000-transaction
tier, before anything was changed:

| phase | ms |
|---|---:|
| pool (best transactions) | 72-97 |
| EVM execution | 184-273 |
| `builder.finish` (transactions trie, receipts trie, bloom) | **262-286** |
| QMDB root | 63-113 |
| assembly | 7 |
| total | 613-783 |

Execution is 1.3 µs a transaction, the same as N42-26's 229 ms for the same
block. The largest phase was the assembly, and half of it was a receipts trie
that the HotStuff header profile overwrites with gov5's keccak a moment later.

And the validator sees more than the builder spends: 862-917 ms for a build
whose function took 650-780, plus 125-149 ms to seal — the seal decoded the
whole payload to construct the header it stamps.

### N42-26's number is a different measurement

Their devlogs (read for the first time in full this round) settle what
156,499 — now 170,546 — is: a *controlled benchmark* mode by their own
`performance-records.md`. `N42_SKIP_TX_VERIFY=1`, a presigned ingest whose
sender the server trusts, and a leader payload cache with a follower fast path
that on a cache hit skips the EVM, the transactions root, the hashed post-state
and post-execution validation entirely (follower import 57 ms, EVM 0 ms). Their
parallel executor has never run in the live path
(`n42_parallel_evm_blocks_total = 0`). Every follower on this fleet executes
every block. The two numbers are not the same thing, and this file keeps
measuring the one where they do.

### Two changes, two rounds

**`n42Engine_getPayloadRaw`** — the built block as RLP instead of a 24 MB JSON
document with 163,000 hex strings in it, split into the header and each
transaction's bytes without decoding any of them, and the seal applied to the
header alone (`raw1`).

**The assembler** — the transactions root with its encodings produced in
parallel, the receipts trie not built on a HotStuff chain (`asm1`).

| | `osaka-ctl` (3 runs) | `raw1` | `asm1` |
|---|---:|---:|---:|
| win2 / win3 | 65,198 / 70,606 | 76,058 / 70,624 | **81,497 / 81,497** |
| cycle | 2.3-2.5 s | 2.14-2.31 s | **2.00 s** |
| seal | 125-149 ms | **4-6 ms** | 4-5 ms |
| build, validator's view | 862-917 ms | 817-887 ms | **642-692 ms** |
| `finish` | 262-286 ms | — | **104-122 ms** |
| leader commit -> body published | 1,069 ms | 925 ms | **733 ms** |

The raw path bought less than expected on the build itself (the JSON was not
the 150-200 ms the gap suggested; the seal was) and the assembler bought what
its phase said it would. Windows 2 and 3 of `asm1` are identical to the
transaction, at 15 blocks a window.

What is left on the leader: pool 75, execution 230, transactions trie ~110,
QMDB root ~100, and ~100 ms between the builder finishing and the validator
holding the block. On the follower: 684 ms from payload to canonical, of
which execution is ~584 — 2.5x what the builder spends executing the same
transactions. That ratio is the next thing to explain, with a profile rather
than a guess.

## Retraction: "gate 9" was not a header-reconstruction defect, and the Amsterdam round that "proved" it was misconfigured

Two things recorded above are withdrawn.

**The defect.** What this file calls gate 9 -- an Amsterdam header that would
not round-trip through a payload, isolated into the `#[ignore]`d test
`a_header_with_an_access_list_hash_is_reconstructible` -- was not in
`header_profile.rs` at all. On the raw-payload path a V4 payload was given
`slot_number = block number` while the EL-built header the fast seal signs
carried `slot_number: None`, so block 1 failed with "no gov5 header variant
hashes". Fixed in `crates/n42/h2-el-rpc/src/engine.rs` (`1b5a77cfe`), with an
Amsterdam round-trip test, by the other session working this tree. The
candidate-dimension work I added to `reconstruct_gov5_h2_block` was aimed at a
field that was never wrong.

**The round that seemed to confirm it.** The Amsterdam round reported here as
"the chain is not making empty blocks" was run without `F7_AMSTERDAM=1`. That
flag is what sets `F7_TX_GAS=210000` *and* runs the precreate flood; without it
no recipient exists, every transfer creates its account at ~205,000 gas, and
the senders are funded for 21,000. I had meanwhile added a competing `--gas`
to the bench script -- duplicating `F7_TX_GAS`, already committed in
`7f5be619e`, and putting two `--gas` flags on the precreate command line. The
round measured that misconfiguration. It says nothing about the chain, and the
edit is reverted.

The shared lesson is not about Amsterdam. Both errors are the same move:
**reading a dirty or unfamiliar tree as my own and acting before running
`git log`.** The same move committed another session's working tree as
`ab98225dc`, and launched fleet rounds that destroyed two of its measurements
mid-window. One tree and one fleet root need one writer at a time: take
`flock /data/blockchain/rust-fleet7-bench/.round.lock`, or at minimum check
`pgrep -f 'fleet7-benc[h].sh'`, before any round.

One residual, unfixed because the file belongs to the other session: the
`--gasceil` tier sizing computes `blk=$(( GASCEIL / 21000 ))` before
`F7_TX_GAS` is defaulted, so an Amsterdam round still sizes its pool and ingest
gate from 21,000 -- about ten times what a 210,000-gas block holds.

### Where the number actually stands

On the default Osaka path, on the tree including the other session's
raw-payload and parallel-assembler work: win1 32,599 / **win2 86,931** / win3
65,198 TPS, 100% occupancy and full(>=95%) in every window, win2 cycle 1.875 s.
This reproduces that session's independently measured 87k. Its provenance is
imperfect -- the round overlapped a rebuild of `h2_validator` (binary mtime
mid-round) -- so it corroborates rather than confirms.

Against the 160,000 target that is still a factor of 1.8, and the credit for
moving 65k -> 87k belongs to the raw payload channel, the parallel assembler
and the single follower decode, not to anything in this section.

## Round 23: the follower, profiled

### What the CPU profile of a follower says

`perf` on node 1 through a measured window, the `profiling` build, read by
thread. Symbols with `--no-inline`; with inline resolution `perf report` did
not finish in an hour against this binary's debug info.

| thread | share | what it is doing |
|---|---:|---|
| `cpu-NN` x32 (rayon) | ~60% | secp256k1 sender recovery (57% of all samples) and keccak |
| `tokio-rt` | 9% | RPC, ingest, gossip |
| `txpool-prewarm` | 7% | pool-side prewarming |
| **`payload-convert`** | **5.5%** | keccak 51%, RLP decode, trie |
| `engine` (serial execution) | 5.1% | blake3 15% (QMDB), then revm state/journal spread thin |
| `receipt-root`, `persistence` | 2-3% | |

Two things fell out of it, one large and one that rewrites an earlier
conclusion.

**The follower converted every payload three times.** `payload-convert` was as
busy as the execution thread. This validator's `convert_payload_to_block`
reconstructed the gov5 block (a full decode with the transactions trie), then
decoded again to learn the Ethereum-shaped hash, then called reth's validator
which decoded a third time — all before the block reached the engine, i.e.
before the "payload -> canonical" phase this file has been measuring. It now
decodes once and runs reth's field checks (shanghai/cancun/prague) on that
block; the gov5 reconstruction is header arithmetic on the same block.

**The sender-recovery cache was never wired.** `N42Node`'s executor builder
created `EthEvmConfig::new(chain_spec)` and stopped; upstream's attaches
`ctx.sender_recovery_cache()` there, and reth consults the cache *on the EVM
config* at import. So `--engine.sender-recovery-cache` measured inert twice
in this file (rounds 18) because the cache did not exist on the path that
reads it, and the ingest was handed `None` to populate. The "eleventh
confirmed-but-inert mechanism" was a mechanism that had never been enabled.
It is attached now, sized at twice the pool (`N42_SENDER_CACHE_MULT=2`,
4,194,304 slots).

### Measured

| | before (`asm2`) | after (`final`, run by the other session on this tree) |
|---|---:|---:|
| follower payload -> canonical, median | 713 ms | **626 ms** |
| leader's own `newPayload` round trip | 717-849 ms | **646-683 ms** |
| win2 | 86,930 | 86,931 |

Window 2 is 16 blocks either way — the 30 s window quantises to 12/13/14/15/16
blocks, which is 65,197 / 70,631 / 76,058 / 81,497 / 86,931 TPS, and every
number in rounds 22-23 is one of those. The cycle behind 16 is 1.875 s; the
next step is 17 blocks at 1.765 s, which window 1 of `conv2` reached once
(82,765, occupancy 89.6%).

### A regression, found by the other session

The raw payload path broke Amsterdam: for a V4 payload the client named the
block number as EIP-7843's slot while the header the fast seal signed had none,
and every importer rebuilt a header with the payload's slot and could not
reproduce the hash. Block 1 refused on every node. Fixed with a unit test that
takes an Amsterdam block over the raw path, seals it from the header and
reconstructs it as a follower would (`1b5a77cfe`). The Osaka rounds never saw
it because only V4 carries a slot.

Two sessions were launching rounds on one fleet root that evening and wiped
each other twice; `fleet7-bench.sh` now holds `flock` on the root for the
whole round.

## The window TPS in this file is an integer block count in disguise

Every window recorded above is full blocks of exactly 163,000 transactions over
30 seconds. So the "TPS" column was never a measurement of throughput; it is
`blocks x 163,000 / 30`, an integer times a constant:

| blocks | tps | cycle |
|---:|---:|---:|
| 12 | 65,200 | 2.500s |
| 13 | 70,633 | 2.308s |
| 14 | 76,067 | 2.143s |
| 15 | 81,500 | 2.000s |
| 16 | 86,933 | 1.875s |
| 17 | 92,367 | 1.765s |

Against what this file actually recorded: 65,198, 70,606, 76,058, 81,497,
86,931. The same numbers. The `osaka-ctl` / `raw1` / `asm1` comparison is
12/13 vs 14/13 vs 15/15 blocks.

Three consequences, and the third is the one that matters.

**The metric's resolution is one block** -- 5,433 TPS, which is 8.3% at twelve
blocks and 6.2% at sixteen. This is the mechanism behind the rule already in
CLAUDE.md that a difference under about 10% between single rounds is invisible.
It is not sampling noise; below one block the difference is *unrepresentable*.
A real 5% improvement reports as exactly zero, and a real 1% and a real 6%
report as the same number.

**The derived cycle is not an escape.** `cycle = 30 / blocks` is the same
integer wearing different units, and inherits the same resolution.

**"asm1's windows 2 and 3 are identical to the transaction" said nothing.**
It was recorded above as though the round were unusually reproducible. Both
windows held 15 blocks; two windows agreeing to the transaction is what
*always* happens when the block count matches and every block is full. It is
an artifact of the metric, not a property of the configuration.

### What to measure instead

The interval between consecutive block timestamps, as a mean and a spread over
the whole round. It is continuous, so a 3% change is a 3% reading; it gives a
variance for free, so a round can state its own confidence instead of borrowing
the repeat-script's; and it separates a cycle that got tighter from one whose
tail got shorter, which a window count cannot express at all.

### The target, in the unit that is continuous

At this block size, 160,000 TPS is a **1.019 s cycle** and today's window 2 is
1.875 s. The user's 720,000 would be 0.226 s. Stating the goal as "1.8x the
throughput" hides that the whole remaining distance is 856 ms of cycle, which
is the same budget the phase breakdown above is already itemising: pool 75,
execution 230, transactions trie ~110, QMDB root ~100, ~100 between the builder
finishing and the validator holding the block, and 684 on the follower.

## Round 24: the follower's loop, and a continuous cycle

### The instrument first

A 30 s window counts whole blocks, so at this tier its TPS is an integer times
5,433: 65,197 / 70,631 / 76,058 / 81,497 / 86,931 / 92,363 / 97,776 for 12 to
18 blocks. A 6% change is one count and a 5% one is invisible, which makes
every single-round comparison in rounds 22-23 a direction at best. The other
session pointed this out, and it is right. `scripts/fleet7-cycle.py` reports
the interval between consecutive full blocks (mean, median, p90) from the
execution layer's log, and `scripts/fleet7-viewcycle.py` splits each cycle on
the next leader's clock into four segments that sum to it exactly:
publish -> receive, receive -> vote, vote -> decide, decide -> publish.

Re-read that way, the day so far (node 0, full-block intervals, mean / median):

| round | change | cycle |
|---|---|---:|
| `instr1` | baseline + ingest fix | 2.303 / 2.310 s |
| `raw1` | raw getPayload, header seal | 2.166 / 2.159 |
| `asm1` | parallel assembler | 1.973 / 1.947 |
| `raw2` | loopback payload channel | 2.068 / 2.031 |
| `conv1` | one follower decode, sender cache wired | 1.878 / 1.852 |
| `cache4g` | cross-block cache 4096 MB | 1.871 / 1.865 (no effect) |
| `ahead1` | + build-ahead | 2.171 / 1.957 (worse; stays off) |
| `rawnp1` | raw newPayload | 1.868 / 1.837 (no effect on its own) |
| `direct2` | direct push, topic skipped | 1.842 / 1.834 |
| `rawbody1` | body handed over undecoded | 2.411 / **1.650** (p90 7.3 s) |
| **`yamuxbuf1`** | yamux buffer cap = window | **1.654 / 1.544 (p90 2.21)** |

### What the follower's loop was doing

`cache4g`, on the next leader's clock (medians): publish -> receive 248 ms,
**receive -> vote 922 ms**, vote -> decide 7 ms, decide -> publish 579 ms. The
execution layer's own import inside the 922 was 637. Timing the loop's stages
found the rest:

* **~210 ms handling the body event.** With the block topic carrying bodies,
  each member received a 15 MB message and, as a gossipsub mesh member,
  forwarded it to six peers — from the consensus loop, because the swarm is
  polled there. Direct push was off in every bench round (`F7_DIRECT_PUSH`
  defaulted to 0); on, and with the topic skipped once the push reached every
  member, the same event costs ~30 ms.
* **The body was decoded and re-encoded.** 163,000 transactions parsed into
  envelopes, the transactions root checked, every one encoded back for the
  payload — ~200 ms — and the execution layer decodes once more regardless.
  The body is now split into header and transaction bytes and the payload
  built from those (`execution_data_from_raw_parts`, tested equal to the
  typed path).
* **The JSON `newPayload` was not the cost it looked.** Replacing it with the
  loopback channel (5-13 ms to decode on the execution layer) moved the
  receive -> vote median by 30 ms. It stays, because it is strictly less
  work, but the ~285 ms it was supposed to explain was the two items above.
* **Importing on body arrival rather than proposal arrival** changed nothing
  measurable: the proposal follows the body by ~25 ms.

### The tail was yamux closing connections

Every recent round had 18-36 `yamux::connection: buffer of stream grows beyond
limit` per node, each followed by `dial failed`. The 16 MiB receive window
was set in round 18; yamux 0.12's separate 1 MiB per-stream buffer cap was not,
and it closes the whole connection when unread data passes it. A validator
that awaits a 700 ms import does not poll its swarm meanwhile, so a peer
sending into the window filled the cap in that time. When the dropped
connection carried a proposal or a quorum's votes, the view timed out at six
seconds — the p90 of 2.4 s and the p99 of 7 s. With the cap at the window:
zero drops, p90 2.21 s, and windows of 19/18/17 blocks.

### Where the cycle is now

`yamuxbuf1`: median 1.544 s, mean 1.654 s. The next leader's clock, from the
last decomposable round (`cache4g`, before the follower fixes) and the
follower's own timings after them: receive -> vote is now ~730 ms of which the
execution layer's import is ~700; decide -> publish ~580-640 of which the
build is ~500; publish -> receive ~250-300 for a 13-15 MB body across loopback,
which at 50 MB/s is the next thing that does not look like a floor.

160,000 TPS at this block size is a 1.019 s cycle. From 1.544: the import
(700), the build (500) and the transfer (250-300) each have to give.

## Round 25: every block is executed twice on the critical path, and a leader tenure

### The structure the phase table was hiding

Read from `yamuxbuf1`'s logs rather than from the earlier phase table: the
leader's `payload build phases` says `exec_ms=530` for 163,000 transfers, and
the follower's `raw newPayload` says `engine_ms=600-750`, of which the QMDB
root is 65-130. Both sides execute the same block at ~3.3 µs a transaction,
which is gov5's 3.135. The "follower executes 2.5x slower than the builder"
question this file carried was a comparison of two tiers; there is nothing
to explain.

What the numbers do say is structural. A block is executed **twice on the
critical path**: once by the leader that builds it, and once by the *next*
leader, which has to import it before it can build on it (and by every
follower, whose import-gated votes the quorum waits for). Two executions of
530-600 ms already exceed the 1.019 s cycle the target needs, before the
transfer and everything else. So either execution itself gets faster (round
21 says reth's parallel executor is at parity for this workload) or the
second execution leaves the critical path.

### Leader tenure

`hotstuff.leaderTenure` in the genesis (default 1): the leader of view `v` is
validator `(v / tenure) % n`. Tenure 1 is gov5's round-robin, byte for byte,
and the only value a mixed fleet can run -- the v4 shadow verifier and
`h2_finality` check the rule, so this is a chain parameter, not a node
option. With a tenure the same node leads consecutive views; it already
holds the state of the block it just built (`import_ms=1`) and can build
the next one while the fleet is importing this one. The cycle becomes
`max(build, transfer + import + vote)` instead of their sum -- on the
current numbers about 0.9-0.95 s, which is under the target. The price is
liveness: a leader that stops proposing costs up to `tenure` view timeouts,
because a timeout advances the view by one. `F7_LEADER_TENURE=<views>`
derives a bench genesis; `F7_INGEST_FORWARD=1` is needed with it (below).

### What the first tenure round found (tenure 16): three defects, none in the idea

`tenure16`: cycle mean 2.841 s against a 1.654 baseline, windows of 14/9/7
blocks, blocks not full. All three causes were found in the logs.

**1. reth's engine deadlocks against a long-lived payload job.** Every
leader timeout ("proposed; the votes did not arrive", seven in the round)
sat at a tenure boundary and was preceded by 8 seconds of silence on the
new leader: its execution layer's engine took no message at all -- not the
commit forkchoice, not the next `newPayload` -- until the validator's 8 s
RPC timeout fired. reth 2.5.1's engine tree (`tree/mod.rs`,
`wait_for_event`) blocks its whole message loop from the moment a
persistence completes until **every open payload job's build lease is
released**, and a lease is released when the job is resolved. Round-robin
never noticed: a job lives ~800 ms, from `forkchoiceUpdated` to
`getPayload`. Build-ahead holds one open across the whole view, and the
loop that would resolve it was itself waiting on the blocked engine. This
is also the mechanism behind "build-ahead measured worse" in rounds 22-24.
Fix: the prepared build is a task that resolves its payload the moment the
first build is done; the job lives for one build. (`tenure16b`: one
leader timeout, zero transport errors.)

**2. The pool is stale when the ahead build starts.** The pool learns of
a canonical block a little after the execution layer has it. A build
started the moment its parent was imported found all 163,000 of the
parent's transactions still pending (`txs=326288` per build) and executed
each one to fail on the nonce: `exec_ms` 1,134-3,157 instead of 530, and
one build of `txs=82652 gas=0`. Fix: the builder reads the sender's account
nonce from the state it is about to execute against (cached after the
first transaction of each sender) and skips a transaction below it before
executing. `tenure16b`: `stale=163000` skipped per ahead build, `exec_ms`
back to normal.

**3. A leader that builds every block has to refill its pool every block.**
The flood gives each node's ingest one seventh of the senders; the other
six sevenths reach a pool by gossip, and the gossip forwarder was JSON
`eth_sendRawTransaction` in batches of 1,000 with a queue of four and the
excess dropped -- tens of thousands a second at best. Round-robin needed
163,000 per seven cycles from that; a tenure needs 163,000 per cycle.
`tenure16b` shows it directly: occupancy 80-84%, blocks not full, at
1.77-2.0 s. Fix: `--el-ingest` hands gossiped transactions to the same
binary ingest the flood uses (parallel sender recovery, pool gate by
delayed reply), on four connections.

The rounds' numbers are **perturbed**, both ways: the other session's
rebuilds replaced binaries under `tenure16b`, and mine under its round 1.
Both fleets measure on one root; the numbers above are cited for the
mechanisms they exposed, not as results. The clean measurement is the next
round: tenure 16 with all three fixes, on an idle root.

## Round 26: the follower's import, taken apart with reth's own metrics

`F7_METRICS_BASE=<port>` puts each execution layer's Prometheus metrics on
loopback; one round of them (node 1, 155 blocks, 8.7M transactions) says what
a full block's import is made of, per block at 163,000 transactions:

| piece | per block | source |
|---|---:|---|
| payload conversion (decode + transactions trie) | 160-200 ms -> 80-114 -> **30-49** | `n42::engine_validator` log |
| transaction iterator wait | **81 ms** (0.50 µs/tx) | `transaction_wait_histogram` |
| EVM execution | **349 ms** (2.14 µs/tx) | `transaction_execution_histogram` |
| of which state reads from the provider | 63 ms (32k fetches at 1.96 µs) | `state_provider_account_fetch_latency` |
| QMDB root | ~95 ms -> **~39** | `state_root_histogram` |
| persistence, off the critical path in principle | 365 ms per batch of ~3 blocks | `persistence_duration` |

Four things moved.

**Prewarming off** (`--engine.disable-prewarming`, bench default): reth's
prewarmer executes the block's transactions on the worker pool to warm the
state cache while the serial loop runs; at this block size it is the same
work twice against the same cache. Execution 584 -> 365-500 ms; windows 17/16
-> 18/18. Pool-side prewarming stays: without it, 15/15.

**The conversion in parallel**: the transactions root over the payload's
bytes and the decodes into envelopes were sequential; now the root is
computed while the decodes run on the pool, and the trie itself is built in
parallel (`parallel_ordered_trie_root`: groups of up to 256 leaves by key
prefix, each a `HashBuilder`, joined into the top-level builder as branches —
checked equal to alloy's at twenty sizes). The same trie is the leader's
assembly. 160-200 -> 30-49 ms on the follower; assembly 104-139 -> 41-65 on
the leader (with the root below).

**The QMDB root batched**: the compat tree hashed as it went, about fifteen
blake3 calls per operation in sequence. It now hashes the leaves on the pool,
makes the structural writes without hashing, and rehashes each touched twig
once, in parallel. ~95 -> ~39 ms per block; gov5's fixtures unchanged.

**Persistence every eight blocks** (`--engine.persistence-threshold 8
--engine.memory-block-buffer-target 6`): the engine loop stops taking
messages while a batch hands off, and with 163,000-transaction blocks a
batch is ~365 ms. Fewer of them:

| round | persistence | cycle mean / median / p90 |
|---|---|---:|
| `qmdb1` | every 2 (default) | 1.752 / 1.603 / 2.139 s |
| `persist86` | every 8 | **1.386 / 1.376 / 1.712** |
| `persist20` | every 20 | 1.445 / 1.373 / 1.885 |
| `persist86b` | every 8 | 1.596 / 1.437 / 2.120 (one 5.5 s timeout) |

Windows of 25/21/20 blocks — **130,057 TPS in window 1 of `persist86`**, the
first six-figure window on the comparable workload.

Two negatives, recorded: forwarding gossiped transactions through the binary
ingest so the sender cache is populated for every transaction
(`F7_INGEST_FORWARD=1`) left `transaction_wait` at 0.56 µs/tx — the wait is
the iterator's channel receive, not recovery; and `--engine.disable-state-cache`
cannot be combined with pool-side prewarming.

What is left in the import: execution at 2.1 µs a transaction (~350 ms), of
which the provider's reads are 63 ms; the iterator's ~80 ms; the root ~40. On
the leader, execution ~200 ms of a ~350-400 ms build, with excursions to
400-700 that coincide with persistence. Between them, a 13-15 MB body across
loopback in ~250-300 ms.

## Round 27: tenure against round-robin, paired, and what starves a tenure

Same binaries (the other session's 01:19 build, with rounds 25-26 in it),
same supply, idle root, back to back.

| | tenure 1 (`base1d`) | tenure 16 (`tenure16d`) |
|---|---:|---:|
| cycle mean / median / p90 | **1.445 / 1.404 / 1.803 s** | 2.569 / 2.413 / 4.361 |
| windows (blocks) | 23 / 21 / 20, all full | 21 / 14 / 11 |
| occupancy | 94-100% | 72-81% |
| window TPS | 117,401 / 114,039 / 108,636 | 92,414 / 59,487 / 43,235 |
| leader timeouts / transport errors | 1 / 0 | 1 / 0 |

Round-robin at 1.40 s median is the round-26 result reproduced. The tenure
is worse -- and the reason is not the tenure.

**The ahead build works, and it is fast.** Node 1's first six blocks in its
tenure: cycle ~1.5 s, leader `exec_ms` 250-270 against the round-robin
leader's 400-900, `stale=163000` skipped per build at ~40 ms. Then:

**The tenure starves.** From the seventh block the leader's `exec_ms`
climbs (533, 817, 874, 928), the cycle stretches to 2.3-2.9 s, and at the
thirteenth its pool is empty -- a build of `txs=155004 gas=0`, every
transaction stale. Over the same seconds every *follower* pool sits at the
407k ingest gate (the flood's "deepest pool seen 408k"), and the leader's
goes 395k -> 245k -> 350k -> 0. The generator is gated by the fullest
pool, which is a follower's.

The mechanism: each node's ingest receives one seventh of the senders and
the rest arrives by gossip through the forwarder. Whatever the leader's
forwarder dropped under load -- and it drops at `INBOUND_TX_CAP` when its
lanes are stalled by the gate -- leaves that sender's later nonces
unbuildable *on the leader* for the whole tenure, while the followers,
which have the missing nonce, hold them as pending. Round-robin never
shows this: the next leader has what this one lacks. A single leader for
sixteen views has no such cover. The forwarder over the binary ingest
(round 25) raised the rate but not the guarantee; what the tenure needs is
every pool holding the same transactions without gossip, which is how gov5
floods (every transaction to every node) and now `tx_flood --ingest-all`
(`F7_INGEST_ALL=1`, with `F7_NO_TX_GOSSIP=1`). Measured next.

**`exec_ms` grows over a round in both modes.** The round-robin leader's
builds, in chain order (blocks 103-166): 220-300 ms with excursions that
get more frequent -- 547 at #124, 689 at #152, 899 at #166 -- roughly every
six to eight blocks, which is the persistence cadence, over a slow drift
from state growth (two million recipients being created). A tenure leader
meets every persistence, so it sees the excursions compressed: 250 -> 928
in twenty seconds. Not a tenure defect; the same curve, faster.

## Round 28: bodies over plain TCP, and what the leader's slowdown is

### The transfer

`scripts/fleet7-viewcycle.py` put publish -> receive at 248-307 ms for a
13-15 MB body on the same host: the libp2p push writes each copy through Noise
and yamux from the leader's swarm, polled on its consensus loop, and the
receiver reads it the same way. `crate::body_channel` carries the same bytes
over a plain socket of their own — one persistent connection per peer on the
member's libp2p port plus 1000, a length-prefixed frame per body, a task per
peer to write and a task per connection to read — and the libp2p push stays
as the fallback for a peer the channel does not reach.

| | before (`persist86`) | `body1` |
|---|---:|---:|
| publish -> receive, median | 248 ms | **28 ms** |
| decode on arrival | — | 12-18 ms |
| receive -> vote | 922 -> 700 ms (after round 26) | 699 ms |
| vote -> decide | 7 ms | 60 ms |
| decide -> publish | 579 ms | 675 ms |
| cycle, median | 1.376 s | 1.529 s (view) / 1.480 (intervals) |

The transfer is gone from the cycle and the cycle did not move by that
much: what the followers gained at the front, the leader lost at the back.

### The leader slows down inside a round

The other session measured a leader's build execution growing from 271 to
527 ms across its nine builds in one round, and a tenure leader from 250 to
928 ms within twenty seconds; this file's three-round repeats degrade the same
way (1.476, 1.564, 1.650 s medians in `rep-b`). The mechanism is the state
model: the QMDB compat tree is append-only and in memory, as gov5's is, so a
round of 163,000-transaction blocks adds ~326,000 entries — a new `Entry`, a
map insertion, a retired slot — to every node per block, tens of millions per
round, and every state read that misses the execution cache walks a map that
size. The builder reads more of them than the follower (it selects from a
pool of 400,000 as well as executing), which is why it shows first. That is a
storage-engine project, not a tuning knob; recorded here so the next
measurement is not misread as noise.

`--engine.suppress-persistence-during-build` (`suppress1`) did not change the
excursions (leader execution median 290, p90 516, max 1,000 ms; cycle 1.514 s
median) and is not adopted.

### What remains, in one place

Per full block on the follower: EVM execution ~350 ms at 2.1 µs a transaction
(the builder does the same transactions at 1.3 µs with a warm `CachedReads`;
the difference is reth's cached state provider and the per-transaction
receipt and index bookkeeping in the serial loop), the iterator's channel
~80 ms, the root ~40, conversion ~35. On the leader: execution ~200-290 ms
growing with the round, pool selection ~75, assembly ~50. The transfer is
~30. Consensus itself — vote to decide, decide to build start — is under
100 ms. At a 1.4-1.5 s cycle the target of 1.019 s needs the two executions
to give, and every follower still executes every block.

### The record, three rounds

`rep-c`, the configuration as committed at `7c2c15e8b` (direct push, body
channel, no block prewarming, persistence every eight, parallel conversion
and assembly, batched QMDB root), three consecutive rounds:

| | median | min | max | spread |
|---|---:|---:|---:|---:|
| win1 TPS | **114,584** | 113,747 | 118,553 | 4% |
| win2 TPS | 108,615 | 103,177 | 108,630 | 5% |
| win3 TPS | 97,762 | 97,760 | 103,171 | 6% |
| full-block cycle, median per round | 1.544 / 1.420 / 1.417 s | | | |

Against the day's start (`rep-a` at the same block size: win1 93,379, cycle
medians 1.73-1.81 s) and the file's first comparable figure (65,197 at 2.5 s).
