#!/usr/bin/env bash
# Throughput round for the all-Rust seven-node fleet.
#
#   scripts/fleet7-bench.sh --tag baseline [--senders N] [--pertx N] [--offset N]
#                           [--windows N] [--window-sec N] [--profile-node i]
#
# One round is: fresh datadirs -> launch at the bench tier -> let the base fee
# decay -> fund a fresh sender set -> flood -> measure N windows.
#
# The structure and most of the rules come from gov5's
# `docs/QS_TPS_BENCHMARK.md` and `scripts/qs/bench-run.sh`, which paid for each
# of them with a wasted round. The ones that carry over unchanged:
#
#   * A fresh --offset every round. Derived accounts keep their nonces, and one
#     lost transaction leaves a hole that queues everything above it forever.
#   * Fresh datadirs, not a restart. There is no pool journal here, but a chain
#     that already ran a round carries its base fee forward, which is the same
#     trap one layer down.
#   * Let the base fee decay before flooding. A full block raises it 12.5%; a
#     round begun above the flood's price dies in its funding phase and the
#     windows dutifully report an idle chain.
#   * Report every window, and read occupancy beside TPS. Fast empty blocks and
#     slow full blocks give the same mid-range number for opposite reasons.
#   * Treat window 1 as the measurement. The base fee climbs during a round, so
#     a long round outlives its own validity.
#   * Pull profiles OUTSIDE the measured windows. gov5 measured a 15-25% drop in
#     the windows during which they fetched one.

set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

TAG=round
SENDERS=2000
PERTX=200
OFFSET=$(( $(date +%s) % 1000000 ))
WINDOWS=3
WINDOW_SEC=30
DECAY_SEC=30
CONC=32
RPCBATCH=100
# 100,000 gwei, not gov5's 10. Their fee arithmetic is the same but their blocks
# are not: at a 480M limit the EIP-1559 target is 240M, so every full block
# raises the base fee 12.5%, and at this chain's one-second pacing a 10 gwei cap
# is crossed about twenty seconds into the round -- inside the first window,
# where gov5's thirty-two-thread rig had a minute or more. Their rule 6 allows
# either neutralisation; raising the price is the one that survives a fast
# chain. It costs nothing here: funding is senders x (pertx+10) x 21000 x price
# and this genesis funds its accounts with far more than any round can spend.
# At 1e14 the cap is not reached until roughly ninety-eight consecutive full
# blocks, which covers three thirty-second windows.
GASPRICE=100000000000000
GASCEIL=
PROFILE_NODE=-1
SHARD=
# How many accounts the round's transfers pay.
#
# One was the old shape and it was the wrong one: a 163,000-transaction block
# paying a single account writes one account, where the same block with
# scattered recipients writes 163,000 -- five orders of magnitude of state that
# every earlier number in this file left out. N42-26's generator spreads over up
# to two million, so this does too, and the comparison is a comparison.
#
# It also makes parallel execution measurable at all: every transfer paying the
# same account is a write-write conflict on every transfer.
RECIPIENTS=${F7_RECIPIENTS:-2000000}

while (( $# )); do
  case $1 in
    --tag)          TAG=$2; shift 2 ;;
    --senders)      SENDERS=$2; shift 2 ;;
    --pertx)        PERTX=$2; shift 2 ;;
    --offset)       OFFSET=$2; shift 2 ;;
    --windows)      WINDOWS=$2; shift 2 ;;
    --window-sec)   WINDOW_SEC=$2; shift 2 ;;
    --decay-sec)    DECAY_SEC=$2; shift 2 ;;
    --conc)         CONC=$2; shift 2 ;;
    --rpcbatch)     RPCBATCH=$2; shift 2 ;;
    --gasprice)     GASPRICE=$2; shift 2 ;;
    --gasceil)      GASCEIL=$2; shift 2 ;;
    --profile-node) PROFILE_NODE=$2; shift 2 ;;
    --recipients)   RECIPIENTS=$2; shift 2 ;;
    --shard-senders) SHARD=--shard-senders; shift ;;
    -h|--help)      sed -n '2,8p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# The bench tier, exported so fleet7-env.sh builds the node arguments with it.
# Declared here and nowhere else, for the reason at the top of fleet7-env.sh.
export F7_PROFILE=${F7_PROFILE:-bench}
# Direct push on by default for a bench round: the leader hands the body to
# every member over its own stream and, with the whole mesh reached, does not
# publish it on the topic at all. Measured: the follower's transport drain for
# a body went from ~210 ms (topic delivery plus forwarding six copies from the
# consensus loop) to ~30 ms, and once yamux's buffer cap matched its window the
# block cycle's p90 fell from 2.4 s to 2.2 s with no connection drops.
# F7_DIRECT_PUSH=0 restores topic delivery, which a fleet with gov5 members needs.
export F7_DIRECT_PUSH=${F7_DIRECT_PUSH:-1}
# Sized from the gas tier rather than fixed, so the cap never quietly becomes
# the binding constraint when the tier moves. 8 MB holds a 480M-gas block of
# transfers (~2.5 MB of RLP) with room to spare, and that ratio is kept: a cap
# that starts truncating blocks presents as a gas ceiling that does not work,
# which is a slow thing to recognise.
export N42_MAX_GOSSIP_MB=${N42_MAX_GOSSIP_MB:-$(( ${GASCEIL:-480000000} / 60000000 ))}
# A separate chain, not the production-shape one. Its period is 1 s rather than
# 3, and its genesis gas limit is the tier's -- both are chain parameters, so a
# round cannot borrow them from a flag.
#
# The period is the chain's clock, not a floor on how fast blocks may be made.
# A header's timestamp is its parent's plus the period whatever rate blocks
# actually arrive at, so pacing below the period produces a chain whose own
# clock runs ahead of the wall clock rather than an invalid block. gov5 do the
# same when they benchmark a 3 s chainspec at 500 ms.
export F7_GENESIS=${F7_GENESIS:-$(cd "$HERE/.." && pwd)/crates/chainspec/res/genesis/n42_fleet7_bench.json}

# --gasceil sets the tier's gas limit in the *genesis*, not only as the builder's
# ceiling, because those are not interchangeable. A block's gas limit may move by
# 1/1024 of its parent's per block, so a chain born at 480M reaches a 960M
# ceiling after roughly 710 blocks -- eighteen minutes at this fleet's cycle,
# where the flood starts at thirty seconds. Pointed at a ceiling it has not
# climbed to yet, a round measures the chain it was born as.
#
# The derived genesis is written per round rather than checked in: it differs
# from the bench chain in one field, and a second near-identical genesis in the
# tree is one more thing to keep in sync for no reason.
if [[ -n $GASCEIL ]]; then
  export F7_BENCH_GASCEIL=$GASCEIL
  # The pool and the ingest gate are sized from the tier, not left where the
  # previous tier put them.
  #
  # A pool that cannot hold one block is a builder that can never fill one, and
  # nothing says so: the blocks come out short and the round reports it as the
  # chain's rate. At the 480M tier a block is 22,857 transfers against a
  # 120,000-slot pool -- five blocks' worth -- and at 3.42G it is 163,000
  # against the same 120,000, which is less than one. Three blocks' worth is the
  # ratio this file settled on: enough that the builder always has a full block
  # in front of it, not so much that the pool's own bookkeeping grows for
  # nothing.
  #
  # The gate follows the pool rather than the block, because its job is to stop
  # the generator from filling the pool, not to stop it from filling a block.
  blk=$(( GASCEIL / 21000 ))
  : "${F7_BENCH_POOL_SLOTS:=$(( blk * 3 ))}"
  : "${N42_TX_INGEST_HIGH_WATER:=$(( F7_BENCH_POOL_SLOTS * 5 / 6 ))}"
  export F7_BENCH_POOL_SLOTS N42_TX_INGEST_HIGH_WATER
  echo "tier sizing  : ${blk} tx/block, pool ${F7_BENCH_POOL_SLOTS}, ingest gate ${N42_TX_INGEST_HIGH_WATER}"
  DERIVED=${F7_ROOT:-/data/blockchain/rust-fleet7-bench}/genesis-${GASCEIL}.json
  mkdir -p "$(dirname "$DERIVED")"
  python3 -c "import json,sys
g = json.load(open(sys.argv[1]))
g['gasLimit'] = hex(int(sys.argv[3]))
json.dump(g, open(sys.argv[2], 'w'), indent=2)" "$F7_GENESIS" "$DERIVED" "$GASCEIL"
  export F7_GENESIS=$DERIVED
fi
# Amsterdam on top of whatever tier the round chose. reth executes a block in
# parallel only when it carries an EIP-7928 access list, and a builder makes
# one only past Amsterdam, so this one field in the genesis is the switch
# between the serial `while` loop and the rayon path for every node's import.
# Derived per round like the gas tier, and for the same reason.
if [[ ${F7_AMSTERDAM:-0} == 1 ]]; then
  DERIVED=${F7_ROOT:-/data/blockchain/rust-fleet7-bench}/genesis-amsterdam-$(basename "$F7_GENESIS")
  mkdir -p "$(dirname "$DERIVED")"
  python3 -c "import json,sys
g = json.load(open(sys.argv[1]))
g['config']['amsterdamTime'] = 0
json.dump(g, open(sys.argv[2], 'w'), indent=2)" "$F7_GENESIS" "$DERIVED"
  export F7_GENESIS=$DERIVED
fi
# The gas limit on every transfer, and whether the round creates its recipients
# before measuring.
#
# 21,000 is a transfer on every fork before Amsterdam. revm's Amsterdam carries
# EIP-8037, which charges state creation up front: a transfer that *creates*
# its recipient is refused below ~207,000 of limit and, mined with 21,000,
# fails inside execution -- charged, nonce advanced, value never moved. The
# first Amsterdam round here funded 6,000 senders that way and reported an idle
# chain. Measured on this chain: a creating transfer uses 204,600 gas, an
# update 21,000, so a 3.42G block holds ~18,600 creations or 163,000 updates.
#
# N42-26 measures on Cancun, where a creation costs the same 21,000 as an
# update. The comparable measurement on an Amsterdam chain is therefore updates:
# F7_PRECREATE runs a flood that touches every recipient slot before the
# windows start (6,000 x 500 = 3,000,000 transfers cover 99.9% of the 2,000,000
# slots, by the same hash the measured flood uses), and the windows then
# measure the same state writes N42-26's do after their first two million.
if [[ ${F7_AMSTERDAM:-0} == 1 ]]; then
  : "${F7_TX_GAS:=210000}"
  : "${F7_PRECREATE:=1}"
fi
: "${F7_TX_GAS:=21000}"
: "${F7_PRECREATE:=0}"
# The interval is a measurement parameter here, not a property of the chain.
export F7_BLOCK_INTERVAL_MS=${F7_BLOCK_INTERVAL_MS:-1000}
# The chain's own baseTimeout unless a round overrides it, and NOT a multiple of
# the pacing.
#
# gov5 pairs a 3,000 ms period with a 6,000 ms baseTimeout, and a first reading
# of that as "the timeout should be twice the interval" led to setting it to
# 500 ms at 250 ms pacing. Three runs each say that is 20% *slower*: 685,710
# transactions a round against 858,658 at the genesis value, with the two ranges
# not overlapping. The ratio is not the invariant. A timeout has to exceed the
# cycle a block actually takes, and this fleet's cycle at the 480M tier is
# 1.4-2.5 s however fast the pacing asks for blocks -- so a 500 ms timeout fires
# during ordinary operation and throws away views that were about to succeed
# (timeouts per block went 0.37 -> 2.09). gov5's 2x works because 6 s is
# comfortably longer than their block; 2x of 250 ms is shorter than mine.
export F7_VIEW_TIMEOUT_MS=${F7_VIEW_TIMEOUT_MS:-}
export F7_ROOT=${F7_ROOT:-/data/blockchain/rust-fleet7-bench}
source "$HERE/fleet7-env.sh"

# The output directory before anything can refuse, so a refusal leaves a record.
#
# Everything that rejects a round -- the staleness guard, the base-fee decay, the
# faucet -- used to run before `mkdir`, so an early exit produced no directory,
# no round.txt and no reason. Four rounds died that way and each cost a re-run to
# find out why. A failure that leaves nothing behind is the same defect class as
# a failure that leaves a wrong number.
OUT=$F7_ROOT/bench-$TAG
mkdir -p "$OUT"
# One round at a time on this root. Two sessions launching rounds on the same
# datadirs wiped each other's fleets mid-window twice in one evening; the lock
# is held for the whole round and a second launcher refuses rather than waits,
# because a round that waited would start on a chain it did not decay itself.
# fd 9 is closed (9>&-) on everything spawned below, or the nodes that outlive
# the round would keep the lock and the next round would refuse itself.
exec 9>"$F7_ROOT/.round.lock"
if ! flock -n 9; then
  echo "REFUSING: another round holds $F7_ROOT/.round.lock (pgrep -f 'fleet7-benc[h].sh')" >&2
  exit 1
fi
exec > >(tee -a "$OUT/round.txt") 2>&1

f7_check_binary_fresh || exit 1

# F7_LEADER_TENURE=<views>: every validator leads that many consecutive views
# (`hotstuff.leaderTenure`), so a leader builds block h+1 while the fleet is
# still importing h and one of a block's two executions leaves the critical
# path. A chain rule, so it is derived into its own genesis; the config section
# is not part of the genesis hash, so the chain id and hash are unchanged.
if [[ -n ${F7_LEADER_TENURE:-} ]]; then
  DERIVED=${F7_ROOT:-/data/blockchain/rust-fleet7-bench}/genesis-tenure${F7_LEADER_TENURE}-$(basename "$F7_GENESIS")
  python3 -c "import json,sys
g = json.load(open(sys.argv[1]))
g['config']['hotstuff']['leaderTenure'] = int(sys.argv[3])
json.dump(g, open(sys.argv[2], 'w'), indent=2)" "$F7_GENESIS" "$DERIVED" "$F7_LEADER_TENURE"
  export F7_GENESIS=$DERIVED
fi
CHAIN=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['config']['chainId'])" "$F7_GENESIS")
RPCS=$(for ((i = 0; i < F7_NODES; i++)); do printf 'http://127.0.0.1:%s,' $((F7_HTTP_BASE + i)); done | sed 's/,$//')

{
  echo "round        : $TAG"
  echo "tier         : gossip ${N42_MAX_GOSSIP_MB}MB, gas ceiling ${F7_BENCH_GASCEIL}, pool ${F7_BENCH_POOL_SLOTS}, pacing ${F7_BLOCK_INTERVAL_MS}ms, view timeout ${F7_VIEW_TIMEOUT_MS:-genesis}${F7_AMSTERDAM:+, amsterdam}${F7_LEADER_TENURE:+, leader tenure $F7_LEADER_TENURE}"
  echo "supply       : $SENDERS senders x $PERTX tx, offset $OFFSET, conc $CONC, batch $RPCBATCH${SHARD:+, sharded}, $RECIPIENTS recipients, gas $F7_TX_GAS${F7_PRECREATE:+, precreate $F7_PRECREATE}"
  echo "windows      : $WINDOWS x ${WINDOW_SEC}s after ${DECAY_SEC}s of base-fee decay"
}

"$HERE/fleet7.sh" up --fresh 9>&-

# Empty blocks until the base fee has actually decayed, rather than for a fixed
# time.
#
# A fresh chain does *not* start at its floor: block 1 is 875,000,000 wei and
# every empty block takes 12.5% off, so reaching the low thousands needs about
# 120 blocks. Whether thirty seconds contains 120 blocks depends on how quickly
# the fleet came up, and when it does not the flood starts against a base fee
# still in the tens of millions.
#
# That is not a hypothetical. Two rounds of the same build reported 43,426 TPS
# and 10,666 TPS; the difference was 7,887 wei against 31,060,570 at the start,
# and nothing in the output said so. The first diagnosis of it -- "the datadirs
# were not wiped" -- was wrong too: the chain was fresh both times and simply
# had not decayed as far.
#
# So the wait is on the number, with the old duration as the floor and a
# generous ceiling. A round that cannot reach the target says so and stops,
# because a round that starts above it is not measuring the tier it claims to.
: "${DECAY_TARGET:=100000}"
: "${DECAY_MAX_SEC:=180}"
read_basefee() {
  curl -s --max-time 5 -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}' \
    "http://127.0.0.1:$F7_HTTP_BASE" \
    | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result']['baseFeePerGas'],16))" 2>/dev/null || echo 0
}
DECAY_START=$SECONDS
sleep "$DECAY_SEC"
BASEFEE=$(read_basefee)
while (( BASEFEE > DECAY_TARGET && SECONDS - DECAY_START < DECAY_MAX_SEC )); do
  sleep 2
  BASEFEE=$(read_basefee)
done
echo "decay        : ${BASEFEE} wei after $((SECONDS - DECAY_START))s of empty blocks (target ${DECAY_TARGET})"
if (( BASEFEE > DECAY_TARGET )); then
  echo "REFUSING: the base fee did not reach ${DECAY_TARGET} wei in ${DECAY_MAX_SEC}s; the chain is not making empty blocks"
  exit 1
fi
echo "base fee     : $BASEFEE wei against a $GASPRICE cap"
if (( BASEFEE >= GASPRICE )); then
  echo "REFUSING: the base fee is at or above the flood's price; this round would die in funding"
  exit 1
fi

# The flood runs in the background; the windows are measured while it runs.
#
# Pinned off the fleet's cores. Signing is the flood's own cost -- a secp256k1
# signature per transaction, and it re-signs a batch it has to retry -- so an
# unpinned generator competes with the nodes it is measuring and the round
# reports the contention as the chain's.
FLOOD_CORES=${F7_FLOOD_CORES:-$((F7_CORE_OFFSET + F7_NODES * F7_CORES_PER_NODE))-$(($(nproc) - 1))}
FLOOD_PIN=""
[[ $F7_PIN == 1 ]] && FLOOD_PIN="taskset -c $FLOOD_CORES"
echo "flood cores  : ${FLOOD_CORES}"
# The binary ingest path, when a round asked for one. Funding stays on RPC --
# it is six thousand transactions once and it reads nonces back -- so the RPC
# list is passed either way.
INGEST_ARG=()
if [[ -n ${F7_INGEST:-} ]]; then
  INGESTS=$(for ((i = 0; i < F7_NODES; i++)); do printf '127.0.0.1:%s,' $((F7_INGEST_BASE + i)); done | sed 's/,$//')
  INGEST_ARG=(--ingest "$INGESTS")
  # F7_INGEST_ALL=1: every transaction to every node's ingest, so no pool
  # depends on gossip for what another pool holds. gov5's methodology, and
  # what a leader with a tenure needs; pair it with F7_NO_TX_GOSSIP=1 or the
  # fleet gossips what every pool already has.
  [[ ${F7_INGEST_ALL:-0} == 1 ]] && INGEST_ARG+=(--ingest-all)
  echo "ingest       : $INGESTS"
fi
# Create the recipients first, when the round asked for it (see F7_PRECREATE
# above). Synchronous: it has to be *mined*, not merely accepted, before the
# windows start, so after the flood exits the pool is watched until it drains.
if [[ $F7_PRECREATE == 1 ]]; then
  PRE_START=$SECONDS
  $FLOOD_PIN "$F7_BIN/examples/tx_flood" --rpc "$RPCS" --chain-id "$CHAIN" \
    "${INGEST_ARG[@]}" --recipients "$RECIPIENTS" \
    --senders 6000 --pertx 500 --offset $((OFFSET + 500000)) --gasprice "$GASPRICE" --gas "$F7_TX_GAS" \
    --conc "$CONC" --rpcbatch "$RPCBATCH" \
    > "$OUT/precreate.log" 2>&1 < /dev/null 9>&- || { echo "REFUSING: the precreate flood failed; see $OUT/precreate.log"; exit 1; }
  read_pending() {
    curl -s --max-time 5 -X POST -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"txpool_status","params":[]}' \
      "http://127.0.0.1:$F7_HTTP_BASE" \
      | python3 -c "import sys,json;r=json.load(sys.stdin)['result'];print(int(r['pending'],16)+int(r['queued'],16))" 2>/dev/null || echo 1
  }
  PENDING=$(read_pending)
  while (( PENDING > 0 && SECONDS - PRE_START < 900 )); do
    sleep 5
    PENDING=$(read_pending)
  done
  echo "precreate    : $(grep -c . "$OUT/precreate.log") log lines, pool at $PENDING after $((SECONDS - PRE_START))s, base fee now $(read_basefee) wei"
  if (( PENDING > 0 )); then
    echo "REFUSING: the precreate transfers did not drain within 900s"
    exit 1
  fi
fi

setsid $FLOOD_PIN "$F7_BIN/examples/tx_flood" --rpc "$RPCS" --chain-id "$CHAIN" \
  "${INGEST_ARG[@]}" --recipients "$RECIPIENTS" \
  --senders "$SENDERS" --pertx "$PERTX" --offset "$OFFSET" --gasprice "$GASPRICE" --gas "$F7_TX_GAS" \
  --conc "$CONC" --rpcbatch "$RPCBATCH" $SHARD \
  > "$OUT/flood.log" 2>&1 < /dev/null 9>&- &
FLOOD=$!
echo "flood        : pid $FLOOD, log $OUT/flood.log"

# Wait for funding to mine before the first window, or window 1 measures the
# funding phase instead of the flood.
for _ in $(seq 1 180); do
  grep -aq "mined through nonce" "$OUT/flood.log" 2>/dev/null && break
  # Only the flood giving up ends the round. Matching the word "error" caught
  # the flood's own diagnostics -- "submit failed: error decoding response
  # body" is one refused batch out of thousands, not a dead round -- and
  # aborted a round that was working.
  grep -aq "^Error:" "$OUT/flood.log" 2>/dev/null && { cat "$OUT/flood.log"; exit 1; }
  sleep 1
done
grep -a "faucet\|funding" "$OUT/flood.log"

for ((w = 1; w <= WINDOWS; w++)); do
  "$HERE/fleet7-measure.py" "$F7_HTTP_BASE" "$WINDOW_SEC" "win$w"
  # A profile is pulled between windows, never inside one.
  if (( PROFILE_NODE >= 0 && w < WINDOWS )); then
    "$HERE/fleet7-profile.sh" "$PROFILE_NODE" "$OUT/profile-win$w" 2>&1 | tail -3
  fi
done

echo "--- resources at the end of the round ---"
"$HERE/fleet7.sh" stats | tail -3
kill "$FLOOD" 2>/dev/null || true
tail -3 "$OUT/flood.log"
echo "round recorded in $OUT/round.txt"
