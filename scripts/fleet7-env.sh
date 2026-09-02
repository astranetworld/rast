#!/usr/bin/env bash
# Single source of truth for the all-Rust seven-node fleet.
#
# Every other script sources this file, and the launch arguments are built
# here rather than in the script that starts a node. That is gov5's lesson,
# paid for once already (scripts/qs/qs-env.sh): the Windows fleet declared its
# environment inside the deploy script, a rolling restart driven by a different
# script silently dropped one lever, and the whole transaction index went with
# it. A lever declared outside the thing that launches the process is a lever
# that gets dropped.
#
# One node is two processes: an `n42` execution layer and an `h2_validator`
# consensus member that drives it over the Engine API. gov5 runs both inside
# one process; the port count and the memory profile below are the price of
# that difference, and it is measured rather than assumed.

set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# ---------------------------------------------------------------- layout ----
# NOT /tmp. /tmp on this host is a 69 GB tmpfs, so a datadir there is resident
# memory — the opposite of what this fleet is for.
: "${F7_ROOT:=/data/blockchain/rust-fleet7}"
: "${F7_GENESIS:=$REPO/crates/chainspec/res/genesis/n42_fleet7.json}"
: "${F7_BIN:=$REPO/target/release}"

# Refuse to launch a validator binary older than the code it was built from.
#
# A round takes minutes and reports a number whatever it measured, so a stale
# binary is not an error that announces itself -- it is a result, filed against
# the wrong change. This session came within one command of measuring a reverted
# edit because the binary was built at 07:45 and the source reverted at 07:54.
# F7_SKIP_STALE_CHECK=1 for the rare case where that is deliberate.
f7_check_binary_fresh() {
  local bin=$F7_BIN/examples/h2_validator newest
  [[ ${F7_SKIP_STALE_CHECK:-0} == 1 ]] && return 0
  [[ -x $bin ]] || return 0
  # `src` and `examples` only. Test and bench sources do not go into this
  # binary, and counting them made the guard refuse a round because a *test*
  # had been edited after the build -- which cost eighty minutes of a
  # measurement that then reported "no completed runs".
  # Exactly the sources that go into *this* binary: the crate's `src` trees
  # and its own example file. Earlier versions counted the whole `tests` and
  # `examples` directories, so editing a test -- or a different example --
  # refused a round that would have been perfectly valid. Both cost a
  # measurement.
  newest=$(find "$REPO/crates/n42/h2-node/src" "$REPO/crates/n42/h2-net/src" "$REPO/crates/n42/h2-consensus/src" "$REPO/crates/n42/h2-execution/src" "$REPO/crates/n42/h2-el-rpc/src" "$REPO/crates/n42/h2-node/examples/h2_validator.rs" -name '*.rs' -newer "$bin" -print -quit 2>/dev/null)
  [[ -z $newest ]] && return 0
  echo "REFUSING: $bin is older than $newest" >&2
  echo "  A round would measure the previous build and report it as this one." >&2
  echo "  cargo build --release -p n42-h2-node --example h2_validator" >&2
  echo "  (F7_SKIP_STALE_CHECK=1 to run anyway)" >&2
  return 1
}
: "${F7_NODES:=7}"
: "${F7_SEED:=n42-fleet7-validator}"

# ------------------------------------------------------------------ ports ---
# All below 32768, so none of them can be claimed by an outbound connection
# from another process: net.ipv4.ip_local_port_range starts at 32768 here, and
# the gov5 fleet lost a node on two consecutive starts to exactly that.
: "${F7_AUTH_BASE:=8600}"    # Engine API (auth), one per node
: "${F7_HTTP_BASE:=8700}"    # public JSON-RPC
: "${F7_INGEST_BASE:=8900}"  # binary transaction ingest, loopback only
: "${F7_PAYLOAD_BASE:=8950}" # raw payload channel to the validator, loopback only
: "${F7_DEVP2P_BASE:=8800}"  # bound but unused; devp2p is off, see below
: "${F7_P2P_BASE:=19000}"    # consensus libp2p
: "${F7_MOBILE_BASE:=21000}" # mobile_* endpoint, off unless F7_MOBILE=1

# ------------------------------------------------------------------- load ---
# Transactions per second the fleet is offered, 0 for none. A fleet measured on
# empty blocks says nothing about the costs that scale with transactions, and on
# gov5's fleet that is where the dominant one lived: with the tx-lookup tail
# tier off, every transaction wrote a random-key row into MDBX and
# `mdbx_txn_commit` went from 0.5 ms to 1.9 s a block at 22.8k txs
# (their docs/QS_TPS_BENCHMARK.md).
#
# One sender per funded account, because one key is one nonce sequence and two
# senders sharing a key race it. These are hardhat's well-known development
# accounts, the ones this genesis alloc funds; tests/e2e.sh already uses the
# first. Development keys, on a chain that exists for an afternoon.
: "${F7_TXGEN_RATE:=0}"
: "${F7_TXGEN_SENDERS:=4}"
F7_DEV_KEYS=(
  0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
  0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
  0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
  0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
  0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba
)

# f7_start_load <seconds> -- one sender per account, each pointed at a
# different member's RPC so no single node is both the only entry point and a
# proposer.
f7_start_load() {
  local secs=$1 i key rate chain
  [[ ${F7_TXGEN_RATE:-0} == 0 ]] && return 0
  chain=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['config']['chainId'])" "$F7_GENESIS")
  rate=$(python3 -c "import sys;print(float(sys.argv[1])/int(sys.argv[2]))" "$F7_TXGEN_RATE" "$F7_TXGEN_SENDERS")
  for ((i = 0; i < F7_TXGEN_SENDERS && i < ${#F7_DEV_KEYS[@]}; i++)); do
    key=${F7_DEV_KEYS[$i]}
    setsid "$F7_BIN/examples/send_tx" \
      --rpc "http://127.0.0.1:$((F7_HTTP_BASE + i % F7_NODES))" \
      --key "$key" --to 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f \
      --chain-id "$chain" --rate "$rate" --seconds "$secs" --quiet \
      > "$F7_ROOT/txgen-$i.log" 2>&1 < /dev/null &
  done
  echo "load: $F7_TXGEN_RATE tx/s offered by $F7_TXGEN_SENDERS senders for ${secs}s"
}

# f7_txcount <lo> <hi> -- transactions sealed in (lo, hi], read from node 0.
f7_txcount() {
  python3 -c '
import json, sys, urllib.request
port, lo, hi = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
def call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}", body, {"content-type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=5)).get("result")
total = 0
for n in range(lo + 1, hi + 1):
    b = call("eth_getBlockByNumber", [hex(n), False])
    total += len(b["transactions"]) if b else 0
print(total)
' "$((F7_HTTP_BASE))" "$1" "$2" 2>/dev/null || echo 0
}

# ------------------------------------------------------------ cpu binding ---
# The one lever that resizes every thread pool at once. tokio, rayon and reth
# all size themselves from `available_parallelism`, which on Linux reads the
# CPU affinity mask -- so pinning a node to N cores caps its worker threads,
# its rayon pool, and reth's prewarming and proof workers, without a flag for
# each. Unpinned on this 256-core host, a single node asks for hundreds of
# threads and seven of them ask for thousands.
# gov5 sizes GOMAXPROCS per node as nproc/7 and notes that raising it
# oversubscribes, because the critical path is largely serial -- a total CPU
# reading well under 100% is normal and is NOT evidence of spare throughput.
: "${F7_CORES_PER_NODE:=$([[ ${F7_PROFILE:-lean} == bench ]] && echo 32 || echo 8)}"
: "${F7_CORE_OFFSET:=0}"
: "${F7_PIN:=1}"

# ------------------------------------------------------------- allocator ----
# The execution layer is built with jemalloc, and jemalloc's defaults are sized
# for one big process on a big machine: an arena per few cores, each holding its
# own cache of dirty pages, and transparent huge pages on top, which round every
# one of those caches up to two megabytes. Seven nodes on one host pay that
# seven times over for memory none of them is using. Measured on this fleet, the
# execution layer's resident set was 288 MB of anonymous memory of which 258 MB
# was huge pages.
#
# `abort_conf:true` is deliberate: a typo in this string is otherwise ignored in
# silence, and a lever that quietly does nothing is worse than no lever. It
# earned its place immediately -- the obvious name for this variable,
# `_RJEM_MALLOC_CONF`, is the one tikv-jemallocator uses when it keeps the
# `_rjem_` prefix, and this binary does not. Setting that name changed nothing
# and said nothing. `MALLOC_CONF` is the one this build reads.
: "${F7_JEMALLOC:=abort_conf:true,narenas:2,dirty_decay_ms:2000,muzzy_decay_ms:0,background_thread:true,thp:never}"

# ----------------------------------------------------------- bench tier -----
# The `bench` profile is `lean` plus the four settings gov5 found decide the
# number (their docs/QS_TPS_BENCHMARK.md). Three of them were missing from a
# fresh rig on their side, and get any of them wrong and the round measures the
# harness instead of the chain.
#
# 1. Gas ceiling. The genesis says 30M; a throughput tier needs far more, and
#    reth takes it as --builder.gaslimit.
# 2. The gossip size cap, which presents as a gas cap: N42_MAX_GOSSIP_MB, set
#    by fleet7-bench.sh, because 1 MiB holds a block to ~8,500 transfers no
#    matter what the gas ceiling says.
# 3. Pool depth. The default cannot hold one block of this tier, so the builder
#    fills a block by draining and waiting -- 100% occupancy, long block time,
#    low CPU. Bigger is not better either: the pool's own work grows with depth,
#    so this is roughly two to four blocks' worth.
# 4. The sender cache. Recovering a sender is ~50 us of secp256k1 and it is the
#    largest import component whenever the followers' pools do not already hold
#    the block's transactions. reth's levers are --engine.sender-recovery-cache
#    and --engine.txpool-prewarming.
# Worker counts, as an array so a round can set them once. The lean tier keeps
# the frugal values; the bench tier takes upstream's defaults by omitting the
# flags entirely, which is what `F7_EL_WORKERS=()` means.
if [[ ${F7_PROFILE:-lean} == bench ]]; then
  : "${F7_WORKERS:=default}"
else
  : "${F7_WORKERS:=2}"
fi
if [[ $F7_WORKERS == default ]]; then
  F7_EL_WORKERS=()
else
  F7_EL_WORKERS=(
    --engine.storage-worker-count "$F7_WORKERS"
    --engine.account-worker-count "$F7_WORKERS"
    --engine.prewarming-threads "$F7_WORKERS"
  )
fi

: "${F7_BENCH_GASCEIL:=480000000}"
: "${F7_BENCH_POOL_SLOTS:=120000}"
: "${F7_BENCH_POOL_MB:=512}"

# --------------------------------------------------------------- profile ----
# `baseline` runs the stock defaults, so the cost of every lever in `lean` can
# be quoted against a number measured on this host rather than guessed. It has
# to be stock all the way down, allocator included, or the comparison quietly
# credits one lever with another's saving.
: "${F7_PROFILE:=lean}"
[[ $F7_PROFILE == lean ]] && export MALLOC_CONF="$F7_JEMALLOC"

# Log level. The validator's own logs are the fleet's only progress record, so
# they stay at info; debug costs real write bandwidth at seven nodes.
# `Not publishing a message that has already been published` is gossipsub
# telling us the duplicate suppression worked, once per duplicate, at WARN. On
# a seven-node mesh that is several lines a block and says nothing. Everything
# else stays visible on purpose -- `libp2p_request_response`'s "Dropping inbound
# stream because we are at capacity" is how a request storm announces itself,
# and silencing it would have hidden the one this fleet found.
: "${F7_LOG_EL:=info}"
: "${F7_LOG_V:=info,libp2p_gossipsub=error}"
: "${F7_MOBILE:=0}"

# --------------------------------------------------------- network identity -
# Fixed libp2p identities, so the fleet can be wired with a static mesh and a
# restarted node comes back as itself. Not secrets: loopback host identities,
# the same shape gov5 uses (a hex secp256k1 secret in the datadir).
F7_NETKEYS=(
  "$(printf '11%.0s' {1..32})" "$(printf '22%.0s' {1..32})"
  "$(printf '33%.0s' {1..32})" "$(printf '44%.0s' {1..32})"
  "$(printf '55%.0s' {1..32})" "$(printf '66%.0s' {1..32})"
  "$(printf '77%.0s' {1..32})"
)

# f7_peer_id <index> -- the peer id that node's fixed network key yields.
f7_peer_id() { "$F7_BIN/examples/h2_keygen" --libp2p-peer-id "${F7_NETKEYS[$1]}"; }

f7_node_dir() { echo "$F7_ROOT/node$1"; }

# The chain the running fleet was started on.
#
# `hotstuff` lives in the genesis `config`, which the genesis header does not
# cover, so a fleet whose committee pool or epoch length was edited under it
# keeps the same genesis hash and the same fork digest: the members still meet
# on the wire and still gossip. They diverge only at the committee-evidence
# link, where a restarted member computes a different `parentBeaconRoot` for
# every block and its execution layer rejects the chain from the first header
# on. That is a correct rejection and a completely opaque one -- observed here
# as `parent beacon root ... is not the parent's committee evidence` on a node
# rolled after the genesis had been edited mid-run. Recording the file at `up`
# and refusing to roll against a different one turns it into a sentence.
f7_genesis_fingerprint() { sha256sum "$F7_GENESIS" | cut -d' ' -f1; }

f7_record_genesis() { f7_genesis_fingerprint > "$F7_ROOT/genesis.sha256"; }

f7_check_genesis() {
  local recorded
  [[ -r $F7_ROOT/genesis.sha256 ]] || return 0
  recorded=$(cat "$F7_ROOT/genesis.sha256")
  [[ $recorded == "$(f7_genesis_fingerprint)" ]] && return 0
  echo "$F7_GENESIS has changed since this fleet was started." >&2
  echo "Restarting one member against it would put a node on different consensus" >&2
  echo "parameters than its peers; it would connect, and reject every block." >&2
  echo "Run 'fleet7.sh up --fresh' to move the whole fleet instead." >&2
  return 1
}

# --------------------------------------------------------------- validators -
# Derived, not drawn: the same seed reproduces the set in the genesis, so the
# fleet can be rebuilt from this file and the chain spec alone. Dev only.
f7_place_keys() {
  local i=$1 d
  d=$(f7_node_dir "$i")
  mkdir -p "$d/consensus" "$d/el"
  [[ -f $F7_ROOT/keys/validator-$i.key ]] || {
    mkdir -p "$F7_ROOT/keys"
    "$F7_BIN/examples/h2_keygen" --count "$F7_NODES" --seed "$F7_SEED" \
      --out-dir "$F7_ROOT/keys" > /dev/null
  }
  ( umask 077; printf '%s' "${F7_NETKEYS[$i]}" > "$d/consensus/network-key" )
}

# ------------------------------------------------------------ launch args ---
# f7_el_args <index> -> fills F7_EL_ARGS[]
f7_el_args() {
  local i=$1 d
  d=$(f7_node_dir "$i")
  F7_EL_ARGS=(
    node
    --chain "$F7_GENESIS"
    --datadir "$d/el"
    --authrpc.addr 127.0.0.1 --authrpc.port "$((F7_AUTH_BASE + i))"
    --authrpc.jwtsecret "$F7_ROOT/jwt.hex"
    --http --http.addr 127.0.0.1 --http.port "$((F7_HTTP_BASE + i))"
    --http.api eth,net,web3,txpool
    --ipcdisable
    --port "$((F7_DEVP2P_BASE + i))"

    # devp2p is off entirely, not merely undiscovered. Every block this node
    # will ever see arrives over the Engine API from its own validator, which
    # got it from the consensus gossip; a devp2p mesh between the seven would
    # carry the same blocks a second time and, worse, offer reth a backfill
    # path -- and backfill computes Merkle-Patricia roots in its own stage,
    # which on a QMDB chain rejects every header (see qmdb-reth/src/strategy.rs).
    --disable-discovery --no-persist-peers
    --max-inbound-peers 0 --max-outbound-peers 0 --disable-tx-gossip

    # reth writes a debug-level log file by default, 200 MB x 5 per node. At
    # seven nodes that is the largest single writer on the box and none of it
    # is chain data.
    --log.file.max-files 0
    --color never
  )

  if [[ $F7_PROFILE == lean || $F7_PROFILE == bench ]]; then
    F7_EL_ARGS+=(
      # Memory. The defaults are sized for a mainnet archive node on a
      # dedicated host; each of these is per node, so the figure to read is
      # seven times what it says.
      # F7_CROSS_BLOCK_CACHE_MB overrides it for a round: at the 163,000-
      # transaction tier with 2,000,000 recipients the accounts a block reads
      # do not fit in 128 MB, and a follower's execution reads them from the
      # state provider instead of the cache.
      --engine.cross-block-cache-size "${F7_CROSS_BLOCK_CACHE_MB:-128}"   # default 4096 MB

      # Worker counts, which are a memory setting in the lean tier and a
      # throughput setting in the bench tier -- the same three numbers, read
      # two different ways, and they were left at the memory reading when the
      # goal changed. Upstream defaults them to the node's parallelism (and
      # twice that for storage workers), which `taskset` makes 32 per node
      # here; pinning them to 2 caps the work that recovers senders and warms
      # state at a sixteenth of the cores the node is given.
      #
      # It matters at ingress rather than at import: 62-68 ms to add a
      # 22,857-transaction block cannot contain 1.14 s of serial secp256k1, so
      # recovery is already being paid when transactions enter the pool and
      # carried to import by the sender cache. Two threads is about 40,000
      # recoveries a second against an ingress of roughly 22,000 -- close
      # enough that oversupply may be where it first binds, which is a
      # hypothesis and not yet a measurement.
      "${F7_EL_WORKERS[@]}"

      # The RPC caches serve queries this fleet does not make.
      --rpc-cache.max-receipts 64
      --rpc-cache.max-headers 128
      --rpc-cache.max-cached-tx-hashes 2000
      --rpc-cache.max-concurrent-db-requests 32
      --rpc.max-tracing-requests 4
      --rpc.disable-metrics

      --txpool.disable-blobs-support
      --txpool.disable-transactions-backup

      # Address space, not resident memory -- but seven 8 TB maps is a lot of
      # page-table bookkeeping for a chain that will not reach one.
      --db.max-size 32GB
      --db.rocksdb-block-cache-size 64MB
      --db.balstore-cache-size 4
      --db.disable-metrics
    )
  fi

  # Values that differ by profile are emitted here, once. clap refuses a
  # repeated argument outright, so a `bench` block that merely appended its own
  # pool sizing on top of `lean`'s did not override it -- the node would not
  # start at all. That is at least loud; the same shape of mistake against a
  # last-wins parser would have quietly benchmarked the lean pool and reported
  # the result as the tier's.
  local pool_slots=2000 pool_mb=4 account_slots=16 validation_tasks=0 cache_blocks=64
  # The lean caps are sized for a fleet whose only client is its own validator.
  # A round has sixty-four flood threads plus a measurement polling every node,
  # and a node answers the overflow with HTTP 429 -- which killed a round
  # outright when the measurement treated that as fatal.
  local rpc_connections=32 blocking_io=8
  if [[ $F7_PROFILE == bench ]]; then
    pool_slots=$F7_BENCH_POOL_SLOTS
    pool_mb=$F7_BENCH_POOL_MB
    # One sender may have a whole window's worth of transactions in flight.
    account_slots=4096
    validation_tasks=4
    # A block of this tier is worth more than the lean cache holds, and the
    # measurement reads every block back.
    cache_blocks=256
    rpc_connections=512
    blocking_io=128
  fi
  F7_EL_ARGS+=(
    # The pool holds what one validator submits, not what a public mempool
    # receives -- until the bench tier, where it holds two to four blocks.
    --txpool.pending-max-count "$pool_slots" --txpool.pending-max-size "$pool_mb"
    --txpool.basefee-max-count "$pool_slots" --txpool.basefee-max-size "$pool_mb"
    --txpool.queued-max-count "$pool_slots"  --txpool.queued-max-size "$pool_mb"
    --txpool.max-account-slots "$account_slots"
    --txpool.additional-validation-tasks "$validation_tasks"
    --rpc-cache.max-blocks "$cache_blocks"
    --rpc.max-connections "$rpc_connections"
    --rpc.max-blocking-io-requests "$blocking_io"
  )

  # One lever at a time, opt-in, so a tier change is never confounded with the
  # thing a round is measuring. reth's own note on this one: "useful on chains
  # with short block times where persistence I/O can interfere with block
  # building latency" -- which is this tier exactly, and the leader's
  # commit-to-publish interval is the largest term left in the cycle.
  [[ ${F7_SUPPRESS_PERSISTENCE:-0} == 1 ]] && F7_EL_ARGS+=(--engine.suppress-persistence-during-build)

  if [[ $F7_PROFILE == bench ]]; then
    F7_EL_ARGS+=(
      --builder.gaslimit "$F7_BENCH_GASCEIL"
      # reth caps the fee of a transaction accepted over RPC at 1 ETH. That is
      # a rail for humans, and a load generator walks straight into it: this
      # tier's price has to be high enough that the base fee cannot climb past
      # it inside a window, and 21,000 gas at 100,000 gwei is 2.1 ETH a
      # transfer. Without this the whole round is refused during funding, and
      # what it looks like is a chain that will not accept transactions.
      --rpc.txfeecap 0
      # Sender recovery is the largest import component when the followers'
      # pools are cold, which sharded supply guarantees.
      # `F7_NO_SENDER_CACHE=1` drops it, which is the A/B that says whether the
      # cache carries a sender from pool admission to block import at all. gov5
      # measured their equivalent at exactly 0% under warm pools, because the
      # hint pass reads the sender off the pooled transaction object and never
      # reaches the cache.
      $( [[ ${F7_NO_SENDER_CACHE:-0} == 1 ]] || echo --engine.sender-recovery-cache )
      $( [[ ${F7_NO_TXPOOL_PREWARM:-0} == 1 ]] || echo --engine.txpool-prewarming )
      # F7_EL_EXTRA: any further execution-layer flags, for a single-variable
      # round (e.g. --engine.disable-prewarming). Word-split on purpose.
      ${F7_EL_EXTRA:-}
    )
  fi

  # No flag twice. clap refuses a repeated argument, so a profile that appends
  # its own value on top of another profile's does not override it -- the node
  # simply does not start, and the round dies after the fleet has been wiped and
  # relaunched. That has cost two rounds here; catching it while the array is
  # being built costs nothing and says which flag.
  local repeated
  repeated=$(printf '%s\n' "${F7_EL_ARGS[@]}" | grep '^--' | sort | uniq -d | tr '\n' ' ')
  if [[ -n ${repeated// /} ]]; then
    echo "fleet7-env: profile $F7_PROFILE builds duplicate execution-layer flags: $repeated" >&2
    echo "            each is set in more than one profile block; emit it once." >&2
    return 1
  fi
}

# f7_validator_args <index> -> fills F7_V_ARGS[]
f7_validator_args() {
  local i=$1 j d
  d=$(f7_node_dir "$i")
  F7_V_ARGS=(
    --chain "$F7_GENESIS"
    --index "$i"
    --bls-key "$(cat "$F7_ROOT/keys/validator-$i.key")"
    --el "http://127.0.0.1:$((F7_AUTH_BASE + i))"
    --jwt "$F7_ROOT/jwt.hex"
    --listen "/ip4/127.0.0.1/tcp/$((F7_P2P_BASE + i))"
    --datadir "$d/consensus"
    --propose
  )
  # `--el-rpc` turns on transaction gossip in both directions: this node
  # publishes what its pool admitted, and hands what the fleet publishes to
  # `eth_sendRawTransaction`. F7_NO_TX_GOSSIP=1 leaves it off, which is a
  # diagnostic rather than a tier -- the flood already submits to all seven
  # RPCs, so in a bench round the gossip carries nothing the pools do not
  # already have, and dropping it isolates what the forwarding costs. On a real
  # fleet it is how a transaction reaches the nodes it was not sent to.
  [[ ${F7_NO_TX_GOSSIP:-0} == 1 ]] || F7_V_ARGS+=(--el-rpc "http://127.0.0.1:$((F7_HTTP_BASE + i))")
  # F7_INGEST_FORWARD=1: what the fleet gossips reaches the pool through the
  # binary ingest rather than through eth_sendRawTransaction, which is worth
  # an order of magnitude to a leader whose pool has to refill every block
  # (a leader with a tenure). Opt-in, not implied by F7_INGEST: it is a
  # variable of its own, and a validator binary built before the flag existed
  # refuses to start with it.
  [[ ${F7_INGEST_FORWARD:-0} == 1 && -n ${F7_INGEST:-} ]] && F7_V_ARGS+=(--el-ingest "127.0.0.1:$((F7_INGEST_BASE + i))")
  [[ $F7_PROFILE == lean ]] && F7_V_ARGS+=(--worker-threads 2)
  # A throughput round is not trying to honour a block interval, it is trying to
  # find the ceiling, so the bench tier paces in milliseconds and overrides the
  # chain's period -- gov5's `--block-interval-ms`, by the same name. Under a
  # second the chain's timestamps leave the wall clock; that is a benchmark
  # property and never a fleet one.
  [[ -n ${F7_BLOCK_INTERVAL_MS:-} ]] && F7_V_ARGS+=(--block-interval-ms "$F7_BLOCK_INTERVAL_MS")
  # The view timeout has to move with the pacing. gov5's chains pair a 3,000 ms
  # period with a 6,000 ms baseTimeout -- twice the interval. Overriding the
  # pacing to 250 ms and leaving the timeout at the genesis value makes it
  # twenty-four times the interval, so a view where the leader does not propose
  # costs twenty-four block-times. Measured at 250 ms: 61 timeouts across seven
  # nodes in a round of 164 blocks, about 6% of views, each 6 s.
  [[ -n ${F7_VIEW_TIMEOUT_MS:-} ]] && F7_V_ARGS+=(--timeout-ms "$F7_VIEW_TIMEOUT_MS")
  # The leader hands its body to every member directly as well as publishing it.
  # Measured motivation: a body arrives in 30 ms at the median and 1.1 s at the
  # p90, and the p90 is the mesh queueing rather than the bytes.
  [[ ${F7_DIRECT_PUSH:-0} == 1 ]] && F7_V_ARGS+=(--direct-block-push)
  [[ $F7_MOBILE == 1 ]] && F7_V_ARGS+=(--mobile "127.0.0.1:$((F7_MOBILE_BASE + i))")
  # A static full mesh, as gov5 wires its seven. Peering everyone through one
  # node instead would make that node the fleet's single point of failure for
  # a property -- connectivity -- that HotStuff-2 otherwise tolerates losing.
  for ((j = 0; j < F7_NODES; j++)); do
    ((j == i)) && continue
    F7_V_ARGS+=(--peer "/ip4/127.0.0.1/tcp/$((F7_P2P_BASE + j))/p2p/${F7_PEERIDS[$j]}")
  done
}

# f7_pin <index> -- echoes the taskset prefix for that node, or nothing.
f7_pin() {
  local i=$1 lo hi
  [[ $F7_PIN == 1 ]] || return 0
  lo=$((F7_CORE_OFFSET + i * F7_CORES_PER_NODE))
  hi=$((lo + F7_CORES_PER_NODE - 1))
  echo "taskset -c $lo-$hi"
}

# ------------------------------------------------------------ process ops ---
# f7_spawn <pidfile> <logfile> <command...> -- start detached, and record the
# pid of the process that actually runs.
#
# NOT `setsid cmd & echo $!`. setsid execs in place when the caller is not
# already a process group leader and forks when it is, so `$!` is the node's pid
# most of the time and setsid's pid the rest of the time -- and which one you
# get depends on the shell that happened to call it. Observed here: one node's
# pidfile was off by one, `f7_stop` looked up a pid that no longer existed,
# decided the node was not running, and `down` reported "fleet stopped" with a
# node still holding its ports. The next `up --fresh` would have deleted that
# node's datadir underneath it.
#
# The shell writes its own pid and then execs, so the file names the process
# that will still be there afterwards, whichever way setsid goes.
f7_spawn() {
  local pidfile=$1 logfile=$2
  shift 2
  setsid bash -c 'echo $$ > "$1"; exec "${@:3}" >> "$2" 2>&1 < /dev/null' _     "$pidfile" "$logfile" "$@" &
  # Give the exec a moment, then check the file names something plausible.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ -s $pidfile ]] && return 0
    sleep 0.2
  done
  echo "warning: $pidfile was never written" >&2
  return 1
}

# f7_pid <index> <el|v> -- the recorded pid, only if it is alive and is still
# the process we started. A stale pidfile can name something else entirely
# after a reboot, and a fleet script that "stopped" such a pid would kill it.
f7_pid() {
  local d pid comm want
  d=$(f7_node_dir "$1")
  case $2 in el) want=n42;; v) want=h2_validator;; *) return 1;; esac
  [[ -r $d/$2.pid ]] || return 1
  pid=$(awk '{print $1; exit}' "$d/$2.pid" 2>/dev/null) || return 1
  [[ -n ${pid:-} ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  comm=$(cat "/proc/$pid/comm" 2>/dev/null) || return 1
  [[ $comm == "$want"* ]] || return 1
  echo "$pid"
}

# f7_stop <index> <el|v> [timeout] -- SIGTERM and wait. NEVER SIGKILL: a hard
# kill truncates the MDBX spill and leaves the QMDB forest snapshot behind the
# database head, which is a node that will not start again.
f7_stop() {
  local i=$1 what=$2 timeout=${3:-120} pid waited=0
  pid=$(f7_pid "$i" "$what") || return 0
  kill -TERM "$pid"
  while kill -0 "$pid" 2>/dev/null; do
    ((waited >= timeout)) && {
      echo "node $i $what (pid $pid) did not exit in ${timeout}s -- NOT killing; investigate" >&2
      return 1
    }
    sleep 1
    waited=$((waited + 1))
  done
}

f7_rotate_logs() {
  local d=$1 stamp f
  stamp=$(date +%Y%m%d-%H%M%S)
  for f in "$d"/*.log; do
    [[ -s $f ]] && mv "$f" "$f.$stamp"
  done
  return 0
}

# f7_height <index> -- the execution layer's head, or nothing if it is not up.
f7_height() {
  curl -s --max-time 5 -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    "http://127.0.0.1:$((F7_HTTP_BASE + $1))" |
    python3 -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null
}

# f7_hash_at <index> <number>
f7_hash_at() {
  curl -s --max-time 5 -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x$(printf %x "$2")\",false]}" \
    "http://127.0.0.1:$((F7_HTTP_BASE + $1))" |
    python3 -c "import sys,json;b=json.load(sys.stdin).get('result');print(b['hash'] if b else 'none')" 2>/dev/null
}

# Peer ids are needed by every caller that builds validator args; resolve them
# once here so no script computes its own and drifts.
F7_PEERIDS=()
f7_load_peerids() {
  local i
  ((${#F7_PEERIDS[@]} == F7_NODES)) && return 0
  F7_PEERIDS=()
  for ((i = 0; i < F7_NODES; i++)); do
    F7_PEERIDS+=("$(f7_peer_id "$i")")
  done
}
