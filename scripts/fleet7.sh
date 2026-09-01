#!/usr/bin/env bash
# The all-Rust seven-node fleet: start, stop, watch, measure.
#
#   scripts/fleet7.sh up [--fresh]     start seven nodes (--fresh wipes the datadirs)
#   scripts/fleet7.sh down             stop them, gracefully
#   scripts/fleet7.sh status           heights, hashes, agreement
#   scripts/fleet7.sh stats            resident memory, threads, disk written
#   scripts/fleet7.sh watch <seconds>  sample stats over a window and report
#   scripts/fleet7.sh roll <i>         stop and restart one node, and check it rejoins
#
# Every launch argument comes from scripts/fleet7-env.sh; see the comment at
# the top of that file for why.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fleet7-env.sh"

usage() { sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; }

# --------------------------------------------------------------------- up ---
cmd_up() {
  local fresh= i d pin
  for arg in "$@"; do case $arg in --fresh) fresh=1 ;; esac; done

  [[ -x $F7_BIN/n42 ]] || { echo "no $F7_BIN/n42 -- cargo build --release -p n42 -p n42-h2-node --bins --examples" >&2; exit 1; }
  [[ -r $F7_GENESIS ]] || { echo "no genesis at $F7_GENESIS" >&2; exit 1; }

  cmd_down >/dev/null 2>&1 || true

  mkdir -p "$F7_ROOT"
  [[ -f $F7_ROOT/jwt.hex ]] || { openssl rand -hex 32 > "$F7_ROOT/jwt.hex"; chmod 600 "$F7_ROOT/jwt.hex"; }
  # A fresh round keeps the previous one's logs. `rm -rf` on the node directory
  # took the datadir and the evidence together, so a round's tails could not be
  # re-measured once the next round had started -- which is exactly when you
  # want to compare them.
  if [[ -n $fresh ]]; then
    for ((i = 0; i < F7_NODES; i++)); do
      d=$(f7_node_dir "$i")
      f7_rotate_logs "$d"
      rm -rf "$d/el" "$d/consensus" "$d/el.pid" "$d/v.pid"
    done
  fi

  f7_load_peerids
  f7_record_genesis
  echo "fleet: $F7_NODES nodes, profile $F7_PROFILE, $( [[ $F7_PIN == 1 ]] && echo "$F7_CORES_PER_NODE cores each" || echo "unpinned" ), root $F7_ROOT"

  for ((i = 0; i < F7_NODES; i++)); do
    d=$(f7_node_dir "$i")
    f7_place_keys "$i"
    f7_rotate_logs "$d"
    pin=$(f7_pin "$i")

    f7_el_args "$i"
    N42_TX_INGEST="${F7_INGEST:+127.0.0.1:$((F7_INGEST_BASE + i))}" \
    N42_PAYLOAD_SERVE="127.0.0.1:$((F7_PAYLOAD_BASE + i))" \
    N42_SENDER_CACHE_MULT="${F7_SENDER_CACHE_MULT:-2}" \
      RUST_LOG="$F7_LOG_EL" f7_spawn "$d/el.pid" "$d/el.log" $pin "$F7_BIN/n42" "${F7_EL_ARGS[@]}"
  done

  # Wait for every execution layer before starting any validator: a validator
  # whose Engine API is not answering yet spends its first views failing to
  # build, which on a fleet that all starts at once is every view.
  for ((i = 0; i < F7_NODES; i++)); do
    d=$(f7_node_dir "$i")
    for _ in $(seq 1 120); do
      grep -aq "RPC auth server started" "$d/el.log" 2>/dev/null && break
      sleep 1
    done
    grep -aq "RPC auth server started" "$d/el.log" || {
      echo "node $i: execution layer never opened its auth port; see $d/el.log" >&2; exit 1; }
  done
  echo "execution layers up"

  for ((i = 0; i < F7_NODES; i++)); do
    d=$(f7_node_dir "$i")
    pin=$(f7_pin "$i")
    f7_validator_args "$i"
    RUST_LOG="$F7_LOG_V" f7_spawn "$d/v.pid" "$d/v.log" $pin "$F7_BIN/examples/h2_validator" "${F7_V_ARGS[@]}"
  done
  echo "validators up"
}

# ------------------------------------------------------------------- down ---
cmd_down() {
  local i rc=0
  # Validators first: stopping an execution layer out from under a proposing
  # validator makes it log a wall of build failures on the way out.
  for ((i = 0; i < F7_NODES; i++)); do f7_stop "$i" v || rc=1; done
  for ((i = 0; i < F7_NODES; i++)); do f7_stop "$i" el || rc=1; done
  # Verify against the ports, not against the pidfiles that were just used.
  # "Stopped everything I have a record of" and "nothing is running" are
  # different claims, and a pidfile that names the wrong process makes the first
  # one true while the second is false -- after which `up --fresh` deletes a
  # datadir out from under a live node.
  # Every port the fleet binds, not just the execution layers'. The first
  # version of this check looked at 8600/8700 only, and three validators
  # survived a `down` on their consensus ports: they then dialled the next
  # fleet's members from a different chain, which showed up as
  # "peer is on a different chain; it will disconnect" and a chain stuck at
  # view 1 — a wedge with no cause visible anywhere in the new fleet's own logs.
  local ports=() i
  for ((i = 0; i < F7_NODES; i++)); do
    ports+=("$((F7_AUTH_BASE + i))" "$((F7_HTTP_BASE + i))" "$((F7_P2P_BASE + i))")
  done
  local listening
  listening=$(ss -ltnH 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' | sort -u |
    grep -Fxf <(printf '%s\n' "${ports[@]}") || true)
  if [[ -n $listening ]]; then
    echo "STILL LISTENING after stopping every recorded pid: $(echo "$listening" | tr '\n' ' ')" >&2
    ss -ltnp 2>/dev/null | grep -E "127.0.0.1:($(printf '%s|' "${ports[@]}" | sed 's/|$//'))\b" >&2 || true
    echo "Do not run 'up --fresh' until these are gone; it would wipe a live node's datadir" >&2
    echo "and a survivor from another chain wedges the next fleet at its first view." >&2
    return 1
  fi
  echo "fleet stopped"
  return $rc
}

# ----------------------------------------------------------------- status ---
cmd_status() {
  local i h heights=() min= agree=1 ref
  printf '%-6s %-8s %-8s %-10s %s\n' node el v height "head hash"
  for ((i = 0; i < F7_NODES; i++)); do
    h=$(f7_height "$i")
    heights+=("${h:--}")
    [[ -n ${h:-} ]] && { [[ -z ${min:-} ]] || ((h < min)); } && min=$h
    printf '%-6s %-8s %-8s %-10s\n' "$i" \
      "$(f7_pid "$i" el >/dev/null && echo up || echo down)" \
      "$(f7_pid "$i" v  >/dev/null && echo up || echo down)" \
      "${h:--}"
  done
  [[ -z ${min:-} ]] && { echo "no node answered"; return 1; }
  # Agreement is the only property worth printing for a fleet: seven heights
  # that differ by one are healthy, seven hashes that differ at one height are
  # a fork.
  echo
  echo "common height $min:"
  ref=$(f7_hash_at 0 "$min")
  for ((i = 0; i < F7_NODES; i++)); do
    h=$(f7_hash_at "$i" "$min")
    [[ $h == "$ref" ]] || agree=0
    printf '  node %s %s\n' "$i" "$h"
  done
  [[ $agree == 1 ]] && echo "AGREED at $min" || echo "DISAGREEMENT at $min"
}

# ------------------------------------------------------------------ stats ---
# Resident memory, thread count, and bytes actually written to disk per node.
# read_bytes/write_bytes in /proc/<pid>/io are what reached the block layer,
# so page-cache writes that were never flushed do not inflate them.
cmd_stats() {
  local i pid rss thr wr tot_rss=0 tot_thr=0 tot_wr=0 what
  printf '%-6s %-12s %8s %7s %10s\n' node process RSS_MB threads written_MB
  for ((i = 0; i < F7_NODES; i++)); do
    for what in el v; do
      pid=$(f7_pid "$i" "$what") || { printf '%-6s %-12s %8s\n' "$i" "$what" down; continue; }
      rss=$(( $(awk '/^VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0) / 1024 ))
      thr=$(awk '/^Threads/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
      wr=$(( $(awk '/^write_bytes/{print $2}' "/proc/$pid/io" 2>/dev/null || echo 0) / 1048576 ))
      printf '%-6s %-12s %8s %7s %10s\n' "$i" "$what" "$rss" "$thr" "$wr"
      tot_rss=$((tot_rss + rss)); tot_thr=$((tot_thr + thr)); tot_wr=$((tot_wr + wr))
    done
  done
  printf '%-6s %-12s %8s %7s %10s\n' TOTAL '' "$tot_rss" "$tot_thr" "$tot_wr"
  echo "datadir: $(du -sh "$F7_ROOT" 2>/dev/null | cut -f1)"
}

# ------------------------------------------------------------------ watch ---
# One measurement, not a stream: heights and written bytes at both ends of a
# window, so blocks/second and MB/block come out of the same sample.
# Loopback bytes: the fleet's whole conversation -- consensus gossip, block
# bodies, and every Engine API call -- crosses `lo` and nothing else on a quiet
# host does. Not attributable per process, which is why it is reported as one
# number for the fleet rather than a column per node.
lo_bytes() { cat /sys/class/net/lo/statistics/tx_bytes; }

cmd_watch() {
  local secs=${1:-300} i h0=() h1=() w0=0 w1=0 pid what rss n0 n1
  n0=$(lo_bytes)
  for ((i = 0; i < F7_NODES; i++)); do h0+=("$(f7_height "$i")"); done
  for ((i = 0; i < F7_NODES; i++)); do for what in el v; do
    pid=$(f7_pid "$i" "$what") || continue
    w0=$((w0 + $(awk '/^write_bytes/{print $2}' "/proc/$pid/io" 2>/dev/null || echo 0)))
  done; done
  f7_start_load "$secs"
  echo "watching ${secs}s from height ${h0[0]:--} ..."
  sleep "$secs"
  n1=$(lo_bytes)
  for ((i = 0; i < F7_NODES; i++)); do h1+=("$(f7_height "$i")"); done
  for ((i = 0; i < F7_NODES; i++)); do for what in el v; do
    pid=$(f7_pid "$i" "$what") || continue
    w1=$((w1 + $(awk '/^write_bytes/{print $2}' "/proc/$pid/io" 2>/dev/null || echo 0)))
  done; done
  local produced=$(( ${h1[0]:-0} - ${h0[0]:-0} ))
  echo
  cmd_stats
  echo
  echo "window        : ${secs}s"
  echo "blocks        : $produced ($(python3 -c "print(f'{$produced/$secs:.3f}')") /s, target $(python3 -c "
import json;print(round(1/json.load(open('$F7_GENESIS'))['config']['hotstuff']['period'],3))") /s)"
  echo "written       : $(( (w1 - w0) / 1048576 )) MB total, $(python3 -c "
p=$produced
print(f'{(($w1-$w0)/1048576)/p:.2f}' if p else 'n/a')") MB/block"
  echo "loopback      : $(( (n1 - n0) / 1048576 )) MB, $(python3 -c "
p=$produced
print(f'{(($n1-$n0)/1048576)/p:.2f}' if p else 'n/a')") MB/block"
  local txs
  txs=$(f7_txcount "${h0[0]:-0}" "${h1[0]:-0}")
  echo "transactions  : $txs sealed, $(python3 -c "
import sys
t,b,s=int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3])
print(f'{t/b:.1f}/block, {t/s:.1f} tps' if b else 'n/a')" "$txs" "$produced" "$secs")"
  echo "heights       : ${h1[*]}"
  echo "log growth    : $(du -shc "$F7_ROOT"/node*/[ev]*.log 2>/dev/null | tail -1 | cut -f1) of logs on disk"
}

# ------------------------------------------------------------------- roll ---
# Stop one node and start it again on the same datadirs. This is the only path
# that exercises what a restart actually depends on -- the consensus vote log,
# the libp2p identity, and the QMDB delta log replaying onto its checkpoint --
# and a fleet whose members cannot be restarted one at a time cannot be
# upgraded, moved, or repaired without stopping the chain.
cmd_roll() {
  local i=${1:?which node} d before after pin
  d=$(f7_node_dir "$i")
  f7_check_genesis || return 1
  f7_load_peerids
  before=$(f7_height "$i")
  echo "node $i: at height ${before:--}, stopping"
  f7_stop "$i" v
  f7_stop "$i" el
  f7_rotate_logs "$d"
  pin=$(f7_pin "$i")
  f7_el_args "$i"
  N42_TX_INGEST="${F7_INGEST:+127.0.0.1:$((F7_INGEST_BASE + i))}" \
  N42_PAYLOAD_SERVE="127.0.0.1:$((F7_PAYLOAD_BASE + i))" \
  N42_SENDER_CACHE_MULT="${F7_SENDER_CACHE_MULT:-2}" \
    RUST_LOG="$F7_LOG_EL" f7_spawn "$d/el.pid" "$d/el.log" $pin "$F7_BIN/n42" "${F7_EL_ARGS[@]}"
  for _ in $(seq 1 120); do grep -aq "RPC auth server started" "$d/el.log" 2>/dev/null && break; sleep 1; done
  f7_validator_args "$i"
  RUST_LOG="$F7_LOG_V" f7_spawn "$d/v.pid" "$d/v.log" $pin "$F7_BIN/examples/h2_validator" "${F7_V_ARGS[@]}"
  echo "node $i: restarted; how the QMDB forest came back:"
  grep -a "QMDB" "$d/el.log" | sed 's/\x1b\[[0-9;]*m//g' | head -4
  # A node that restarts but never commits again is worse than one that stayed
  # down, because the fleet still counts it toward a quorum it is not serving.
  echo "node $i: waiting to commit again..."
  for _ in $(seq 1 120); do grep -aq "^COMMIT" "$d/v.log" 2>/dev/null && break; sleep 1; done
  after=$(f7_height "$i")
  echo "node $i: height ${after:--} (fleet $(f7_height 0)), commits since restart $(grep -ac '^COMMIT' "$d/v.log")"
  grep -aci "error" "$d/el.log" | xargs -I{} echo "node $i: {} error lines in the execution layer log"
}

case ${1:-} in
  up) shift; cmd_up "$@" ;;
  down) cmd_down ;;
  status) cmd_status ;;
  stats) cmd_stats ;;
  watch) shift; cmd_watch "$@" ;;
  roll) shift; cmd_roll "$@" ;;
  *) usage; exit 1 ;;
esac
