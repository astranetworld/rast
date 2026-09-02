#!/usr/bin/env bash
# A CPU profile of one node, and the folded stacks to read it with.
#
#   scripts/fleet7-profile.sh <node index> <output prefix> [seconds]
#
# gov5's nodes serve pprof over HTTP because Go's runtime carries a profiler.
# This one does not, so the profile comes from `perf` against the running
# process. The output is the same shape -- symbol, share of samples -- and can
# be read the same way.
#
# THE BINARY HAS TO CARRY SYMBOLS. `[profile.release]` in this workspace sets
# `strip = "symbols"`, so a profile of a release build resolves nothing and
# `perf report` spends minutes producing an empty file rather than saying why.
# Build the fleet with the `profiling` profile, which exists for this
# (`inherits = "release"`, `debug = "full"`, `strip = "none"`), and point
# F7_BIN at it:
#
#   cargo build --profile profiling -p n42 -p n42-h2-node --bins --examples
#   F7_BIN=target/profiling scripts/fleet7-bench.sh --tag prof --profile-node 0
#
# TIMING: gov5 measured that *pulling* a profile is not free, even though
# leaving the profiling flags on is: two windows during which they fetched one
# fell from ~11,800 to 9,903 and 8,759 TPS. Take profiles between measured
# windows, never inside one. `fleet7-bench.sh` does that for you.

set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$HERE/fleet7-env.sh"

# --report <prefix>: turn a recording into the two views, long after the round,
# when nothing is being measured.
if [[ ${1:-} == --report ]]; then
  prefix=${2:?output prefix}
  perf report -i "$prefix.data" --stdio --no-children --percent-limit 0.5 2>/dev/null |
    grep -v '^#' | grep -v '^$' | head -40 > "$prefix.flat.txt" || true
  perf report -i "$prefix.data" --stdio --children --percent-limit 1.0 2>/dev/null |
    grep -v '^#' | grep -v '^$' | head -60 > "$prefix.tree.txt" || true
  echo "top symbols in $prefix:"
  head -12 "$prefix.flat.txt" | sed 's/^/  /'
  exit 0
fi

# --alloc <prefix>: read the heap profiles a jemalloc-prof node has written.
#
# The instrument this fleet was missing. gov5's finding 3 is explicit that the
# cost it found -- a pool lock held across two database transaction opens per
# validated transaction -- "never showed in a CPU profile, because the work is
# cgo and allocation rather than Go CPU"; a `perf record` of this fleet is blind
# to its own dialect of that. jemalloc can answer it, and the binary already has
# the feature.
#
#   cargo build --profile profiling -p n42 --bin n42 --features jemalloc-prof
#   MALLOC_CONF=prof:true,prof_active:true,lg_prof_interval:30,prof_prefix:<dir>/heap \
#     F7_BIN=target/profiling scripts/fleet7-bench.sh --tag alloc
#   scripts/fleet7-profile.sh --alloc <dir>/heap
#
# `lg_prof_interval:30` dumps every gibibyte allocated, which at this tier is
# every few seconds. jeprof is not packaged on Ubuntu; it is a perl script
# inside the vendored jemalloc and this instantiates it on first use.
if [[ ${1:-} == --alloc ]]; then
  prefix=${2:?heap prefix}
  jeprof=${JEPROF:-$HOME/.local/bin/jeprof}
  if [[ ! -x $jeprof ]]; then
    template=$(find "$HOME/.cargo/registry/src" -name 'jeprof.in' -path '*jemalloc*' | head -1)
    [[ -n $template ]] || { echo "no jeprof.in in the cargo registry; build once with jemalloc" >&2; exit 1; }
    mkdir -p "$(dirname "$jeprof")"
    sed -e 's/@JEMALLOC_PREFIX@//g' -e 's/@jemalloc_version@/5.3.0/g' "$template" > "$jeprof"
    chmod +x "$jeprof"
    echo "instantiated $jeprof from $template"
  fi
  latest=$(ls -t "$prefix"*.heap 2>/dev/null | head -1)
  [[ -n $latest ]] || { echo "no heap dumps at $prefix*.heap" >&2; exit 1; }
  echo "heap profile : $latest"
  "$jeprof" --show_bytes --text "${F7_BIN:-target/profiling}/n42" "$latest" 2>/dev/null | head -25
  exit 0
fi

NODE=${1:?node index}
PREFIX=${2:?output prefix}
SECS=${3:-20}

pid=$(f7_pid "$NODE" el) || { echo "node $NODE execution layer is not running" >&2; exit 1; }
mkdir -p "$(dirname "$PREFIX")"

# Say so before spending twenty seconds recording something unreadable.
if ! file "$F7_BIN/n42" 2>/dev/null | grep -q "with debug_info\|not stripped"; then
  echo "warning: $F7_BIN/n42 has no symbols; this profile will name nothing." >&2
  echo "         build --profile profiling and set F7_BIN=target/profiling." >&2
fi

# -g for call graphs; --call-graph dwarf would be more accurate on a release
# build with frame pointers omitted, but it is far more expensive to record and
# this profile has to perturb the node as little as possible. `-F 199` is a
# prime rate, so the sampler cannot lock step with a periodic block cycle and
# report one phase of it as the whole node.
perf record -F 199 -g --pid "$pid" -o "$PREFIX.data" -- sleep "$SECS" 2>/dev/null || {
  echo "perf record failed; /proc/sys/kernel/perf_event_paranoid is $(cat /proc/sys/kernel/perf_event_paranoid)" >&2
  exit 1
}

# Recording only. Reading the samples back is the expensive half -- `perf report`
# against a 2.3 GB binary with full DWARF takes minutes -- and doing it here
# would sit between two measured windows and delay the next one, which is the
# opposite of why profiles are taken between windows at all.
echo "profile      : node $NODE, ${SECS}s recorded to $PREFIX.data ($(du -h "$PREFIX.data" | cut -f1))"
echo "             : read it later with 'fleet7-profile.sh --report $PREFIX'"
