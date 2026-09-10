#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Both chains and the box, per 30 s window, for one leg.

    scripts/fleet7-windows.py <bench dir> [<mem samples file>]

`fleet7-leader.py` reads the leader's chain and `fleet7-phases.py` the
followers', each over a whole leg. This prints the two side by side per
window -- the leader's build phases from `builds-node0.log`, every follower's
import (`engine_ms` of `raw newPayload`) from `builds-node{1..6}.log` -- and
beside them the box's counters from the launcher's 5 s samples
(`mem-<tag>.txt`: fleet major faults, MemAvailable, one execution layer's
RSS), because the same leg can lose window 1 to the leader's chain and
windows 2-3 to memory, and the round total cannot tell the two apart
(`docs/FLEET7_PLAN_V3.md`, section 1.3).

Windows are 30 s of wall clock from the leader's first full build, so they
line up with `fleet7-measure.py`'s to within a block. A build is "full" at
150,000 transactions or more; adjust `FULL` for another tier.
"""
import glob
import os
import re
import statistics as st
import sys
from datetime import datetime, timezone

FULL = 150_000
WINDOWS = 4
TS = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)Z')
FIELD = re.compile(r'([a-z_]+)=(\d+)')
CLEAN = re.compile(r'\x1b\[[0-9;]*m')


def rows(path, key):
    out = []
    if not os.path.exists(path):
        return out
    for raw in open(path, errors='ignore'):
        if key not in raw:
            continue
        line = CLEAN.sub('', raw)
        m = TS.match(line)
        if not m:
            continue
        t = datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc).timestamp()
        out.append((t, {a: int(b) for a, b in FIELD.findall(line)}))
    return out


def med(values):
    return f'{st.median(values):.0f}' if values else '-'


def mem_samples(path, day):
    """(epoch, fleet_majflt, MemAvailable GB, el_rss GB) from a launcher sample file."""
    out = []
    if not path or not os.path.exists(path):
        return out
    for line in open(path, errors='ignore'):
        m = re.match(r'^(\d\d):(\d\d):(\d\d) ', line)
        if not m:
            continue
        h, mi, s = (int(x) for x in m.groups())
        # The samples are local time; `day` is the leg's UTC date from the logs.
        # The offset between the two is taken from the first sample against
        # the first build, so a leg that crosses midnight still lines up.
        t = day + h * 3600 + mi * 60 + s
        f = {k: v for k, v in re.findall(r'([A-Za-z_]+)[=:]([0-9.]+)', line)}
        out.append((t, int(f.get('fleet_majflt', 0) or 0), float(f.get('MemAvailable', 0) or 0), float(f.get('el_rss', 0) or 0)))
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    bench = sys.argv[1].rstrip('/')
    mem_path = sys.argv[2] if len(sys.argv) > 2 else None
    if mem_path is None:
        tag = os.path.basename(bench).replace('bench-', '')
        for cand in glob.glob(os.path.expanduser(f'~/.claude/jobs/*/tmp/mem-{tag}.txt')):
            mem_path = cand
    builds = [(t, d) for t, d in rows(f'{bench}/builds-node0.log', 'payload build phases') if d.get('txs', 0) >= FULL]
    if not builds:
        print('no full builds in', bench)
        return
    t0 = builds[0][0]
    followers = {}
    for path in sorted(glob.glob(f'{bench}/builds-node[1-9].log')):
        node = os.path.basename(path)[len('builds-'):-len('.log')]
        followers[node] = [(t, d) for t, d in rows(path, 'raw newPayload') if d.get('txs', 0) >= FULL]
    samples = mem_samples(mem_path, 0)
    if samples:
        # Align the samples' clock to the logs': the first sample is taken
        # when the flood starts funding, a few seconds before the first build.
        first_local = samples[0][0]
        day = t0 - (t0 % 86400)
        shift = 0
        for cand in (-86400, 0, 86400):
            if day + first_local + cand <= t0 + 60:
                shift = cand
        samples = [(day + t + shift, a, b, c) for t, a, b, c in samples]
        # Local time is not UTC on this box; pick the hour offset that puts the
        # first sample just before the first build.
        best = min(range(-14, 15), key=lambda h: abs((samples[0][0] + h * 3600) - (t0 - 20)))
        samples = [(t + best * 3600, a, b, c) for t, a, b, c in samples]

    print(f'--- {bench}: both chains and the box, 30 s windows from the first full build ---')
    print(f'{"win":4s} {"builds":>6s} {"exec":>5s} {"fold":>5s} {"finish":>6s} {"asm":>4s} {"build":>5s} | '
          + ' '.join(f'{n[-5:]:>6s}' for n in followers) + ' | '
          + f'{"majflt/30s":>10s} {"avail GB":>8s} {"el RSS":>6s}')
    for w in range(WINDOWS):
        a, b = t0 + 30 * w, t0 + 30 * (w + 1)
        ws = [d for t, d in builds if a <= t < b]
        # The leader logs `payload build phases` only for builds through the
        # payload service; a window with none still has the followers' side.
        if not ws and not any(a <= t < b for im in followers.values() for t, _ in im):
            continue
        line = (f'{"w" + str(w + 1):4s} {len(ws):6d} {med([d.get("par_exec_ms", 0) for d in ws]):>5s} '
                f'{med([d.get("par_fold_ms", 0) for d in ws]):>5s} {med([d.get("finish_ms", 0) for d in ws]):>6s} '
                f'{med([d.get("assemble_ms", 0) for d in ws]):>4s} {med([d.get("total_ms", 0) for d in ws]):>5s} | ')
        line += ' '.join(f'{med([d["engine_ms"] for t, d in im if a <= t < b and "engine_ms" in d]):>6s}' for im in followers.values())
        sw = [s for s in samples if a <= s[0] < b]
        if sw:
            faults = sw[-1][1] - sw[0][1]
            line += f' | {faults:10d} {st.median([s[2] for s in sw]):8.1f} {st.median([s[3] for s in sw]):6.2f}'
        else:
            line += ' |          -        -      -'
        print(line)
    print()
    print('leader: builder phases (ms, median of full builds on node0); followers: engine_ms of raw newPayload per node')
    print('box: fleet major faults within the window, MemAvailable and one EL RSS (medians) from the launcher\'s samples'
          + ('' if samples else ' -- no sample file found; pass it as the second argument'))


if __name__ == '__main__':
    main()
