#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The distribution of a leg's full-block cycles, and what the long ones were.

Window 1 of the record configuration reads a median cycle of ~550 ms and a
mean of ~610 (loop117 S1): the difference is a handful of blocks a window
whose cycle is 0.7-1.1 s, and those are where the blocks a window loses go.
This prints, per 30 s window from the first full body, the mean / median /
p25 / p75 / max of the body-to-body interval over every leader, the sum of
the excess over a threshold (in blocks at the median), and then for every
cycle over the threshold the leader's own lines between the two bodies:
whether it was a tenure change (a different leader published the next body),
how long its own-block import and its build ahead took, and where the build
started -- the shapes seen so far are the QMDB checkpoint (own import
245-571 ms and build 700-1000 on the same block: the tree cloned under the
forest lock) and the tenure change (the new leader's build starts only after
its import of the parent, forkchoice + build ~450 ms).

usage: fleet7-cycles.py <bench dir> [threshold ms, default 700] [windows, default 3]
"""
import glob
import re
import statistics
import sys
from datetime import datetime

BENCH = sys.argv[1]
THRESHOLD = float(sys.argv[2]) if len(sys.argv) > 2 else 700.0
WINDOWS = int(sys.argv[3]) if len(sys.argv) > 3 else 3
CLEAN = re.compile(r'\x1b\[[0-9;]*m')
BIG_BODY = 500_000

lines = []
for path in sorted(glob.glob(f'{BENCH}/node*-v.log')):
    node = path.split('/')[-1][:5]
    for raw in open(path, errors='ignore'):
        line = CLEAN.sub('', raw).rstrip()
        if ' INFO' not in line and ' WARN' not in line:
            continue
        try:
            t = datetime.fromisoformat(line[:26]).timestamp()
        except ValueError:
            continue
        lines.append((t, node, line[28:]))
lines.sort()


def body_bytes(line):
    m = re.search(r'bytes=(\d+)', line)
    return int(m.group(1)) if m else 0


pub = [(t, n, i) for i, (t, n, l) in enumerate(lines)
       if ('block body prepared' in l or 'published block body' in l) and body_bytes(l) > BIG_BODY]
if len(pub) < 2:
    print('no full bodies')
    sys.exit(0)
t_first = pub[0][0]
print(f'--- {BENCH}: full-block cycles (body to body, over every leader), 30 s windows from the first full body ---')
print(f'{"win":4s} {"n":>3s} {"mean":>5s} {"median":>6s} {"p25":>5s} {"p75":>5s} {"max":>5s} {"over " + str(int(THRESHOLD)):>9s} {"=blocks":>7s}  tenure-change cycles')
for w in range(WINDOWS):
    lo, hi = t_first + 30 * w, t_first + 30 * (w + 1)
    seg = [(pub[i + 1][0] - pub[i][0]) * 1000 for i in range(len(pub) - 1) if lo <= pub[i][0] < hi]
    changes = [(pub[i + 1][0] - pub[i][0]) * 1000 for i in range(len(pub) - 1)
               if lo <= pub[i][0] < hi and pub[i + 1][1] != pub[i][1]]
    if not seg:
        break
    seg.sort()
    med = statistics.median(seg)
    excess = sum(x - THRESHOLD for x in seg if x > THRESHOLD)
    print(f'w{w + 1:<3d} {len(seg):3d} {statistics.mean(seg):5.0f} {med:6.0f} {seg[len(seg) // 4]:5.0f} '
          f'{seg[3 * len(seg) // 4]:5.0f} {seg[-1]:5.0f} {excess:8.0f}ms {excess / med:7.1f}  '
          f'{len(changes)} x {statistics.mean(changes) if changes else 0:.0f}')

print(f'\n--- cycles over {THRESHOLD:.0f} ms in window 1: the leader\'s own lines between the two bodies ---')
for i in range(len(pub) - 1):
    t0, n0, i0 = pub[i]
    t1, n1, i1 = pub[i + 1]
    if not (t_first <= t0 < t_first + 30):
        continue
    if (t1 - t0) * 1000 < THRESHOLD:
        continue
    kind = 'tenure change' if n1 != n0 else 'same leader'
    print(f'\n== {(t1 - t0) * 1000:.0f} ms, {n0} -> {n1} ({kind})')
    for t, n, l in lines[i0:i1 + 1]:
        if n not in (n0, n1):
            continue
        if 'import-gated' in l or 'received Decide' in l or 'sending vote' in l:
            continue
        l = re.sub(r'process_event\{view=(\d+) kind="([a-z_]+)"\}:', r'v\1', l)
        l = re.sub(r'0x[0-9a-f]{64}', lambda m: m.group(0)[:10], l)
        l = re.sub(r'n42(::|\.)(cl::|interop::|h2\.)?', '', l)
        print(f'  {(t - t0) * 1000:+6.0f} {n} {l[:170]}')
