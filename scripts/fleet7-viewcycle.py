#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Where a full block's cycle goes, on the next leader's clock.

For consecutive full blocks h -> h+1 (leader L1 published h, leader L2 published h+1):
  publish->recv : L1 publishes body(h) -> L2 receives body(h)
  recv->vote    : L2 receives body(h) -> L2 sends its vote on h  (import + vote gating)
  vote->decide  : L2 votes -> L2 receives Decide for h            (waiting for the quorum)
  decide->pub   : L2 commits h -> L2 publishes body(h+1)          (build + seal + encode)
These four sum to publish(h+1) - publish(h) exactly (one cross-node hop at the start).
usage: viewcycle.py <fleet root> [log suffix, e.g. .20260901-230122]
"""
import glob, re, statistics, sys
from datetime import datetime
ROOT = sys.argv[1] if len(sys.argv) > 1 else '/data/blockchain/rust-fleet7-bench'
SUF = sys.argv[2] if len(sys.argv) > 2 else ''
CLEAN = re.compile(r'\x1b\[[0-9;]*m'); STAMP = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+)Z')
HASH = re.compile(r'(?:decide\.)?block_hash="?(0x[0-9a-f]+)"?'); BYTES = re.compile(r'bytes=(\d+)')
def ts(line):
    m = STAMP.match(line); return datetime.fromisoformat(m.group(1)).timestamp() if m else None
pub, recv, vote, decide, big = {}, {}, {}, {}, set()   # keyed (hash) -> per node dicts
for path in sorted(glob.glob(f'{ROOT}/node*/v.log{SUF}')):
    node = path.split('/')[-2]
    for raw in open(path, errors='ignore'):
        line = CLEAN.sub('', raw); t = ts(line)
        if t is None: continue
        h = HASH.search(line); key = h.group(1) if h else None
        if not key: continue
        if 'published block body' in line or 'block body prepared' in line:
            # `block body prepared` is the leader's line on the direct-push
            # path, where the topic (and its `published` line) is not used.
            b = BYTES.search(line); size = int(b.group(1)) if b else 0
            if key not in pub:
                pub[key] = (t, node)
            if size > 500_000: big.add(key)
        elif 'block body received' in line:
            recv.setdefault(key, {}).setdefault(node, t)
        elif 'sending vote to leader' in line:
            vote.setdefault(key, {}).setdefault(node, t)
        elif 'received Decide, committing block' in line:
            decide.setdefault(key, {}).setdefault(node, t)
order = sorted((t, k) for k, (t, n) in pub.items() if k in big)
segs = {k: [] for k in ('publish->recv', 'recv->vote', 'vote->decide', 'decide->pub', 'cycle')}
for (t0, h), (t1, h2) in zip(order, order[1:]):
    l2 = pub[h2][1]
    r = recv.get(h, {}).get(l2); v = vote.get(h, {}).get(l2); d = decide.get(h, {}).get(l2)
    if None in (r, v, d) or t1 - t0 > 10: continue
    segs['publish->recv'].append(r - t0); segs['recv->vote'].append(v - r)
    segs['vote->decide'].append(d - v); segs['decide->pub'].append(t1 - d); segs['cycle'].append(t1 - t0)
for name, xs in segs.items():
    if not xs: print(f'{name:16s} n=0'); continue
    xs = sorted(xs); p90 = xs[min(len(xs)-1, int(0.9*len(xs)))]
    print(f'{name:16s} n={len(xs):3d} mean={statistics.mean(xs)*1000:7.0f}ms median={statistics.median(xs)*1000:7.0f}ms p90={p90*1000:7.0f}ms')
