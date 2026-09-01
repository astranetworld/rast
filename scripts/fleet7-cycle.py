#!/usr/bin/env python3
# Copyright (c) 2017-2025 N42 Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Continuous block cycle: intervals between consecutive full blocks in an EL log."""
import re, sys, statistics
from datetime import datetime
pat = re.compile(r'^(\S+)\s+INFO (?:reth_node_events::node: )?Block added to canonical chain number=(\d+) .*? txs=(\d+) ')
def parse(path, min_txs=150000):
    ts = []
    for line in open(path, errors='replace'):
        m = pat.match(line)
        if not m: continue
        if int(m.group(3)) < min_txs: 
            ts.append(None); continue
        t = datetime.fromisoformat(m.group(1).replace('Z', '+00:00')).timestamp()
        ts.append(t)
    gaps = []
    for a, b in zip(ts, ts[1:]):
        if a is not None and b is not None:
            gaps.append(b - a)
    return gaps
for path in sys.argv[1:]:
    g = parse(path)
    if len(g) < 5:
        print(f"{path}: {len(g)} full-block intervals"); continue
    g.sort()
    p = lambda q: g[min(len(g)-1, int(q*len(g)))]
    print(f"{path.split('/')[-1]:28s} n={len(g):3d} mean={statistics.mean(g):.3f}s median={statistics.median(g):.3f}s p90={p(0.9):.3f}s max={g[-1]:.3f}s")
