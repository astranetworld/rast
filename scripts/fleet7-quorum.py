#!/usr/bin/env python3
"""What the quorum actually waits for, per block.

`fleet7-phases.py` reports the median import barrier across all seven
validators. A quorum certificate needs five of seven votes, so the leader
waits for the **fifth** vote, not the median one, and the two slowest
importers do not hold the chain up at all. Round 43 showed why that
distinction matters: a leg whose median barrier was 577 ms read the same
0.652 s cycle as one whose median was 480, which the median cannot explain.

For every block hash this prints, across the fleet:

    votes      how many of the seven validators voted at all
    5th        the fifth vote's delay after that validator saw the block
               (`waiting for execution validation` -> `sending vote to leader`)
    median     the same delay at the median validator, for comparison
    slowest    the seventh, which the chain never waits for

Usage: fleet7-quorum.py [fleet root or an archived round directory] [quorum, default 5]
"""

import datetime
import glob
import re
import statistics
import sys

CLEAN = re.compile(r'\x1b\[[0-9;]*m')
STAMP = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+)Z')
HASH = re.compile(r'\b([0-9a-fx]{10,66})\b')

ROOT = sys.argv[1] if len(sys.argv) > 1 else '/data/blockchain/rust-fleet7-bench'
QUORUM = int(sys.argv[2]) if len(sys.argv) > 2 else 5


def stamp(line):
    m = STAMP.match(line)
    return datetime.datetime.fromisoformat(m.group(1)) if m else None


def main():
    # block hash -> list of one delay per validator that voted
    delays = {}
    # The live fleet keeps `node<i>/v.log`; an archived round keeps
    # `node<i>-v.log` beside its round.txt. Read whichever is there.
    paths = sorted(glob.glob(f'{ROOT}/node*/v.log')) or sorted(glob.glob(f'{ROOT}/node*-v.log'))
    for path in paths:
        seen = {}
        for raw in open(path, errors='ignore'):
            line = CLEAN.sub('', raw)
            ts = stamp(line)
            if ts is None:
                continue
            h = HASH.search(line)
            key = h.group(1) if h else None
            if key is None:
                continue
            if 'waiting for execution validation' in line:
                seen.setdefault(key, ts)
            elif 'sending vote to leader' in line and key in seen:
                delays.setdefault(key, []).append((ts - seen.pop(key)).total_seconds() * 1000)

    full = [sorted(v) for v in delays.values() if len(v) >= QUORUM]
    if not full:
        print(f'no block reached {QUORUM} votes in {ROOT}')
        return 1

    def report(name, values):
        values = sorted(values)
        n = len(values)
        print(
            f'{name:<28} n={n:>5} median={statistics.median(values):>8.1f}ms '
            f'p90={values[int(n * 0.9)]:>8.1f}ms p99={values[min(n - 1, int(n * 0.99))]:>8.1f}ms '
            f'max={values[-1]:>8.1f}ms'
        )

    print(f'--- votes per block, quorum {QUORUM} of 7 ({ROOT}) ---')
    print(f'blocks with at least {QUORUM} votes: {len(full)}')
    report(f'the {QUORUM}th vote (the quorum)', [v[QUORUM - 1] for v in full])
    report('the median validator', [statistics.median(v) for v in full])
    report('the slowest validator', [v[-1] for v in full])
    report('the fastest validator', [v[0] for v in full])
    spread = [v[-1] - v[QUORUM - 1] for v in full]
    report('slowest minus quorum', spread)
    return 0


if __name__ == '__main__':
    sys.exit(main())
