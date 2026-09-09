#!/usr/bin/env python3
"""Where the LEADER's cycle goes, per 30 s window, from the fleet's validator logs.

`fleet7-phases.py` measures the followers (body received -> vote). This script
measures the other chain, the one that turned out to be the critical path in
loop108 (`docs/FLEET7_PLAN_V2.md`): the leader's own-block import, the engine's
forkchoice round trip that starts the build ahead, the build itself, how long
the leader then WAITS for that build after it already holds the quorum, and the
gap from its commit to the next body leaving.

    scripts/fleet7-leader.py [ROOT]          # default /data/blockchain/rust-fleet7-bench

Run it at the end of a leg on the live `node*/v.log` (the bench copies only
node0's execution log into `bench-<tag>/`). Windows are 30 s of wall clock from
the first full body prepared, so they line up with `fleet7-measure.py`'s.

Reading it: `waited_for_ahead` is the number that matters. It is the time the
leader spent, after the parent's quorum was in hand, waiting for its own build
to finish. When it is positive on nearly every block, the leader's chain is the
cycle and nothing done to the followers' import can show; when it is zero, the
followers are the cycle. A change to the leader's side is judged by this
column first and by TPS second.
"""
import glob
import re
import statistics as st
import sys
from datetime import datetime

ROOT = sys.argv[1] if len(sys.argv) > 1 else '/data/blockchain/rust-fleet7-bench'
BIG_BODY = 10_000_000
CLEAN = re.compile(r'\x1b\[[0-9;]*m')
TS = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)Z')
KINDS = {
    'built a block ahead': 'ahead',
    'leader build path': 'propose',
    'block body prepared': 'prepared',
    'own block imported by header': 'own',
    'vote log sync was slow': 'fsync',
    'block committed!': 'commit',
}
FIELD = re.compile(r'([a-z_]+)=(\d+)')


def main():
    rows = []
    for path in sorted(glob.glob(f'{ROOT}/node*/v.log')):
        for raw in open(path, errors='ignore'):
            kind = next((v for k, v in KINDS.items() if k in raw), None)
            if kind is None:
                continue
            line = CLEAN.sub('', raw)
            m = TS.match(line)
            if not m:
                continue
            t = datetime.fromisoformat(m.group(1)).timestamp()
            d = {a: int(b) for a, b in FIELD.findall(line)}
            rows.append((t, kind, d))
    rows.sort(key=lambda r: r[0])
    full = [t for t, k, d in rows if k == 'prepared' and d.get('bytes', 0) > BIG_BODY]
    if not full:
        print('no full bodies in', ROOT)
        return
    t0 = min(full)

    def med(rs, kind, field, pred=lambda d: True):
        v = [d[field] for _, k, d in rs if k == kind and field in d and pred(d)]
        return (f'{st.median(v):.0f}', len(v)) if v else ('-', 0)

    print(f'--- leader chain ({ROOT}), full blocks, 30 s windows from the first full body ---')
    print(f'{"win":5s} {"bodies":>6s} {"own_rt":>6s} {"fcu":>5s} {"build":>5s} {"waited":>6s} {"n":>3s} {"commit->body":>12s} {"cycle":>6s} {"encode":>6s} {"fsync":>6s}')
    for i in range(6):
        a, b = t0 + 30 * i, t0 + 30 * (i + 1)
        rs = [r for r in rows if a <= r[0] < b]
        bodies = sum(1 for _, k, d in rs if k == 'prepared' and d.get('bytes', 0) > BIG_BODY)
        if not bodies:
            continue
        waited, n = med(rs, 'propose', 'fcu_ms')
        ev = [(t, k, d) for t, k, d in rs if k == 'commit' or (k == 'prepared' and d.get('bytes', 0) > BIG_BODY)]
        gaps, cyc, last_c, last_p = [], [], None, None
        for t, k, d in ev:
            if k == 'commit':
                last_c = t
                continue
            if last_c is not None and 0 < t - last_c < 2:
                gaps.append((t - last_c) * 1000)
            if last_p is not None and 0 < t - last_p < 3:
                cyc.append((t - last_p) * 1000)
            last_p = t
        fs, fsn = med(rs, 'fsync', 'sync_ms')
        print(f'{"win" + str(i + 1):5s} {bodies:6d} {med(rs, "own", "round_trip_ms")[0]:>6s} {med(rs, "ahead", "fcu_ms")[0]:>5s} '
              f'{med(rs, "ahead", "build_ms")[0]:>5s} {waited:>6s} {n:3d} '
              f'{(f"{st.median(gaps):.0f}" if gaps else "-"):>12s} {(f"{st.median(cyc):.0f}" if cyc else "-"):>6s} '
              f'{med(rs, "prepared", "encode_ms", lambda d: d.get("bytes", 0) > BIG_BODY)[0]:>6s} {fs + "x" + str(fsn):>6s}')
    print()
    print('own_rt  = own block imported by header, round trip ms      fcu/build = the build ahead: forkchoice round trip, then the payload job')
    print('waited  = ms the leader waited for its build ahead AFTER holding the quorum (n = blocks that had a build ahead)')
    print('commit->body = leader commit of the parent -> next full body prepared      cycle = full body to full body on the leader')


if __name__ == '__main__':
    main()
