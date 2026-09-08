#!/usr/bin/env python3
"""Compact free memory into huge pages before a fleet7 leg, without root.

Maps N GB anonymous, touches it, asks the kernel to collapse it into 2 MB
pages (`MADV_COLLAPSE`, which compacts synchronously whatever the host's THP
`defrag` says), reports how much of it is huge, and exits -- freeing the huge
pages as order-9 blocks the fleet's `MALLOC_CONF=thp:always` heaps then take
without a fault fallback.

Why (round 43, loop96): a leg's window 1 reads 239-247k when the fleet's heaps
get huge pages from a ready pool (the previous leg's freed heap) and 177-196k
when the pool is gone (after a build, a datc run, or minutes of idling): the
first THP fallback wakes kswapd under `defrag=defer`, which then reclaims
7-11 GB of page cache every 5 s for the rest of the leg and the fleet's MDBX
pages go with it (350-560k major faults a 5 s). A pool of ~60 GB carries
window 1.

Usage: hugeprep.py [working set GB=30] [collapse passes=2] [pool target GB=40] [rounds=4] [reserve GB=12]
"""
import mmap
import sys
import time

MADV_COLLAPSE = 25


def anon_huge_kb():
    with open('/proc/self/smaps_rollup') as f:
        for line in f:
            if line.startswith('AnonHugePages:'):
                return int(line.split()[1])
    return 0


def buddy():
    with open('/proc/buddyinfo') as f:
        for line in f:
            p = line.split()
            if p[3] == 'Normal':
                orders = list(map(int, p[4:]))
                return sum(orders[9:]), orders[-1]
    return 0, 0


def mem_kb(field):
    with open('/proc/meminfo') as f:
        for line in f:
            if line.startswith(field + ':'):
                return int(line.split()[1])
    return 0


def pool_gb():
    o9, o10 = buddy()
    return (o9 * 2 + o10 * 4) / 1024.0


def one_round(gb, passes):
    """Maps `gb`, populates it, collapses it, frees it. Returns the pool after."""
    size = int(gb) << 30
    m = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    m.madvise(mmap.MADV_HUGEPAGE)
    t0 = time.time()
    # Every page written, not one byte per 2 MB: under a THP fallback the
    # sparse version allocates 4 KB per 2 MB, so it applies no pressure at all
    # and leaves the page cache in place -- and then MADV_COLLAPSE has nothing
    # contiguous to work with (round 43, loop99: 202 of 240 chunks refused, a
    # 14 GB pool, and the leg read the slow mode). Writing the whole region
    # evicts clean page cache first, which is what the fleet's own heaps would
    # have done at the flood's start.
    block = b'\x01' * (1 << 20)
    for _ in range(size >> 20):
        m.write(block)
    faulted = anon_huge_kb() >> 10
    wrote = time.time() - t0
    # Collapse in 256 MB chunks: one MADV_COLLAPSE over the whole map stops at
    # the first 2 MB region it cannot get a huge page for (ENOMEM) and leaves
    # the rest untried (loop97: 61% after three "passes" of 0.2 s).
    chunk = 256 << 20
    huge, failed = faulted, 0
    for _ in range(passes):
        failed = 0
        for off in range(0, size, chunk):
            try:
                m.madvise(MADV_COLLAPSE, off, min(chunk, size - off))
            except OSError:
                failed += 1
        huge = anon_huge_kb() >> 10
        if huge >= (size >> 20) * 0.97:
            break
    m.close()
    time.sleep(0.5)
    print(
        f'hugeprep: {gb:.0f} GB written in {wrote:.1f}s ({faulted} MB huge at the fault), '
        f'collapsed to {huge} MB ({100 * huge / (size >> 20):.0f}%, {failed} chunks refused), '
        f'pool now {pool_gb():.0f} GB, cached {mem_kb("Cached") / (1 << 20):.0f} GB',
        flush=True,
    )
    return pool_gb()


def mem_kb(field):
    with open('/proc/meminfo') as f:
        for line in f:
            if line.startswith(field + ':'):
                return int(line.split()[1])
    return 0


def main(argv):
    gb = float(argv[0]) if argv else 30.0
    passes = int(argv[1]) if len(argv) > 1 else 2
    target = float(argv[2]) if len(argv) > 2 else 40.0
    rounds = int(argv[3]) if len(argv) > 3 else 4
    reserve = float(argv[4]) if len(argv) > 4 else 12.0
    # A working set the box has room to move into: 30 GB collapses whole where
    # 60 GB is refused for want of anywhere to put the huge pages, and each
    # round hands its huge pages back to the pool, so rounds accumulate
    # (round 43: 17 -> 38 -> 43 GB over three rounds of 30-45 GB).
    available = mem_kb('MemAvailable') / (1 << 20)
    if gb > available - reserve:
        gb = max(0.0, available - reserve)
        print(f'hugeprep: trimmed to {gb:.0f} GB (MemAvailable {available:.0f} GB, reserve {reserve:.0f})', flush=True)
    if gb < 1:
        print('hugeprep: no room; nothing done', flush=True)
        return 0
    have = pool_gb()
    print(f'hugeprep: pool {have:.0f} GB before, target {target:.0f} GB', flush=True)
    for _ in range(rounds):
        if have >= target:
            break
        have = one_round(gb, passes)
    print(f'hugeprep: pool {have:.0f} GB after', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
