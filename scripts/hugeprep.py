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

Usage: hugeprep.py [GB=60] [passes=3]
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


def main(argv):
    gb = float(argv[0]) if argv else 60.0
    passes = int(argv[1]) if len(argv) > 1 else 3
    size = int(gb * (1 << 30))
    huge = 1 << 21
    print(f'hugeprep: order9+={buddy()[0]} order10={buddy()[1]} before', flush=True)
    m = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    m.madvise(mmap.MADV_HUGEPAGE)
    t0 = time.time()
    # Touch one byte per 2 MB: enough for a huge-page fault, and for a
    # fallback it leaves the rest of the 2 MB region unpopulated, which
    # MADV_COLLAPSE fills (max_ptes_none 511 allows it).
    for off in range(0, size, huge):
        m[off] = 1
    touched = anon_huge_kb() >> 10
    print(f'hugeprep: touched {gb:.0f} GB in {time.time() - t0:.1f}s, {touched} MB huge at the fault', flush=True)
    # Collapse in 256 MB chunks: one MADV_COLLAPSE over the whole map stops
    # at the first 2 MB region it cannot get a huge page for (ENOMEM) and
    # leaves the rest untried (loop97: 61% after three "passes" of 0.2 s).
    chunk = 256 << 20
    for i in range(passes):
        t1 = time.time()
        failed = 0
        for off in range(0, size, chunk):
            try:
                m.madvise(MADV_COLLAPSE, off, min(chunk, size - off))
            except OSError:
                failed += 1
        now = anon_huge_kb() >> 10
        print(f'hugeprep: collapse pass {i + 1}: {now} MB huge ({100 * now / (size >> 20):.0f}%), '
              f'{failed} of {size // chunk} chunks refused, {time.time() - t1:.1f}s', flush=True)
        if now >= (size >> 20) * 0.97:
            break
    m.close()
    time.sleep(1)
    o9, o10 = buddy()
    print(f'hugeprep: order9+={o9} order10={o10} after (freed)', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
