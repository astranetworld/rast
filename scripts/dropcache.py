#!/usr/bin/env python3
"""Evict clean file pages from the page cache without root.

Walks the given directories and asks the kernel to drop every regular file's
cached pages (`posix_fadvise(POSIX_FADV_DONTNEED)`), which needs only read
access. Mapped pages and dirty pages stay; everything else goes.

Why: a fleet7 leg that starts with file cache beyond the tmpfs (round 43: the
build's artifacts after `cargo build`, gov5's files after a datc run, a perf
profile) reads 125-196k on window 1; a leg that starts with none reads
239-247k -- thirty legs, no exception. The kernel reclaims the stale pages
during the leg and the fleet's fresh MDBX pages go with them (major faults
27-37k against 9-12k a leg). Run this after anything that reads or writes
files at scale and before the leg starts. `scripts/fleet7-bench.sh` runs it
over the build tree and the bench root when `F7_DROP_CACHE=1`.

Usage: dropcache.py [-q] DIR... ; prints Cached from /proc/meminfo before and after.
"""
import os
import sys


def cached_gb():
    with open('/proc/meminfo') as f:
        for line in f:
            if line.startswith('Cached:'):
                return int(line.split()[1]) / 1e6
    return 0.0


def drop(path):
    total = 0
    files = 0
    for root, dirs, names in os.walk(path, onerror=lambda e: None):
        for n in names:
            p = os.path.join(root, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.isfile(p) or os.path.islink(p) or st.st_size == 0:
                continue
            try:
                fd = os.open(p, os.O_RDONLY | os.O_NOATIME if hasattr(os, 'O_NOATIME') else os.O_RDONLY)
            except OSError:
                try:
                    fd = os.open(p, os.O_RDONLY)
                except OSError:
                    continue
            try:
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                total += st.st_size
                files += 1
            except OSError:
                pass
            finally:
                os.close(fd)
    return files, total


def main(argv):
    quiet = '-q' in argv
    dirs = [a for a in argv if a != '-q']
    if not dirs:
        print(__doc__)
        return 2
    before = cached_gb()
    files = 0
    size = 0
    for d in dirs:
        f, s = drop(d)
        files += f
        size += s
    after = cached_gb()
    if not quiet:
        print(f'dropcache: {files} files ({size / 1e9:.1f} GB on disk) advised; Cached {before:.1f}G -> {after:.1f}G')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
