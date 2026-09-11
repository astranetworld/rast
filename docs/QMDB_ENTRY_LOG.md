# The QMDB entry log on disk -- design (plan v3 phase M, the 1M form)

*2026-09-10. Written from loop121's heap profile (`NATIVE_FLEET7.md`, loop121) and a read of
`crates/n42/twig-core/src/qmdb_compat.rs` and `crates/n42/qmdb-state/src/forest.rs`. Not
implemented yet; this is the design the implementation follows.*

## 1. What the memory is today

`QmdbCompatTree` keeps the whole state in the heap:

    entries: Vec<Entry { key: Hash, value: Vec<u8>, active: bool }>   64 B a slot + a ~96 B heap value
    twigs:   Vec<Twig { nodes: Box<[Hash; 4096]>, bits: [u8; 256], bits_root, root }>   64 B a slot (the merkle nodes)
    index:   KeyIndex (256 sharded HashMap<Hash, u64>)                 ~60 B an *active* key

About 220 B a slot, and QMDB appends a slot for every changed entry: 147,000 a block at the
bench tier (~33 MB), 15M slots after 100 blocks (3.3 GB, 4.2 with the Vec's doubling), 90% of
them dead within ten blocks -- an update deactivates the old slot, whose *leaf hash stays
frozen in the twig* (`Twig::set_active(local, false)` only clears the bit). Beside the tree the
forest keeps a `BlockRecord` per block for 64 blocks (the sorted operations and the undo
record with the retired entries' values, ~35 MB a block, ~2 GB). At 1M TPS the tree would
grow 200 MB a second a node. An in-memory entry log is not a stopgap at that rate, it is the
wall; gov5 keeps the entries in files and only twig roots, active bits and the key index in
memory, and that is the form this design adopts.

## 2. What reads an entry's bytes

Everything on the hot path needs the *leaf hash*, the *active bit* and the *key index*; the
entry bytes themselves are read by:

| reader | slots | when |
| --- | --- | --- |
| `undo_entries` (the block's undo record) | the ~133,000 slots a block retires | every block apply |
| `entry_at` for the forest's delta (`delta_of_applied`) | the block's appended range, and the retired slots (`changed`) | once per block, right after compute |
| `snapshot()` (the checkpoint) | every slot | every checkpoint |
| `get` / `prove` | one active slot | proofs, tests |
| `apply_undo`'s `EntryMismatch` check | the revived slots | reorgs only |
| `portable_export` | every slot | a tool, on a stopped node |

None of them needs a dead slot's bytes *in memory*: the retired slots' bytes go into the undo
record at retirement (a copy), the delta's `changed` entries only flip `active` (a slot's
content never changes after its append), and the checkpoint and the export are sequential
reads of everything.

## 3. The design

**`EntryStore`**: an append-only file `qmdb/entries.log` of records `[key 32][len u32][value]`,
one per slot in slot order, plus in memory a `Vec<u64>` of record offsets (8 B a slot; a
per-twig base with `u32` deltas later if 8 B matters). The file is opened read-mapped
(`mmap`, read-only) for lookups and appended through an ordinary writer; the map is
re-established when the file grows past the mapped length (rare: map in 1 GB steps).

In memory per slot: the twig node (64 B), the active bit, the offset (8 B). A slot costs
~72 B instead of ~220, and nothing per slot is a separate heap allocation. Step 2 (below)
takes the node arrays of long-dead twigs out too.

**Appends stay in memory until the block is filed.** A block's appended entries are written
into a staging `Vec<Entry>` during `apply_sorted_ops`; reads of those slots come from the
staging buffer. `QmdbForest::insert` (the block filed under its hash) flushes the staging
buffer to the file in one sequential write (~20 MB a block at the bench tier). A pending
block that is reverted instead (`move_to`, the pending-build undo) drops its staging buffer
and never touches the file. So the file holds exactly the filed slots, in order, and a
revert of a *filed* block (a branch switch within the retention window) truncates the file
to `prev_next_slot` -- the same truncation `apply_undo` does to `entries` today.

**Reads.** `undo_entries` reads 133,000 records at random from the map: the retired slots are
recent (an account's previous update), so the pages are in the page cache, and the page cache
is what this design gives back to the box -- it is evictable, the heap was not. `entry_at` for
the delta reads the appended range from the staging buffer (still live) and the `changed`
slots' keys from the map (the delta carries the key and `active`; the value is redundant and
the v2 delta drops it, see 4). `get` and `prove` read one record. `apply_undo`'s mismatch
check compares the key from the map. A revival needs no value copy: the record is still in
the file.

**Restart.** Map the file, bound it by the checkpoint's `next_slot` (a torn tail past it is
truncated: a crash between the file append and the delta append leaves records the delta log
does not know), hash every record on the worker pool (15M blake3 leaves, ~2-3 s), rebuild the
twigs' node arrays from the leaves and the checkpoint's active bits, and the key index from the
active slots (key from the map).

## 4. What it does to persistence

The delta log and the checkpoint stop carrying entry bytes:

- **Delta v2**: `{ head, base_next_slot, next_slot, changed: Vec<(slot, active)> }` -- the
  appended range is *in the entry file* by construction (filed before the block is canonical),
  so the delta names it by its bounds; ~2 MB a block instead of ~20.
- **Checkpoint v2**: `{ head, next_slot, twig bits (256 B a twig), twig roots }` -- ~7,000
  twigs at 15M slots is ~2 MB. It is rewritten by the background compaction as today (the
  compaction replays checkpoint + sealed segment: now a bit-flip replay over 2 MB, milliseconds)
  or, being this small, simply every block; either way the 300-800 MB rewrites of loop118-120
  are gone with the entries they carried.
- **Portable export** (gov5's format, full entries including dead ones) reads the entry file
  sequentially -- *more* complete than today, where an export needs the checkpoint to hold
  every entry.
- The forest's `BlockRecord` keeps the sorted operations for a re-apply; with the entries in
  the file it can keep offsets instead of values (or just the retention knob
  `N42_QMDB_RETAIN_DEPTH`, loop122).

Formats are versioned (`ForestSnapshot::VERSION`, `ForestDelta::VERSION`); a node with a v1
checkpoint on disk starts by writing the entry file from it once (the migration is the
snapshot's own entry list, in slot order).

## 5. Step 2: long-dead twigs keep only their root

A twig whose 2048 slots are all dead contributes only its root to the world root and can
never serve a proof. Its `nodes` array (128 KB) goes once every slot in it has been dead for
longer than the retention window (a revival by an undo of a recent block can only touch a slot
that was active until that block, so a twig dead for longer than `retain_depth` blocks cannot
be revived). Track per twig the block at which it went fully dead; trim on `set_canonical`.
With it the in-memory cost is bounded by the *live* twigs rather than the append history --
which is what makes 1M TPS a bounded-memory number at all (at 200 MB/s of state change the
64 B-a-slot node arrays alone would be 3.8 GB an hour without it).

## 6. Cost model and what to measure

Per node at 100 bench blocks: entries 4.2 GB -> 0 (offsets 120 MB); nodes 1.0 GB -> 1.0
(step 1) -> live twigs only (step 2); records 2 GB -> the knob; checkpoint compaction 300-800 MB
rewrites -> gone. The fleet's anonymous memory in a leg (9.6 -> 109 GB in loop121) should
stay under ~40 GB, and windows 2-3, which lose 30-35% to page-cache reclaim today, should
read within a few blocks of window 1. Judge by `fleet7-windows.py`'s MemAvailable and major
faults per window on a D-A-D-A round, then by windows 2-3.

## 7. Status (2026-09-10 evening)

- Step 1 done (`056c6a235`): `Entries::{Heap, File}`; `N42_QMDB_ENTRY_FILE=1`. loop123: the
  fleet's anonymous memory peaks 15-20 GB lower, window 2's major faults fall by half to three
  quarters, and both chains paid ~70 ms a block for 266,000 random reads into a mapping
  re-established every 64 MB (minor faults on cached pages).
- The mapping is chunked (`bad780f40`): sealed 256 MB chunks mapped once with populated page
  tables; loop124 measures it.
- Step 3a done (delta v2 + slot-only undo, `492a2ab29`): the retired slots are read by nothing
  on the block path any more; loop125 measures it.
- Steps 3b and 4 done (the file as the persistence): `forest.ckpt` = cursor + active bits, the
  delta's appended range by its bounds, `sync` before the delta, restart by hashing the file's
  records and rebuilding twigs and index from the bits, a torn tail dropped, the version-1
  checkpoint migrated once, the portable export from the file. loop126 measures it (with the
  appends buffered and written in one call, `05c7d984c`: the per-record write syscalls were
  the file store's remaining root-phase cost, loop125).
- Step 5 done: a twig whose slots are all dead, all appended before the retention window's
  oldest cursor and last retired before it too keeps only its root and bits (`trim_dead_twigs`,
  called by the forest on every head move; `N42_QMDB_TRIM_TWIGS=0` turns it off). loop127
  measures it in file mode against the same without trimming.

## 8. Implementation order

1. `EntryStore` trait with the in-memory implementation (today's `Vec<Entry>`) and the file
   implementation; `QmdbCompatTree` generic over it (the gov5 vector tests run on both).
2. Staging buffer + flush on `insert`; `apply_undo` truncation of the file.
3. Delta v2 and checkpoint v2 in `qmdb-state`/`qmdb-reth`, with the v1 migration and the
   replay tests (`node_state.rs` already has the rotation, torn-log and sealed-segment tests).
4. The restart path (hash-everything rebuild) and `portable_export` from the file.
5. Step 2 (twig trimming) behind a knob, measured on its own.
