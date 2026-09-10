// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one QMDB forest a node keeps, shared by everything that computes,
//! checks, or proves a state root.
//!
//! The payload builder, the engine validator, and the mobile endpoint must all
//! see the same trees: a root the builder computed from one forest and a
//! validator checked against another would disagree even when both are
//! correct. So there is exactly one, behind a lock, cloned by handle.
//!
//! It starts uninitialised. The trees can only be restored once the node's
//! database is open and the canonical head is known, which happens after the
//! components that hold this handle are built. Until [`QmdbNodeState::initialize`]
//! runs, every operation fails — loudly, as an error the engine reports — rather
//! than computing a root from an empty forest and calling a real block invalid.
//!
//! # Persistence
//!
//! The canonical head's tree is written to disk when the head moves, and read
//! back at startup. A QMDB tree cannot be reconstructed from the execution
//! layer's state, because the root depends on the append history and reth's
//! tables do not keep it; so a snapshot that is missing or behind the database's
//! head is a node that cannot compute the next root, and it says so instead of
//! starting. The exception is a database at genesis, which is seeded from the
//! alloc exactly as gov5 does.
//!
//! What is written per block is a *delta*, not the tree. Serialising the whole
//! forest every time the head moved cost the size of the world state per block:
//! tolerable on a devnet whose state is twenty accounts, and impossible on a
//! chain whose state is tens of gigabytes, where it would mean rewriting all of
//! it every three seconds. So `forest.bin` is a checkpoint and `forest.log`
//! holds the deltas taken since it; the checkpoint is rewritten only when the
//! log has grown past it, which bounds the log at twice the state and makes the
//! amortised cost of a block the size of that block.
//!
//! Startup replays the log onto the checkpoint one delta at a time and stops at
//! the database's head. Stopping matters: the forest follows the canonical
//! chain while the database persists on its own schedule, so the log routinely
//! runs ahead of the head a restarted node finds, and the blocks past it arrive
//! again through the engine.
//!
//! # Rewriting the checkpoint without touching the tree
//!
//! The checkpoint used to be taken from the live forest: stand the tree at the
//! head, clone it, serialise and write it -- the clone under the forest lock,
//! the rest on the canonical follower's task. At the fleet7 bench tier that is
//! a 300-800 MB tree cloned under the lock every 10-50 blocks, ~0.5 s during
//! which the builder's next block and the follower's import both wait, and the
//! move to the head reverts the build in flight so the next computation
//! replays it (loop117: the leader's own import 245-571 ms and its build
//! 713-1029 ms on exactly those blocks, ~4 stalls a window). So the checkpoint
//! is now compacted from the files instead: when the log has outgrown the
//! checkpoint, `forest.log` is renamed to `forest.log.sealed` and a plain
//! thread replays the old checkpoint plus the sealed segment into a new
//! checkpoint -- the same state, by the same replay a restart performs --
//! writes it, and deletes the segment; new deltas go to a fresh `forest.log`
//! meanwhile. The forest lock is never taken. A restart while the segment
//! exists replays checkpoint, segment, log in that order (a delta the
//! checkpoint already covers is skipped, so a crash between the checkpoint's
//! rename and the segment's deletion is harmless) and compacts the segment
//! again. `N42_QMDB_CHECKPOINT_SYNC=1` keeps the old path, and
//! `N42_QMDB_CHECKPOINT_RATIO=<n>` lets the log grow to `n` times the
//! checkpoint before either path runs (default 1).

use n42_twig_core::qmdb_compat::QmdbOperation;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use alloy_primitives::{Address, B256};
use n42_qmdb_state::{
    BlockChanges, ForestDelta, ForestSnapshot, PreparedBlock, QmdbForest, StateError,
    StateProofProvider,
};
use n42_twig_core::qmdb_compat::QmdbProof;
use reth_chainspec::ChainSpec;
use tracing::{debug, info, warn};

use crate::changes::changes_from_alloc;

const SNAPSHOT_FILE: &str = "forest.bin";
const DELTA_LOG_FILE: &str = "forest.log";
/// The log segment a background compaction is folding into the checkpoint.
const SEALED_LOG_FILE: &str = "forest.log.sealed";

/// Below this the log is left to grow even if it has passed the checkpoint.
/// Without a floor, a chain whose state is a few kilobytes would rewrite its
/// checkpoint on almost every block — the very cost this is here to avoid.
const MIN_LOG_BEFORE_CHECKPOINT: u64 = 1 << 20;

/// `N42_QMDB_CHECKPOINT_SYNC=1`: rewrite the checkpoint from the live forest
/// on the canonical follower, as before, instead of compacting the files on a
/// background thread. The A/B's off arm; read once.
fn checkpoint_sync() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_QMDB_CHECKPOINT_SYNC").is_ok_and(|v| v == "1"))
}

/// `N42_QMDB_CHECKPOINT_RATIO`: how many times the checkpoint's size the log
/// may reach before the checkpoint is rewritten (default 1: the log is
/// bounded at the size of the state). Bounds the disk at `1 + ratio` times
/// the state and what a restart has to replay at `ratio` times it.
fn checkpoint_ratio() -> u64 {
    static RATIO: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *RATIO.get_or_init(|| {
        std::env::var("N42_QMDB_CHECKPOINT_RATIO")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(1)
    })
}

/// `N42_QMDB_COMPACT_NICE`: the compaction thread's nice value (default 10),
/// so its read, replay and write of the whole state yield to the builder and
/// the import on the same cores. 0 leaves it at the process's priority.
fn compact_nice() -> i32 {
    static NICE: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *NICE.get_or_init(|| {
        std::env::var("N42_QMDB_COMPACT_NICE")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .map(|n| n.clamp(0, 19))
            .unwrap_or(10)
    })
}

/// Lowers the calling thread's priority to [`compact_nice`].
fn apply_compact_nice() {
    let nice = compact_nice();
    if nice == 0 {
        return;
    }
    // SAFETY: setpriority on the calling thread (PRIO_PROCESS with a thread
    // id) is a plain syscall with no memory effects; a failure leaves the
    // priority as it was.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        libc::setpriority(libc::PRIO_PROCESS, tid, nice);
    }
}

/// `N42_QMDB_RETAIN_DEPTH`: how many blocks below the head the forest keeps
/// its records for (the sorted operations to re-apply a block after a move,
/// and the undo record with the entries it deactivated). The default is the
/// forest's own (64). At the bench tier a record is ~35 MB, so 64 of them
/// are ~2 GB a node (loop121's heap profile); HotStuff-2 finality is two
/// views and the persisted head lags the canonical one by a block or two, so
/// a much shallower window is safe -- it must only exceed that lag, since
/// persistence walks the records from the persisted head to the block.
fn retain_depth() -> Option<u64> {
    static DEPTH: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *DEPTH.get_or_init(|| {
        std::env::var("N42_QMDB_RETAIN_DEPTH")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|n| *n >= 2)
    })
}

/// The forest with the configured record retention.
fn with_configured_retention(forest: QmdbForest) -> QmdbForest {
    match retain_depth() {
        Some(depth) => forest.with_retain_depth(depth),
        None => forest,
    }
}

/// Why the node's QMDB state could not be used.
#[derive(Debug, thiserror::Error)]
pub enum NodeStateError {
    /// A portable snapshot could not be used.
    #[error("portable QMDB snapshot: {0}")]
    Portable(String),
    /// Nothing has restored the trees yet. See the module docs.
    #[error("QMDB state is not initialised; the node cannot compute state roots yet")]
    Uninitialised,
    /// The snapshot on disk names a different head than the database.
    ///
    /// Behind means blocks were committed that the forest never saw; ahead
    /// means the database was rolled back under it. Neither can be repaired
    /// by replay here, since replaying needs the trees this node is missing.
    #[error(
        "QMDB snapshot is at block {snapshot_number} ({snapshot_hash}) but the database head is \
         block {head_number} ({head_hash}); the forest cannot be rebuilt from execution state"
    )]
    SnapshotMismatch {
        /// Where the snapshot stands.
        snapshot_number: u64,
        /// Its hash.
        snapshot_hash: B256,
        /// Where the database stands.
        head_number: u64,
        /// Its hash.
        head_hash: B256,
    },
    /// No snapshot, and the database is past genesis.
    #[error(
        "no QMDB snapshot at {path} and the database head is block {head_number}; a QMDB chain \
         cannot start from execution state alone"
    )]
    NoSnapshot {
        /// Where the snapshot was looked for.
        path: PathBuf,
        /// The database head.
        head_number: u64,
    },
    /// The genesis alloc produced a root other than the one in the genesis
    /// header — the chain spec was not built for QMDB.
    #[error(
        "genesis alloc has QMDB root {computed} but the genesis header carries {header}; \
         the chain spec must declare stateScheme \"qmdb\" so its genesis is built for QMDB"
    )]
    GenesisRootMismatch {
        /// What the alloc hashes to.
        computed: B256,
        /// What the header says.
        header: B256,
    },
    /// The trees themselves refused an operation.
    #[error(transparent)]
    State(#[from] StateError),
    /// The snapshot file could not be read or written.
    #[error("QMDB snapshot at {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The snapshot file did not decode.
    #[error("QMDB snapshot at {path} is unreadable: {source}")]
    Decode {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: bincode::Error,
    },
}

struct Inner {
    forest: Mutex<Option<QmdbForest>>,
    chain: Arc<ChainSpec>,
    dir: PathBuf,
    /// Where the delta log stands: the append cursor the next delta will be
    /// taken against, how many bytes of log lie after the checkpoint, and how
    /// big that checkpoint was. Held beside the forest rather than inside it,
    /// because none of it is state — it is bookkeeping about a file.
    persist: Mutex<PersistCursor>,
    /// The background compaction's thread, kept so a test (or a shutdown)
    /// can wait for it. Only ever one: the cursor's `compacting` flag stops a
    /// second from starting while it runs.
    compaction: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// The delta log's position, as the node last left it.
#[derive(Debug, Default, Clone, Copy)]
struct PersistCursor {
    /// The block the checkpoint plus the log currently stand at, so a
    /// block's own delta (captured when it was computed) can be used when
    /// it is that block's child.
    head: B256,
    /// The append cursor the checkpoint plus the log currently describe.
    next_slot: u64,
    /// Bytes of `forest.log` that belong to that description. A restart that
    /// stopped short of the end leaves this below the file's length, and the
    /// next append truncates the remainder rather than writing after it.
    log_len: u64,
    /// Size of the checkpoint the log is measured against.
    checkpoint_len: u64,
    /// A background compaction is folding `forest.log.sealed` into the
    /// checkpoint; no second one starts, and the log is not rotated again,
    /// until it has finished.
    compacting: bool,
}

/// A handle to the node's QMDB state. Cheap to clone; all clones share it.
#[derive(Clone)]
pub struct QmdbNodeState {
    inner: Arc<Inner>,
}

/// Two handles are equal when they share the forest — the only comparison that
/// means anything for a handle, and what lets types holding one keep their
/// derived `PartialEq`.
impl PartialEq for QmdbNodeState {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for QmdbNodeState {}

impl std::fmt::Debug for QmdbNodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let forest = self.lock();
        f.debug_struct("QmdbNodeState")
            .field("dir", &self.inner.dir)
            .field("initialised", &forest.is_some())
            .field("head", &forest.as_ref().map(QmdbForest::head))
            .finish()
    }
}

impl QmdbNodeState {
    /// A handle for `chain`, persisting under `dir`. Not yet usable — see
    /// [`Self::initialize`].
    pub fn new(chain: Arc<ChainSpec>, dir: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(Inner {
                forest: Mutex::new(None),
                chain,
                dir: dir.into(),
                persist: Mutex::new(PersistCursor::default()),
                compaction: Mutex::new(None),
            }),
        }
    }

    /// Where the snapshot lives.
    pub fn snapshot_path(&self) -> PathBuf {
        self.inner.dir.join(SNAPSHOT_FILE)
    }

    /// Where the delta log lives.
    pub fn delta_log_path(&self) -> PathBuf {
        self.inner.dir.join(DELTA_LOG_FILE)
    }

    /// Where the log segment under compaction lives, while one is.
    pub fn sealed_log_path(&self) -> PathBuf {
        self.inner.dir.join(SEALED_LOG_FILE)
    }

    fn cursor(&self) -> MutexGuard<'_, PersistCursor> {
        self.inner
            .persist
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock(&self) -> MutexGuard<'_, Option<QmdbForest>> {
        self.inner
            .forest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs `f` on the forest, or fails if nothing has initialised it.
    fn with_forest<T>(
        &self,
        f: impl FnOnce(&mut QmdbForest) -> Result<T, StateError>,
    ) -> Result<T, NodeStateError> {
        let mut guard = self.lock();
        let forest = guard.as_mut().ok_or(NodeStateError::Uninitialised)?;
        Ok(f(forest)?)
    }

    /// Restores the trees for a database whose canonical head is `head`.
    ///
    /// From the snapshot if it matches the head; from the alloc if the database
    /// is at genesis; otherwise an error, since a QMDB chain cannot start from
    /// execution state alone. Idempotent once initialised.
    pub fn initialize(&self, head: (u64, B256)) -> Result<(), NodeStateError> {
        // Both locks, in the order every other path takes them: the persistence
        // cursor first, then the forest. Taking them the other way round here
        // would be a lock-order inversion against `on_canonical`, and the only
        // thing keeping it from deadlocking would be that initialisation
        // happens to finish before the canonical follower is spawned.
        let mut cursor = self.cursor();
        let mut guard = self.lock();
        if guard.is_some() {
            return Ok(());
        }
        let (head_number, head_hash) = head;
        let path = self.snapshot_path();

        let log_path = self.delta_log_path();

        let forest = match read_snapshot(&path)? {
            Some(checkpoint) => {
                let checkpoint_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                // A segment a compaction had sealed but not folded in when the
                // node last stopped comes first: the log's deltas continue
                // from its end. What the checkpoint already covers is skipped.
                let sealed_path = self.sealed_log_path();
                let sealed = sealed_path.exists();
                let (checkpoint, sealed_head) = if sealed {
                    let (state, _) = replay_delta_log(&sealed_path, checkpoint, Some(head_hash))?;
                    let at = (state.head_number, state.head_hash);
                    (state, Some(at))
                } else {
                    (checkpoint, None)
                };
                // Walk the log forward until the state stands at the head the
                // database is at. The log can end short of it (a delta was lost
                // to a crash) or run past it (the forest followed blocks the
                // database had not persisted); only the first is an error.
                let (snapshot, log_len) =
                    replay_delta_log(&log_path, checkpoint, Some(head_hash))?;
                if snapshot.head_hash != head_hash {
                    return Err(NodeStateError::SnapshotMismatch {
                        snapshot_number: snapshot.head_number,
                        snapshot_hash: snapshot.head_hash,
                        head_number,
                        head_hash,
                    });
                }
                *cursor = PersistCursor {
                    head: snapshot.head_hash,
                    next_slot: snapshot.tree.next_slot,
                    log_len,
                    checkpoint_len,
                    compacting: false,
                };
                info!(
                    target: "n42.qmdb",
                    block = head_number, %head_hash, log_bytes = log_len, sealed,
                    "restored the QMDB forest",
                );
                let forest = QmdbForest::from_snapshot(&snapshot)?;
                // The interrupted compaction resumes: the segment is folded
                // into the checkpoint as it would have been.
                if let Some(sealed_head) = sealed_head {
                    self.spawn_compaction(&mut cursor, sealed_head);
                }
                forest
            }
            None if head_number == 0 => {
                let chain = &self.inner.chain;
                let forest =
                    QmdbForest::genesis(head_hash, &changes_from_alloc(&chain.genesis.alloc))?;
                let header_root = chain.genesis_header.state_root;
                if forest.root() != header_root {
                    return Err(NodeStateError::GenesisRootMismatch {
                        computed: forest.root(),
                        header: header_root,
                    });
                }
                info!(target: "n42.qmdb", root = %forest.root(), "seeded the QMDB forest from the genesis alloc");
                // A genesis forest has no checkpoint on disk yet; the first
                // head move writes one, and until then there is nothing for a
                // delta to be measured against.
                let _ = std::fs::remove_file(&log_path);
                let _ = std::fs::remove_file(self.sealed_log_path());
                *cursor = PersistCursor {
                    head: forest.head().1,
                    next_slot: forest.next_slot(),
                    log_len: 0,
                    checkpoint_len: 0,
                    compacting: false,
                };
                forest
            }
            None => {
                return Err(NodeStateError::NoSnapshot { path, head_number });
            }
        };
        *guard = Some(with_configured_retention(forest));
        Ok(())
    }

    /// Restores the forest from a cross-client portable snapshot — gov5's
    /// `n42-qmdb-export` output, or this node's own [`Self::portable_export`]
    /// — for a database being initialised at the snapshot's block rather than
    /// at genesis. The snapshot is authenticated, bound to `(chain_id,
    /// genesis_hash)`, must be at `expected_head`, and its root must equal
    /// `expected_root`, the state root of the header the caller trusts.
    /// Persisted at once so the node's next start finds it under that head.
    pub fn initialize_from_portable(
        &self,
        portable: &[u8],
        chain_id: u64,
        genesis_hash: B256,
        expected_head: (u64, B256),
        expected_root: B256,
    ) -> Result<(), NodeStateError> {
        use n42_twig_core::qmdb_compat::QmdbPortableSnapshot;
        let snapshot = QmdbPortableSnapshot::decode(portable)
            .map_err(|e| NodeStateError::Portable(e.to_string()))?;
        let at = (snapshot.block_number, B256::from(snapshot.block_hash));
        if at != expected_head {
            return Err(NodeStateError::Portable(format!(
                "snapshot is at block {} {:?}, the header at {} {:?}",
                at.0, at.1, expected_head.0, expected_head.1
            )));
        }
        let tree = snapshot
            .verify_and_build(chain_id, &genesis_hash.0)
            .map_err(|e| NodeStateError::Portable(e.to_string()))?;
        let root = B256::from(tree.root());
        if root != expected_root {
            return Err(NodeStateError::Portable(format!(
                "snapshot root {root:?} is not the header's state root {expected_root:?}"
            )));
        }
        let mut forest = QmdbForest::from_tree(expected_head.0, expected_head.1, tree);
        let mut cursor = self.cursor();
        let snapshot = forest.snapshot()?;
        let checkpoint_len = write_snapshot(&self.snapshot_path(), &snapshot)?;
        // Any log left in this datadir describes a different chain of states.
        // Its first delta would be refused for standing on the wrong cursor,
        // which is safe but reads as corruption; removing it is the truth.
        let _ = std::fs::remove_file(self.delta_log_path());
        let _ = std::fs::remove_file(self.sealed_log_path());
        *cursor = PersistCursor {
            head: snapshot.head_hash,
            next_slot: snapshot.tree.next_slot,
            log_len: 0,
            checkpoint_len,
            compacting: false,
        };
        info!(target: "n42.qmdb", block = expected_head.0, head = %expected_head.1, %root, "restored the QMDB forest from a portable snapshot");
        *self.lock() = Some(with_configured_retention(forest));
        Ok(())
    }

    /// The persisted forest as a cross-client portable snapshot, for another
    /// node to start from. Reads the snapshot file; the node need not be
    /// running.
    pub fn portable_export(&self, chain_id: u64, genesis_hash: B256) -> Result<Vec<u8>, NodeStateError> {
        use n42_twig_core::qmdb_compat::{QmdbPortableSnapshot, QmdbSlotEntry, QmdbSlotSnapshot};
        let path = self.snapshot_path();
        let checkpoint =
            read_snapshot(&path)?.ok_or(NodeStateError::NoSnapshot { path, head_number: 0 })?;
        // The checkpoint alone is not the persisted head: the deltas written
        // since it are the rest of the story, and an export taken without them
        // would be a state some blocks behind the one it claims to be at.
        let (snapshot, _) = replay_delta_log(&self.delta_log_path(), checkpoint, None)?;
        let tree = QmdbForest::from_snapshot(&snapshot)?;
        let entries = snapshot
            .tree
            .entries
            .iter()
            .enumerate()
            .map(|(slot, entry)| QmdbSlotEntry {
                slot: slot as u64,
                key: entry.key,
                value: entry.value.clone(),
                active: entry.active,
            })
            .collect();
        let portable = QmdbPortableSnapshot {
            chain_id,
            genesis_hash: genesis_hash.0,
            block_number: snapshot.head_number,
            block_hash: snapshot.head_hash.0,
            root: tree.root().0,
            slots: QmdbSlotSnapshot { next_slot: snapshot.tree.next_slot, entries },
        };
        portable.encode().map_err(|e| NodeStateError::Portable(e.to_string()))
    }

    /// Whether [`Self::initialize`] has run.
    pub fn is_initialized(&self) -> bool {
        self.lock().is_some()
    }

    /// Computes the tree a block would have on `parent`, for a producer that
    /// will learn the block's hash only after sealing the root into it.
    pub fn compute(&self, parent: B256, changes: &BlockChanges) -> Result<PreparedBlock, NodeStateError> {
        self.with_forest(|forest| forest.compute(parent, changes))
    }

    /// [`Self::compute`] from leaf operations already built
    /// (`sorted_operations_from_execution`).
    pub fn compute_operations(&self, parent: B256, ops: Vec<QmdbOperation>) -> Result<PreparedBlock, NodeStateError> {
        self.with_forest(|forest| forest.compute_operations(parent, ops))
    }

    /// [`Self::validate_block`] from leaf operations already built.
    pub fn validate_block_operations(
        &self,
        parent: B256,
        block_hash: B256,
        number: u64,
        ops: Vec<QmdbOperation>,
        header_root: B256,
    ) -> Result<B256, NodeStateError> {
        self.with_forest(|forest| {
            if let Some(root) = forest.root_of(&block_hash) {
                return Ok(root);
            }
            let prepared = forest.compute_operations(parent, ops)?;
            let root = prepared.root;
            if root == header_root {
                forest.insert(block_hash, number, prepared)?;
            } else {
                warn!(
                    target: "n42.qmdb",
                    %block_hash, number, computed = %root, header = %header_root,
                    "block's state root does not match its QMDB root",
                );
            }
            Ok(root)
        })
    }

    /// Files a producer's computed tree under the block it turned out to be.
    pub fn insert(&self, block_hash: B256, number: u64, prepared: PreparedBlock) -> Result<(), NodeStateError> {
        self.with_forest(|forest| forest.insert(block_hash, number, prepared))
    }

    /// Computes a validated block's root and files its tree if the header agrees.
    ///
    /// Returns the computed root either way — the validator compares it to the
    /// header and is the one that declares the block invalid — but only a block
    /// whose header matches gets a tree. Filing an invalid block's tree would
    /// let a later block build on state consensus never accepted.
    pub fn validate_block(
        &self,
        parent: B256,
        block_hash: B256,
        number: u64,
        changes: &BlockChanges,
        header_root: B256,
    ) -> Result<B256, NodeStateError> {
        self.with_forest(|forest| {
            if let Some(root) = forest.root_of(&block_hash) {
                return Ok(root);
            }
            let prepared = forest.compute(parent, changes)?;
            let root = prepared.root;
            if root == header_root {
                forest.insert(block_hash, number, prepared)?;
            } else {
                warn!(
                    target: "n42.qmdb",
                    %block_hash, number, computed = %root, header = %header_root,
                    "block's state root does not match its QMDB root",
                );
            }
            Ok(root)
        })
    }

    /// The root after `block_hash`, if its tree is held.
    /// Files a computed block under the hash consensus sealed it with. See
    /// `QmdbForest::rename`.
    pub fn rename(&self, from: B256, to: B256) -> Result<(), NodeStateError> {
        self.with_forest(|forest| forest.rename(from, to))
    }

    /// The root of a block the forest holds, if it does.
    pub fn root_of(&self, block_hash: &B256) -> Option<B256> {
        self.lock().as_ref()?.root_of(block_hash)
    }

    /// The canonical head the forest stands at.
    pub fn head(&self) -> Option<(u64, B256)> {
        self.lock().as_ref().map(QmdbForest::head)
    }

    /// Advances the canonical head and persists its tree.
    ///
    /// A head the forest does not hold is an error rather than a silent gap: it
    /// means a block reached the canonical chain without passing through this
    /// node's validation, and the forest can no longer compute the next root.
    pub fn on_canonical(&self, block_hash: B256) -> Result<(), NodeStateError> {
        let mut cursor = self.cursor();
        // No checkpoint yet (a forest seeded from the alloc, or one whose log
        // has outgrown it): write the tree once, and the deltas that follow are
        // measured against it.
        if cursor.checkpoint_len == 0 {
            return self.checkpoint(block_hash, &mut cursor);
        }
        // The block's own delta from its parent, captured when it was
        // computed, when the persisted state is its parent (or an ancestor
        // whose every step is held): nothing here moves the tree, which may
        // stand at the next block's build by now. Otherwise -- a branch switch,
        // a restored forest, a block whose delta went by the other path -- the
        // difference is measured by standing the tree at the head as before.
        let ready = self.with_forest(|forest| {
            forest.set_canonical(block_hash)?;
            Ok(forest.take_block_deltas(cursor.head, cursor.next_slot, block_hash))
        })?;
        if let Some(deltas) = ready {
            for delta in &deltas {
                let written = append_delta(&self.delta_log_path(), cursor.log_len, delta)?;
                cursor.next_slot = delta.next_slot;
                cursor.log_len = written;
                debug!(
                    target: "n42.qmdb",
                    block = delta.head_number, block_hash = %delta.head_hash,
                    appended = delta.appended.len(), changed = delta.changed.len(),
                    "persisted a QMDB block from its own delta",
                );
            }
            cursor.head = block_hash;
            // The tree's move bookkeeping describes changes since the last
            // measured delta; what these deltas carried is measured now, and
            // any move that follows records itself afresh.
            self.with_forest(|forest| {
                forest.forget_changes();
                Ok(())
            })?;
            if checkpoint_due(&cursor) {
                return self.rewrite_checkpoint(block_hash, &mut cursor);
            }
            return Ok(());
        }
        let delta = self.with_forest(|forest| {
            forest.set_canonical(block_hash)?;
            forest.delta_since(cursor.next_slot)
        })?;
        // Rewriting the checkpoint costs the whole state, so it is worth doing
        // only once the log it replaces has grown to the same size. That bounds
        // what a restart has to replay, bounds the disk to twice the state, and
        // leaves the per-block cost at the size of the block.
        //
        // The measured delta is appended first either way: the compaction
        // folds the log as it stands, and the synchronous checkpoint's
        // snapshot covers it too (the log is then emptied).
        let written = append_delta(&self.delta_log_path(), cursor.log_len, &delta)?;
        cursor.head = block_hash;
        cursor.next_slot = delta.next_slot;
        cursor.log_len = written;
        debug!(
            target: "n42.qmdb",
            block = delta.head_number, %block_hash,
            appended = delta.appended.len(), changed = delta.changed.len(),
            "persisted the QMDB head as a delta",
        );
        if checkpoint_due(&cursor) {
            return self.rewrite_checkpoint(block_hash, &mut cursor);
        }
        Ok(())
    }

    /// The checkpoint, rewritten at `block_hash` = the log's head: from the
    /// files on a background thread (the default), or from the live forest
    /// on this one (`N42_QMDB_CHECKPOINT_SYNC=1`).
    fn rewrite_checkpoint(
        &self,
        block_hash: B256,
        cursor: &mut PersistCursor,
    ) -> Result<(), NodeStateError> {
        if checkpoint_sync() {
            return self.checkpoint(block_hash, cursor);
        }
        if cursor.compacting {
            // The previous compaction is still running; the log keeps growing
            // and the next head asks again.
            return Ok(());
        }
        let head = self.with_forest(|forest| Ok(forest.head()))?;
        let sealed_path = self.sealed_log_path();
        if sealed_path.exists() {
            // A compaction that failed left its segment behind (it is still
            // needed: the checkpoint does not cover it). Fold that one first;
            // the log is rotated once it is gone.
            warn!(target: "n42.qmdb", path = %sealed_path.display(), "a sealed QMDB log segment is still waiting to be compacted; retrying it");
            self.spawn_compaction(cursor, head);
            return Ok(());
        }
        let log_path = self.delta_log_path();
        if !log_path.exists() {
            return Ok(());
        }
        std::fs::rename(&log_path, &sealed_path).map_err(|source| NodeStateError::Io {
            path: log_path.clone(),
            source,
        })?;
        // The log starts again from nothing; the cursor's head and slot are
        // unchanged, because checkpoint + sealed segment is the state they
        // describe.
        cursor.log_len = 0;
        self.spawn_compaction(cursor, head);
        Ok(())
    }

    /// Starts the thread that folds `forest.log.sealed` into the checkpoint,
    /// ending at `sealed_head`. The cursor's `compacting` flag is set here
    /// and cleared by the thread.
    fn spawn_compaction(&self, cursor: &mut PersistCursor, sealed_head: (u64, B256)) {
        cursor.compacting = true;
        let state = self.clone();
        let spawned = std::thread::Builder::new()
            .name("qmdb-compact".into())
            .spawn(move || state.compact(sealed_head));
        let mut slot = self.inner.compaction.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match spawned {
            Ok(handle) => {
                // A finished predecessor's handle is replaced; joining it is
                // free since `compacting` was clear when this one started.
                if let Some(previous) = slot.take() {
                    let _ = previous.join();
                }
                *slot = Some(handle);
            }
            Err(err) => {
                cursor.compacting = false;
                warn!(target: "n42.qmdb", %err, "could not start the QMDB compaction thread; the log keeps growing");
            }
        }
    }

    /// The compaction thread's body: checkpoint + sealed segment, replayed the
    /// way a restart replays them, written as the new checkpoint; then the
    /// segment is deleted. Nothing here takes the forest lock.
    fn compact(&self, sealed_head: (u64, B256)) {
        apply_compact_nice();
        let started = std::time::Instant::now();
        let path = self.snapshot_path();
        let sealed_path = self.sealed_log_path();
        let result = (|| -> Result<(u64, u64), NodeStateError> {
            let checkpoint = read_snapshot(&path)?.ok_or_else(|| NodeStateError::NoSnapshot {
                path: path.clone(),
                head_number: sealed_head.0,
            })?;
            let read_ms = started.elapsed().as_millis() as u64;
            let (snapshot, _) = replay_delta_log(&sealed_path, checkpoint, Some(sealed_head.1))?;
            if snapshot.head_hash != sealed_head.1 {
                return Err(NodeStateError::SnapshotMismatch {
                    snapshot_number: snapshot.head_number,
                    snapshot_hash: snapshot.head_hash,
                    head_number: sealed_head.0,
                    head_hash: sealed_head.1,
                });
            }
            let len = write_snapshot(&path, &snapshot)?;
            // The segment goes only once the checkpoint that covers it is on
            // disk; a crash in between leaves a segment a restart skips.
            let _ = std::fs::remove_file(&sealed_path);
            Ok((len, read_ms))
        })();
        let mut cursor = self.cursor();
        cursor.compacting = false;
        match result {
            Ok((len, read_ms)) => {
                cursor.checkpoint_len = len;
                info!(
                    target: "n42.qmdb",
                    block = sealed_head.0, block_hash = %sealed_head.1, bytes = len,
                    read_ms, total_ms = started.elapsed().as_millis() as u64,
                    "compacted the QMDB log into a new checkpoint",
                );
            }
            Err(err) => {
                // The files are still consistent (checkpoint + segment + log);
                // the segment is retried at the next due point.
                warn!(target: "n42.qmdb", %err, "QMDB compaction failed; the sealed segment is kept");
            }
        }
    }

    /// Waits for a background compaction, if one is running. For tests and
    /// for a shutdown that wants the checkpoint settled.
    pub fn wait_for_compaction(&self) {
        let handle = self.inner.compaction.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }

    /// Writes the whole tree and starts a fresh log, from the live forest.
    fn checkpoint(
        &self,
        block_hash: B256,
        cursor: &mut PersistCursor,
    ) -> Result<(), NodeStateError> {
        let started = std::time::Instant::now();
        let snapshot = self.with_forest(|forest| {
            forest.set_canonical(block_hash)?;
            let snapshot = forest.snapshot()?;
            // The changes are in the snapshot now, so the next delta must be
            // measured from it rather than carrying them a second time.
            forest.forget_changes();
            Ok(snapshot)
        })?;
        let path = self.snapshot_path();
        let len = write_snapshot(&path, &snapshot)?;
        // Order matters: the log is emptied only once the checkpoint that
        // supersedes it is on disk, so a crash between the two leaves a log
        // that is merely redundant rather than a state with neither.
        let _ = std::fs::remove_file(self.delta_log_path());
        *cursor = PersistCursor {
            head: block_hash,
            next_slot: snapshot.tree.next_slot,
            log_len: 0,
            checkpoint_len: len,
            compacting: cursor.compacting,
        };
        info!(
            target: "n42.qmdb",
            block = snapshot.head_number, %block_hash, bytes = len,
            total_ms = started.elapsed().as_millis() as u64,
            "checkpointed the QMDB head",
        );
        Ok(())
    }
}

/// Whether the log has grown to the point where the checkpoint is rewritten.
fn checkpoint_due(cursor: &PersistCursor) -> bool {
    cursor.log_len >= cursor.checkpoint_len.saturating_mul(checkpoint_ratio())
        && cursor.log_len >= MIN_LOG_BEFORE_CHECKPOINT
}

impl StateProofProvider for QmdbNodeState {
    fn state_root(&self) -> B256 {
        self.lock().as_ref().map(QmdbForest::root).unwrap_or_default()
    }

    fn prove_account(&self, address: Address) -> Option<QmdbProof> {
        self.lock().as_mut()?.prove_account(address)
    }

    fn prove_storage(&self, address: Address, slot: B256) -> Option<QmdbProof> {
        self.lock().as_mut()?.prove_storage(address, slot)
    }
}

fn read_snapshot(path: &Path) -> Result<Option<ForestSnapshot>, NodeStateError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(NodeStateError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    bincode::deserialize(&bytes)
        .map(Some)
        .map_err(|source| NodeStateError::Decode {
            path: path.to_path_buf(),
            source,
        })
}

/// Writes to a temporary file and renames, so a crash mid-write leaves the
/// previous snapshot rather than a truncated one. A truncated snapshot would
/// fail to decode and stop the node; a stale one is merely behind, which the
/// startup check reports.
fn write_snapshot(path: &Path, snapshot: &ForestSnapshot) -> Result<u64, NodeStateError> {
    let io = |source| NodeStateError::Io {
        path: path.to_path_buf(),
        source,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let bytes = bincode::serialize(snapshot).map_err(|source| NodeStateError::Decode {
        path: path.to_path_buf(),
        source,
    })?;
    let temp = path.with_extension("bin.tmp");
    std::fs::write(&temp, &bytes).map_err(io)?;
    std::fs::rename(&temp, path).map_err(io)?;
    Ok(bytes.len() as u64)
}

/// A delta log record: a length, a digest of the payload, then the payload.
///
/// The digest is what makes a torn tail detectable. A crash between the write
/// and the flush leaves a partial record, and a partial bincode payload can
/// still decode into a structurally valid delta whose contents are nonsense —
/// which, applied, would give a tree that never existed and a root nothing
/// could explain. A record that does not hash to its header is discarded, and
/// with it everything after it.
const RECORD_HEADER: usize = 12;

fn frame_delta(delta: &ForestDelta) -> Result<Vec<u8>, NodeStateError> {
    let payload = bincode::serialize(delta).map_err(|source| NodeStateError::Decode {
        path: PathBuf::from(DELTA_LOG_FILE),
        source,
    })?;
    let digest = alloy_primitives::keccak256(&payload);
    let mut record = Vec::with_capacity(RECORD_HEADER + payload.len());
    record.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    record.extend_from_slice(&digest[..4]);
    record.extend_from_slice(&payload);
    Ok(record)
}

/// Appends one delta at `from`, truncating anything after it, and returns the
/// log's new length.
///
/// Truncating rather than seeking to the end is deliberate: a restart that
/// stopped replaying short of the log's end leaves records describing a future
/// the forest no longer stands in, and appending after them would interleave
/// two histories in one file.
fn append_delta(path: &Path, from: u64, delta: &ForestDelta) -> Result<u64, NodeStateError> {
    use std::io::{Seek, SeekFrom, Write};
    let io = |source| NodeStateError::Io {
        path: path.to_path_buf(),
        source,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let record = frame_delta(delta)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        // Not truncated on open: the length this record belongs after is
        // `from`, which the `set_len` below establishes exactly. Truncating
        // here would throw away every earlier delta.
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(io)?;
    file.set_len(from).map_err(io)?;
    file.seek(SeekFrom::Start(from)).map_err(io)?;
    file.write_all(&record).map_err(io)?;
    Ok(from + record.len() as u64)
}

/// Replays `path` onto `checkpoint`, stopping at `head_hash` if it is reached.
///
/// Returns the state and how many bytes of the log it accounts for, so a later
/// append writes over whatever was left rather than after it.
fn replay_delta_log(
    path: &Path,
    checkpoint: ForestSnapshot,
    stop_at: Option<B256>,
) -> Result<(ForestSnapshot, u64), NodeStateError> {
    let mut state = checkpoint;
    if stop_at == Some(state.head_hash) {
        // Already there. Anything in the log describes blocks past the head,
        // which will arrive again through the engine.
        return Ok((state, 0));
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((state, 0)),
        Err(source) => {
            return Err(NodeStateError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    let mut at = 0usize;
    let mut good = 0u64;
    while at + RECORD_HEADER <= bytes.len() {
        let len = u64::from_le_bytes(
            bytes[at..at + 8].try_into().expect("eight bytes"),
        );
        // Every one of these is a bound on a number that came out of a file a
        // crash may have cut in half. A torn length field is the whole reason
        // the digest below exists, and computing `start + len` before checking
        // it would wrap before the digest ever got a look.
        let Ok(len) = usize::try_from(len) else { break };
        let start = at + RECORD_HEADER;
        let Some(end) = start.checked_add(len) else { break };
        let Some(payload) = bytes.get(start..end) else { break };
        if alloy_primitives::keccak256(payload)[..4] != bytes[at + 8..start] {
            warn!(target: "n42.qmdb", offset = at, "QMDB delta log is torn here; ignoring the rest");
            break;
        }
        let Ok(delta) = bincode::deserialize::<ForestDelta>(payload) else {
            warn!(target: "n42.qmdb", offset = at, "QMDB delta did not decode; ignoring the rest");
            break;
        };
        // A delta the checkpoint already covers -- a sealed segment whose
        // compaction wrote its checkpoint and then stopped before deleting
        // the segment -- stands on an older cursor and lands no later than
        // the state does; it is skipped. A delta on the wrong cursor that
        // would move the state forward is the corruption `apply_delta`
        // refuses.
        if delta.base_next_slot != state.tree.next_slot && delta.head_number <= state.head_number {
            at = end;
            good = at as u64;
            continue;
        }
        state.apply_delta(&delta)?;
        at = end;
        good = at as u64;
        if stop_at == Some(state.head_hash) {
            break;
        }
    }
    Ok((state, good))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_genesis::Genesis;

    fn qmdb_chain() -> Arc<ChainSpec> {
        let genesis: Genesis = serde_json::from_str(
            r#"{
                "config": { "chainId": 1143, "shanghaiTime": 0, "cancunTime": 0, "stateScheme": "qmdb" },
                "alloc": { "0x0000000000000000000000000000000000000001": { "balance": "0x64" } },
                "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0",
                "extraData": "0x", "nonce": "0x0",
                "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "coinbase": "0x0000000000000000000000000000000000000000",
                "number": "0x0", "gasUsed": "0x0",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }"#,
        )
        .unwrap();
        Arc::new(crate::chainspec::with_declared_state_scheme(genesis.into()).unwrap())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("n42-qmdb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn nothing_works_before_initialisation() {
        let state = QmdbNodeState::new(qmdb_chain(), scratch("uninit"));
        assert!(matches!(
            state.compute(B256::ZERO, &BlockChanges::new()),
            Err(NodeStateError::Uninitialised)
        ));
    }

    #[test]
    fn a_genesis_database_is_seeded_from_the_alloc() {
        let chain = qmdb_chain();
        let state = QmdbNodeState::new(chain.clone(), scratch("genesis"));
        state.initialize((0, chain.genesis_hash())).unwrap();
        assert_eq!(state.state_root(), chain.genesis_header.state_root);
    }

    /// The chain spec was parsed without the scheme, so its genesis header
    /// carries an MPT root. Seeding from the alloc gives a QMDB root, and the two
    /// must not be silently reconciled.
    #[test]
    fn a_genesis_built_for_mpt_is_refused() {
        let genesis: Genesis = serde_json::from_str(
            r#"{
                "config": { "chainId": 1143, "shanghaiTime": 0, "cancunTime": 0 },
                "alloc": { "0x0000000000000000000000000000000000000001": { "balance": "0x64" } },
                "difficulty": "0x0", "gasLimit": "0x1c9c380", "timestamp": "0x0",
                "extraData": "0x", "nonce": "0x0",
                "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "coinbase": "0x0000000000000000000000000000000000000000",
                "number": "0x0", "gasUsed": "0x0",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }"#,
        )
        .unwrap();
        let chain: Arc<ChainSpec> = Arc::new(genesis.into());
        let state = QmdbNodeState::new(chain.clone(), scratch("mpt-genesis"));
        assert!(matches!(
            state.initialize((0, chain.genesis_hash())),
            Err(NodeStateError::GenesisRootMismatch { .. })
        ));
    }

    #[test]
    fn the_head_survives_a_restart_and_a_stale_snapshot_is_refused() {
        let chain = qmdb_chain();
        let dir = scratch("restart");
        let genesis_hash = chain.genesis_hash();

        let state = QmdbNodeState::new(chain.clone(), &dir);
        state.initialize((0, genesis_hash)).unwrap();
        let block1 = B256::repeat_byte(0x11);
        let root = state
            .validate_block(genesis_hash, block1, 1, &BlockChanges::new(), {
                // Compute the expected root first so the header "matches".
                state.compute(genesis_hash, &BlockChanges::new()).unwrap().root
            })
            .unwrap();
        state.on_canonical(block1).unwrap();

        // A new process, same directory, database at block 1.
        let restarted = QmdbNodeState::new(chain.clone(), &dir);
        restarted.initialize((1, block1)).unwrap();
        assert_eq!(restarted.head(), Some((1, block1)));
        assert_eq!(restarted.state_root(), root);

        // A database that moved on without this forest.
        let behind = QmdbNodeState::new(chain, &dir);
        assert!(matches!(
            behind.initialize((5, B256::repeat_byte(0x55))),
            Err(NodeStateError::SnapshotMismatch { .. })
        ));
    }

    /// The delta log rotates. A five-minute fleet run never reaches this — the
    /// log has to outgrow the checkpoint first, which on a small chain takes
    /// about a thousand blocks — so the one path that deletes state on disk is
    /// the one a live test would not have covered.
    #[test]
    fn the_log_rotates_into_a_new_checkpoint_and_the_head_still_restores() {
        use n42_qmdb_state::AccountState;
        use alloy_primitives::{Address, U256};

        let chain = qmdb_chain();
        let dir = scratch("rotate");
        let state = QmdbNodeState::new(chain.clone(), &dir);
        state.initialize((0, chain.genesis_hash())).unwrap();

        let mut parent = chain.genesis_hash();
        let mut root = B256::ZERO;
        let mut rotated = false;
        let mut previous_log = 0u64;
        for number in 1..=20_000u64 {
            // A fresh account every block, so every delta carries an append and
            // the log grows the way a real one does.
            let mut changes = BlockChanges::new();
            changes.set_account(
                Address::from_word(B256::from(U256::from(number))),
                AccountState { nonce: number, balance: U256::from(number), code_hash: B256::ZERO },
            );
            let hash = B256::from(U256::from(number) << 64);
            let prepared = state.compute(parent, &changes).unwrap();
            root = prepared.root;
            state.insert(hash, number, prepared).unwrap();
            state.on_canonical(hash).unwrap();
            let log = std::fs::metadata(state.delta_log_path()).map(|m| m.len()).unwrap_or(0);
            // A rotation is the log getting shorter: the checkpoint that
            // replaced it is on disk and the log started again.
            if log < previous_log {
                rotated = true;
            }
            previous_log = log;
            parent = hash;
        }
        assert!(rotated, "the log never outgrew its checkpoint, last size {previous_log}");
        // The compaction runs behind the chain; once it is done the sealed
        // segment is in the checkpoint and gone from the directory.
        state.wait_for_compaction();
        assert!(!state.sealed_log_path().exists(), "a sealed segment survived its compaction");
        assert!(!state.cursor().compacting);

        // What rotation is for: a node that restarts after one restores the
        // same state, from a checkpoint it never wrote the whole of per block.
        let restarted = QmdbNodeState::new(chain, &dir);
        restarted.initialize((20_000, parent)).unwrap();
        assert_eq!(restarted.head(), Some((20_000, parent)));
        assert_eq!(restarted.state_root(), root);
    }

    /// A node can stop while a compaction is in flight: the checkpoint is
    /// then behind, the sealed segment carries the blocks up to the rotation
    /// and the log the ones after it. A restart replays all three in order,
    /// and resumes the compaction. And if the node stopped between the new
    /// checkpoint's rename and the segment's deletion, the segment describes
    /// blocks the checkpoint already holds, and the replay skips them.
    #[test]
    fn a_restart_during_compaction_replays_the_sealed_segment_then_the_log() {
        use n42_qmdb_state::AccountState;
        use alloy_primitives::{Address, U256};

        let chain = qmdb_chain();
        let dir = scratch("sealed");
        let state = QmdbNodeState::new(chain.clone(), &dir);
        state.initialize((0, chain.genesis_hash())).unwrap();

        let mut parent = chain.genesis_hash();
        let mut roots = vec![state.state_root()];
        let mut hashes = vec![parent];
        let mut advance = |state: &QmdbNodeState, number: u64, parent: &mut B256| {
            let mut changes = BlockChanges::new();
            changes.set_account(
                Address::from_word(B256::from(U256::from(number))),
                AccountState { nonce: number, balance: U256::from(number), code_hash: B256::ZERO },
            );
            let hash = B256::from(U256::from(number) << 64);
            let prepared = state.compute(*parent, &changes).unwrap();
            roots.push(prepared.root);
            state.insert(hash, number, prepared).unwrap();
            state.on_canonical(hash).unwrap();
            hashes.push(hash);
            *parent = hash;
        };
        for number in 1..=5 {
            advance(&state, number, &mut parent);
        }
        // The rotation by hand, without the thread that would fold it in: the
        // state a crash mid-compaction leaves. The cursor's log length starts
        // again, as `rewrite_checkpoint` leaves it.
        std::fs::rename(state.delta_log_path(), state.sealed_log_path()).unwrap();
        state.cursor().log_len = 0;
        for number in 6..=10 {
            advance(&state, number, &mut parent);
        }
        let sealed_copy = dir.join("sealed.copy");
        std::fs::copy(state.sealed_log_path(), &sealed_copy).unwrap();
        drop(state);

        // Checkpoint (block 1) + sealed segment (2-5) + log (6-10).
        let restarted = QmdbNodeState::new(chain.clone(), &dir);
        restarted.initialize((10, hashes[10])).unwrap();
        assert_eq!(restarted.head(), Some((10, hashes[10])));
        assert_eq!(restarted.state_root(), roots[10]);
        // The interrupted compaction resumed and finished: the checkpoint now
        // stands at block 5 and the segment is gone.
        restarted.wait_for_compaction();
        assert!(!restarted.sealed_log_path().exists());
        let checkpoint = read_snapshot(&restarted.snapshot_path()).unwrap().unwrap();
        assert_eq!((checkpoint.head_number, checkpoint.head_hash), (5, hashes[5]));
        assert_eq!(restarted.cursor().checkpoint_len, std::fs::metadata(restarted.snapshot_path()).unwrap().len());
        drop(restarted);

        // The segment reappears although the checkpoint covers it (a crash
        // between the checkpoint's rename and the segment's deletion): every
        // delta in it is skipped, the log still applies, the root is the same.
        std::fs::copy(&sealed_copy, dir.join(SEALED_LOG_FILE)).unwrap();
        let again = QmdbNodeState::new(chain.clone(), &dir);
        again.initialize((10, hashes[10])).unwrap();
        assert_eq!(again.state_root(), roots[10]);
        again.wait_for_compaction();
        assert!(!again.sealed_log_path().exists());
        drop(again);

        // And a plain restart after all of it, the ordinary way.
        let plain = QmdbNodeState::new(chain, &dir);
        plain.initialize((10, hashes[10])).unwrap();
        assert_eq!(plain.state_root(), roots[10]);
        assert_eq!(plain.head(), Some((10, hashes[10])));
    }

    /// A crash can cut the log in half. The last record is then partly there,
    /// and a partly-there bincode payload can still decode into a structurally
    /// valid delta whose contents are nonsense — which, applied, would give a
    /// tree that never existed and a root nothing could explain. The record's
    /// digest is what stops that, so it is worth a test that actually tears one.
    #[test]
    fn a_torn_log_costs_the_last_block_and_not_the_state() {
        use n42_qmdb_state::AccountState;
        use alloy_primitives::{Address, U256};

        let chain = qmdb_chain();
        let dir = scratch("torn");
        let state = QmdbNodeState::new(chain.clone(), &dir);
        state.initialize((0, chain.genesis_hash())).unwrap();

        let mut parent = chain.genesis_hash();
        let mut hashes = vec![parent];
        let mut roots = vec![state.state_root()];
        for number in 1..=5u64 {
            let mut changes = BlockChanges::new();
            changes.set_account(
                Address::from_word(B256::from(U256::from(number))),
                AccountState { nonce: number, balance: U256::from(number), code_hash: B256::ZERO },
            );
            let hash = B256::from(U256::from(number) << 64);
            let prepared = state.compute(parent, &changes).unwrap();
            roots.push(prepared.root);
            state.insert(hash, number, prepared).unwrap();
            state.on_canonical(hash).unwrap();
            hashes.push(hash);
            parent = hash;
        }

        // Tear the tail: the last record loses its final bytes, as a process
        // killed between the write and the flush would leave it.
        let log = state.delta_log_path();
        let len = std::fs::metadata(&log).unwrap().len();
        std::fs::OpenOptions::new().write(true).open(&log).unwrap().set_len(len - 12).unwrap();

        // Block 4 is intact and restores exactly.
        let restarted = QmdbNodeState::new(chain.clone(), &dir);
        restarted.initialize((4, hashes[4])).unwrap();
        assert_eq!(restarted.head(), Some((4, hashes[4])));
        assert_eq!(restarted.state_root(), roots[4]);

        // Block 5 is the one that was torn away, and the node says so rather
        // than starting on a state it cannot account for.
        let ahead = QmdbNodeState::new(chain, &dir);
        assert!(matches!(
            ahead.initialize((5, hashes[5])),
            Err(NodeStateError::SnapshotMismatch { .. })
        ));
    }

    #[test]
    fn a_database_past_genesis_with_no_snapshot_cannot_start() {
        let chain = qmdb_chain();
        let state = QmdbNodeState::new(chain, scratch("no-snapshot"));
        assert!(matches!(
            state.initialize((7, B256::repeat_byte(0x77))),
            Err(NodeStateError::NoSnapshot { head_number: 7, .. })
        ));
    }

    #[test]
    fn a_block_whose_header_disagrees_gets_no_tree() {
        let chain = qmdb_chain();
        let state = QmdbNodeState::new(chain.clone(), scratch("mismatch"));
        let genesis_hash = chain.genesis_hash();
        state.initialize((0, genesis_hash)).unwrap();

        let bad = B256::repeat_byte(0xBB);
        let computed = state
            .validate_block(genesis_hash, bad, 1, &BlockChanges::new(), B256::repeat_byte(0xEE))
            .unwrap();
        assert_ne!(computed, B256::repeat_byte(0xEE), "the real root is reported");
        assert!(state.root_of(&bad).is_none(), "but the invalid block leaves no tree");
        assert!(matches!(
            state.on_canonical(bad),
            Err(NodeStateError::State(StateError::UnknownBlock(_)))
        ));
    }
}
