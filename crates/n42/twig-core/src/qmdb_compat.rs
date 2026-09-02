//! QMDB split-commitment compatibility core.
//!
//! gov5 QMDB freezes an appended leaf forever. Updates and deletes only alter
//! the twig's active bitmap, and a twig commits `hash(leaf_root, bits_root)`.
//! The existing [`crate::TwigTree`] intentionally predates that representation
//! and nulls inactive leaves, so it must not be used to import replay-v2 QMDB
//! state. This small, isolated core is the compatibility baseline.

use std::{collections::HashMap, io::Read};

use crate::{Hash, NULL_HASH, TWIG_HEIGHT, TWIG_SIZE, hash_leaf, hash_node, null_level};

const BITS_PREFIX: u8 = 0x03;
const BITS_BYTES: usize = TWIG_SIZE / 8;
const PROOF_CODEC_VERSION: u8 = 0x02;
const MAX_UPPER_PATH: usize = 64;
const PORTABLE_SNAPSHOT_MAGIC: &[u8; 8] = b"N42QMDB\x01";
const PORTABLE_SNAPSHOT_DIGEST_SIZE: usize = 32;
const PORTABLE_SNAPSHOT_HEADER_SIZE: usize = 8 + 8 + 32 + 8 + 32 + 32 + 8 + 8;
const PORTABLE_SNAPSHOT_ENTRY_SIZE: usize = 8 + 1 + 32 + 4;
const MAX_PORTABLE_VALUE_SIZE: usize = 16 << 20;

/// Keccak-256 of empty bytecode. gov5 treats both this value and zero as an empty code hash when
/// serializing a QMDB account leaf.
pub const GOV5_EMPTY_CODE_HASH: Hash = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// gov5 QMDB account key: `Blake3(address)` with no domain prefix.
pub fn gov5_account_key(address: &[u8; 20]) -> Hash {
    *blake3::hash(address).as_bytes()
}

/// gov5 QMDB storage key: `Blake3(address || slot)` with no domain prefix.
pub fn gov5_storage_key(address: &[u8; 20], slot: &[u8; 32]) -> Hash {
    let mut input = [0_u8; 52];
    input[..20].copy_from_slice(address);
    input[20..].copy_from_slice(slot);
    *blake3::hash(&input).as_bytes()
}

/// Exact gov5 `StateAccount.MarshalV2` leaf encoding.
///
/// The balance must be a 32-byte big-endian integer. Non-zero nonce uses unsigned LEB128;
/// non-zero balance uses a one-byte length followed by minimal big-endian bytes; non-empty code
/// hash is stored verbatim. The first byte is the presence bitmap (nonce=1, balance=2, code=8).
pub fn encode_gov5_account_value(nonce: u64, balance: &[u8; 32], code_hash: &Hash) -> Vec<u8> {
    let balance_start = balance.iter().position(|byte| *byte != 0);
    let has_code = *code_hash != NULL_HASH && *code_hash != GOV5_EMPTY_CODE_HASH;
    let mut value = Vec::with_capacity(
        1 + if nonce == 0 { 0 } else { 10 }
            + balance_start.map_or(0, |start| 1 + balance.len() - start)
            + if has_code { 32 } else { 0 },
    );
    value.push(0);
    if nonce != 0 {
        value[0] |= 1;
        let mut remaining = nonce;
        while remaining >= 0x80 {
            value.push((remaining as u8) | 0x80);
            remaining >>= 7;
        }
        value.push(remaining as u8);
    }
    if let Some(start) = balance_start {
        value[0] |= 2;
        value.push((balance.len() - start) as u8);
        value.extend_from_slice(&balance[start..]);
    }
    if has_code {
        value[0] |= 8;
        value.extend_from_slice(code_hash);
    }
    value
}

/// One deterministic QMDB mutation. `None` deactivates the current live slot for `key`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct QmdbOperation {
    pub key: Hash,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum QmdbOperationError {
    #[error("QMDB block mutation contains duplicate key {0:?}")]
    DuplicateKey(Hash),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct QmdbEntrySnapshot {
    pub key: Hash,
    pub value: Vec<u8>,
    pub active: bool,
}

/// Portable, positional QMDB state. Every slot below `next_slot` must be
/// present, including dead slots: their frozen leaves are consensus-relevant.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct QmdbSnapshot {
    pub next_slot: u64,
    pub entries: Vec<QmdbEntrySnapshot>,
}

/// The position-tagged form of gov5's `qmdb.SlotEntry`. This is the direct
/// importer boundary for a replay-v2 exporter: slot position is consensus
/// data, not an implementation detail.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct QmdbSlotEntry {
    pub slot: u64,
    pub key: Hash,
    pub value: Vec<u8>,
    pub active: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct QmdbSlotSnapshot {
    pub next_slot: u64,
    pub entries: Vec<QmdbSlotEntry>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QmdbSnapshotError {
    #[error("QMDB snapshot has {entries} entries but next_slot is {next_slot}")]
    NonPositional { entries: usize, next_slot: u64 },
    #[error("QMDB snapshot has duplicate active key {0:?}")]
    DuplicateActiveKey(Hash),
    #[error("QMDB slot log is not contiguous: expected slot {expected}, got {got}")]
    NonContiguousSlotLog { expected: u64, got: u64 },
}

/// Cross-client QMDB bootstrap metadata plus its complete positional slot log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmdbPortableSnapshot {
    pub chain_id: u64,
    pub genesis_hash: Hash,
    pub block_number: u64,
    pub block_hash: Hash,
    pub root: Hash,
    pub slots: QmdbSlotSnapshot,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QmdbPortableError {
    #[error("QMDB portable snapshot I/O failed: {0}")]
    Io(String),
    #[error("QMDB portable snapshot is truncated")]
    Truncated,
    #[error("unsupported QMDB portable snapshot version")]
    UnsupportedVersion,
    #[error("QMDB portable snapshot content hash mismatch")]
    ContentHashMismatch,
    #[error("QMDB portable snapshot has {entries} entries but next slot is {next_slot}")]
    NonPositional { entries: u64, next_slot: u64 },
    #[error("QMDB portable slot log is not contiguous: expected {expected}, got {got}")]
    NonContiguousSlotLog { expected: u64, got: u64 },
    #[error("QMDB portable slot {slot} has invalid active flag {flag}")]
    InvalidActiveFlag { slot: u64, flag: u8 },
    #[error("QMDB portable slot {slot} value is too large: {size}")]
    ValueTooLarge { slot: u64, size: usize },
    #[error("QMDB portable snapshot has {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("QMDB portable snapshot chain id {got} does not equal expected {expected}")]
    WrongChainId { expected: u64, got: u64 },
    #[error("QMDB portable snapshot genesis hash does not match the expected chain")]
    WrongGenesisHash,
    #[error("QMDB portable snapshot root does not match its positional slot log")]
    RootMismatch,
}

/// Result of a bounded-memory streaming verification. Only one 2048-leaf twig
/// and the compact upper-root list are retained, regardless of replay length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmdbPortableVerification {
    pub chain_id: u64,
    pub genesis_hash: Hash,
    pub block_number: u64,
    pub block_hash: Hash,
    pub root: Hash,
    pub next_slot: u64,
    pub live_count: u64,
}

/// Verify a portable snapshot from a stream without materializing its values or
/// full append log. This is the full-replay observer path: peak tree memory is
/// one twig plus one 32-byte root per historical twig.
pub fn verify_portable_stream<R: Read>(
    reader: R,
    expected_chain_id: u64,
    expected_genesis_hash: &Hash,
) -> Result<QmdbPortableVerification, QmdbPortableError> {
    let mut reader = PortableHashingReader::new(reader);
    if reader.array::<8>()? != *PORTABLE_SNAPSHOT_MAGIC {
        return Err(QmdbPortableError::UnsupportedVersion);
    }
    let chain_id = u64::from_le_bytes(reader.array()?);
    if chain_id != expected_chain_id {
        return Err(QmdbPortableError::WrongChainId {
            expected: expected_chain_id,
            got: chain_id,
        });
    }
    let genesis_hash = reader.array()?;
    if genesis_hash != *expected_genesis_hash {
        return Err(QmdbPortableError::WrongGenesisHash);
    }
    let block_number = u64::from_le_bytes(reader.array()?);
    let block_hash = reader.array()?;
    let claimed_root = reader.array()?;
    let next_slot = u64::from_le_bytes(reader.array()?);
    let entry_count = u64::from_le_bytes(reader.array()?);
    if entry_count != next_slot {
        return Err(QmdbPortableError::NonPositional {
            entries: entry_count,
            next_slot,
        });
    }

    let nulls = null_level();
    let mut current_twig = (next_slot > 0).then(|| Twig::new(&nulls));
    // Grow `twig_roots` on demand: `next_slot` is attacker-controlled header data
    // (the `entry_count == next_slot` guard above is also attacker-controlled), so
    // reserving `next_slot / TWIG_SIZE` up front would let a 1-byte lie force a
    // multi-GB reservation before a single entry is validated. `push` amortizes.
    let mut twig_roots: Vec<Hash> = Vec::new();
    let mut live_count = 0_u64;
    let mut value = Vec::new();
    for expected in 0..entry_count {
        let slot = u64::from_le_bytes(reader.array()?);
        if slot != expected {
            return Err(QmdbPortableError::NonContiguousSlotLog {
                expected,
                got: slot,
            });
        }
        let flag = reader.array::<1>()?[0];
        if flag > 1 {
            return Err(QmdbPortableError::InvalidActiveFlag { slot, flag });
        }
        let key = reader.array()?;
        let value_len = u32::from_le_bytes(reader.array()?) as usize;
        if value_len > MAX_PORTABLE_VALUE_SIZE {
            return Err(QmdbPortableError::ValueTooLarge {
                slot,
                size: value_len,
            });
        }
        reader.fill_vec(&mut value, value_len)?;
        let local = slot as usize % TWIG_SIZE;
        let twig = current_twig
            .as_mut()
            .expect("a non-empty stream always has a current twig");
        twig.set_leaf_unchecked(local, hash_leaf(&key, &value));
        if flag == 1 {
            twig.bits[local / 8] |= 1 << (local % 8);
            live_count += 1;
        }
        if local + 1 == TWIG_SIZE {
            twig.recompute();
            twig_roots.push(twig.root);
            if expected + 1 < entry_count {
                current_twig = Some(Twig::new(&nulls));
            }
        }
    }
    if next_slot > 0 && !(next_slot as usize).is_multiple_of(TWIG_SIZE) {
        let twig = current_twig
            .as_mut()
            .expect("a partial final twig is present");
        twig.recompute();
        twig_roots.push(twig.root);
    }
    reader.finish()?;

    let root = fold_portable_twig_roots(&twig_roots);
    if root != claimed_root {
        return Err(QmdbPortableError::RootMismatch);
    }
    Ok(QmdbPortableVerification {
        chain_id,
        genesis_hash,
        block_number,
        block_hash,
        root,
        next_slot,
        live_count,
    })
}

fn fold_portable_twig_roots(twig_roots: &[Hash]) -> Hash {
    if twig_roots.is_empty() {
        return NULL_HASH;
    }
    let capacity = twig_roots.len().next_power_of_two();
    let mut upper = vec![NULL_HASH; capacity * 2];
    upper[capacity..capacity + twig_roots.len()].copy_from_slice(twig_roots);
    for index in (1..capacity).rev() {
        upper[index] = hash_node(&upper[index * 2], &upper[index * 2 + 1]);
    }
    upper[1]
}

struct PortableHashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
}

impl<R: Read> PortableHashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], QmdbPortableError> {
        let mut out = [0_u8; N];
        self.inner.read_exact(&mut out).map_err(portable_io_error)?;
        self.hasher.update(&out);
        Ok(out)
    }

    fn fill_vec(&mut self, out: &mut Vec<u8>, len: usize) -> Result<(), QmdbPortableError> {
        out.resize(len, 0);
        self.inner.read_exact(out).map_err(portable_io_error)?;
        self.hasher.update(out);
        Ok(())
    }

    fn finish(mut self) -> Result<(), QmdbPortableError> {
        let mut claimed_digest = [0_u8; PORTABLE_SNAPSHOT_DIGEST_SIZE];
        self.inner
            .read_exact(&mut claimed_digest)
            .map_err(portable_io_error)?;
        if self.hasher.finalize().as_bytes() != &claimed_digest {
            return Err(QmdbPortableError::ContentHashMismatch);
        }
        let mut trailing = [0_u8; 1];
        match self.inner.read(&mut trailing) {
            Ok(0) => Ok(()),
            Ok(size) => Err(QmdbPortableError::TrailingBytes(size)),
            Err(error) => Err(portable_io_error(error)),
        }
    }
}

fn portable_io_error(error: std::io::Error) -> QmdbPortableError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        QmdbPortableError::Truncated
    } else {
        QmdbPortableError::Io(error.to_string())
    }
}

impl QmdbPortableSnapshot {
    /// Encode the portable v1 layout shared with gov5. The final Blake3 digest
    /// authenticates every preceding byte, including chain/checkpoint identity.
    pub fn encode(&self) -> Result<Vec<u8>, QmdbPortableError> {
        self.validate_positions()?;
        let mut capacity = PORTABLE_SNAPSHOT_HEADER_SIZE + PORTABLE_SNAPSHOT_DIGEST_SIZE;
        for entry in &self.slots.entries {
            if entry.value.len() > MAX_PORTABLE_VALUE_SIZE {
                return Err(QmdbPortableError::ValueTooLarge {
                    slot: entry.slot,
                    size: entry.value.len(),
                });
            }
            capacity += PORTABLE_SNAPSHOT_ENTRY_SIZE + entry.value.len();
        }
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(PORTABLE_SNAPSHOT_MAGIC);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.block_number.to_le_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.slots.next_slot.to_le_bytes());
        out.extend_from_slice(&(self.slots.entries.len() as u64).to_le_bytes());
        for entry in &self.slots.entries {
            out.extend_from_slice(&entry.slot.to_le_bytes());
            out.push(u8::from(entry.active));
            out.extend_from_slice(&entry.key);
            out.extend_from_slice(&(entry.value.len() as u32).to_le_bytes());
            out.extend_from_slice(&entry.value);
        }
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        Ok(out)
    }

    /// Decode and authenticate a portable v1 snapshot. Root and chain identity
    /// are checked separately by [`Self::verify_and_build`].
    pub fn decode(encoded: &[u8]) -> Result<Self, QmdbPortableError> {
        if encoded.len() < PORTABLE_SNAPSHOT_HEADER_SIZE + PORTABLE_SNAPSHOT_DIGEST_SIZE {
            return Err(QmdbPortableError::Truncated);
        }
        let payload_len = encoded.len() - PORTABLE_SNAPSHOT_DIGEST_SIZE;
        let (payload, claimed_digest) = encoded.split_at(payload_len);
        if blake3::hash(payload).as_bytes() != claimed_digest {
            return Err(QmdbPortableError::ContentHashMismatch);
        }
        let mut reader = PortableReader::new(payload);
        if reader.take(PORTABLE_SNAPSHOT_MAGIC.len())? != PORTABLE_SNAPSHOT_MAGIC {
            return Err(QmdbPortableError::UnsupportedVersion);
        }
        let chain_id = reader.u64()?;
        let genesis_hash = reader.hash()?;
        let block_number = reader.u64()?;
        let block_hash = reader.hash()?;
        let root = reader.hash()?;
        let next_slot = reader.u64()?;
        let entry_count = reader.u64()?;
        if entry_count != next_slot {
            return Err(QmdbPortableError::NonPositional {
                entries: entry_count,
                next_slot,
            });
        }
        if entry_count > (reader.remaining() / PORTABLE_SNAPSHOT_ENTRY_SIZE) as u64 {
            return Err(QmdbPortableError::Truncated);
        }
        let entry_capacity =
            usize::try_from(entry_count).map_err(|_| QmdbPortableError::Truncated)?;
        let mut entries = Vec::with_capacity(entry_capacity);
        for expected in 0..entry_count {
            let slot = reader.u64()?;
            if slot != expected {
                return Err(QmdbPortableError::NonContiguousSlotLog {
                    expected,
                    got: slot,
                });
            }
            let flag = reader.byte()?;
            if flag > 1 {
                return Err(QmdbPortableError::InvalidActiveFlag { slot, flag });
            }
            let key = reader.hash()?;
            let value_len = reader.u32()? as usize;
            if value_len > MAX_PORTABLE_VALUE_SIZE {
                return Err(QmdbPortableError::ValueTooLarge {
                    slot,
                    size: value_len,
                });
            }
            let value = reader.take(value_len)?.to_vec();
            entries.push(QmdbSlotEntry {
                slot,
                key,
                value,
                active: flag == 1,
            });
        }
        if reader.remaining() != 0 {
            return Err(QmdbPortableError::TrailingBytes(reader.remaining()));
        }
        Ok(Self {
            chain_id,
            genesis_hash,
            block_number,
            block_hash,
            root,
            slots: QmdbSlotSnapshot { next_slot, entries },
        })
    }

    /// Enforce chain identity and rebuild the split commitment from every slot.
    pub fn verify_and_build(
        &self,
        expected_chain_id: u64,
        expected_genesis_hash: &Hash,
    ) -> Result<QmdbCompatTree, QmdbPortableError> {
        if self.chain_id != expected_chain_id {
            return Err(QmdbPortableError::WrongChainId {
                expected: expected_chain_id,
                got: self.chain_id,
            });
        }
        if self.genesis_hash != *expected_genesis_hash {
            return Err(QmdbPortableError::WrongGenesisHash);
        }
        let tree =
            QmdbCompatTree::from_slot_snapshot(&self.slots).map_err(|error| match error {
                QmdbSnapshotError::NonPositional { entries, next_slot } => {
                    QmdbPortableError::NonPositional {
                        entries: entries as u64,
                        next_slot,
                    }
                }
                QmdbSnapshotError::NonContiguousSlotLog { expected, got } => {
                    QmdbPortableError::NonContiguousSlotLog { expected, got }
                }
                QmdbSnapshotError::DuplicateActiveKey(_) => QmdbPortableError::RootMismatch,
            })?;
        if tree.root() != self.root {
            return Err(QmdbPortableError::RootMismatch);
        }
        Ok(tree)
    }

    fn validate_positions(&self) -> Result<(), QmdbPortableError> {
        if self.slots.next_slot != self.slots.entries.len() as u64 {
            return Err(QmdbPortableError::NonPositional {
                entries: self.slots.entries.len() as u64,
                next_slot: self.slots.next_slot,
            });
        }
        for (expected, entry) in self.slots.entries.iter().enumerate() {
            if entry.slot != expected as u64 {
                return Err(QmdbPortableError::NonContiguousSlotLog {
                    expected: expected as u64,
                    got: entry.slot,
                });
            }
        }
        Ok(())
    }
}

struct PortableReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PortableReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], QmdbPortableError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or(QmdbPortableError::Truncated)?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, QmdbPortableError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, QmdbPortableError> {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, QmdbPortableError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn hash(&mut self) -> Result<Hash, QmdbPortableError> {
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(self.take(32)?);
        Ok(hash)
    }
}

/// A gov5 QMDB v2 membership proof.  Its byte encoding is deliberately kept
/// separate from the legacy [`crate::TwigProof`]: QMDB commits a frozen leaf
/// tree plus an active-bits root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmdbProof {
    pub key: Hash,
    pub value: Vec<u8>,
    pub slot: u64,
    pub twig_path: [Hash; TWIG_HEIGHT],
    pub active_bits: [u8; BITS_BYTES],
    pub upper_path: Vec<Hash>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QmdbProofCodecError {
    #[error("QMDB proof is truncated at byte {offset}")]
    Truncated { offset: usize },
    #[error("QMDB proof version {0:#x} is unsupported")]
    UnsupportedVersion(u8),
    #[error("QMDB proof twig height {got} does not equal {expected}")]
    WrongTwigHeight { got: u8, expected: usize },
    #[error("QMDB proof upper path length {0} exceeds {MAX_UPPER_PATH}")]
    UpperPathTooLong(usize),
    #[error("QMDB proof value length overflows usize")]
    ValueLengthOverflow,
    #[error("QMDB proof has {0} trailing bytes")]
    TrailingBytes(usize),
}

impl QmdbProof {
    /// Encode the exact v2 proof layout consumed by gov5 and [`Self::decode`].
    pub fn encode(&self) -> Result<Vec<u8>, QmdbProofCodecError> {
        if self.upper_path.len() > MAX_UPPER_PATH {
            return Err(QmdbProofCodecError::UpperPathTooLong(self.upper_path.len()));
        }
        let value_len = u32::try_from(self.value.len())
            .map_err(|_| QmdbProofCodecError::ValueLengthOverflow)?;
        let mut out = Vec::with_capacity(
            1 + 32
                + 8
                + 1
                + TWIG_HEIGHT * 32
                + BITS_BYTES
                + 1
                + self.upper_path.len() * 32
                + 4
                + self.value.len(),
        );
        out.push(PROOF_CODEC_VERSION);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.push(TWIG_HEIGHT as u8);
        for sibling in &self.twig_path {
            out.extend_from_slice(sibling);
        }
        out.extend_from_slice(&self.active_bits);
        out.push(self.upper_path.len() as u8);
        for sibling in &self.upper_path {
            out.extend_from_slice(sibling);
        }
        out.extend_from_slice(&value_len.to_le_bytes());
        out.extend_from_slice(&self.value);
        Ok(out)
    }

    /// Decode the exact v2 proof layout emitted by gov5 `qmdb.Proof.Marshal`.
    /// The transport envelope (SSZ/snappy/RPC) is intentionally outside this
    /// low-level verifier.
    pub fn decode(bytes: &[u8]) -> Result<Self, QmdbProofCodecError> {
        let mut pos = 0;
        let version = read_u8(bytes, &mut pos)?;
        if version != PROOF_CODEC_VERSION {
            return Err(QmdbProofCodecError::UnsupportedVersion(version));
        }
        let key = read_hash(bytes, &mut pos)?;
        let slot = u64::from_le_bytes(read_array(bytes, &mut pos)?);
        let twig_height = read_u8(bytes, &mut pos)?;
        if twig_height as usize != TWIG_HEIGHT {
            return Err(QmdbProofCodecError::WrongTwigHeight {
                got: twig_height,
                expected: TWIG_HEIGHT,
            });
        }
        let mut twig_path = [NULL_HASH; TWIG_HEIGHT];
        for hash in &mut twig_path {
            *hash = read_hash(bytes, &mut pos)?;
        }
        let active_bits = read_array(bytes, &mut pos)?;
        let upper_len = read_u8(bytes, &mut pos)? as usize;
        if upper_len > MAX_UPPER_PATH {
            return Err(QmdbProofCodecError::UpperPathTooLong(upper_len));
        }
        let mut upper_path = Vec::with_capacity(upper_len);
        for _ in 0..upper_len {
            upper_path.push(read_hash(bytes, &mut pos)?);
        }
        let value_len = u32::from_le_bytes(read_array(bytes, &mut pos)?);
        let value_len =
            usize::try_from(value_len).map_err(|_| QmdbProofCodecError::ValueLengthOverflow)?;
        let value = read_bytes(bytes, &mut pos, value_len)?.to_vec();
        if pos != bytes.len() {
            return Err(QmdbProofCodecError::TrailingBytes(bytes.len() - pos));
        }
        Ok(Self {
            key,
            value,
            slot,
            twig_path,
            active_bits,
            upper_path,
        })
    }

    /// Verify membership against a QMDB world root and the key requested by the caller.
    ///
    /// The explicit key binding is mandatory at an untrusted RPC boundary: a Merkle proof can be
    /// internally valid while answering a different query. Slot high bits must also be exhausted
    /// by the authenticated upper path, otherwise the same path could be relabelled as a twig
    /// outside the committed tree.
    pub fn verify_for_key(&self, root: &Hash, expected_key: &Hash) -> bool {
        if self.key != *expected_key {
            return false;
        }
        let mut local = (self.slot % TWIG_SIZE as u64) as usize;
        if self.active_bits[local / 8] & (1 << (local % 8)) == 0 {
            return false;
        }
        let mut node = hash_leaf(&self.key, &self.value);
        for sibling in &self.twig_path {
            node = if local & 1 == 0 {
                hash_node(&node, sibling)
            } else {
                hash_node(sibling, &node)
            };
            local >>= 1;
        }
        node = hash_node(&node, &hash_bits(&self.active_bits));
        let mut twig_id = self.slot / TWIG_SIZE as u64;
        for sibling in &self.upper_path {
            node = if twig_id & 1 == 0 {
                hash_node(&node, sibling)
            } else {
                hash_node(sibling, &node)
            };
            twig_id >>= 1;
        }
        twig_id == 0 && node == *root
    }
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> Result<u8, QmdbProofCodecError> {
    Ok(*read_bytes(bytes, pos, 1)?
        .first()
        .expect("one requested byte is present"))
}

fn read_hash(bytes: &[u8], pos: &mut usize) -> Result<Hash, QmdbProofCodecError> {
    read_array(bytes, pos)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<[u8; N], QmdbProofCodecError> {
    let mut out = [0; N];
    out.copy_from_slice(read_bytes(bytes, pos, N)?);
    Ok(out)
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    pos: &mut usize,
    len: usize,
) -> Result<&'a [u8], QmdbProofCodecError> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or(QmdbProofCodecError::Truncated { offset: *pos })?;
    let out = &bytes[*pos..end];
    *pos = end;
    Ok(out)
}

#[derive(Clone)]
struct Entry {
    key: Hash,
    value: Vec<u8>,
    active: bool,
}

#[derive(Clone)]
struct Twig {
    nodes: Box<[Hash; 2 * TWIG_SIZE]>,
    bits: [u8; BITS_BYTES],
    bits_root: Hash,
    root: Hash,
}

impl Twig {
    fn new(nulls: &[Hash; TWIG_HEIGHT + 1]) -> Self {
        let mut nodes = Box::new([NULL_HASH; 2 * TWIG_SIZE]);
        for (index, node) in nodes.iter_mut().enumerate().take(TWIG_SIZE).skip(1) {
            let depth = (u32::BITS - 1 - (index as u32).leading_zeros()) as usize;
            *node = nulls[TWIG_HEIGHT - depth];
        }
        let bits = [0u8; BITS_BYTES];
        let bits_root = hash_bits(&bits);
        let root = hash_node(&nodes[1], &bits_root);
        Self {
            nodes,
            bits,
            bits_root,
            root,
        }
    }

    fn set_leaf(&mut self, local: usize, leaf: Hash) {
        let mut node = TWIG_SIZE + local;
        self.nodes[node] = leaf;
        while node > 1 {
            node >>= 1;
            self.nodes[node] = hash_node(&self.nodes[node * 2], &self.nodes[node * 2 + 1]);
        }
        self.refresh_root();
    }

    fn set_active(&mut self, local: usize, active: bool) {
        let byte = local / 8;
        let mask = 1 << (local % 8);
        if active {
            self.bits[byte] |= mask;
        } else {
            self.bits[byte] &= !mask;
        }
        self.bits_root = hash_bits(&self.bits);
        self.refresh_root();
    }

    fn set_leaf_unchecked(&mut self, local: usize, leaf: Hash) {
        self.nodes[TWIG_SIZE + local] = leaf;
    }

    fn recompute(&mut self) {
        for start in (1..TWIG_SIZE).rev() {
            self.nodes[start] = hash_node(&self.nodes[start * 2], &self.nodes[start * 2 + 1]);
        }
        self.bits_root = hash_bits(&self.bits);
        self.refresh_root();
    }

    fn refresh_root(&mut self) {
        self.root = hash_node(&self.nodes[1], &self.bits_root);
    }

    /// The bit set and root, after bits changed and leaves did not.
    fn rehash_bits(&mut self) {
        self.bits_root = hash_bits(&self.bits);
        self.refresh_root();
    }
}

/// A twig whose bit set changed; its leaves did not.
const DIRTY_BITS: u8 = 1;
/// A twig that took new leaves (and possibly bit changes).
const DIRTY_LEAVES: u8 = 2;

fn mark_dirty(dirty: &mut Vec<u8>, twig_id: usize, level: u8) {
    if dirty.len() <= twig_id {
        dirty.resize(twig_id + 1, 0);
    }
    dirty[twig_id] = dirty[twig_id].max(level);
}

/// The leaf hash of every operation that writes a value, on the worker pool
/// when the `rayon` feature is on.
fn leaf_hashes(operations: &[QmdbOperation]) -> Vec<Option<Hash>> {
    let leaf = |operation: &QmdbOperation| operation.value.as_ref().map(|value| hash_leaf(&operation.key, value));
    #[cfg(feature = "rayon")]
    {
        use rayon::prelude::*;
        operations.par_iter().map(leaf).collect()
    }
    #[cfg(not(feature = "rayon"))]
    {
        operations.iter().map(leaf).collect()
    }
}

/// Rehashes every twig marked in `dirty`, each independently of the others.
fn rehash_dirty(twigs: &mut [Twig], dirty: &[u8]) {
    let work = |(twig_id, twig): (usize, &mut Twig)| match dirty.get(twig_id).copied().unwrap_or(0) {
        DIRTY_LEAVES => twig.recompute(),
        DIRTY_BITS => twig.rehash_bits(),
        _ => {}
    };
    #[cfg(feature = "rayon")]
    {
        use rayon::prelude::*;
        twigs.par_iter_mut().enumerate().for_each(work);
    }
    #[cfg(not(feature = "rayon"))]
    {
        twigs.iter_mut().enumerate().for_each(work);
    }
}

fn hash_bits(bits: &[u8; BITS_BYTES]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[BITS_PREFIX]);
    hasher.update(bits);
    *hasher.finalize().as_bytes()
}

/// One slot deactivated during a block: it was live with `(key, value)`
/// immediately before the block. A slot dies at most once — slots are never
/// reused — so entries never conflict across blocks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UndoEntry {
    /// The slot that was deactivated.
    pub slot: u64,
    /// The key it held.
    pub key: Hash,
    /// The value it held.
    pub value: Vec<u8>,
}

/// One block's undo record: what it takes to roll the tree back across it.
///
/// This is gov5's `BlockUndo`. The append-only structure makes the revert
/// exact: slots the block appended occupy `[prev_next_slot, next_slot)` and are
/// truncated; slots it deactivated are `entries` and are revived. A QMDB root
/// is a function of the append history, so re-executing a competing block on
/// an un-reverted tree appends at shifted slots and forks the root permanently
/// against a node that only ever applied the winner. Reverting first restores
/// the exact pre-block tree, and re-applying the sibling then lands on the same
/// slots on every node.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockUndo {
    /// The append cursor before the block's operations.
    pub prev_next_slot: u64,
    /// The slots the block deactivated, with what they held.
    pub entries: Vec<UndoEntry>,
    /// `appended_keys[i]` is the key appended at slot `prev_next_slot + i`.
    /// Not needed to revert an in-memory tree, whose entries are always
    /// readable; carried so the record is self-describing, as gov5's is.
    pub appended_keys: Vec<Hash>,
}

/// Why an undo record could not be applied.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QmdbUndoError {
    /// The record was taken from a tree further along than this one.
    #[error("undo record is ahead of this tree (prev={prev}, next={next})")]
    Ahead {
        /// The record's cursor.
        prev: u64,
        /// The tree's cursor.
        next: u64,
    },
    /// A block is being recorded; reverting under it would corrupt the record.
    #[error("cannot apply an undo record while undo recording is active")]
    RecordingActive,
    /// A revived slot's entry disagrees with the record — the record does not
    /// belong to this tree's history.
    #[error("undo entry for slot {slot} does not match the tree's entry")]
    EntryMismatch {
        /// The slot in question.
        slot: u64,
    },
}

/// A correctness-first QMDB tree for cross-client bootstrap and vectors.
///
/// It deliberately rebuilds the small upper tree on root reads. gov5's
/// incremental upper-tree and eviction optimizations can be added after this
/// representation has complete replay-v2 vectors.
#[derive(Clone)]
pub struct QmdbCompatTree {
    entries: Vec<Entry>,
    index: HashMap<Hash, u64>,
    twigs: Vec<Twig>,
    next_slot: u64,
    /// The record being captured, between `start_undo_recording` and
    /// `stop_undo_recording`.
    recording: Option<BlockUndo>,
}

impl std::fmt::Debug for QmdbCompatTree {
    /// Summary only. The leaf set is the whole world state, so printing it would
    /// turn a stray `{:?}` into a memory event — and the root is not included
    /// either, because reading it rebuilds the upper tree and a debug format
    /// should not cost that.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbCompatTree")
            .field("leaves", &self.len())
            .field("next_slot", &self.next_slot())
            .finish_non_exhaustive()
    }
}

impl Default for QmdbCompatTree {
    fn default() -> Self {
        Self::new()
    }
}

impl QmdbCompatTree {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
            twigs: Vec::new(),
            next_slot: 0,
            recording: None,
        }
    }

    pub fn next_slot(&self) -> u64 {
        self.next_slot
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn get(&self, key: &Hash) -> Option<&[u8]> {
        self.index
            .get(key)
            .map(|slot| self.entries[*slot as usize].value.as_slice())
    }

    /// Generate a gov5-compatible membership proof for an active key.
    pub fn prove(&self, key: &Hash) -> Option<QmdbProof> {
        let slot = *self.index.get(key)?;
        let twig_id = slot as usize / TWIG_SIZE;
        let local = slot as usize % TWIG_SIZE;
        let twig = &self.twigs[twig_id];

        let mut twig_path = [NULL_HASH; TWIG_HEIGHT];
        let mut node = TWIG_SIZE + local;
        for sibling in &mut twig_path {
            *sibling = twig.nodes[node ^ 1];
            node >>= 1;
        }

        let cap = self.twigs.len().next_power_of_two();
        let mut upper = vec![NULL_HASH; cap * 2];
        for (index, twig) in self.twigs.iter().enumerate() {
            upper[cap + index] = twig.root;
        }
        for index in (1..cap).rev() {
            upper[index] = hash_node(&upper[index * 2], &upper[index * 2 + 1]);
        }
        let mut upper_path = Vec::with_capacity(cap.trailing_zeros() as usize);
        let mut upper_node = cap + twig_id;
        while upper_node > 1 {
            upper_path.push(upper[upper_node ^ 1]);
            upper_node >>= 1;
        }

        Some(QmdbProof {
            key: *key,
            value: self.entries[slot as usize].value.clone(),
            slot,
            twig_path,
            active_bits: twig.bits,
            upper_path,
        })
    }

    /// Append a new frozen leaf, deactivating an earlier live slot for `key`.
    pub fn set(&mut self, key: Hash, value: Vec<u8>) {
        if let Some(old_slot) = self.index.get(&key).copied() {
            self.record_deactivation(old_slot);
            self.deactivate(old_slot);
        }
        if let Some(record) = self.recording.as_mut() {
            record.appended_keys.push(key);
        }
        let slot = self.next_slot;
        self.next_slot += 1;
        let twig_id = (slot as usize) / TWIG_SIZE;
        let local = (slot as usize) % TWIG_SIZE;
        self.ensure_twig(twig_id);
        self.twigs[twig_id].set_leaf(local, hash_leaf(&key, &value));
        self.twigs[twig_id].set_active(local, true);
        self.entries.push(Entry {
            key,
            value,
            active: true,
        });
        self.index.insert(key, slot);
    }

    /// Deactivate a key without erasing its frozen leaf.
    pub fn delete(&mut self, key: &Hash) -> bool {
        let Some(slot) = self.index.remove(key) else {
            return false;
        };
        self.record_deactivation(slot);
        self.deactivate(slot);
        true
    }

    /// Begins capturing an undo record for the operations that follow — one
    /// block's worth. A record already being captured is discarded.
    pub fn start_undo_recording(&mut self) {
        self.recording = Some(BlockUndo {
            prev_next_slot: self.next_slot,
            entries: Vec::new(),
            appended_keys: Vec::new(),
        });
    }

    /// Ends the capture and returns the block's record, or `None` if recording
    /// was never started.
    pub fn stop_undo_recording(&mut self) -> Option<BlockUndo> {
        self.recording.take()
    }

    /// Like [`Self::apply_sorted_ops`], returning the record that undoes it.
    pub fn apply_sorted_ops_recorded(
        &mut self,
        operations: impl IntoIterator<Item = QmdbOperation>,
    ) -> Result<(Hash, BlockUndo), QmdbOperationError> {
        self.start_undo_recording();
        let root = match self.apply_sorted_ops(operations) {
            Ok(root) => root,
            Err(error) => {
                // A refused batch mutates nothing, so there is nothing to undo.
                self.recording = None;
                return Err(error);
            }
        };
        let undo = self.recording.take().unwrap_or_default();
        Ok((root, undo))
    }

    /// Rolls the tree back across one block, using that block's undo record.
    ///
    /// Reverting deeper means applying records newest first. Afterwards the
    /// root equals, byte for byte, the root the tree had immediately before the
    /// block — and re-applying the same operations lands on the same slots.
    ///
    /// Nothing is mutated until every check has passed, so a refused record
    /// leaves the tree exactly as it was.
    pub fn apply_undo(&mut self, undo: &BlockUndo) -> Result<(), QmdbUndoError> {
        if self.recording.is_some() {
            return Err(QmdbUndoError::RecordingActive);
        }
        let prev = undo.prev_next_slot;
        if prev > self.next_slot {
            return Err(QmdbUndoError::Ahead {
                prev,
                next: self.next_slot,
            });
        }
        // Revivals below the cursor must name what the slot actually holds:
        // a record from another history would otherwise revive the wrong key.
        for entry in undo.entries.iter().filter(|entry| entry.slot < prev) {
            let held = &self.entries[entry.slot as usize];
            if held.key != entry.key || held.value != entry.value {
                return Err(QmdbUndoError::EntryMismatch { slot: entry.slot });
            }
        }

        let mut touched_twigs = std::collections::BTreeSet::new();

        // 1. Truncate the block's appends: drop their index mappings, clear
        //    their bits, null their leaves.
        for slot in prev..self.next_slot {
            let entry = &self.entries[slot as usize];
            if entry.active && self.index.get(&entry.key) == Some(&slot) {
                self.index.remove(&entry.key);
            }
            let twig_id = (slot as usize) / TWIG_SIZE;
            let local = (slot as usize) % TWIG_SIZE;
            let twig = &mut self.twigs[twig_id];
            twig.set_leaf_unchecked(local, NULL_HASH);
            twig.bits[local / 8] &= !(1 << (local % 8));
            touched_twigs.insert(twig_id);
        }
        self.entries.truncate(prev as usize);
        self.next_slot = prev;

        // 2. Drop twigs the truncation emptied entirely. The boundary twig,
        //    if `prev` cuts through it, stays and is recomputed below.
        let twigs_remaining = if prev == 0 {
            0
        } else {
            ((prev - 1) as usize) / TWIG_SIZE + 1
        };
        self.twigs.truncate(twigs_remaining);
        touched_twigs.retain(|id| *id < twigs_remaining);

        // 3. Revive the slots the block deactivated. Only those below the
        //    cursor: a slot the block both appended and killed is gone with
        //    the truncation.
        for entry in undo.entries.iter().filter(|entry| entry.slot < prev) {
            let slot = entry.slot;
            self.entries[slot as usize].active = true;
            self.index.insert(entry.key, slot);
            let twig_id = (slot as usize) / TWIG_SIZE;
            let local = (slot as usize) % TWIG_SIZE;
            self.twigs[twig_id].bits[local / 8] |= 1 << (local % 8);
            touched_twigs.insert(twig_id);
        }

        for twig_id in touched_twigs {
            self.twigs[twig_id].recompute();
        }
        Ok(())
    }

    /// Captures a slot's pre-deactivation state into the active record.
    fn record_deactivation(&mut self, slot: u64) {
        let Some(record) = self.recording.as_mut() else {
            return;
        };
        let entry = &self.entries[slot as usize];
        record.entries.push(UndoEntry {
            slot,
            key: entry.key,
            value: entry.value.clone(),
        });
    }

    /// Apply one block's mutations in the exact deterministic order used by gov5. Duplicates are
    /// rejected before the tree is changed so a malformed conversion cannot partially mutate it.
    pub fn apply_sorted_ops(
        &mut self,
        operations: impl IntoIterator<Item = QmdbOperation>,
    ) -> Result<Hash, QmdbOperationError> {
        let mut operations = operations.into_iter().collect::<Vec<_>>();
        operations.sort_unstable_by_key(|operation| operation.key);
        for pair in operations.windows(2) {
            if pair[0].key == pair[1].key {
                return Err(QmdbOperationError::DuplicateKey(pair[0].key));
            }
        }
        // The same mutations as `set`/`delete` one after another, with the
        // hashing taken out of the sequence. Per operation those hash a leaf,
        // walk eleven nodes to the twig root, rehash the twig's whole bit set,
        // and do the bit set again for the slot being retired -- about fifteen
        // blake3 calls, all sequential; a 163,000-transfer block is ~326,000
        // operations and its root cost ~100 ms on the importer's critical
        // path. Here the leaf hashes are computed up front on the worker pool,
        // the structural writes are made in order without hashing, and each
        // touched twig is then rehashed once, in parallel: a twig that took
        // new leaves gets one full recompute (one hash per node instead of
        // eleven per leaf), a twig that only retired slots gets its bit set
        // and root. The tree these produce is the tree `set`/`delete` produce,
        // and a test says so operation for operation.
        let leaves = leaf_hashes(&operations);
        let mut dirty: Vec<u8> = Vec::with_capacity(self.twigs.len() + operations.len() / TWIG_SIZE + 2);
        for (operation, leaf) in operations.into_iter().zip(leaves) {
            match (operation.value, leaf) {
                (Some(value), Some(leaf)) => self.set_deferred(operation.key, value, leaf, &mut dirty),
                _ => {
                    self.delete_deferred(&operation.key, &mut dirty);
                }
            }
        }
        rehash_dirty(&mut self.twigs, &dirty);
        Ok(self.root())
    }

    /// `set`, with the twig's hashing left to [`rehash_dirty`].
    fn set_deferred(&mut self, key: Hash, value: Vec<u8>, leaf: Hash, dirty: &mut Vec<u8>) {
        if let Some(old_slot) = self.index.get(&key).copied() {
            self.record_deactivation(old_slot);
            self.deactivate_deferred(old_slot, dirty);
        }
        if let Some(record) = self.recording.as_mut() {
            record.appended_keys.push(key);
        }
        let slot = self.next_slot;
        self.next_slot += 1;
        let twig_id = (slot as usize) / TWIG_SIZE;
        let local = (slot as usize) % TWIG_SIZE;
        self.ensure_twig(twig_id);
        let twig = &mut self.twigs[twig_id];
        twig.nodes[TWIG_SIZE + local] = leaf;
        twig.bits[local / 8] |= 1 << (local % 8);
        mark_dirty(dirty, twig_id, DIRTY_LEAVES);
        self.entries.push(Entry {
            key,
            value,
            active: true,
        });
        self.index.insert(key, slot);
    }

    /// `delete`, with the twig's hashing left to [`rehash_dirty`].
    fn delete_deferred(&mut self, key: &Hash, dirty: &mut Vec<u8>) -> bool {
        let Some(slot) = self.index.remove(key) else {
            return false;
        };
        self.record_deactivation(slot);
        self.deactivate_deferred(slot, dirty);
        true
    }

    /// `deactivate`, with the twig's hashing left to [`rehash_dirty`].
    fn deactivate_deferred(&mut self, slot: u64, dirty: &mut Vec<u8>) {
        let entry = &mut self.entries[slot as usize];
        if !entry.active {
            return;
        }
        entry.active = false;
        let twig_id = (slot as usize) / TWIG_SIZE;
        let local = (slot as usize) % TWIG_SIZE;
        self.twigs[twig_id].bits[local / 8] &= !(1 << (local % 8));
        mark_dirty(dirty, twig_id, DIRTY_BITS);
    }

    pub fn root(&self) -> Hash {
        if self.twigs.is_empty() {
            return NULL_HASH;
        }
        let cap = self.twigs.len().next_power_of_two();
        let mut upper = vec![NULL_HASH; cap * 2];
        for (index, twig) in self.twigs.iter().enumerate() {
            upper[cap + index] = twig.root;
        }
        for index in (1..cap).rev() {
            upper[index] = hash_node(&upper[index * 2], &upper[index * 2 + 1]);
        }
        upper[1]
    }

    /// The entry at `slot`, if the tree has one.
    ///
    /// This is what lets a caller record what a block changed without walking
    /// the whole leaf set: the slots a block appends are the contiguous range
    /// above the previous append cursor, and the slots it deactivates are named
    /// by its [`BlockUndo`]. Both are read one at a time through here, so the
    /// cost of persisting a block is the size of the block rather than the size
    /// of the state.
    pub fn entry_at(&self, slot: u64) -> Option<QmdbEntrySnapshot> {
        let entry = self.entries.get(usize::try_from(slot).ok()?)?;
        Some(QmdbEntrySnapshot {
            key: entry.key,
            value: entry.value.clone(),
            active: entry.active,
        })
    }

    pub fn snapshot(&self) -> QmdbSnapshot {
        QmdbSnapshot {
            next_slot: self.next_slot,
            entries: self
                .entries
                .iter()
                .map(|entry| QmdbEntrySnapshot {
                    key: entry.key,
                    value: entry.value.clone(),
                    active: entry.active,
                })
                .collect(),
        }
    }

    pub fn from_snapshot(snapshot: &QmdbSnapshot) -> Result<Self, QmdbSnapshotError> {
        if snapshot.next_slot != snapshot.entries.len() as u64 {
            return Err(QmdbSnapshotError::NonPositional {
                entries: snapshot.entries.len(),
                next_slot: snapshot.next_slot,
            });
        }
        let mut tree = Self::new();
        tree.next_slot = snapshot.next_slot;
        for (slot, entry) in snapshot.entries.iter().enumerate() {
            let twig_id = slot / TWIG_SIZE;
            let local = slot % TWIG_SIZE;
            tree.ensure_twig(twig_id);
            tree.twigs[twig_id].set_leaf_unchecked(local, hash_leaf(&entry.key, &entry.value));
            if entry.active {
                if tree.index.insert(entry.key, slot as u64).is_some() {
                    return Err(QmdbSnapshotError::DuplicateActiveKey(entry.key));
                }
                tree.twigs[twig_id].set_active(local, true);
            }
            tree.entries.push(Entry {
                key: entry.key,
                value: entry.value.clone(),
                active: entry.active,
            });
        }
        for twig in &mut tree.twigs {
            twig.recompute();
        }
        Ok(tree)
    }

    /// Import a gov5-style `SnapshotLog` only when every append slot is
    /// present. A sparse live-key export is insufficient: a dead entry's
    /// frozen leaf still contributes to the QMDB root. Rejecting it is safer
    /// than silently creating a root that cannot match replay-v2 checkpoints.
    pub fn from_slot_snapshot(snapshot: &QmdbSlotSnapshot) -> Result<Self, QmdbSnapshotError> {
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for (expected, entry) in snapshot.entries.iter().enumerate() {
            let expected = expected as u64;
            if entry.slot != expected {
                return Err(QmdbSnapshotError::NonContiguousSlotLog {
                    expected,
                    got: entry.slot,
                });
            }
            entries.push(QmdbEntrySnapshot {
                key: entry.key,
                value: entry.value.clone(),
                active: entry.active,
            });
        }
        Self::from_snapshot(&QmdbSnapshot {
            next_slot: snapshot.next_slot,
            entries,
        })
    }

    fn ensure_twig(&mut self, twig_id: usize) {
        // Called once per `set`, but the twig almost always exists already.
        // `null_level()` is 11 hash compressions, so computing it before the
        // guard burned them on every entry of a full import for nothing.
        if self.twigs.len() > twig_id {
            return;
        }
        let nulls = null_level();
        while self.twigs.len() <= twig_id {
            self.twigs.push(Twig::new(&nulls));
        }
    }

    fn deactivate(&mut self, slot: u64) {
        let entry = &mut self.entries[slot as usize];
        if !entry.active {
            return;
        }
        entry.active = false;
        let twig_id = (slot as usize) / TWIG_SIZE;
        let local = (slot as usize) % TWIG_SIZE;
        self.twigs[twig_id].set_active(local, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The batched apply is `set`/`delete` in order: same root, same undo
    /// record, same snapshot, over blocks that create, update, delete and
    /// re-create keys across twig boundaries.
    #[test]
    fn batched_apply_matches_one_operation_at_a_time() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let key_of = |n: u64| {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&n.to_le_bytes());
            key
        };
        let mut batched = QmdbCompatTree::new();
        let mut one_by_one = QmdbCompatTree::new();
        for block in 0..6 {
            let count = if block == 0 { 1_800 } else { 900 };
            let mut seen = std::collections::HashSet::new();
            let mut operations = Vec::new();
            while operations.len() < count {
                let r = next();
                let key = key_of(r % 2_500);
                if !seen.insert(key) {
                    continue;
                }
                let value = if r % 7 == 0 && block > 0 {
                    None
                } else {
                    Some((0..(8 + (r % 40) as usize)).map(|i| (r as u8).wrapping_add(i as u8)).collect())
                };
                operations.push(QmdbOperation { key, value });
            }
            let mut ordered = operations.clone();
            ordered.sort_unstable_by_key(|operation| operation.key);
            one_by_one.start_undo_recording();
            for operation in ordered {
                match operation.value {
                    Some(value) => one_by_one.set(operation.key, value),
                    None => {
                        one_by_one.delete(&operation.key);
                    }
                }
            }
            let expected_root = one_by_one.root();
            let expected_undo = one_by_one.stop_undo_recording().unwrap();
            let (root, undo) = batched.apply_sorted_ops_recorded(operations).unwrap();
            assert_eq!(root, expected_root, "root differs at block {block}");
            assert_eq!(undo, expected_undo, "undo record differs at block {block}");
            assert_eq!(batched.snapshot(), one_by_one.snapshot(), "snapshot differs at block {block}");
        }
    }

    #[derive(serde::Deserialize)]
    struct CrossClientVector {
        version: String,
        workload: CrossClientWorkload,
        checkpoints: CrossClientCheckpoints,
        proof: CrossClientProof,
        portable: CrossClientPortable,
    }

    #[derive(serde::Deserialize)]
    struct CrossClientWorkload {
        insert_count: u64,
        updates: Vec<[u64; 2]>,
        deletes: Vec<u64>,
    }

    #[derive(serde::Deserialize)]
    struct CrossClientCheckpoints {
        insert_root: String,
        update_root: String,
        delete_root: String,
        next_slot: u64,
        live_count: usize,
        snapshot_entries: usize,
    }

    #[derive(serde::Deserialize)]
    struct CrossClientProof {
        key: u64,
        hex: String,
    }

    #[derive(serde::Deserialize)]
    struct CrossClientPortable {
        hex: String,
    }

    fn key(byte: u8) -> Hash {
        [byte; 32]
    }

    fn interop_key(value: u64) -> Hash {
        let mut key = [0_u8; 32];
        key[..8].copy_from_slice(&value.to_le_bytes());
        key
    }

    fn interop_value(value: u64) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    #[test]
    fn gov5_state_leaf_codec_matches_marshal_v2_layout() {
        let zero = [0_u8; 32];
        assert_eq!(encode_gov5_account_value(0, &zero, &zero), [0]);
        assert_eq!(
            encode_gov5_account_value(100_000, &zero, &GOV5_EMPTY_CODE_HASH),
            hex::decode("01a08d06").unwrap()
        );

        let mut one_eth = [0_u8; 32];
        one_eth[24..].copy_from_slice(&1_000_000_000_000_000_000_u64.to_be_bytes());
        assert_eq!(
            encode_gov5_account_value(0, &one_eth, &zero),
            hex::decode("02080de0b6b3a7640000").unwrap()
        );

        let code_hash = [0x12; 32];
        let mut balance = [0_u8; 32];
        balance[24..].copy_from_slice(&5_000_000_000_000_000_000_u64.to_be_bytes());
        let encoded = encode_gov5_account_value(42, &balance, &code_hash);
        assert_eq!(encoded[0], 0x0b);
        assert_eq!(
            &encoded[1..11],
            &hex::decode("2a084563918244f40000").unwrap()
        );
        assert_eq!(&encoded[11..], &code_hash);
    }

    #[test]
    fn gov5_keys_and_sorted_block_mutations_are_deterministic() {
        let address = [0x11; 20];
        let slot = [0x22; 32];
        assert_eq!(
            gov5_account_key(&address),
            *blake3::hash(&address).as_bytes()
        );
        let mut storage_input = [0_u8; 52];
        storage_input[..20].copy_from_slice(&address);
        storage_input[20..].copy_from_slice(&slot);
        assert_eq!(
            gov5_storage_key(&address, &slot),
            *blake3::hash(&storage_input).as_bytes()
        );

        let operations = vec![
            QmdbOperation {
                key: key(3),
                value: Some(b"three".to_vec()),
            },
            QmdbOperation {
                key: key(1),
                value: Some(b"one".to_vec()),
            },
            QmdbOperation {
                key: key(2),
                value: Some(b"two".to_vec()),
            },
        ];
        let mut sorted = QmdbCompatTree::new();
        let sorted_root = sorted.apply_sorted_ops(operations).unwrap();
        let mut expected = QmdbCompatTree::new();
        expected.set(key(1), b"one".to_vec());
        expected.set(key(2), b"two".to_vec());
        expected.set(key(3), b"three".to_vec());
        assert_eq!(sorted_root, expected.root());

        let before = sorted.snapshot();
        let duplicate = sorted.apply_sorted_ops([
            QmdbOperation {
                key: key(4),
                value: Some(b"first".to_vec()),
            },
            QmdbOperation {
                key: key(4),
                value: None,
            },
        ]);
        assert_eq!(duplicate, Err(QmdbOperationError::DuplicateKey(key(4))));
        assert_eq!(sorted.snapshot(), before);
    }

    #[test]
    fn matches_gov5_cross_client_v1_vectors() {
        let vector: CrossClientVector =
            serde_json::from_str(include_str!("../testdata/cross_client_v1.json")).unwrap();
        assert_eq!(vector.version, "n42-qmdb-interop-v1");

        let mut tree = QmdbCompatTree::new();
        for value in 0..vector.workload.insert_count {
            tree.set(interop_key(value), interop_value(value));
        }
        assert_eq!(hex::encode(tree.root()), vector.checkpoints.insert_root);

        for [key, value] in vector.workload.updates {
            tree.set(interop_key(key), interop_value(value));
        }
        assert_eq!(hex::encode(tree.root()), vector.checkpoints.update_root);

        for key in vector.workload.deletes {
            assert!(tree.delete(&interop_key(key)));
        }
        let final_root = tree.root();
        assert_eq!(hex::encode(final_root), vector.checkpoints.delete_root);
        assert_eq!(tree.next_slot(), vector.checkpoints.next_slot);
        assert_eq!(tree.len(), vector.checkpoints.live_count);

        let snapshot = tree.snapshot();
        assert_eq!(snapshot.entries.len(), vector.checkpoints.snapshot_entries);
        let slots = QmdbSlotSnapshot {
            next_slot: snapshot.next_slot,
            entries: snapshot
                .entries
                .iter()
                .enumerate()
                .map(|(slot, entry)| QmdbSlotEntry {
                    slot: slot as u64,
                    key: entry.key,
                    value: entry.value.clone(),
                    active: entry.active,
                })
                .collect(),
        };
        assert_eq!(
            QmdbCompatTree::from_slot_snapshot(&slots).unwrap().root(),
            final_root
        );

        let proof_bytes = hex::decode(vector.proof.hex).unwrap();
        let proof = QmdbProof::decode(&proof_bytes).unwrap();
        assert_eq!(proof.key, interop_key(vector.proof.key));
        assert!(proof.verify_for_key(&final_root, &interop_key(vector.proof.key)));

        let portable_bytes = hex::decode(vector.portable.hex).unwrap();
        let portable = QmdbPortableSnapshot::decode(&portable_bytes).unwrap();
        assert_eq!(portable.chain_id, 1143);
        assert_eq!(portable.genesis_hash, interop_key(0x11));
        assert_eq!(portable.block_number, 42);
        assert_eq!(portable.block_hash, interop_key(0x22));
        assert_eq!(portable.slots.next_slot, 3);
        assert_eq!(
            portable
                .verify_and_build(1143, &interop_key(0x11))
                .unwrap()
                .root(),
            portable.root
        );
    }

    #[test]
    fn portable_snapshot_roundtrip_checks_identity_root_and_digest() {
        let mut tree = QmdbCompatTree::new();
        for value in 0..2050 {
            tree.set(interop_key(value), interop_value(value));
        }
        tree.set(interop_key(7), interop_value(1_000_007));
        assert!(tree.delete(&interop_key(9)));
        let snapshot = tree.snapshot();
        let genesis_hash = interop_key(0x11);
        let portable = QmdbPortableSnapshot {
            chain_id: 1143,
            genesis_hash,
            block_number: 42,
            block_hash: interop_key(0x22),
            root: tree.root(),
            slots: QmdbSlotSnapshot {
                next_slot: snapshot.next_slot,
                entries: snapshot
                    .entries
                    .iter()
                    .enumerate()
                    .map(|(slot, entry)| QmdbSlotEntry {
                        slot: slot as u64,
                        key: entry.key,
                        value: entry.value.clone(),
                        active: entry.active,
                    })
                    .collect(),
            },
        };
        let encoded = portable.encode().unwrap();
        let decoded = QmdbPortableSnapshot::decode(&encoded).unwrap();
        assert_eq!(decoded, portable);
        assert_eq!(
            decoded
                .verify_and_build(1143, &genesis_hash)
                .unwrap()
                .root(),
            portable.root
        );
        assert!(matches!(
            decoded.verify_and_build(1, &genesis_hash),
            Err(QmdbPortableError::WrongChainId {
                expected: 1,
                got: 1143
            })
        ));

        let mut wrong_root = decoded.clone();
        wrong_root.root[0] ^= 0x80;
        let wrong_root = QmdbPortableSnapshot::decode(&wrong_root.encode().unwrap()).unwrap();
        assert!(matches!(
            wrong_root.verify_and_build(1143, &genesis_hash),
            Err(QmdbPortableError::RootMismatch)
        ));

        let mut tampered = encoded;
        tampered[PORTABLE_SNAPSHOT_HEADER_SIZE] ^= 0x80;
        assert!(matches!(
            QmdbPortableSnapshot::decode(&tampered),
            Err(QmdbPortableError::ContentHashMismatch)
        ));
    }

    /// Builds a positional portable snapshot from `n` sequential inserts so the
    /// streaming verifier can be exercised against the same pinned root as the
    /// in-memory path.
    fn build_sequential_portable(chain_id: u64, genesis: Hash, n: u64) -> QmdbPortableSnapshot {
        let mut tree = QmdbCompatTree::new();
        for value in 0..n {
            tree.set(interop_key(value), interop_value(value));
        }
        let snapshot = tree.snapshot();
        QmdbPortableSnapshot {
            chain_id,
            genesis_hash: genesis,
            block_number: 7,
            block_hash: interop_key(0x99),
            root: tree.root(),
            slots: QmdbSlotSnapshot {
                next_slot: snapshot.next_slot,
                entries: snapshot
                    .entries
                    .iter()
                    .enumerate()
                    .map(|(slot, entry)| QmdbSlotEntry {
                        slot: slot as u64,
                        key: entry.key,
                        value: entry.value.clone(),
                        active: entry.active,
                    })
                    .collect(),
            },
        }
    }

    // HIGH-2 regression: the streaming full-replay verifier (`verify_portable_stream`,
    // the path that actually runs the 87.8M-slot replay) was previously exercised
    // only by the example binary. Pin it to the same root as the in-memory path.
    #[test]
    fn verify_portable_stream_matches_in_memory_root() {
        let genesis = interop_key(0x11);
        let portable = build_sequential_portable(1143, genesis, 2050);
        let in_memory_root = portable.verify_and_build(1143, &genesis).unwrap().root();
        let encoded = portable.encode().unwrap();

        let streamed = verify_portable_stream(encoded.as_slice(), 1143, &genesis).unwrap();
        assert_eq!(
            streamed.root, portable.root,
            "streaming root must match snapshot claim"
        );
        assert_eq!(
            streamed.root, in_memory_root,
            "streaming path must agree with in-memory path"
        );
        assert_eq!(streamed.next_slot, 2050);
        assert_eq!(streamed.live_count, 2050);

        // Wrong chain identity is rejected before any root work.
        assert!(matches!(
            verify_portable_stream(encoded.as_slice(), 1, &genesis),
            Err(QmdbPortableError::WrongChainId {
                expected: 1,
                got: 1143
            })
        ));
    }

    // MEDIUM-3 regression: a non-power-of-two twig count exercises the padding
    // fold (`next_power_of_two`) that all prior fixtures (exactly 2 twigs) skipped.
    // 5000 entries = 3 twigs (2048 + 2048 + 904). Streaming and in-memory folds
    // must agree, so an accidental divergence in either fold is caught.
    #[test]
    fn verify_portable_stream_non_power_of_two_twig_count() {
        let genesis = interop_key(0x11);
        let portable = build_sequential_portable(1143, genesis, 5000);
        let in_memory_root = portable.verify_and_build(1143, &genesis).unwrap().root();
        let encoded = portable.encode().unwrap();

        let streamed = verify_portable_stream(encoded.as_slice(), 1143, &genesis).unwrap();
        assert_eq!(
            streamed.root, in_memory_root,
            "3-twig fold must agree across paths"
        );
        assert_eq!(streamed.next_slot, 5000);
    }

    // HIGH-1 regression: an oversized `next_slot` header field must not drive a
    // pre-authentication multi-GB allocation. With the `Vec::new()` fix the
    // verifier reads on demand and fails fast on the truncated body instead of
    // reserving `next_slot / TWIG_SIZE` hashes up front.
    #[test]
    fn oversized_next_slot_header_does_not_preallocate() {
        let huge: u64 = 1 << 40; // ~5.4e8 twigs => ~17GB if reserved up front
        let mut header = Vec::new();
        header.extend_from_slice(PORTABLE_SNAPSHOT_MAGIC);
        header.extend_from_slice(&1143u64.to_le_bytes()); // chain_id
        header.extend_from_slice(&interop_key(0x11)); // genesis
        header.extend_from_slice(&7u64.to_le_bytes()); // block_number
        header.extend_from_slice(&interop_key(0x99)); // block_hash
        header.extend_from_slice(&[0u8; 32]); // claimed_root
        header.extend_from_slice(&huge.to_le_bytes()); // next_slot
        header.extend_from_slice(&huge.to_le_bytes()); // entry_count == next_slot
        // No entries / no valid digest: the stream must error on the first missing
        // entry read, never having reserved for `huge` twigs.
        let result = verify_portable_stream(header.as_slice(), 1143, &interop_key(0x11));
        assert!(
            result.is_err(),
            "truncated oversized stream must fail, not OOM"
        );
    }

    #[test]
    fn split_commitment_freezes_deleted_leaf() {
        let mut tree = QmdbCompatTree::new();
        tree.set(key(1), b"first".to_vec());
        let inserted_root = tree.root();

        let nulls = null_level();
        let mut leaf_root = hash_leaf(&key(1), b"first");
        for sibling in nulls.iter().take(TWIG_HEIGHT) {
            leaf_root = hash_node(&leaf_root, sibling);
        }
        let mut active_bits = [0u8; BITS_BYTES];
        active_bits[0] = 1;
        assert_eq!(
            inserted_root,
            hash_node(&leaf_root, &hash_bits(&active_bits))
        );

        assert!(tree.delete(&key(1)));
        let deleted_root = tree.root();
        assert_ne!(inserted_root, deleted_root);
        // Crucially, the leaf root is still the original leaf hash; only the
        // bitmap changes. This is where legacy TwigTree intentionally differs.
        assert_eq!(
            deleted_root,
            hash_node(&leaf_root, &hash_bits(&[0; BITS_BYTES]))
        );
        assert_eq!(tree.next_slot(), 1);
    }

    #[test]
    fn snapshot_preserves_dead_slots_and_root() {
        let mut tree = QmdbCompatTree::new();
        tree.set(key(1), b"old".to_vec());
        tree.set(key(1), b"new".to_vec());
        tree.delete(&key(1));
        let root = tree.root();
        let snapshot = tree.snapshot();
        assert_eq!(snapshot.entries.len(), 2);
        assert!(snapshot.entries.iter().all(|entry| !entry.active));
        assert_eq!(
            QmdbCompatTree::from_snapshot(&snapshot).unwrap().root(),
            root
        );
    }

    #[test]
    fn slot_snapshot_preserves_positions_and_rejects_sparse_history() {
        let mut tree = QmdbCompatTree::new();
        tree.set(key(1), b"old".to_vec());
        tree.set(key(1), b"new".to_vec());
        let snapshot = tree.snapshot();
        let slot_snapshot = QmdbSlotSnapshot {
            next_slot: snapshot.next_slot,
            entries: snapshot
                .entries
                .iter()
                .enumerate()
                .map(|(slot, entry)| QmdbSlotEntry {
                    slot: slot as u64,
                    key: entry.key,
                    value: entry.value.clone(),
                    active: entry.active,
                })
                .collect(),
        };
        assert_eq!(
            QmdbCompatTree::from_slot_snapshot(&slot_snapshot)
                .unwrap()
                .root(),
            tree.root()
        );

        let mut sparse = slot_snapshot;
        sparse.entries.remove(0);
        assert!(matches!(
            QmdbCompatTree::from_slot_snapshot(&sparse),
            Err(QmdbSnapshotError::NonContiguousSlotLog {
                expected: 0,
                got: 1
            })
        ));
    }

    #[test]
    fn decodes_and_verifies_gov5_v2_proof_layout() {
        let mut tree = QmdbCompatTree::new();
        tree.set(key(7), b"proof-value".to_vec());
        let root = tree.root();

        let nulls = null_level();
        let mut encoded = Vec::new();
        encoded.push(PROOF_CODEC_VERSION);
        encoded.extend_from_slice(&key(7));
        encoded.extend_from_slice(&0_u64.to_le_bytes());
        encoded.push(TWIG_HEIGHT as u8);
        // Slot zero is a left child at every level, so every sibling is the
        // all-null subtree of the corresponding height.
        for sibling in nulls.iter().take(TWIG_HEIGHT) {
            encoded.extend_from_slice(sibling);
        }
        let mut bits = [0_u8; BITS_BYTES];
        bits[0] = 1;
        encoded.extend_from_slice(&bits);
        encoded.push(0); // one twig: no upper path
        encoded.extend_from_slice(&(b"proof-value".len() as u32).to_le_bytes());
        encoded.extend_from_slice(b"proof-value");

        let proof = QmdbProof::decode(&encoded).unwrap();
        assert!(proof.verify_for_key(&root, &key(7)));
        assert!(!proof.verify_for_key(&root, &key(8)));

        let mut unauthenticated_slot = proof.clone();
        unauthenticated_slot.slot += TWIG_SIZE as u64;
        assert!(!unauthenticated_slot.verify_for_key(&root, &key(7)));

        let mut dead = proof.clone();
        dead.active_bits[0] = 0;
        assert!(!dead.verify_for_key(&root, &key(7)));
        encoded.push(0);
        assert!(matches!(
            QmdbProof::decode(&encoded),
            Err(QmdbProofCodecError::TrailingBytes(1))
        ));
    }

    #[test]
    fn generated_proof_roundtrips_exact_codec_and_root() {
        let mut tree = QmdbCompatTree::new();
        let indexed_key = |index: u64| {
            let mut out = [0_u8; 32];
            out[..8].copy_from_slice(&index.to_le_bytes());
            out
        };
        for index in 0..(TWIG_SIZE + 3) {
            tree.set(indexed_key(index as u64), index.to_le_bytes().to_vec());
        }
        let query = indexed_key((TWIG_SIZE + 1) as u64);
        let proof = tree.prove(&query).expect("active key has proof");
        assert!(proof.verify_for_key(&tree.root(), &query));
        let encoded = proof.encode().unwrap();
        assert_eq!(QmdbProof::decode(&encoded).unwrap(), proof);
        assert!(tree.prove(&indexed_key(u64::MAX)).is_none());
    }
}

#[cfg(test)]
mod undo_tests {
    //! The property gov5's `ApplyUndo` exists for: after a revert the tree is
    //! *byte-identical* to one that never saw the block — not merely equal in
    //! state — so a competing block re-applied afterwards lands on the same
    //! slots as it does on a node that only ever applied the winner.

    use super::*;

    fn key(n: u64) -> Hash {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&n.to_be_bytes());
        *blake3::hash(&key).as_bytes()
    }

    fn sets(range: std::ops::Range<u64>, tag: u8) -> Vec<QmdbOperation> {
        range
            .map(|n| QmdbOperation {
                key: key(n),
                value: Some(vec![tag, n as u8]),
            })
            .collect()
    }

    fn seeded(n: u64) -> QmdbCompatTree {
        let mut tree = QmdbCompatTree::new();
        tree.apply_sorted_ops(sets(0..n, 0xA0)).unwrap();
        tree
    }

    #[test]
    fn a_reverted_block_leaves_no_trace() {
        let mut tree = seeded(10);
        let before_root = tree.root();
        let before_slot = tree.next_slot();
        let before_len = tree.len();

        // Overwrite three, delete two, append four.
        let mut ops = sets(2..5, 0xB0);
        ops.push(QmdbOperation { key: key(7), value: None });
        ops.push(QmdbOperation { key: key(8), value: None });
        ops.extend(sets(20..24, 0xC0));
        let (after_root, undo) = tree.apply_sorted_ops_recorded(ops).unwrap();
        assert_ne!(after_root, before_root);
        assert_eq!(undo.prev_next_slot, before_slot);
        assert_eq!(undo.entries.len(), 5, "three overwrites and two deletes deactivated a slot each");
        assert_eq!(undo.appended_keys.len(), 7, "three overwrites and four inserts appended");

        tree.apply_undo(&undo).unwrap();
        assert_eq!(tree.root(), before_root, "root is restored byte for byte");
        assert_eq!(tree.next_slot(), before_slot, "the append cursor is rewound");
        assert_eq!(tree.len(), before_len);
        assert_eq!(tree.get(&key(2)), Some(&[0xA0, 2][..]), "an overwritten key holds its old value");
        assert_eq!(tree.get(&key(7)), Some(&[0xA0, 7][..]), "a deleted key is back");
        assert!(tree.get(&key(20)).is_none(), "an appended key is gone");
        // And a proof at a revived slot verifies against the restored root.
        let proof = tree.prove(&key(7)).expect("revived key has a leaf");
        assert!(proof.verify_for_key(&tree.root(), &key(7)));
    }

    /// The sibling-switch case from gov5's comment on `RevertBlock`.
    #[test]
    fn a_sibling_applied_after_a_revert_matches_a_node_that_never_saw_the_loser() {
        let loser = || {
            let mut ops = sets(1..3, 0xB0);
            ops.push(QmdbOperation { key: key(5), value: None });
            ops
        };
        let winner = || sets(4..6, 0xC0);

        let mut honest = seeded(10);
        let honest_root = honest.apply_sorted_ops(winner()).unwrap();

        let mut reorged = seeded(10);
        let (_, undo) = reorged.apply_sorted_ops_recorded(loser()).unwrap();
        reorged.apply_undo(&undo).unwrap();
        let reorged_root = reorged.apply_sorted_ops(winner()).unwrap();

        assert_eq!(reorged_root, honest_root);
        assert_eq!(reorged.snapshot(), honest.snapshot(), "not just the root: the whole layout");

        // And without the revert it forks, which is the whole reason for it.
        let mut naive = seeded(10);
        naive.apply_sorted_ops(loser()).unwrap();
        assert_ne!(naive.apply_sorted_ops(winner()).unwrap(), honest_root);
    }

    #[test]
    fn reverting_deeper_applies_records_newest_first() {
        let mut tree = seeded(10);
        let root0 = tree.root();
        let (root1, undo1) = tree.apply_sorted_ops_recorded(sets(0..3, 0xB1)).unwrap();
        let (_, undo2) = tree.apply_sorted_ops_recorded(sets(1..4, 0xB2)).unwrap();
        let (_, undo3) = tree.apply_sorted_ops_recorded(sets(2..5, 0xB3)).unwrap();

        tree.apply_undo(&undo3).unwrap();
        tree.apply_undo(&undo2).unwrap();
        assert_eq!(tree.root(), root1);
        tree.apply_undo(&undo1).unwrap();
        assert_eq!(tree.root(), root0);
    }

    /// Appends that cross into a new twig must drop that twig on revert, and a
    /// twig the cursor cuts through must be rebuilt, not merely bit-flipped.
    #[test]
    fn a_revert_across_a_twig_boundary_restores_the_twig_count() {
        let mut tree = seeded((TWIG_SIZE as u64) - 5);
        let before_root = tree.root();
        let twigs_before = tree.twigs.len();
        assert_eq!(twigs_before, 1);

        let (_, undo) = tree.apply_sorted_ops_recorded(sets(5000..5100, 0xD0)).unwrap();
        assert_eq!(tree.twigs.len(), 2, "the appends spilled into a second twig");

        tree.apply_undo(&undo).unwrap();
        assert_eq!(tree.twigs.len(), 1, "the spilled twig is dropped");
        assert_eq!(tree.root(), before_root);
    }

    #[test]
    fn a_key_appended_and_deleted_in_one_block_is_simply_gone() {
        let mut tree = seeded(4);
        let before_root = tree.root();
        // apply_sorted_ops refuses duplicate keys, so do the two steps by hand.
        tree.start_undo_recording();
        tree.set(key(99), vec![1]);
        assert!(tree.delete(&key(99)));
        let undo = tree.stop_undo_recording().unwrap();
        assert_eq!(undo.entries.len(), 1, "the delete recorded a deactivation");
        assert!(undo.entries[0].slot >= undo.prev_next_slot, "of a slot the block itself appended");

        tree.apply_undo(&undo).unwrap();
        assert_eq!(tree.root(), before_root);
        assert!(tree.get(&key(99)).is_none());
    }

    #[test]
    fn a_record_from_another_history_is_refused_without_mutating() {
        let mut tree = seeded(10);
        let root = tree.root();
        let mut other = seeded(10);
        other.apply_sorted_ops(sets(0..1, 0xEE)).unwrap();
        let (_, foreign) = other.apply_sorted_ops_recorded(sets(0..1, 0xEF)).unwrap();
        // `foreign` revives slot 10 as key(0)/[0xEE,0]; this tree's slot 10
        // does not exist at all — its cursor is 10.
        assert!(matches!(tree.apply_undo(&foreign), Err(QmdbUndoError::Ahead { .. })));
        assert_eq!(tree.root(), root);

        // A record whose cursor fits but whose revival names the wrong value.
        let (_, mut mine) = tree.apply_sorted_ops_recorded(sets(0..1, 0xB0)).unwrap();
        let revived = mine.entries[0].slot;
        mine.entries[0].value = vec![0xFF];
        assert_eq!(tree.apply_undo(&mine), Err(QmdbUndoError::EntryMismatch { slot: revived }));
    }

    #[test]
    fn a_revert_while_recording_is_refused() {
        let mut tree = seeded(3);
        let (_, undo) = tree.apply_sorted_ops_recorded(sets(0..1, 0xB0)).unwrap();
        tree.start_undo_recording();
        assert_eq!(tree.apply_undo(&undo), Err(QmdbUndoError::RecordingActive));
        tree.stop_undo_recording();
        tree.apply_undo(&undo).unwrap();
    }
}
