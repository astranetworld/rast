// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use ethcore::snapshot::{ManifestData, SnapshotService};
use ethereum_types::H256;
use keccak_hash::keccak;

use std::collections::HashSet;
use std::iter::FromIterator;
use log::trace;

#[derive(PartialEq, Eq, Debug)]
pub enum ChunkType {
	State(H256),
	Block(H256),
}

pub struct Snapshot {
	pending_state_chunks: Vec<H256>,
	pending_block_chunks: Vec<H256>,
	downloading_chunks: HashSet<H256>,
	completed_chunks: HashSet<H256>,
	snapshot_hash: Option<H256>,
	bad_hashes: HashSet<H256>,
	initialized: bool,
}

impl Snapshot {
	/// Create a new instance.
	pub fn new() -> Snapshot {
		Snapshot {
			pending_state_chunks: Vec::new(),
			pending_block_chunks: Vec::new(),
			downloading_chunks: HashSet::new(),
			completed_chunks: HashSet::new(),
			snapshot_hash: None,
			bad_hashes: HashSet::new(),
			initialized: false,
		}
	}

	/// Sync the Snapshot completed chunks with the Snapshot Service
	pub fn initialize(&mut self, snapshot_service: &SnapshotService) {
		if self.initialized {
			return;
		}

		if let Some(completed_chunks) = snapshot_service.completed_chunks() {
			self.completed_chunks = HashSet::from_iter(completed_chunks);
		}

		trace!(
			target: "snapshot",
			"Snapshot is now initialized with {} completed chunks.",
			self.completed_chunks.len(),
		);

		self.initialized = true;
	}

	/// Clear everything.
	pub fn clear(&mut self) {
		self.pending_state_chunks.clear();
		self.pending_block_chunks.clear();
		self.downloading_chunks.clear();
		self.completed_chunks.clear();
		self.snapshot_hash = None;
		self.initialized = false;
	}

	/// Check if currently downloading a snapshot.
	pub fn have_manifest(&self) -> bool {
		self.snapshot_hash.is_some()
	}

	/// Reset collection for a manifest RLP
	pub fn reset_to(&mut self, manifest: &ManifestData, hash: &H256) {
		self.clear();
		self.pending_state_chunks = manifest.state_hashes.clone();
		self.pending_block_chunks = manifest.block_hashes.clone();
		self.snapshot_hash = Some(hash.clone());
	}

	/// Validate chunk and mark it as downloaded
	pub fn validate_chunk(&mut self, chunk: &[u8]) -> Result<ChunkType, ()> {
		let hash = keccak(chunk);
		if self.completed_chunks.contains(&hash) {
			trace!(target: "sync", "Ignored proccessed chunk: {:x}", hash);
			return Err(());
		}
		self.downloading_chunks.remove(&hash);
		if self.pending_block_chunks.iter().any(|h| h == &hash) {
			self.completed_chunks.insert(hash.clone());
			return Ok(ChunkType::Block(hash));
		}
		if self.pending_state_chunks.iter().any(|h| h == &hash) {
			self.completed_chunks.insert(hash.clone());
			return Ok(ChunkType::State(hash));
		}
		trace!(target: "sync", "Ignored unknown chunk: {:x}", hash);
		Err(())
	}

	/// Find a chunk to download
	pub fn needed_chunk(&mut self) -> Option<H256> {
		// Find next needed chunk: first block, then state chunks
		let chunk = {
			let chunk_filter = |h| !self.downloading_chunks.contains(h) && !self.completed_chunks.contains(h);

			let needed_block_chunk = self.pending_block_chunks.iter()
				.filter(|&h| chunk_filter(h))
				.map(|h| *h)
				.next();

			// If no block chunks to download, get the state chunks
			if needed_block_chunk.is_none() {
				self.pending_state_chunks.iter()
					.filter(|&h| chunk_filter(h))
					.map(|h| *h)
					.next()
			} else {
				needed_block_chunk
			}
		};

		if let Some(hash) = chunk {
			self.downloading_chunks.insert(hash.clone());
		}
		chunk
	}

	pub fn clear_chunk_download(&mut self, hash: &H256) {
		self.downloading_chunks.remove(hash);
	}

	// note snapshot hash as bad.
	pub fn note_bad(&mut self, hash: H256) {
		self.bad_hashes.insert(hash);
	}

	// whether snapshot hash is known to be bad.
	pub fn is_known_bad(&self, hash: &H256) -> bool {
		self.bad_hashes.contains(hash)
	}

	pub fn snapshot_hash(&self) -> Option<H256> {
		self.snapshot_hash
	}

	pub fn total_chunks(&self) -> usize {
		self.pending_block_chunks.len() + self.pending_state_chunks.len()
	}

	pub fn done_chunks(&self) -> usize {
		self.completed_chunks.len()
	}

	pub fn is_complete(&self) -> bool {
		self.total_chunks() == self.completed_chunks.len()
	}
}




/// A sink for produced chunks.
pub type ChunkSink<'a> = dyn FnMut(&[u8]) -> ::std::io::Result<()> + 'a;

/// Components necessary for snapshot creation and restoration.
pub trait SnapshotComponents: Send {
	/// Create secondary snapshot chunks; these corroborate the state data
	/// in the state chunks.
	///
	/// Chunks shouldn't exceed the given preferred size, and should be fed
	/// uncompressed into the sink.
	///
	/// This will vary by consensus engine, so it's exposed as a trait.
	fn chunk_all(
		&mut self,
		chain: &BlockChain,
		block_at: H256,
		chunk_sink: &mut ChunkSink,
		progress: &Progress,
		preferred_size: usize,
	) -> Result<(), Error>;

	/// Create a rebuilder, which will have chunks fed into it in aribtrary
	/// order and then be finalized.
	///
	/// The manifest, a database, and fresh `BlockChain` are supplied.
	///
	/// The engine passed to the `Rebuilder` methods will be the same instance
	/// that created the `SnapshotComponents`.
	fn rebuilder(
		&self,
		chain: BlockChain,
		db: Arc<dyn BlockChainDB>,
		manifest: &ManifestData,
	) -> Result<Box<dyn Rebuilder>, ::error::Error>;

	/// Minimum supported snapshot version number.
	fn min_supported_version(&self) -> u64;

	/// Current version number
	fn current_version(&self) -> u64;
}



/// Snapshot creation and restoration for PoA chains.
/// Chunk format:
///
/// [FLAG, [header, epoch data], ...]
///   - Header data at which transition occurred,
///   - epoch data (usually list of validators and proof of change)
///
/// FLAG is a bool: true for last chunk, false otherwise.
///
/// The last item of the last chunk will be a list containing data for the warp target block:
/// [header, transactions, uncles, receipts, parent_td].
pub struct PoaSnapshot;

impl SnapshotComponents for PoaSnapshot {
	fn chunk_all(
		&mut self,
		chain: &BlockChain,
		block_at: H256,
		sink: &mut ChunkSink,
		_progress: &Progress,
		preferred_size: usize,
	) -> Result<(), Error> {
		let number = chain.block_number(&block_at)
			.ok_or_else(|| Error::InvalidStartingBlock(BlockId::Hash(block_at)))?;

		let mut pending_size = 0;
		let mut rlps = Vec::new();

		for (_, transition) in chain.epoch_transitions()
			.take_while(|&(_, ref t)| t.block_number <= number)
		{
			// this can happen when our starting block is non-canonical.
			if transition.block_number == number && transition.block_hash != block_at {
				break
			}

			let header = chain.block_header_data(&transition.block_hash)
				.ok_or_else(|| Error::BlockNotFound(transition.block_hash))?;

			let entry = {
				let mut entry_stream = RlpStream::new_list(2);
				entry_stream
					.append_raw(&header.into_inner(), 1)
					.append(&transition.proof);

				entry_stream.out()
			};

			// cut of the chunk if too large.
			let new_loaded_size = pending_size + entry.len();
			pending_size = if new_loaded_size > preferred_size && !rlps.is_empty() {
				write_chunk(false, &mut rlps, sink)?;
				entry.len()
			} else {
				new_loaded_size
			};

			rlps.push(entry);
		}

		let (block, receipts) = chain.block(&block_at)
			.and_then(|b| chain.block_receipts(&block_at).map(|r| (b, r)))
			.ok_or_else(|| Error::BlockNotFound(block_at))?;
		let block = block.decode()?;

		let parent_td = chain.block_details(block.header.parent_hash())
			.map(|d| d.total_difficulty)
			.ok_or_else(|| Error::BlockNotFound(block_at))?;

		rlps.push({
			let mut stream = RlpStream::new_list(5);
			stream
				.append(&block.header)
				.append_list(&block.transactions)
				.append_list(&block.uncles)
				.append(&receipts)
				.append(&parent_td);
			stream.out()
		});

		write_chunk(true, &mut rlps, sink)?;

		Ok(())
	}

	fn rebuilder(
		&self,
		chain: BlockChain,
		db: Arc<dyn BlockChainDB>,
		manifest: &ManifestData,
	) -> Result<Box<dyn Rebuilder>, ::error::Error> {
		Ok(Box::new(ChunkRebuilder {
			manifest: manifest.clone(),
			warp_target: None,
			chain: chain,
			db: db.key_value().clone(),
			had_genesis: false,
			unverified_firsts: Vec::new(),
			last_epochs: Vec::new(),
		}))
	}

	fn min_supported_version(&self) -> u64 { 3 }
	fn current_version(&self) -> u64 { 3 }
}



use std::error;
use std::fmt;

use crate::ids::BlockId;


// use ethtrie::TrieError;
use rlp::DecoderError;




/// Snapshot-related errors.
#[derive(Debug)]
pub enum Error {
	/// Invalid starting block for snapshot.
	InvalidStartingBlock(BlockId),
	/// Block not found.
	BlockNotFound(H256),
	/// Incomplete chain.
	IncompleteChain,
	/// Best block has wrong state root.
	WrongStateRoot(H256, H256),
	/// Wrong block hash.
	WrongBlockHash(u64, H256, H256),
	/// Too many blocks contained within the snapshot.
	TooManyBlocks(u64, u64),
	/// Old starting block in a pruned database.
	OldBlockPrunedDB,
	/// Missing code.
	MissingCode(Vec<H256>),
	/// Unrecognized code encoding.
	UnrecognizedCodeState(u8),
	/// Restoration aborted.
	RestorationAborted,
	// /// Trie error.
	// Trie(TrieError),
	/// Decoder error.
	Decoder(DecoderError),
	/// Io error.
	Io(::std::io::Error),
	/// Snapshot version is not supported.
	VersionNotSupported(u64),
	/// Max chunk size is to small to fit basic account data.
	ChunkTooSmall,
	/// Oversized chunk
	ChunkTooLarge,
	/// Snapshots not supported by the consensus engine.
	SnapshotsUnsupported,
	/// Bad epoch transition.
	BadEpochProof(u64),
	/// Wrong chunk format.
	WrongChunkFormat(String),
	/// Unlinked ancient block chain
	UnlinkedAncientBlockChain,
}

impl error::Error for Error {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Error::Trie(e) => Some(e),
			Error::Decoder(e) => Some(e),
			Error::Io(e) => Some(e),
			_ => None,
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Error::InvalidStartingBlock(ref id) => write!(f, "Invalid starting block: {:?}", id),
			Error::BlockNotFound(ref hash) => write!(f, "Block not found in chain: {}", hash),
			Error::IncompleteChain => write!(f, "Incomplete blockchain."),
			Error::WrongStateRoot(ref expected, ref found) => write!(f, "Final block has wrong state root. Expected {:?}, got {:?}", expected, found),
			Error::WrongBlockHash(ref num, ref expected, ref found) =>
				write!(f, "Block {} had wrong hash. expected {:?}, got {:?}", num, expected, found),
			Error::TooManyBlocks(ref expected, ref found) => write!(f, "Snapshot contained too many blocks. Expected {}, got {}", expected, found),
			Error::OldBlockPrunedDB => write!(f, "Attempted to create a snapshot at an old block while using \
				a pruned database. Please re-run with the --pruning archive flag."),
			Error::MissingCode(ref missing) => write!(f, "Incomplete snapshot: {} contract codes not found.", missing.len()),
			Error::UnrecognizedCodeState(state) => write!(f, "Unrecognized code encoding ({})", state),
			Error::RestorationAborted => write!(f, "Snapshot restoration aborted."),
			Error::Io(ref err) => err.fmt(f),
			Error::Decoder(ref err) => err.fmt(f),
			Error::Trie(ref err) => err.fmt(f),
			Error::VersionNotSupported(ref ver) => write!(f, "Snapshot version {} is not supprted.", ver),
			Error::ChunkTooSmall => write!(f, "Chunk size is too small."),
			Error::ChunkTooLarge => write!(f, "Chunk size is too large."),
			Error::SnapshotsUnsupported => write!(f, "Snapshots unsupported by consensus engine."),
			Error::BadEpochProof(i) => write!(f, "Bad epoch proof for transition to epoch {}", i),
			Error::WrongChunkFormat(ref msg) => write!(f, "Wrong chunk format: {}", msg),
			Error::UnlinkedAncientBlockChain => write!(f, "Unlinked ancient blocks chain"),
		}
	}
}

impl From<::std::io::Error> for Error {
	fn from(err: ::std::io::Error) -> Self {
		Error::Io(err)
	}
}

// impl From<TrieError> for Error {
// 	fn from(err: TrieError) -> Self {
// 		Error::Trie(err)
// 	}
// }

impl From<DecoderError> for Error {
	fn from(err: DecoderError) -> Self {
		Error::Decoder(err)
	}
}

impl<E> From<Box<E>> for Error where Error: From<E> {
	fn from(err: Box<E>) -> Self {
		Error::from(*err)
	}
}

