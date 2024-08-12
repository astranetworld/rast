
use reth_primitives_traits::Header;
use primitive_types::U256;

pub struct ExtendedHeader {
	/// The actual header.
	pub header: Header,
	/// Whether the block underlying this header is considered finalized.
	pub is_finalized: bool,
	/// The parent block difficulty.
	pub parent_total_difficulty: U256,
}

impl ExtendedHeader {
	/// Returns combined difficulty of all ancestors together with the difficulty of this header.
	pub fn total_score(&self) -> U256 {
		self.parent_total_difficulty + *self.header.difficulty()
	}
}

/// Vector of bytes.
pub type Bytes = Vec<u8>;
/// Seal type.
#[derive(Debug, PartialEq, Eq)]
pub enum Seal {
	/// Proposal seal; should be broadcasted, but not inserted into blockchain.
	Proposal(Vec<Bytes>),
	/// Regular block seal; should be part of the blockchain.
	Regular(Vec<Bytes>),
	/// Engine does not generate seal for this block right now.
	None,
}

/// The type of sealing the engine is currently able to perform.
#[derive(Debug, PartialEq, Eq)]
pub enum SealingState {
	/// The engine is ready to seal a block.
	Ready,
	/// The engine can't seal at the moment, and no block should be prepared and queued.
	NotReady,
	/// The engine does not seal internally.
	External,
}