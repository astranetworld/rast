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

//! Generalization of a state machine for a consensus engine.
//! This will define traits for the header, block, and state of a blockchain.

use ethereum_types::{U256, Address,H256};
use reth_primitives::Block;
use reth_primitives::Signature;
use crate::error::Error;
use crate::ids::BlockId;
/// Vector of bytes.
pub type Bytes = Vec<u8>;
/// Type for block number.
pub type BlockNumber = u64;

/// Generalization of types surrounding blockchain-suitable state machines.
pub trait Machine: Send + Sync {
	/// A handle to a blockchain client for this machine.
	type EngineClient: ?Sized;

	/// Errors which can occur when querying or interacting with the machine.
	type Error;

	/// Get the balance, in base units, associated with an account.
	/// Extracts data from the live block.
	fn balance(&self, live: &Block, address: &Address) -> Result<U256, Self::Error>;

	/// Increment the balance of an account in the state of the live block.
	fn add_balance(&self, live: &mut Block, address: &Address, amount: &U256) -> Result<(), Self::Error>;
}

/// Everything that an Engine needs to sign messages.
pub trait EngineSigner: Send + Sync {
	/// Sign a consensus message hash.
	fn sign(&self, hash: H256) -> Result<Signature, Error>;

	/// Signing address
	fn address(&self) -> Address;
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// Actions on a live block's parent block. Only committed when the live block is committed. Those actions here must
/// respect the normal blockchain reorganization rules.
pub enum AncestryAction {
	/// Mark an ancestry block as finalized.
	MarkFinalized(H256),
}

/// Attempted to decompress an uncompressed buffer.
#[derive(Debug)]
pub struct InvalidInput;

impl std::error::Error for InvalidInput {
	fn description(&self) -> &str {
		"Attempted snappy decompression with invalid input"
	}
}


/// Client facilities used by internally sealing Engines.
pub trait EngineClient: Sync + Send + ChainInfo {
	/// Make a new block and seal it.
	fn update_sealing(&self);

	/// Submit a seal for a block in the mining queue.
	fn submit_seal(&self, block_hash: H256, seal: Vec<Bytes>);

	/// Broadcast a consensus message to the network.
	fn broadcast_consensus_message(&self, message: Bytes);

	/// Get the transition to the epoch the given parent hash is part of
	/// or transitions to.
	/// This will give the epoch that any children of this parent belong to.
	///
	/// The block corresponding the the parent hash must be stored already.
	fn epoch_transition_for(&self, parent_hash: H256) -> Option<::engines::EpochTransition>;

	/// Attempt to cast the engine client to a full client.
	fn as_full_client(&self) -> Option<&dyn BlockChainClient>;

	/// Get a block number by ID.
	fn block_number(&self, id: BlockId) -> Option<BlockNumber>;

	/// Get raw block header data by block id.
	fn block_header(&self, id: BlockId) -> Option<encoded::Header>;
}
