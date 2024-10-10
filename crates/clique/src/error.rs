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

use std::{fmt, error};
use std::time::SystemTime;

use derive_more::{Display, From};
use alloy_primitives::{U256, Address, Bloom, B256, U64};
use rlp;
use unexpected::{Mismatch, OutOfBounds};



// pub use executed::{ExecutionError, CallError};
pub type BlockNumber = u64;

/// Errors concerning block processing.
#[derive(Debug, Display, PartialEq, Clone, Eq)]
pub enum BlockError {
	/// Block has too many uncles.
	#[display(fmt = "Block has too many uncles. {}", _0)]
	TooManyUncles(OutOfBounds<usize>),
	/// Extra data is of an invalid length.
	#[display(fmt = "Extra block data too long. {}", _0)]
	ExtraDataOutOfBounds(OutOfBounds<usize>),
	/// Seal is incorrect format.
	#[display(fmt = "Block seal in incorrect format: {}", _0)]
	InvalidSealArity(Mismatch<usize>),
	/// Block has too much gas used.
	#[display(fmt = "Block has too much gas used. {}", _0)]
	TooMuchGasUsed(OutOfBounds<U256>),
	/// Uncles hash in header is invalid.
	#[display(fmt = "Block has invalid uncles hash: {}", _0)]
	InvalidUnclesHash(Mismatch<B256>),
	/// An uncle is from a generation too old.
	#[display(fmt = "Uncle block is too old. {}", _0)]
	UncleTooOld(OutOfBounds<BlockNumber>),
	/// An uncle is from the same generation as the block.
	#[display(fmt = "Uncle from same generation as block. {}", _0)]
	UncleIsBrother(OutOfBounds<BlockNumber>),
	/// An uncle is already in the chain.
	#[display(fmt = "Uncle {} already in chain", _0)]
	UncleInChain(B256),
	/// An uncle is included twice.
	#[display(fmt = "Uncle {} already in the header", _0)]
	DuplicateUncle(B256),
	/// An uncle has a parent not in the chain.
	#[display(fmt = "Uncle {} has a parent not in the chain", _0)]
	UncleParentNotInChain(B256),
	/// State root header field is invalid.
	#[display(fmt = "Invalid state root in header: {}", _0)]
	InvalidStateRoot(Mismatch<B256>),
	/// Gas used header field is invalid.
	#[display(fmt = "Invalid gas used in header: {}", _0)]
	InvalidGasUsed(Mismatch<U256>),
	/// Transactions root header field is invalid.
	#[display(fmt = "Invalid transactions root in header: {}", _0)]
	InvalidTransactionsRoot(Mismatch<B256>),
	/// Difficulty is out of range; this can be used as an looser error prior to getting a definitive
	/// value for difficulty. This error needs only provide bounds of which it is out.
	#[display(fmt = "Difficulty out of bounds: {}", _0)]
	DifficultyOutOfBounds(OutOfBounds<U256>),
	/// Difficulty header field is invalid; this is a strong error used after getting a definitive
	/// value for difficulty (which is provided).
	#[display(fmt = "Invalid block difficulty: {}", _0)]
	InvalidDifficulty(Mismatch<U256>),
	/// Seal element of type H256 (max_hash for Ethash, but could be something else for
	/// other seal engines) is out of bounds.
	#[display(fmt = "Seal element out of bounds: {}", _0)]
	MismatchedH256SealElement(Mismatch<B256>),
	/// Proof-of-work aspect of seal, which we assume is a 256-bit value, is invalid.
	#[display(fmt = "Block has invalid PoW: {}", _0)]
	InvalidProofOfWork(OutOfBounds<U256>),
	/// Some low-level aspect of the seal is incorrect.
	#[display(fmt = "Block has invalid seal.")]
	InvalidSeal,
	/// Gas limit header field is invalid.
	#[display(fmt = "Invalid gas limit: {}", _0)]
	InvalidGasLimit(OutOfBounds<U256>),
	/// Receipts trie root header field is invalid.
	#[display(fmt = "Invalid receipts trie root in header: {}", _0)]
	InvalidReceiptsRoot(Mismatch<B256>),
	/// Timestamp header field is invalid.
	#[display(fmt = "Invalid timestamp in header: {}", _0)]
	InvalidTimestamp(OutOfBoundsTime),
	/// Timestamp header field is too far in future.
	#[display(fmt = "Future timestamp in header: {}", _0)]
	TemporarilyInvalid(OutOfBoundsTime),
	/// Log bloom header field is invalid.
	#[display(fmt = "Invalid log bloom in header: {}", _0)]
	InvalidLogBloom(Box<Mismatch<Bloom>>),
	/// Number field of header is invalid.
	#[display(fmt = "Invalid number in header: {}", _0)]
	InvalidNumber(Mismatch<BlockNumber>),
	/// Block number isn't sensible.
	#[display(fmt = "Implausible block number. {}", _0)]
	RidiculousNumber(OutOfBounds<BlockNumber>),
	/// Timestamp header overflowed
	#[display(fmt = "Timestamp overflow")]
	TimestampOverflow,
	/// Too many transactions from a particular address.
	#[display(fmt = "Too many transactions from: {}", _0)]
	TooManyTransactions(Address),
	/// Parent given is unknown.
	#[display(fmt = "Unknown parent: {}", _0)]
	UnknownParent(B256),
	/// Uncle parent given is unknown.
	#[display(fmt = "Unknown uncle parent: {}", _0)]
	UnknownUncleParent(B256),
	/// No transition to epoch number.
	#[display(fmt = "Unknown transition to epoch number: {}", _0)]
	UnknownEpochTransition(u64),
}

/// Newtype for Display impl to show seconds
#[derive(Debug, Clone, From, PartialEq, Eq)]
pub struct OutOfBoundsTime(OutOfBounds<SystemTime>);

impl fmt::Display for OutOfBoundsTime {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let seconds = self.0
			.map(|st| st.elapsed().unwrap_or_default().as_secs());
		f.write_fmt(format_args!("{}", seconds))
	}
}

impl error::Error for BlockError {
	fn description(&self) -> &str {
		"Block error"
	}
}

// /// Queue error
// #[derive(Debug, Display, From)]
// pub enum QueueError {
// 	/// Queue is full
// 	#[display(fmt = "Queue is full ({})", _0)]
// 	Full(usize),
// 	/// Io channel error
// 	#[display(fmt = "Io channel error: {}", _0)]
// 	Channel(::io::IoError)
// }

// impl error::Error for QueueError {
// 	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
// 		match self {
// 			QueueError::Channel(e) => Some(e),
// 			_ => None,
// 		}
// 	}
// }

/// Block import Error
#[derive(Debug, Display)]
pub enum ImportError {
	/// Already in the block chain.
	#[display(fmt = "Block already in chain")]
	AlreadyInChain,
	/// Already in the block queue
	#[display(fmt = "block already in the block queue")]
	AlreadyQueued,
	/// Already marked as bad from a previous import (could mean parent is bad)
	#[display(fmt = "block known to be bad")]
	KnownBad,
}

impl error::Error for ImportError {}

// /// Api-level error for transaction import
// #[derive(Debug, Clone)]
// pub enum TransactionImportError {
// 	/// Transaction error
// 	Transaction(TransactionError),
// 	/// Other error
// 	Other(String),
// }

// impl From<Error> for TransactionImportError {
// 	fn from(e: Error) -> Self {
// 		match e {
// 			Error::Transaction(transaction_error) => TransactionImportError::Transaction(transaction_error),
// 			_ => TransactionImportError::Other(format!("other block import error: {:?}", e)),
// 		}
// 	}
// }

/// Ethcore Result
pub type EthcoreResult<T> = Result<T, Error>;

/// Ethcore Error
#[derive(Debug, Display, From)]
pub enum Error {
	/// Error concerning block import.
	#[display(fmt = "Import error: {}", _0)]
	Import(ImportError),
	// /// Io channel queue error
	// #[display(fmt = "Queue error: {}", _0)]
	// Queue(QueueError),
	// /// Io create error
	// #[display(fmt = "Io error: {}", _0)]
	// Io(::io::IoError),
	/// Error concerning the Rust standard library's IO subsystem.
	#[display(fmt = "Std Io error: {}", _0)]
	StdIo(::std::io::Error),
	// // /// Error concerning TrieDBs.
	// // #[display(fmt = "Trie error: {}", _0)]
	// // Trie(TrieError),
	// /// Error concerning EVM code execution.
	// #[display(fmt = "Execution error: {}", _0)]
	// Execution(ExecutionError),
	/// Error concerning block processing.
	#[display(fmt = "Block error: {}", _0)]
	Block(BlockError),
	// /// Error concerning transaction processing.
	// #[display(fmt = "Transaction error: {}", _0)]
	// Transaction(TransactionError),
	/// Snappy error
	// #[display(fmt = "Snappy error: {}", _0)]
	// Snappy(InvalidInput),
	/// Consensus vote error.
	#[display(fmt = "Engine error: {}", _0)]
	Engine(EngineError),
	// /// Ethkey error."
	// #[display(fmt = "Ethkey error: {}", _0)]
	// Ethkey(EthkeyError),
	/// RLP decoding errors
	#[display(fmt = "Decoder error: {}", _0)]
	Decoder(rlp::DecoderError),
	/// Snapshot error.
	#[display(fmt = "Snapshot error {}", _0)]
	Snapshot(SnapshotError),
	/// PoW hash is invalid or out of date.
	#[display(fmt = "PoW hash is invalid or out of date.")]
	PowHashInvalid,
	/// The value of the nonce or mishash is invalid.
	#[display(fmt = "The value of the nonce or mishash is invalid.")]
	PowInvalid,
	/// Unknown engine given
	#[display(fmt = "Unknown engine name ({})", _0)]
	UnknownEngineName(String),
	/// A convenient variant for String.
	#[display(fmt = "{}", _0)]
	Msg(String),
}

impl error::Error for Error {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Error::Io(e) => Some(e),
			Error::StdIo(e) => Some(e),
			Error::Trie(e) => Some(e),
			Error::Execution(e) => Some(e),
			Error::Block(e) => Some(e),
			Error::Transaction(e) => Some(e),
			Error::Snappy(e) => Some(e),
			Error::Engine(e) => Some(e),
			Error::Ethkey(e) => Some(e),
			Error::Decoder(e) => Some(e),
			Error::Snapshot(e) => Some(e),
			_ => None,
		}
	}
}

impl From<String> for Error {
	fn from(s: String) -> Self {
		Error::Msg(s)
	}
}

impl From<&str> for Error {
	fn from(s: &str) -> Self {
		Error::Msg(s.into())
	}
}

impl<E> From<Box<E>> for Error where Error: From<E> {
	fn from(err: Box<E>) -> Error {
		Error::from(*err)
	}
}


/// Voting errors.
#[derive(Debug)]
pub enum EngineError {
	/// Signature or author field does not belong to an authority.
	NotAuthorized(Address),
	/// The same author issued different votes at the same step.
	DoubleVote(Address),
	/// The received block is from an incorrect proposer.
	NotProposer(Mismatch<Address>),
	/// Message was not expected.
	UnexpectedMessage,
	/// Seal field has an unexpected size.
	BadSealFieldSize(OutOfBounds<usize>),
	/// Validation proof insufficient.
	InsufficientProof(String),
	/// Failed system call.
	FailedSystemCall(String),
	/// Malformed consensus message.
	MalformedMessage(String),
	/// Requires client ref, but none registered.
	RequiresClient,
	/// Invalid engine specification or implementation.
	InvalidEngine,
	/// Requires signer ref, but none registered.
	RequiresSigner,
	/// Missing Parent Epoch
	MissingParent,
	/// Checkpoint is missing
	CliqueMissingCheckpoint(B256),
	/// Missing vanity data
	CliqueMissingVanity,
	/// Missing signature
	CliqueMissingSignature,
	/// Missing signers
	CliqueCheckpointNoSigner,
	/// List of signers is invalid
	CliqueCheckpointInvalidSigners(usize),
	/// Wrong author on a checkpoint
	CliqueWrongAuthorCheckpoint(Mismatch<Address>),
	/// Wrong checkpoint authors recovered
	CliqueFaultyRecoveredSigners(Vec<String>),
	/// Invalid nonce (should contain vote)
	CliqueInvalidNonce(U64),
	/// The signer signed a block to recently
	CliqueTooRecentlySigned(Address),
	/// Custom
	Custom(String),
}

impl fmt::Display for EngineError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		use self::EngineError::*;
		let msg = match *self {
			CliqueMissingCheckpoint(ref hash) => format!("Missing checkpoint block: {}", hash),
			CliqueMissingVanity => format!("Extra data is missing vanity data"),
			CliqueMissingSignature => format!("Extra data is missing signature"),
			CliqueCheckpointInvalidSigners(len) => format!("Checkpoint block list was of length: {} of checkpoint but
															it needs to be bigger than zero and a divisible by 20", len),
			CliqueCheckpointNoSigner => format!("Checkpoint block list of signers was empty"),
			CliqueInvalidNonce(ref mis) => format!("Unexpected nonce {} expected {} or {}", mis, 0_u64, u64::max_value()),
			CliqueWrongAuthorCheckpoint(ref oob) => format!("Unexpected checkpoint author: {}", oob),
			CliqueFaultyRecoveredSigners(ref mis) => format!("Faulty recovered signers {:?}", mis),
			CliqueTooRecentlySigned(ref address) => format!("The signer: {} has signed a block too recently", address),
			Custom(ref s) => s.clone(),
			DoubleVote(ref address) => format!("Author {} issued too many blocks.", address),
			NotProposer(ref mis) => format!("Author is not a current proposer: {}", mis),
			NotAuthorized(ref address) => format!("Signer {} is not authorized.", address),
			UnexpectedMessage => "This Engine should not be fed messages.".into(),
			BadSealFieldSize(ref oob) => format!("Seal field has an unexpected length: {}", oob),
			InsufficientProof(ref msg) => format!("Insufficient validation proof: {}", msg),
			FailedSystemCall(ref msg) => format!("Failed to make system call: {}", msg),
			MalformedMessage(ref msg) => format!("Received malformed consensus message: {}", msg),
			RequiresClient => format!("Call requires client but none registered"),
			RequiresSigner => format!("Call requires signer but none registered"),
			InvalidEngine => format!("Invalid engine specification or implementation"),
			MissingParent => format!("Parent Epoch is missing from database"),
		};

		f.write_fmt(format_args!("Engine error ({})", msg))
	}
}

impl error::Error for EngineError {
	fn description(&self) -> &str {
		"Engine error"
	}
}




