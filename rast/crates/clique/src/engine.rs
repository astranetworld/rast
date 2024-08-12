

use primitive_types::U256;
use reth_primitives_traits::Header;
use reth_primitives::Block;
use crate::etheader::ExtendedHeader;
use crate::traits::{Machine, EngineSigner, AncestryAction};


use crate::etheader::{Seal,SealingState};

// use types::BlockNumber;
pub type BlockNumber = u64;
use crate::error::{BlockError, Error};
use ethereum_types::{Address, H64, H160, H256};
use std::sync::{Weak, Arc};


#[derive(Debug, PartialEq, Eq)]
pub enum ForkChoice {
	/// Choose the new block.
	New,
	/// Choose the current best block.
	Old,
}


/// A consensus mechanism for the chain. Generally either proof-of-work or proof-of-stake-based.
/// Provides hooks into each of the major parts of block import.
pub trait Engine<M: Machine>: Sync + Send {
	/// The name of this engine.
	fn name(&self) -> &str;

	/// Get access to the underlying state machine.
	// TODO: decouple.
	fn machine(&self) -> &M;

	/// The number of additional header fields required for this engine.
	fn seal_fields(&self, _header: &Header) -> usize { 0 }

	// /// Additional engine-specific information for the user/developer concerning `header`.
	// fn extra_info(&self, _header: &Header) -> BTreeMap<String, String> { BTreeMap::new() }

	/// Maximum number of uncles a block is allowed to declare.
	fn maximum_uncle_count(&self, _block: BlockNumber) -> usize { 0 }

	/// Optional maximum gas limit.
	fn maximum_gas_limit(&self) -> Option<U256> { None }

	/// Block transformation functions, before the transactions.
	/// `epoch_begin` set to true if this block kicks off an epoch.
	fn on_new_block(
		&self,
		_block: &mut Block,
		_epoch_begin: bool,
		_ancestry: &mut dyn Iterator<Item = Block>,
	) -> Result<(), M::Error> {
		Ok(())
	}

	/// Block transformation functions, after the transactions.
	fn on_close_block(&self, _block: &mut Block) -> Result<(), M::Error> {
		Ok(())
	}

	/// Allow mutating the header during seal generation. Currently only used by Clique.
	fn on_seal_block(&self, _block: &mut Block) -> Result<(), Error> { Ok(()) }

	/// Returns the engine's current sealing state.
	fn sealing_state(&self) -> SealingState { SealingState::External }

	/// Attempt to seal the block internally.
	///
	/// If `Some` is returned, then you get a valid seal.
	///
	/// This operation is synchronous and may (quite reasonably) not be available, in which None will
	/// be returned.
	///
	/// It is fine to require access to state or a full client for this function, since
	/// light clients do not generate seals.
	fn generate_seal(&self, _block: &Block, _parent: &Header) -> Seal { Seal::None }

	/// Verify a locally-generated seal of a header.
	///
	/// If this engine seals internally,
	/// no checks have to be done here, since all internally generated seals
	/// should be valid.
	///
	/// Externally-generated seals (e.g. PoW) will need to be checked for validity.
	///
	/// It is fine to require access to state or a full client for this function, since
	/// light clients do not generate seals.
	fn verify_local_seal(&self, header: &Header) -> Result<(), M::Error>;

	/// Phase 1 quick block verification. Only does checks that are cheap. Returns either a null `Ok` or a general error detailing the problem with import.
	/// The verification module can optionally avoid checking the seal (`check_seal`), if seal verification is disabled this method won't be called.
	fn verify_block_basic(&self, _header: &Header) -> Result<(), M::Error> { Ok(()) }

	/// Phase 2 verification. Perform costly checks such as transaction signatures. Returns either a null `Ok` or a general error detailing the problem with import.
	/// The verification module can optionally avoid checking the seal (`check_seal`), if seal verification is disabled this method won't be called.
	fn verify_block_unordered(&self, _header: &Header) -> Result<(), M::Error> { Ok(()) }

	/// Phase 3 verification. Check block information against parent. Returns either a null `Ok` or a general error detailing the problem with import.
	fn verify_block_family(&self, _header: &Header, _parent: &Header) -> Result<(), M::Error> { Ok(()) }

	/// Phase 4 verification. Verify block header against potentially external data.
	/// Should only be called when `register_client` has been called previously.
	fn verify_block_external(&self, _header: &Header) -> Result<(), M::Error> { Ok(()) }

	// /// Genesis epoch data.
	// fn genesis_epoch_data<'a>(&self, _header: &Header, _state: &machine::Call) -> Result<Vec<u8>, String> { Ok(Vec::new()) }

	/// Whether an epoch change is signalled at the given header but will require finality.
	/// If a change can be enacted immediately then return `No` from this function but
	/// `Yes` from `is_epoch_end`.
	///
	/// If auxiliary data of the block is required, return an auxiliary request and the function will be
	/// called again with them.
	/// Return `Yes` or `No` when the answer is definitively known.
	///
	/// Should not interact with state.
	// fn signals_epoch_end<'a>(&self, _header: &Header, _aux: AuxiliaryData<'a>)
	// 	-> EpochChange<M>
	// {
	// 	EpochChange::No
	// }

	/// Whether a block is the end of an epoch.
	///
	/// This either means that an immediate transition occurs or a block signalling transition
	/// has reached finality. The `Headers` given are not guaranteed to return any blocks
	/// from any epoch other than the current. The client must keep track of finality and provide
	/// the latest finalized headers to check against the transition store.
	///
	/// Return optional transition proof.
	// fn is_epoch_end(
	// 	&self,
	// 	_chain_head: &Header,
	// 	_finalized: &[H256],
	// 	_chain: &Headers<Header>,
	// 	_transition_store: &PendingTransitionStore,
	// ) -> Option<Vec<u8>> {
	// 	None
	// }

	/// Whether a block is the end of an epoch.
	///
	/// This either means that an immediate transition occurs or a block signalling transition
	/// has reached finality. The `Headers` given are not guaranteed to return any blocks
	/// from any epoch other than the current. This is a specialized method to use for light
	/// clients since the light client doesn't track finality of all blocks, and therefore finality
	/// for blocks in the current epoch is built inside this method by the engine.
	///
	/// Return optional transition proof.
	// fn is_epoch_end_light(
	// 	&self,
	// 	_chain_head: &Header,
	// 	_chain: &Headers<Header>,
	// 	_transition_store: &PendingTransitionStore,
	// ) -> Option<Vec<u8>> {
	// 	None
	// }

	/// Create an epoch verifier from validation proof and a flag indicating
	/// whether finality is required.
	// fn epoch_verifier<'a>(&self, _header: &Header, _proof: &'a [u8]) -> ConstructedVerifier<'a, M> {
	// 	ConstructedVerifier::Trusted(Box::new(NoOp))
	// }

	/// Populate a header's fields based on its parent's header.
	/// Usually implements the chain scoring rule based on weight.
	fn populate_from_parent(&self, _header: &mut Header, _parent: &Header) { }

	/// Handle any potential consensus messages;
	/// updating consensus state and potentially issuing a new one.
	// fn handle_message(&self, _message: &[u8]) -> Result<(), EngineError> { Err(EngineError::UnexpectedMessage) }

	/// Register a component which signs consensus messages.
	fn set_signer(&self, _signer: Box<dyn EngineSigner>) {}

	/// Sign using the EngineSigner, to be used for consensus tx signing.
	// fn sign(&self, _hash: H256) -> Result<Signature, M::Error> { unimplemented!() }

	/// Add Client which can be used for sealing, potentially querying the state and sending messages.
	fn register_client(&self, _client: Weak<M::EngineClient>) {}

	/// Trigger next step of the consensus engine.
	fn step(&self) {}

	/// Create a factory for building snapshot chunks and restoring from them.
	/// Returning `None` indicates that this engine doesn't support snapshot creation.
	// fn snapshot_components(&self) -> Option<Box<dyn SnapshotComponents>> {
	// 	None
	// }

	/// Whether this engine supports warp sync.
	fn supports_warp(&self) -> bool {
		self.snapshot_components().is_some()
	}

	/// Return a new open block header timestamp based on the parent timestamp.
	fn open_block_header_timestamp(&self, parent_timestamp: u64) -> u64 {
		use std::{time, cmp};

		let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap_or_default();
		cmp::max(now.as_secs() as u64, parent_timestamp + 1)
	}

	/// Check whether the parent timestamp is valid.
	fn is_timestamp_valid(&self, header_timestamp: u64, parent_timestamp: u64) -> bool {
		header_timestamp > parent_timestamp
	}

	/// Gather all ancestry actions. Called at the last stage when a block is committed. The Engine must guarantee that
	/// the ancestry exists.
	fn ancestry_actions(&self, _header: &Header, _ancestry: &mut dyn Iterator<Item = ExtendedHeader>) -> Vec<AncestryAction> {
		Vec::new()
	}

	/// Check whether the given new block is the best block, after finalization check.
	fn fork_choice(&self, new: &ExtendedHeader, best: &ExtendedHeader) -> ForkChoice;

	/// Returns author should used when executing tx's for this block.
	fn executive_author(&self, header: &Header) -> Result<Address, Error> {
		Ok(*header.author())
	}
}

/// Check whether a given block is the best block based on the default total difficulty rule.
pub fn total_difficulty_fork_choice(new: &ExtendedHeader, best: &ExtendedHeader) -> ForkChoice {
	if new.total_score() > best.total_score() {
		ForkChoice::New
	} else {
		ForkChoice::Old
	}
}

// /// Common type alias for an engine coupled with an Ethereum-like state machine.
// // TODO: make this a _trait_ alias when those exist.
// // fortunately the effect is largely the same since engines are mostly used
// // via trait objects.
// pub trait EthEngine: Engine<::machine::EthereumMachine> {
// 	/// Get the general parameters of the chain.
// 	fn params(&self) -> &CommonParams {
// 		self.machine().params()
// 	}

// 	/// Get the EVM schedule for the given block number.
// 	fn schedule(&self, block_number: BlockNumber) -> Schedule {
// 		self.machine().schedule(block_number)
// 	}

// 	/// Builtin-contracts for the chain..
// 	fn builtins(&self) -> &BTreeMap<Address, Builtin> {
// 		self.machine().builtins()
// 	}

// 	/// Attempt to get a handle to a built-in contract.
// 	/// Only returns references to activated built-ins.
// 	fn builtin(&self, a: &Address, block_number: BlockNumber) -> Option<&Builtin> {
// 		self.machine().builtin(a, block_number)
// 	}

// 	/// Some intrinsic operation parameters; by default they take their value from the `spec()`'s `engine_params`.
// 	fn maximum_extra_data_size(&self) -> usize {
// 		self.machine().maximum_extra_data_size()
// 	}

// 	/// The nonce with which accounts begin at given block.
// 	fn account_start_nonce(&self, block: BlockNumber) -> U256 {
// 		self.machine().account_start_nonce(block)
// 	}

// 	/// The network ID that transactions should be signed with.
// 	fn signing_chain_id(&self, env_info: &EnvInfo) -> Option<u64> {
// 		self.machine().signing_chain_id(env_info)
// 	}

// 	/// Returns new contract address generation scheme at given block number.
// 	fn create_address_scheme(&self, number: BlockNumber) -> CreateContractAddress {
// 		self.machine().create_address_scheme(number)
// 	}

// 	/// Verify a particular transaction is valid.
// 	///
// 	/// Unordered verification doesn't rely on the transaction execution order,
// 	/// i.e. it should only verify stuff that doesn't assume any previous transactions
// 	/// has already been verified and executed.
// 	///
// 	/// NOTE This function consumes an `UnverifiedTransaction` and produces `SignedTransaction`
// 	/// which implies that a heavy check of the signature is performed here.
// 	fn verify_transaction_unordered(&self, t: UnverifiedTransaction, header: &Header) -> Result<SignedTransaction, transaction::Error> {
// 		self.machine().verify_transaction_unordered(t, header)
// 	}

// 	/// Perform basic/cheap transaction verification.
// 	///
// 	/// This should include all cheap checks that can be done before
// 	/// actually checking the signature, like chain-replay protection.
// 	///
// 	/// NOTE This is done before the signature is recovered so avoid
// 	/// doing any state-touching checks that might be expensive.
// 	///
// 	/// TODO: Add flags for which bits of the transaction to check.
// 	/// TODO: consider including State in the params.
// 	fn verify_transaction_basic(&self, t: &UnverifiedTransaction, header: &Header) -> Result<(), transaction::Error> {
// 		self.machine().verify_transaction_basic(t, header)
// 	}

// 	/// Additional information.
// 	fn additional_params(&self) -> HashMap<String, String> {
// 		self.machine().additional_params()
// 	}

// 	/// Performs pre-validation of RLP decoded transaction before other processing
// 	fn decode_transaction(&self, transaction: &[u8]) -> Result<UnverifiedTransaction, transaction::Error> {
// 		self.machine().decode_transaction(transaction)
// 	}
// }