use std::error::Error;
use std::sync::Arc;
use keccak_hash::H256;

use primitive_types::U256;
use std::sync::mpsc::{Sender, Receiver};
use alloy_genesis::ChainConfig;
use reth_primitives::{ SealedBlock, SealedHeader};
pub const  SIGNATURE_LENGTH :usize = 96;
pub type Signature = [u8; SIGNATURE_LENGTH];

pub const ADDRESS_LENGTH :usize = 20;
pub type Address = [u8; ADDRESS_LENGTH];
pub const HASH_LENGTH :usize = 32;
pub type Hash = [u8; HASH_LENGTH];

// ChainHeaderReader defines a small collection of methods needed to access the local
// blockchain during header verification.
pub trait ChainHeaderReader {
    // Config retrieves the blockchain's chain configuration.
    fn config(&self) -> Arc<ChainConfig>;

    // CurrentBlock retrieves the current header from the local chain.
    fn current_block(&self) -> Arc<SealedBlock>;

    // GetHeader retrieves a block header from the database by hash and number.
    fn get_header(&self, hash: Hash, number: &U256) -> Arc<SealedHeader>;

    // GetHeaderByNumber retrieves a block header from the database by number.
    fn get_header_by_number(&self, number: &U256) -> Arc<SealedBlock>;

    // GetHeaderByHash retrieves a block header from the database by its hash.
    fn get_header_by_hash(&self, hash: Hash) -> Result<Arc<SealedHeader>, Box<dyn Error>>;

    // GetTd retrieves the total difficulty from the database by hash and number.
    fn get_td(&self, hash: Hash, number: &U256) -> U256;
    fn get_block_by_number(&self, number: &U256) -> Result<Arc<SealedBlock>, Box<dyn Error>>;
    fn get_deposit_info(&self, address: Address) -> (U256, U256);
    fn get_account_reward_unpaid(&self, account: Address) -> Result<U256, Box<dyn Error>>;
}

pub trait ChainReader: ChainHeaderReader {
    // GetBlock retrieves a block from the database by hash and number.
    fn get_block(&self, hash: H256, number: u64) -> Arc<SealedBlock>;

    // GetBlockByNumber retrieves a block by its number.
    fn get_block_by_number(&self, number: &U256) -> Result<Arc<SealedBlock>, Box<dyn std::error::Error>>;
}

pub const  PUBLIC_KEY_LENGTH :usize = 48;
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];
// Verify 结构体定义
pub struct Verify {
    pub address: Address,
    pub public_key: PublicKey,
}

pub trait Api {

    fn sign_merge (header: SealedHeader, deposit_num: u64) -> Result<Signature, Vec<Verify>> ;

}

pub struct API {
    pub namespace: String,
    pub service: Box<dyn Service>,
    pub authenticated: bool,
}

pub trait Service {
    // Define methods that the service should implement.
}

pub trait Has {
    // Has indicates whether a key exists in the database.
    fn has(&self, table: &str, key: &[u8]) -> Result<bool, Box<dyn Error>>;
}

pub trait Getter: Has {

    // GetOne references a readonly section of memory that must not be accessed after txn has terminated
    fn get_one(&self, table: &str, key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;

    // ForEach iterates over entries with keys greater or equal to fromPrefix.
    // walker is called for each eligible entry.
    // If walker returns an error:
    //   - implementations of local db - stop
    //   - implementations of remote db - do not handle this error and may finish (send all entries to client) before error happen.
    fn for_each<F>(&self, table: &str, from_prefix: &[u8], walker: F) -> Result<(), Box<dyn Error>>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), Box<dyn Error>>;

    fn for_prefix<F>(&self, table: &str, prefix: &[u8], walker: F) -> Result<(), Box<dyn Error>>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), Box<dyn Error>>;

    fn for_amount<F>(&self, table: &str, prefix: &[u8], amount: u32, walker: F) -> Result<(), Box<dyn Error>>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), Box<dyn Error>>;
}

pub trait Putter {
    /// Inserts or updates a single entry.
    fn put(&self, table: &str, key: &[u8], value: &[u8]) -> Result<(), Box<dyn Error>>;
}

// EngineReader are read-only methods of the consensus engine
// All of these methods should have thread-safe implementations
pub trait EngineReader: Send + Sync {
    /// Retrieves the Ethereum address of the account that minted the given
    /// block, which may be different from the header's coinbase if a consensus
    /// engine is based on signatures.
    fn author(&self, header: &SealedHeader) -> Result<Address, Box<dyn Error>>;

    /// Determines if transactions are free and don't pay baseFee after EIP-1559.
    fn is_service_transaction(&self, sender: Address) -> bool;

    // /// Returns the consensus type.
    // fn consensus_type(&self) -> ConsensusType;
}

pub trait Engine: EngineReader {
    /// Verifies if a header conforms to the consensus rules of a given engine.
    fn verify_header(&self, chain: &dyn ChainHeaderReader, header: &SealedHeader, seal: bool) -> Result<(), Box<dyn Error>>;

    /// Verifies a batch of headers concurrently and returns channels for async results.
    fn verify_headers(&self, chain: &dyn ChainHeaderReader, headers: Vec<Box<SealedHeader>>, seals: Vec<bool>) -> (Sender<()>, Receiver<Result<(), Box<dyn Error>>>);

    /// Verifies that the given block's uncles conform to the consensus rules of a given engine.
    fn verify_uncles(&self, chain: &dyn ChainReader, block: &SealedBlock) -> Result<(), Box<dyn Error>>;

    /// Prepares the consensus fields of a block header according to the rules of the engine.
    fn prepare(&self, chain: &dyn ChainHeaderReader, header: &SealedHeader) -> Result<(), Box<dyn Error>>;

    // /// Finalizes post-transaction state modifications but does not assemble the block.
    // fn finalize(&self, chain: &dyn ChainHeaderReader, header: &SealedHeader, state: &mut IntraBlockState, txs: Vec<Transaction>, uncles: Vec<Box<dyn IHeader>>) -> Result<(Vec<Reward>, HashMap<Address, U256>), Box<dyn Error>>;

    // /// Finalizes and assembles the final block.
    //fn finalize_and_assemble(&self, chain: &dyn ChainHeaderReader, header: &SealedHeader, state: &mut IntraBlockState, txs: Vec<Transaction>, uncles: Vec<Box<dyn IHeader>>, receipts: Vec<Receipt>) -> Result<(Box<dyn IBlock>, Vec<Reward>, HashMap<Address, U256>), Box<dyn Error>>;

    /// Generates a new sealing request for the given input block.
    fn seal(&self, chain: &dyn ChainHeaderReader, block: &SealedBlock, results: Sender<Box<SealedBlock>>, stop: Receiver<()>) -> Result<(), Box<dyn Error>>;

    /// Returns the hash of a block prior to it being sealed.
    fn seal_hash(&self, header: &SealedHeader) -> H256;

    /// Calculates the difficulty for a new block.
    fn calc_difficulty(&self, chain: &dyn ChainHeaderReader, time: u64, parent: &SealedHeader) -> U256;

    /// Returns the RPC APIs provided by this consensus engine.
    fn apis(&self, chain: &dyn ChainReader) -> Vec<API>;

    /// Terminates any background threads maintained by the consensus engine.
    fn close(&self) -> Result<(), Box<dyn Error>>;
}