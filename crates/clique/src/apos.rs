
use alloy_primitives::{U256, hex, U32, Bloom, BlockNumber, keccak256, B64, B256, Address};

use std::fmt;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use std::error::Error;
use std::hash::Hash;
use std::time::Duration;
use std::time::SystemTime;

use alloy_genesis::ChainConfig;
use std::time:: UNIX_EPOCH;
use std::sync::mpsc::{Sender, Receiver};
use blst::min_sig::Signature;
use blst::min_sig::PublicKey as OtherPublicKey;

use std::io::Cursor;
use std::io::{self, Write};


use reth_primitives::{Block, SealedBlock, SealedHeader};
use tracing::{info, debug, error};
use rast_primitives::{APosConfig, Snapshot};

use reth_primitives_traits::Header;
use reth_primitives::public_key_to_address;
use reth_provider::{BlockReader, ChainSpecProvider, EvmEnvProvider, StateProviderFactory, HeaderProvider};

use secp256k1::{ecdsa, Secp256k1};
use secp256k1::ecdsa::{PublicKey, Message, RecoverableSignature, RecoveryId, SECP256K1};
use secp256k1::Error as SecpError;
use sha2::digest::consts::U2;
use reth_primitives::bytes::Bytes;

use alloy_rlp::{length_of_length, Decodable, Encodable, MaxEncodedLenAssoc};
use bytes::BufMut;
use rand::prelude::SliceRandom;
use rlp::RlpStream;
use reth_chainspec::ChainSpec;

use crate::traits::Engine;

// 配置常量
const CHECKPOINT_INTERVAL: u64 = 2048; // Number of blocks after which to save the vote snapshot to the database
const INMEMORY_SNAPSHOTS: u32 = 128; // Number of recent vote snapshots to keep in memory
const INMEMORY_SIGNATURES: u32 = 4096; // Number of recent block signatures to keep in memory

const WIGGLE_TIME: Duration = Duration::from_millis(500); // Random delay (per signer) to allow concurrent signers
const MERGE_SIGN_MIN_TIME: u64 = 4; // min time for merge sign


// APos proof-of-authority protocol constants
pub const EPOCH_LENGTH: u64 = 30000; // Default number of blocks after which to checkpoint and reset the pending votes

pub const EXTRA_VANITY: usize = 32; // Fixed number of extra-data prefix bytes reserved for signer vanity
///  indicates the byte length required to carry a signature with recovery id.
///  Fixed number of extra-data suffix bytes reserved for signer seal
pub const SIGNATURE_LENGTH: usize = 64 + 1;

pub const NONCE_AUTH_VOTE: [u8; 8] = hex!("ffffffffffffffff"); // Magic nonce number to vote on adding a new signer
pub const NONCE_DROP_VOTE: [u8; 8] = hex!("0000000000000000"); // Magic nonce number to vote on removing a signer
// Difficulty constants
pub const diff_in_turn: U256 = U256::from(2);  // Block difficulty for in-turn signatures
pub const diff_no_turn: U256 = U256::from(1);  // Block difficulty for out-of-turn signatures

pub const FULL_IMMUTABILITY_THRESHOLD: usize= 90000;

pub type BlockNonce = [u8; 8];



#[derive(Debug, Clone)]
pub enum AposError {
    UnknownBlock,
    InvalidCheckpointBeneficiary,
    InvalidVote,
    InvalidCheckpointVote,
    MissingVanity,
    MissingSignature,
    ExtraSigners,
    InvalidCheckpointSigners,
    MismatchingCheckpointSigners,
    InvalidMixDigest,
    InvalidUncleHash,
    InvalidDifficulty,
    WrongDifficulty,
    InvalidTimestamp,
    InvalidVotingChain,
    UnauthorizedSigner,
    RecentlySigned,
    UnTransion,
}

impl std::fmt::Display for AposError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AposError::UnknownBlock => "unknown block",
                AposError::InvalidCheckpointBeneficiary => "beneficiary in checkpoint block non-zero",
                AposError::InvalidVote => "vote nonce not 0x00..0 or 0xff..f",
                AposError::InvalidCheckpointVote => "vote nonce in checkpoint block non-zero",
                AposError::MissingVanity => "extra-data 32 byte vanity prefix missing",
                AposError::MissingSignature => "extra-data 65 byte signature suffix missing",
                AposError::ExtraSigners => "non-checkpoint block contains extra signer list",
                AposError::InvalidCheckpointSigners => "invalid signer list on checkpoint block",
                AposError::MismatchingCheckpointSigners => "mismatching signer list on checkpoint block",
                AposError::InvalidMixDigest => "non-zero mix digest",
                AposError::InvalidUncleHash => "non-empty uncle hash",
                AposError::InvalidDifficulty => "invalid difficulty",
                AposError::WrongDifficulty => "wrong difficulty",
                AposError::InvalidTimestamp => "invalid timestamp",
                AposError::InvalidVotingChain => "invalid voting chain",
                AposError::UnauthorizedSigner => "unauthorized signer",
                AposError::RecentlySigned => "recently signed",
                AposError::UnTransion => "sealing paused while waiting for transactions",
            }
        )
    }
}

impl Error for AposError {}



pub type SignerFn = fn(signer: String, mime_type: &str, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;


#[derive(Debug)]
pub enum RecoveryError {
    MissingSignature,
    InvalidMessage,
    InvalidRecoveryId,
    InvalidSignatureFormat,
    FailedToRecoverPublicKey,
    EcdsaError(SecpError),

}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryError::MissingSignature => write!(f, "Missing signature"),
            RecoveryError::InvalidMessage => write!(f, "Invalid message"),
            RecoveryError::InvalidRecoveryId => write!(f, "Invalid recovery ID"),
            RecoveryError::InvalidSignatureFormat => write!(f, "Invalid signature format"),
            RecoveryError::FailedToRecoverPublicKey => write!(f, "Failed to recover public key"),
            RecoveryError::EcdsaError(e) => write!(f, "ECDSA error: {}", e),
        }
    }
}

impl From<SecpError> for RecoveryError {
    fn from(err: SecpError) -> RecoveryError {
        RecoveryError::EcdsaError(err)
    }
}

impl std::error::Error for RecoveryError {}


// recover_address extracts the Ethereum account address from a signed header.
pub fn recover_address(header: &Header) -> Result<Address, Box<dyn Error>> {
    // If the signature's already cached, return that
    // let hash = header.hash_slow();
    // sigcache: &mut schnellru::LruMap<B256, Address>
    // if let Some(address) = sigcache.get(&hash) {
    //     return Ok(*address);
    // }

    // Retrieve the signature from the header extra-data
    if header.extra_data.len() < SIGNATURE_LENGTH {
        return Err(Box::new(RecoveryError::MissingSignature));
    }
    let signature = &header.extra_data[header.extra_data.len() - SIGNATURE_LENGTH..];

    // Recover the public key and the Ethereum address
    let message = Message::from(seal_hash(header));

    let signature = RecoverableSignature::from_compact(
        &signature[..64],
        RecoveryId::from_i32(signature[64] as i32)?,
    )?;


    Ok(public_key_to_address(SECP256K1.recover_ecdsa(&message, &signature)?))
}


// APos is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
pub struct APos<T, Provider>
where
    Provider: HeaderProvider + StateProviderFactory + BlockReader + EvmEnvProvider + Clone + Unpin + 'static,
{

    config: Arc<APosConfig>,          // Consensus engine configuration parameters
    /// Chain spec
    chain_spec: Arc<ChainSpec>,

    recents: schnellru::LruMap<u64, Snapshot<T>>,    // Snapshots for recent block to speed up reorgs
    signatures: schnellru::LruMap<u64, Vec<u8>>,    // Signatures of recent blocks to speed up mining

    proposals: Arc<RwLock<HashMap<Address, bool>>>,   // Current list of proposals we are pushing

    signer: Address, // Ethereum address of the signing key
    sign_fn: SignerFn,              // Signer function to authorize hashes with
    lock: Arc<RwLock<()>>,               // Protects the signer and proposals fields

    //
    //  Provider,
    provider: Provider,
}


// New creates a APos proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
impl<T, Provider> APos<T, Provider>
where
    Provider: HeaderProvider + StateProviderFactory + BlockReader + EvmEnvProvider + Clone + Unpin + 'static,
{
    pub fn new(
        	// Set any missing consensus parameters to their defaults
        config: APosConfig,
        chain_config: ChainConfig,
    ) -> Arc<dyn Engine> {
        
        let mut conf = config.clone();
        if conf.epoch == 0 {
            conf.epoch = EPOCH_LENGTH;
        }

        // GenesisAlloc the snapshot caches and create the engine
        let recents =schnellru::LruMap::new(schnellru::ByLength::new(INMEMORY_SNAPSHOTS));
        let signatures = schnellru::LruMap::new(schnellru::ByLength::new(INMEMORY_SIGNATURES));

        
        Arc::new(APos {
            config: Arc::new(conf),
            chain_spec: chain_config,
            recents,
            signatures,
            proposals: Arc::new(RwLock::new(HashMap::new())),
            signer: todo!(),
            sign_fn: todo!(),
        })
    }


    /// snapshot retrieves the authorization snapshot at a given point in time.
    pub async fn snapshot(
        &mut self,
        mut number: u64,
        mut hash: B256,
        mut parents: Option(Vec<Header>),
    ) -> Result<Snapshot<T>, Box<dyn Error>> {
        let mut headers: Vec<Header> = Vec::new();
        let mut snap: Snapshot<T>;

        while snap.is_none() {
            //Attempt to retrieve a snapshot from memory
            if let Some(cached_snap) = self.recents.get(&hash) {
                snap = cached_snap.clone();
                break;
            }

           //Attempt to obtain a snapshot from the disk
            if number % CHECKPOINT_INTERVAL == 0 {
                //Load snapshot using database transaction
                if let Ok(s) = load_snapshot(&self.config, &self.signatures, &hash) {
                    snap = s;
                    break;
                } else {

                }
            }

            // If we're at the genesis, snapshot the initial state. Alternatively if we're
            // at a checkpoint block without a parent (light client CHT), or we have piled
            // up more headers than allowed to be reorged (chain reinit from a freezer),
            // consider the checkpoint trusted and snapshot it.
            if number == 0 || (number % self.config.epoch == 0 && (headers.len() > FULL_IMMUTABILITY_THRESHOLD || self.provider.header_by_number(number -1).unwrap().is_none())) {
                if let Ok(Some(checkpoint)) = self.provider.header_by_number(number) {
                    let hash = checkpoint.hash_slow();
            
                    //Calculate the list of signatories
                    let signers_count = (checkpoint.extra_data.len() - EXTRA_VANITY - SIGNATURE_LENGTH) /  Address::len_bytes();

                    let mut signers = Vec::with_capacity(signers_count);
            
                    for i in 0..signers_count {
                        let start = EXTRA_VANITY + i * Address::len_bytes();
                        let end = start + Address::len_bytes();
                        signers.push(Address::from_slice(&checkpoint.extra_data[start..end]));
                    }
            
                   
                    let new_snapshot = Snapshot::new_snapshot(self.config.clone(),  number, hash, signers, F);

                    // new_snapshot.store();
                    info!(
                        "Stored checkpoint snapshot to disk, number: {}, hash: {}",
                        number,
                        hash
                    );
                    break;
                }
            }

                    

            // No snapshot for this header, gather the header and move backward
            let header = if parents.is_some() > 0 {
                // If we have explicit parents, pick from there (enforced)
                let header = parents.pop().unwrap();
                if header.hash_slow() != hash || header.number64() != number {
                    return Err(AposError::UnknownBlock);
                }
                header
            } else {
                //Without a clear parent node (or no more), retrieve from the database
                let header = self.provider.header_by_hash_or_number(hash.into())?;
                Some(header)
            };

            headers.push(header);
            number -= 1;
            hash = header.parent_hash(); 
        }

        //Find the previous snapshot and apply any pending headers to it
        let half_len = headers.len() / 2;
        for i in 0..half_len {
            headers.swap(i, headers.len() - 1 - i);
        }

        let snap = snap.apply(&headers)?;
        self.recents.add(snap.hash, &snap);

        ///If a new checkpoint snapshot is generated, save it to disk
        if snap.number % CHECKPOINT_INTERVAL == 0 && !headers.is_empty() {
            save_snapshot(&snap)?;
            debug!(
                "Stored voting snapshot to disk, number: {}, hash: {}",
                snap.number,
                snap.hash
            );
        }

        Ok(snap)
    }

    /// verifySeal checks whether the signature contained in the header satisfies the
    /// consensus protocol requirements. The method accepts an optional list of parent
    /// headers that aren't yet part of the local blockchain to generate the snapshots
    /// from.
    pub fn verify_seal(
        self,
        snap: &Snapshot<T>,
        header: Header,
        parents: Header,
    ) -> Result<(), Box<dyn std::error::Error>> {

        // Verifying the genesis block is not supported
        if header.number == 0 {
            return Err(AposError::UnknownBlock.into());
        }

        //Analyze the signer and check if they are in the signer list
        let signer = recover_address(&header)?;
        if !snap.signers.contains(&signer) {
            info!("err signer: {}", signer);
            return Err(AposError::UnauthorizedSigner.into());
        }

       //Check the list of recent signatories
        for (seen, recent) in &snap.recents {
            if *recent == signer {
                //If the signer is in the recent list, ensure that the current block can be removed
                let limit = (snap.signers.len() as u64 / 2) + 1;
                if *seen > header.number - limit {
                    return Err(AposError::RecentlySigned.into());
                }
            }
        }

       ///Ensure that the difficulty corresponds to the signer's round
        let in_turn = snap.inturn(header.number, &signer);
        if in_turn && header.difficulty != *diff_in_turn {
            return Err(AposError::WrongDifficulty.into());
        }
        if !in_turn && header.difficulty != *diff_in_turn {
            return Err(AposError::WrongDifficulty.into());
        }

        Ok(())
    }

    /// Prepare implements consensus.Engine, preparing all the consensus fields of the
    /// header for running the transactions on top.
    pub async fn prepare(
        &mut self,
        header: &mut Header,
    ) -> Result<(), Box<dyn std::error::Error>> {
      
       //If the block is not a checkpoint, vote randomly
        header.beneficiary = Address::default();
        header.nonce = 0;


        //Assemble voting snapshots to check which votes are meaningful
        let snap = self.snapshot(header.number - 1, header.parent_hash, None).await.unwrap();

        if header.number %self.config.epoch != 0 {
            //Collect all proposals to be voted on
            let mut addresses: Vec<Address> = self.proposals.iter()
                .filter(|(address, &authorize)| self.valid_vote(address, authorize))
                .map(|(address, _)| *address)
                .collect();
            
            //If there are proposals to be voted on, proceed with the vote
            if !addresses.is_empty() {
                // let mut rng = ;
                header.beneficiary = addresses.choose(&mut rand::thread_rng());

                if let Some(&authorize) = self.proposals.get(header.beneficiary) {
                    if authorize {
                        header.nonce = NONCE_AUTH_VOTE.clone();
                    } else {
                        header.nonce = NONCE_DROP_VOTE.clone();
                    }
                }
            }
        }

        //Copy the signer to prevent data competition
        let signer = self.signer.clone();

        //Set the correct difficulty level
        header.difficulty = calc_difficulty(&snap, &signer);

        //Ensure that the additional data has all its components
        if header.extra_data.len() < EXTRA_VANITY {
            header.extra_data.extend(vec![0x00; EXTRA_VANITY - header.extra_data.len()]);
        }
        header.extra_data.truncate(EXTRA_VANITY);

        if header.number % self.config.epoch == 0 {
            for signer in snap.signers {
                header.extra_data.extend_from_slice(&signer.0);
            }
        }
        header.extra_data.extend(vec![0x00; SIGNATURE_LENGTH]);


        header.mix_hash = Default::default();

      
        // Ensure the timestamp has the correct delay
        let parent = self.provider.header(header.parent_hash)?.ok_or(Err("unknown ancestor".into()))?;

        let parent_time = parent.timestamp;
        header.timestamp = parent_time + self.config.period;

        if header.timestamp < (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + MERGE_SIGN_MIN_TIME) {
            header.timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + MERGE_SIGN_MIN_TIME;
        }

        Ok(())
    }


    // fn finalize(
    //     &self,
    //     chain: &dyn ChainHeaderReader,
    //     header: &mut SealedHeader,
    //     state: &mut IntraBlockState,
    //     txs: Vec<Transaction>,
    //     uncles: Vec<Box<dyn IHeader>>,
    // ) -> Result<(Vec<Reward>, HashMap<Address, U256>), Box<dyn std::error::Error>> {
    //     // No block rewards in PoA, so the state remains as is and uncles are dropped
    //     // chain.config().is_eip158(header.number())
    
    //     let (rewards, unpay_map, err) = do_reward(self.chain_config.clone(), state, header, chain)?;
    //     if err.is_some() {
    //         return Err(err.unwrap().into());
    //     }
    
    //     let raw_header = header;
    //     raw_header.root = state.intermediate_root();
    //     // Todo can not verify author
    //     raw_header.mix_digest = state.before_state_root();
    //     // Todo
    //     // raw_header.uncle_hash = types::calc_uncle_hash(None);
    
    //     Ok((rewards, unpay_map))
    // }
    

    // // FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
    // // nor block rewards given, and returns the final block.
    // fn finalize_and_assemble(
    //     &self,
    //     chain: &dyn ChainHeaderReader,
    //     header: &mut SealedHeader,
    //     state: &mut IntraBlockState,
    //     txs: Vec<Transaction>,
    //     uncles: Vec<Box<dyn IHeader>>,
    //     receipts: Vec<Receipt>,
    // ) -> Result<(Box<dyn IBlock>, Vec<Reward>, HashMap<Address, U256>), Box<dyn std::error::Error>> {
    //     // Finalize block
    //     let (rewards, unpay, err) = self.finalize(chain, header, state, txs.clone(), uncles.clone())?;
    //     if err.is_some() {
    //         return Err(err.unwrap().into());
    //     }

    //     // Assemble and return the final block for sealing
    //     let block = Block::new_block_from_receipt(header, txs, uncles, receipts, rewards.clone());
    //     Ok((Box::new(block), rewards, unpay))
    // }

    // // Authorize injects a private key into the consensus engine to mint new blocks
    // // with.
    // fn authorize(&mut self, signer: Address, sign_fn: SignerFn) {
    //     let _lock = self.lock.lock().unwrap(); // Acquire the lock, automatically releases at the end of the scope

    //     self.signer = signer;
    //     self.sign_fn = Some(sign_fn);
    // }

    async fn seal(
        &mut self,
        block: &Block,
    ) -> Result<(), Box<dyn Error>> {
        

        // Sealing the genesis block is not supported
        if block.number == 0 {
            return Err(AposError::UnknownBlock.into());
        }

        // For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
        if self.config.period == 0 && block.body.is_empty() {
            return Err(AposError::UnTransion);
        }


        // Bail out if we're unauthorized to sign a block
        let snap = self.snapshot(block.number - 1, block.parent_hash.clone(), None).await?;
        if !snap.signers.contains(&self.signer) {
            error!(target: "consensus::engine", "err signer: {}", self.signer);
            return Err(AposError::UnauthorizedSigner)
        }

        // If we're amongst the recent signers, wait for the next block
        for (seen, recent) in snap.recents {
            if recent == self.signer {
                let limit = (snap.signers.len() as u64 / 2) + 1;
                if block.number < limit || seen > block.number - limit {
                    error!(target: "consensus::engine", "Signed recently, must wait for others: limit: {}, seen: {}, number: {}, signer: {}", limit, seen, block.number, self.signer);
                    return Err(AposError::UnauthorizedSigner);
                }
            }
        }

        // Sweet, the protocol permits us to sign the block, wait for our time
        let delay = UNIX_EPOCH
            .checked_add(Duration::from_secs(block.timestamp as u64))
            .unwrap()
            .duration_since(SystemTime::now())
            .unwrap();

        if block.difficulty == diff_no_turn {
            let wiggle = Duration::from_millis((snap.signers.len() as u64 / 2 + 1) * WIGGLE_TIME);
            let delay_with_wiggle = delay + Duration::from_millis(rand::random::<u64>() % wiggle.as_millis() as u64);

            println!(
                "wiggle {:?}, time {:?}, number {}",
                wiggle, delay_with_wiggle, block.number
            );
        }

        // Beijing hard fork logic (if applicable)
        if self.chain_spec.is_beijing_active_at_block(block.number) {

        }

        // Sign all the things!
        let sighash = self.sign_fn(self.signer, seal_hash(&block.header))?;

        block.extra_data[block.extra_data.len() - SIGNATURE_LENGTH..].copy_from_slice(&sighash);

        // Wait until sealing is terminated or delay timeout
        println!("Waiting for slot to sign and propagate, delay: {:?}", delay);
        //

        Ok(())
    }

    // CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX
    pub async fn calc_difficulty(
        &mut self,
        parent: Header,          // assuming IHeader is a trait
    ) -> U256 {
        let snap = self.snapshot(
            parent.number,
            parent.hash_slow(),
            None,
        ).await?;

        calc_difficulty(&snap, self.signer)
    }


    // SealHash returns the hash of a block prior to it being sealed.
    pub fn seal_hash(&self, header: &SealedHeader) -> B256 {
        seal_hash(header)
    }

     // Close implements consensus.Engine. It's a noop for Apoa as there are no background threads.
    pub fn close(&self) -> Result<(), ()> {
        Ok(())
    }

    // APIs implements consensus.Engine, returning the user facing RPC API to allow
    // controlling the signer voting.
    pub fn apis(&self, chain: Arc<dyn ChainReader>) -> Vec<OtherAPI> {
        vec![OtherAPI {
            namespace: "apos".to_string(),
            service: Arc::new(API {
                chain,
                apos: Arc::new(self.clone()),
            }),
            authenticated: true,
        }]
    }
}


 

fn calc_difficulty<T>(snap: &Snapshot<T>, signer: Address) -> U256 {
    if snap.inturn(snap.number + 1, &signer) {
        DIFF_IN_TURN.clone()
    } else {
        DIFF_NO_TURN.clone()
    }
}

// SealHash returns the hash of a block prior to it being sealed.
fn seal_hash(header: &Header) -> B256 {

    struct LocalHeader {
        parent_hash: B256,
        ommers_hash: B256,
        beneficiary: Address,
        state_root: B256,
        transactions_root: B256,
        receipts_root: B256,
        logs_bloom: Bloom,
        difficulty: U256,
        number: BlockNumber,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        extra_data: Bytes,
        mix_hash: B256,
        nonce: u64,
        base_fee_per_gas: Option<u64>,
    }

    impl LocalHeader {
        fn header_payload_length(&self) -> usize {
            let mut length = 0;
            length += self.parent_hash.length(); // Hash of the previous block.
            length += self.ommers_hash.length(); // Hash of uncle blocks.
            length += self.beneficiary.length(); // Address that receives rewards.
            length += self.state_root.length(); // Root hash of the state object.
            length += self.transactions_root.length(); // Root hash of transactions in the block.
            length += self.receipts_root.length(); // Hash of transaction receipts.
            length += self.logs_bloom.length(); // Data structure containing event logs.
            length += self.difficulty.length(); // Difficulty value of the block.
            length += U256::from(self.number).length(); // Block number.
            length += U256::from(self.gas_limit).length(); // Maximum gas allowed.
            length += U256::from(self.gas_used).length(); // Actual gas used.
            length += self.timestamp.length(); // Block timestamp.
            length += self.extra_data.length(); // Additional arbitrary data.
            length += self.mix_hash.length(); // Hash used for mining.
            length += B64::new(self.nonce.to_be_bytes()).length(); // Nonce for mining.

            if let Some(base_fee) = self.base_fee_per_gas {
                // Adding base fee length if it exists.
                length += U256::from(base_fee).length();
            }
            length
        }
    }


    impl Encodable for LocalHeader {
        fn encode(&self, out: &mut dyn BufMut) {
            // Create a header indicating the encoded content is a list with the payload length computed
            // from the header's payload calculation function.
            let list_header =
                alloy_rlp::Header { list: true, payload_length: self.header_payload_length() };
            list_header.encode(out);

            // Encode each header field sequentially
            self.parent_hash.encode(out); // Encode parent hash.
            self.ommers_hash.encode(out); // Encode ommer's hash.
            self.beneficiary.encode(out); // Encode beneficiary.
            self.state_root.encode(out); // Encode state root.
            self.transactions_root.encode(out); // Encode transactions root.
            self.receipts_root.encode(out); // Encode receipts root.
            self.logs_bloom.encode(out); // Encode logs bloom.
            self.difficulty.encode(out); // Encode difficulty.
            U256::from(self.number).encode(out); // Encode block number.
            U256::from(self.gas_limit).encode(out); // Encode gas limit.
            U256::from(self.gas_used).encode(out); // Encode gas used.
            self.timestamp.encode(out); // Encode timestamp.
            self.extra_data.encode(out); // Encode extra data.
            self.mix_hash.encode(out); // Encode mix hash.
            B64::new(self.nonce.to_be_bytes()).encode(out); // Encode nonce.

            // Encode base fee.
            if let Some(ref base_fee) = self.base_fee_per_gas {
                U256::from(*base_fee).encode(out);
            }
        }

        fn length(&self) -> usize {
            let mut length = 0;
            length += self.header_payload_length();
            length += length_of_length(length);
            length
        }
    }

    // 初始化局部结构体
    let mut sigHeader = LocalHeader {
        parent_hash: header.parent_hash,
        ommers_hash: header.ommers_hash,
        beneficiary: header.beneficiary,
        state_root: header.state_root,
        transactions_root: header.transactions_root,
        receipts_root: header.receipts_root,
        logs_bloom: header.logs_bloom,
        difficulty: header.difficulty,
        number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: Bytes::new(),
        mix_hash: header.mix_hash,
        nonce: header.nonce,
        base_fee_per_gas: header.base_fee_per_gas,
    };

    // Handle the extra field, excluding the last CRYPTO_SIGNATURE_LENGTH bytes
    if header.extra_data.len() > SIGNATURE_LENGTH {
        sigHeader.extra_data = Bytes::from(header.extra_data[..header.extra_data.len() - SIGNATURE_LENGTH]);
    }

    keccak256(alloy_rlp::encode(&sigHeader))
}
