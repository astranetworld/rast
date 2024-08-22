
use hex_literal::hex;
use ethereum_types::U256;
use k256::Secp256k1;

use reth_primitives::{SealedBlock, SealedHeader};
// use secp256k1::ffi::NonceFn;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use std::error::Error;
use std::time::Duration;
use lru_cache::LruCache;
use ethereum_types::H256;
use keccak_hash::keccak256;
use secp256k1::{PublicKey, Message};
use std::time::SystemTime;

use alloy_genesis::ChainConfig;
use std::time:: UNIX_EPOCH;
use std::sync::mpsc::{Sender, Receiver};
use blst::min_sig::Signature;
use blst::min_sig::PublicKey as OtherPublicKey;
use sha3::{Digest, Keccak256};
use std::io::Cursor;
use std::io::{self, Write};
use rlp::RlpStream;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
// use tiny_keccak::{Keccak, Hasher};


use crate::snapshot::{APosConfig, Snapshot,Hash,ADDRESS_LENGTH};
use crate::snapshot::Address;
use crate::ast_consensus::{DIFF_IN_TURN,DIFF_NO_TURN};
use crate::traits::{Api, ChainHeaderReader, ChainReader, Engine};
use crate::api::API;
use crate::traits::API as OtherAPI;



// 配置常量
const CHECKPOINT_INTERVAL: u64 = 2048; // Number of blocks after which to save the vote snapshot to the database
const INMEMORY_SNAPSHOTS: usize = 128; // Number of recent vote snapshots to keep in memory
const INMEMORY_SIGNATURES: usize = 4096; // Number of recent block signatures to keep in memory

const WIGGLE_TIME: Duration = Duration::from_millis(500); // Random delay (per signer) to allow concurrent signers
const MERGE_SIGN_MIN_TIME: u64 = 4; // min time for merge sign


// APos proof-of-authority protocol constants
pub const EPOCH_LENGTH: u64 = 30000; // Default number of blocks after which to checkpoint and reset the pending votes

pub const EXTRA_VANITY: usize = 32; // Fixed number of extra-data prefix bytes reserved for signer vanity
pub const EXTRA_SEAL: usize = 64 + 1; // Fixed number of extra-data suffix bytes reserved for signer seal

pub const NONCE_AUTH_VOTE: [u8; 8] = hex!("ffffffffffffffff"); // Magic nonce number to vote on adding a new signer
pub const NONCE_DROP_VOTE: [u8; 8] = hex!("0000000000000000"); // Magic nonce number to vote on removing a signer
// Difficulty constants
pub const diff_in_turn: U256 = U256::from(2);  // Block difficulty for in-turn signatures
pub const diff_no_turn: U256 = U256::from(1);  // Block difficulty for out-of-turn signatures

pub const FULL_IMMUTABILITY_THRESHOLD: usize= 90000;

pub type BlockNonce = [u8; 8];



#[derive(Debug, Clone)]
pub struct SnapshotError {
    msg: String,
}

impl SnapshotError {
    fn new(msg: &str) -> SnapshotError {
        SnapshotError {
            msg: msg.to_string(),
        }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Error for SnapshotError {}


pub const ERR_UNKNOWN_BLOCK: &str = "unknown block";
pub const ERR_INVALID_CHECKPOINT_BENEFICIARY: &str = "beneficiary in checkpoint block non-zero";
pub const ERR_INVALID_VOTE: &str = "vote nonce not 0x00..0 or 0xff..f";
pub const ERR_INVALID_CHECKPOINT_VOTE: &str = "vote nonce in checkpoint block non-zero";
pub const ERR_MISSING_VANITY: &str = "extra-data 32 byte vanity prefix missing";
pub const ERR_MISSING_SIGNATURE: &str = "extra-data 65 byte signature suffix missing";
pub const ERR_EXTRA_SIGNERS: &str = "non-checkpoint block contains extra signer list";
pub const ERR_INVALID_CHECKPOINT_SIGNERS: &str = "invalid signer list on checkpoint block";
pub const ERR_MISMATCHING_CHECKPOINT_SIGNERS: &str = "mismatching signer list on checkpoint block";
pub const ERR_INVALID_MIX_DIGEST: &str = "non-zero mix digest";
pub const ERR_INVALID_UNCLE_HASH: &str = "non empty uncle hash";
pub const ERR_INVALID_DIFFICULTY: &str = "invalid difficulty";
pub const ERR_WRONG_DIFFICULTY: &str = "wrong difficulty";
pub const ERR_INVALID_TIMESTAMP: &str = "invalid timestamp";
pub const ERR_INVALID_VOTING_CHAIN: &str = "invalid voting chain";
pub const ERR_UNAUTHORIZED_SIGNER: &str = "unauthorized signer";
pub const ERR_RECENTLY_SIGNED: &str = "recently signed";


pub type SignerFn = fn(signer: String, mime_type: &str, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;


// ecrecover extracts the Ethereum account address from a signed header.
pub fn ecrecover(header: &SealedHeader, sigcache: &mut LruCache<H256, Address>) -> Result<Address, &'static str> {
    // If the signature's already cached, return that
    let hash = header.hash();
    if let Some(address) = sigcache.get(&hash) {
        return Ok(*address);
    }

    // Retrieve the signature from the header extra-data
    if header.extra.len() < EXTRA_SEAL {
        return Err("Missing signature");
    }
    let signature = &header.extra_data[header.extra.len() - EXTRA_SEAL..];

    let secp = Secp256k1::new();
    // Recover the public key and the Ethereum address
    let message = Message::parse_slice(&seal_hash(header).0).map_err(|_| "Invalid message")?;
    let recovery_id = RecoveryId::parse(signature[64]).map_err(|_| "Invalid recovery ID")?;
    let recoverable_sig = RecoverableSignature::from_compact(&signature[0..64], recovery_id).map_err(|_| "Invalid signature format")?;
    // let pubkey = recover(&message, &signature[..64], &recovery_id).map_err(|_| "Failed to recover public key")?;
    let pubkey = secp.recover_ecdsa(&message, &recoverable_sig).map_err(|_| "Failed to recover public key")?;

    let pubkey_serialized = PublicKey::serialize_uncompressed(&pubkey);

    // Compute the Ethereum address
    let mut signer = [0u8; 20];
    signer.copy_from_slice(&keccak256(&mut pubkey_serialized[1..])[12..]);

    let address = Address::from(signer);

    // Cache the address
    sigcache.put(hash, address);

    Ok(address)
}


// APos is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
pub struct APos {
    config: Arc<APosConfig>,          // Consensus engine configuration parameters
    chain_config: Arc<ChainConfig>,    
    db: Arc<dyn KeyValueDB>,           // Database to store and retrieve snapshot checkpoints        

    recents: Arc<RwLock<LruCache<u64, Snapshot>>>,    // Snapshots for recent block to speed up reorgs
    signatures: Arc<RwLock<LruCache<u64, Vec<u8>>>>,    // Signatures of recent blocks to speed up mining

    proposals: Arc<RwLock<HashMap<Address, bool>>>,   // Current list of proposals we are pushing

    signer: Arc<RwLock<Address>>, // Ethereum address of the signing key
    sign_fn: SignerFn,              // Signer function to authorize hashes with
    lock: Arc<RwLock<()>>,               // Protects the signer and proposals fields

   	// The fields below are for testing only
    fake_diff: bool, 

    // bc: Arc<dyn Blockchain>, 
}


// New creates a APos proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
impl APos{
    pub fn new(
        	// Set any missing consensus parameters to their defaults
        config: APosConfig,
        db: Arc<dyn KeyValueDB>,
        chain_config: Arc<ChainConfig>,
    ) -> Arc<Engine> {
        
        let mut conf = config.clone();
        if conf.epoch == 0 {
            conf.epoch = EPOCH_LENGTH;
        }

        // GenesisAlloc the snapshot caches and create the engine
        let recents = Arc::new(RwLock::new(LruCache::new(INMEMORY_SNAPSHOTS)));
        let signatures = Arc::new(RwLock::new(LruCache::new(INMEMORY_SIGNATURES)));

        
        Arc::new(APos {
            config: Arc::new(conf),
            chain_config,
            db,
            recents,
            signatures,
            proposals: Arc::new(RwLock::new(HashMap::new())),
            signer: todo!(),
            sign_fn: todo!(),
            lock: todo!(),
            fake_diff: todo!(),
        })
    }



    pub async fn snapshot(
        &self,
        chain: Arc<dyn ChainHeaderReader>,
        mut number: u64,
        mut hash: Hash,
        mut parents: SealedHeader,
    ) -> Result<Arc<Snapshot>, Box<dyn Error>> {
        let mut headers: Vec<Box<SealedHeader>> = Vec::new();
        let mut snap: Option<Arc<Snapshot>> = None;

        while snap.is_none() {
            //Attempt to retrieve a snapshot from memory
            if let Some(cached_snap) = self.recents.read().unwrap().get(&hash) {
                snap = Some(cached_snap.clone());
                break;
            }

           //Attempt to obtain a snapshot from the disk
            if number % CHECKPOINT_INTERVAL == 0 {
                //Load snapshot using database transaction
                let load_result = self.db.read().unwrap().view(|tx| {
                    if let Ok(s) = Snapshot::load_snapshot(&self.config, &self.signatures, tx, &hash) {
                        snap = Some(s);
                        Ok(())
                    } else {
                        Err("Failed to load snapshot from disk".into())
                    }
                });

                if load_result.is_ok() {
                    break;
                }
            }

            // If we're at the genesis, snapshot the initial state. Alternatively if we're
            // at a checkpoint block without a parent (light client CHT), or we have piled
            // up more headers than allowed to be reorged (chain reinit from a freezer),
            // consider the checkpoint trusted and snapshot it.
            let h = chain.get_header_by_number(&(number - 1).into());
            if number == 0 || (number % self.config.epoch == 0 && (headers.len() > FULL_IMMUTABILITY_THRESHOLD || h.is_none())) {
                if let Some(checkpoint) = chain.get_header_by_number(number.into()) {
                    let raw_checkpoint = checkpoint.as_any().downcast_ref::<SealedHeader>().unwrap();
                    let hash = checkpoint.hash();
            
                    //Calculate the list of signatories
                    let extra_data = &raw_checkpoint.extra;
                    let signers_count = (extra_data.len() - EXTRA_VANITY - EXTRA_SEAL) / ADDRESS_LENGTH;
                    let mut signers = Vec::with_capacity(signers_count);
            
                    for i in 0..signers_count {
                        let start = EXTRA_VANITY + i * ADDRESS_LENGTH;
                        let end = start + ADDRESS_LENGTH;
                        let mut address = [0u8; ADDRESS_LENGTH];
                        address.copy_from_slice(&extra_data[start..end]);
                        signers.push(Address::from(address));
                    }
            
                   
                    let new_snapshot = Snapshot::new(self.config.clone(), self.signatures.clone(), number, hash, signers);
            
                    //Store snapshot to database
                    if let Err(err) = self.db.update(|tx| new_snapshot.store(tx)) {
                        return Err(err);
                    }
            
                    log::info!(
                        "Stored checkpoint snapshot to disk, number: {}, hash: {}",
                        number,
                        hash
                    );
                    break;
                }
            }

                    
            let mut header: Box<SealedHeader>;

            //If there is a clear parent node, select from it (enforce)
            if !parents.is_empty() {
                //Select from parent node (mandatory execution)
                header = parents.pop().expect("Parents list is not empty");
                if header.hash() != hash || header.number64() != number {
                    return Err(Error::UnknownBlock);
                }
            } else {
               //Without a clear parent node (or no more), retrieve from the database
                header = chain.get_header(hash, &number.into()).ok_or(Error::UnknownBlock)?;
            }

            headers.push(header);
            number -= 1;
            hash = header.parent_hash(); 
        }

        //Find the previous snapshot and apply any pending headers to it
        let half_len = headers.len() / 2;
        for i in 0..half_len {
            headers.swap(i, headers.len() - 1 - i);
        }

        let (snap, err) = snap.apply(&headers);
        if let Err(e) = err {
            return Err(e);
        }

        self.recents.add(snap.hash(), snap);

//If a new checkpoint snapshot is generated, save it to disk
        if snap.number % CHECKPOINT_INTERVAL == 0 && !headers.is_empty() {
            if let Err(err) = self.db.update(|tx| {
                if let Err(e) = snap.store(tx) {
                    return Err(e);
                }
                Ok(())
            }).await {
                return Err(err);
            }

            log::debug!(
                "Stored voting snapshot to disk, number: {}, hash: {}",
                snap.number,
                snap.hash
            );
        }

        Ok(snap)
    }

    pub fn verify_seal(
        self,
        snap: &Snapshot,
        h: SealedHeader,
        parents: SealedHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 检查 genesis block
        let header = h.as_any().downcast_ref::<SealedHeader>().ok_or(ERR_UNKNOWN_BLOCK)?;
        let number = header.number.as_u64();
        if number == 0 {
            return Err(Box::new(ERR_UNKNOWN_BLOCK));
        }

        //Analyze the signer and check if they are in the signer list
        let signer = ecrecover(header, &self.signatures)?;
        if !snap.signers.contains_key(&signer) {
            log::info!("err signer: {}", signer);
            return Err(Box::new(ERR_UNAUTHORIZED_SIGNER));
        }

       //Check the list of recent signatories
        for (seen, recent) in &snap.recents {
            if *recent == signer {
                //If the signer is in the recent list, ensure that the current block can be removed
                let limit = (snap.signers.len() as u64 / 2) + 1;
                if *seen > number - limit {
                    return Err(Box::new(ERR_RECENTLY_SIGNED));
                }
            }
        }

       //Ensure that the difficulty corresponds to the signer's round
        if !self.fake_diff {
            let in_turn = snap.inturn(number, &signer);
            if in_turn && header.difficulty != *diff_in_turn {
                return Err(Box::new(ERR_WRONG_DIFFICULTY));
            }
            if !in_turn && header.difficulty != *diff_in_turn {
                return Err(Box::new(ERR_WRONG_DIFFICULTY));
            }
        }

        Ok(())
    }


    pub fn prepare(
        &self,
        chain: &dyn ChainHeaderReader,
        header: &mut SealedHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // let raw_header = header.as_any_mut().downcast_mut::<SealedHeader>().ok_or("Invalid header type")?;

        let raw_header = header;

      
       //If the block is not a checkpoint, vote randomly
        raw_header.coinbase = Address::default();
        raw_header.nonce = BlockNonce::default();

        let number = raw_header.number.as_u64();

        //Assemble voting snapshots to check which votes are meaningful
        let snap = self.snapshot(chain, number - 1, raw_header.parent_hash, &[])?;

        self.lock.read().unwrap();
        if number %self.config.epoch != 0 {
            //Collect all proposals to be voted on
            let mut addresses: Vec<Address> = self.proposals.iter()
                .filter(|(address, &authorize)| self.valid_vote(address, authorize))
                .map(|(address, _)| *address)
                .collect();
            
            //If there are proposals to be voted on, proceed with the vote
            if !addresses.is_empty() {
                let random_index = rand::thread_rng().gen_range(0..addresses.len());
                raw_header.coinbase = addresses[random_index];

                if let Some(&authorize) = self.proposals.get(&raw_header.coinbase) {
                    if authorize {
                        raw_header.nonce.copy_from_slice(&NONCE_AUTH_VOTE);
                    } else {
                        raw_header.nonce.copy_from_slice(&NONCE_DROP_VOTE);
                    }
                }
            }
        }

        //Copy the signer to prevent data competition
        let signer = self.signer.clone();
        self.lock.read().unwrap();

        //Set the correct difficulty level
        raw_header.difficulty = calc_difficulty(&snap, &signer);

        //Ensure that the additional data has all its components
        if raw_header.extra_data.len() < EXTRA_VANITY {
            raw_header.extra_data.extend(vec![0x00; EXTRA_VANITY - raw_header.extra.len()]);
        }
        raw_header.extra_data.truncate(EXTRA_VANITY);

        if number % self.config.epoch == 0 {
            for signer in snap.signers() {
                raw_header.extra.extend_from_slice(&signer.0);
            }
        }
        raw_header.extra.extend(vec![0x00; EXTRA_SEAL]);

        
        raw_header.mix_digest = Hash::default();

      
        // Ensure the timestamp has the correct delay
        let parent = chain.get_header(raw_header.parent_hash, raw_header.number - 1.into());
        if parent.is_none() {
            return Err("unknown ancestor".into());
        }

        let parent_time = parent.timestamp;
        raw_header.timestamp = parent_time + self.config.period;

        if raw_header.time < (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + MERGE_SIGN_MIN_TIME) {
            raw_header.time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + MERGE_SIGN_MIN_TIME;
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

    fn seal(
        &self,
        chain: Arc<dyn ChainHeaderReader>,
        block: Arc<SealedBlock>,
        results: Sender<Arc<SealedBlock>>,
        stop: Receiver<()>,
    ) -> Result<(), Box<dyn Error>> {
        

        // Sealing the genesis block is not supported
        let number = block.number.as_u64();
        if number == 0 {
            return Err(SnapshotError::new(ERR_UNKNOWN_BLOCK))
        }

        // For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
        if self.config.period == 0 && block.transactions().is_empty() {
            return Err(SnapshotError::new("sealing paused while waiting for transactions"));
        }

        // Don't hold the signer fields for the entire sealing procedure
        let (signer, sign_fn) = {
            let read_lock = self.lock.read().unwrap();
            (self.signer, self.sign_fn.clone())
        };

        // Bail out if we're unauthorized to sign a block
        let snap = self.snapshot(chain.clone(), number - 1, block.parent_hash.clone(), None)?;
        if !snap.signers.contains_key(&signer.unwrap()) {
            println!("err signer: {}", signer.unwrap());
            return Err(SnapshotError::new(ERR_UNAUTHORIZED_SIGNER));
        }

        // If we're amongst the recent signers, wait for the next block
        for (&seen, recent) in &self.recents {
            if recent == signer {
                let limit = (self.signers.len() as u64 / 2) + 1;
                if number < limit || seen > number - limit {
                    return Err(format!(
                        "Signed recently, must wait for others: limit: {}, seen: {}, number: {}, signer: {}",
                        limit, seen, number, signer
                    ));
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
                wiggle, delay_with_wiggle, block.number.as_u64()
            );
        }

        // Beijing hard fork logic (if applicable)
        if self.chain_config.is_beijing(block.number.as_u64()) {
            let member = self.count_depositor();
            let (agg_sign, verifiers, err) = Api::sign_merge(block.clone(), member);
            if err.is_some() {
                return Err(err.unwrap());
            }

            let ss: Vec<OtherPublicKey> = verifiers
                .iter()
                .map(|p| OtherPublicKey::from_bytes(&p.public_key))
                .collect::<Result<_, _>>()?;

            let sig = Signature::from_bytes(&agg_sign)?;
            if !sig.fast_aggregate_verify(true,&ss,&[], block.state_root) {
                return Err("Aggregate signature verification failed".into());
            }

            block.signature = agg_sign;
            block.body_mut().verifiers = verifiers;
        }

        // Sign all the things!
        let sighash = sign_fn.unwrap()(signer.unwrap(), apos_proto(&block))?;

        block.extra_data[block.extra_data.len() - EXTRA_SEAL..].copy_from_slice(&sighash);

        // Wait until sealing is terminated or delay timeout
        println!("Waiting for slot to sign and propagate, delay: {:?}", delay);
        let results_clone = results.clone();
        let block_clone = block.clone();
        std::thread::spawn(move || {
            if stop.recv_timeout(delay).is_err() {
                results_clone.send(block_clone.with_seal(block)).unwrap_or_else(|_| {
                    println!("Sealing result is not read by miner");
                });
            }
        });

        Ok(())
    }

    // CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX
    pub fn calc_difficulty(
        &self,
        chain: &dyn ChainHeaderReader, // assuming ChainHeaderReader is a trait
        time: u64,
        parent: SealedHeader,          // assuming IHeader is a trait
    ) -> U256 {
        let snap_result = self.snapshot(
            chain,
            parent.number,
            parent.hash(),
            None,
        );

        if let Err(_) = snap_result {
            return U256::zero();
        }

        let snap = snap_result.unwrap();
        let signer = {
            let signer_lock = self.signer.read().unwrap();
            signer_lock.clone() // Clone or copy if needed
        };

        calc_difficulty(&snap, &signer)
    }


    // SealHash returns the hash of a block prior to it being sealed.
    pub fn seal_hash(&self, header: &SealedHeader) -> H256 {
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


 

fn calc_difficulty(snap: &Snapshot, signer: Address) -> &U256 {
    if snap.inturn(snap.number + 1, &signer) {
        &DIFF_IN_TURN
    } else {
        &DIFF_NO_TURN
    }
}

// SealHash returns the hash of a block prior to it being sealed.
fn seal_hash(header: &SealedHeader) -> H256 {
    // Create a new Keccak256 hasher
    let mut hasher = Keccak256::new();

    // Encode the header into the hasher
    encode_sig_header(&mut hasher, header);

    // Create a buffer to hold the resulting hash
    let mut hash = H256::zero();
    
    // Write the hash result into the buffer
    hasher.finalize_into(hash.as_mut());

    hash
}


fn apos_proto(header: &SealedHeader) -> Vec<u8> {
    let mut buffer = Cursor::new(Vec::new());
    encode_sig_header(&mut buffer, header);
    buffer.into_inner()
}


fn encode_sig_header<W: Write>(writer: &mut W, header: &SealedHeader) -> io::Result<()> {
    let header = header.to_header();

    let mut rlp_stream = RlpStream::new();

    rlp_stream.append(&header.parent_hash);
    rlp_stream.append(&header.uncle_hash);
    rlp_stream.append(&header.coinbase);
    rlp_stream.append(&header.root);
    rlp_stream.append(&header.tx_hash);
    rlp_stream.append(&header.receipt_hash);
    rlp_stream.append(&header.bloom);
    rlp_stream.append(&header.difficulty);
    rlp_stream.append(&header.number);
    rlp_stream.append(&header.gas_limit);
    rlp_stream.append(&header.gas_used);
    rlp_stream.append(&header.time);

    // Handle the extra field, excluding the last CRYPTO_SIGNATURE_LENGTH bytes
    if header.extra.len() > EXTRA_SEAL {
        rlp_stream.append(&header.extra[..header.extra.len() - EXTRA_SEAL]);
    } else {
        rlp_stream.append(&[] as &[u8]); // Append an empty slice if extra is too short
    }

    rlp_stream.append(&header.mix_digest);
    rlp_stream.append(&header.nonce);

    if let Some(base_fee) = header.base_fee {
        rlp_stream.append(&base_fee);
    }

    writer.write_all(rlp_stream.out().as_ref())?;
    Ok(())
}
