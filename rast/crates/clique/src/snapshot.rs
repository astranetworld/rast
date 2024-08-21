// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.Epoch

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

// use ethcore::snapshot::{ManifestData, SnapshotService};
use std::collections::{HashMap, HashSet};
use reth_primitives::SealedHeader;
use serde::{Serialize, Deserialize};
use num_bigint::BigInt;
use lru::LruCache;
use std::error::Error;

use std::hash::Hasher;
use std::sync::Mutex;

use k256::ecdsa::Signature;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::apos::ecrecover;
use crate::apos::{NONCE_AUTH_VOTE, NONCE_DROP_VOTE};
use crate::traits::{Getter, Putter};

pub const ADDRESS_LENGTH :usize = 20;
pub const HASH_LENGTH :usize = 32;
pub const  SIGNATURE_LENGTH :usize = 96;

pub type Address = [u8; ADDRESS_LENGTH];
pub type Hash = [u8; HASH_LENGTH];
// pub type Signature = [u8; SIGNATURE_LENGTH];



#[derive(Serialize, Deserialize)]
pub struct Vote {
    pub signer: Address,    // Authorized signer that cast this vote
    pub block: u64,                // Block number the vote was cast in (expire old votes)
    pub address: Address,   // Account being voted on to change its authorization
    pub authorize: bool,           // Whether to authorize or deauthorize the voted account
}

#[derive(Serialize, Deserialize)]
pub struct Tally {
    pub authorize: bool,           // Whether the vote is about authorizing or kicking someone
    pub votes: i32,                // Number of votes until now wanting to pass the proposal
}
#[derive(Clone)]
#[derive(Serialize, Deserialize)]
pub struct APosConfig {
    pub period: u64,          // Number of seconds between blocks to enforce
    pub epoch: u64,           // Epoch length to reset votes and checkpoint

    pub reward_epoch: u64,    // Reward epoch duration
    pub reward_limit: BigInt, // Maximum reward limit per epoch

    pub deposit_contract: String,     // Deposit contract
    pub deposit_nft_contract: String, // Deposit NFT contract
    pub deposit_fuji_contract: String // Deposit FUJI NFT contract
}
#[derive(Clone)]
pub struct Snapshot {
    pub config: APosConfig,      // Consensus engine parameters to fine tune behavior
    pub sigcache: Mutex<LruCache<u64, Signature>>,               // Cache of recent block signatures to speed up ecrecover

    pub number: u64,                           // Block number where the snapshot was created
    pub hash: Hash,                     // Block hash where the snapshot was created
    pub signers: HashSet<Address>,      // Set of authorized signers at this moment
    pub recents: HashMap<u64, Address>, // Set of recent signers for spam protections
    pub votes: Vec<Vote>,                      // List of votes cast in chronological order
    pub tally: HashMap<Address, Tally>, // Current vote tally to avoid recalculating
}

impl Snapshot {

	// 创建一个新的 Snapshot
    pub fn new_snapshot(
        config: Arc<APosConfig>,
        sigcache: Arc<Mutex<LruCache<u64, Signature>>>,
        number: u64,
        hash: Hash,
        signers: Vec<Address>,
    ) -> Self {
        let mut snap = Snapshot {
            config,
            sigcache,
            number,
            hash,
            signers: HashSet::new(),
            recents: HashMap::new(),
            votes: Vec::new(),
            tally: HashMap::new(),
        };

        for signer in signers {
            snap.signers.insert(signer);
        }

        snap
    }

	//Load existing snapshot
    pub fn load_snapshot(
        config: Arc<APosConfig>,
        sigcache: Arc<Mutex<LruCache<u64, Signature>>>,
        tx: &dyn Getter, 
        hash: Hash,
    ) -> Result<Self, Error> {
        let blob = tx.get_snapshot(hash)
            .map_err(|e| Error::LoadError(e.to_string()))?;
        
        let mut snap: Snapshot = serde_json::from_slice(&blob)
            .map_err(|e| Error::LoadError(e.to_string()))?;
        
        snap.config = config;
        snap.sigcache = sigcache;

        Ok(snap)
    }

    //Store the snapshot in the database
    pub fn store(&self, tx: &dyn Putter) -> Result<(), Error> {
        let blob = serde_json::to_vec(self)
            .map_err(|e| Error::StoreError(e.to_string()))?;
        
        tx.put_snapshot(self.hash, &blob)
            .map_err(|e| Error::StoreError(e.to_string()))
    }

	// Create a deep copy of the snapshot
    pub fn copy(&self) -> Self {
        let mut cpy = Self {
            config: Arc::clone(&self.config), 
            sigcache: Arc::clone(&self.sigcache), 
            number: self.number,
            hash: self.hash.clone(), 
            signers: self.signers.clone(),
            recents: self.recents.clone(),
            votes: self.votes.clone(),
            tally: self.tally.clone(),
        };
        
        // No need for special handling for votes if Vec<T> implements Clone
        // Deep copy is handled by the clone method for each type.

        cpy
    }

	 // valid_vote Return whether voting is meaningful in the current snapshot context
	 pub fn valid_vote(&self, address: &str, authorize: bool) -> bool {
        match self.signers.get(address) {
            Some(&signer) => (signer && !authorize) || (!signer && authorize),
            None => authorize,
        }
    }

    // cast Add a new vote to the voting statistics
    pub fn cast(&mut self, address: String, authorize: bool) -> bool {
        // 确保投票是有意义的
        if !self.valid_vote(&address, authorize) {
            return false;
        }
    //Add voting to existing statistics or create a new one
        if let Some(tally) = self.tally.get_mut(&address) {
            tally.votes += 1;
        } else {
            self.tally.insert(address, Tally { authorize, votes: 1 });
        }
        true
    }

    // uncast Remove previously cast votes from the voting statistics
    pub fn uncast(&mut self, address: &str, authorize: bool) -> bool {
        // If there is no statistical record, it means this is a suspended vote and should be discarded directly
        if let Some(tally) = self.tally.get_mut(address) {
            //Ensure that we only remove eligible votes
            if tally.authorize != authorize {
                return false;
            }
            //Otherwise, remove this vote
            if tally.votes > 1 {
                tally.votes -= 1;
            } else {
                self.tally.remove(address);
            }
            true
        } else {
            false
        }
    }

	 //Create a new authorization snapshot using the given header information
	 pub fn apply(&self, headers: SealedHeader) -> Result<Snapshot, &'static str> {
        //If there is no header information, return the current snapshot directly
        if headers.is_empty() {
            return Ok(self.clone());
        }

        //Check the validity of header information
        for i in 0..headers.len() - 1 {
            if headers[i + 1].number() != headers[i].number() + 1 {
                return Err("Invalid voting chain");
            }
        }
        if headers[0].number() != self.number + 1 {
            return Err("Invalid voting chain");
        }

        //Create a new snapshot
        let mut snap = self.copy();
        let start = Instant::now();
        let mut logged = Instant::now();

        for (i, i_header) in headers.iter().enumerate() {
            let header = i_header.as_ref();
            let number = header.number();

            //If it is a checkpoint block, remove all votes
            if number % self.config.epoch == 0 {
                snap.votes.clear();
                snap.tally.clear();
            }

            //Remove the oldest signer from the recent signer collection to allow them to sign again
            if number >= (snap.signers.len() as u64 / 2 + 1) {
                snap.recents.remove(&(number - snap.signers.len() as u64 / 2 + 1));
            }

            //Verify the signer and check if they are in the signer list
            let signer = ecrecover(header, &self.sigcache)?;
            if !snap.signers.contains(&signer) {
                return Err("Unauthorized signer");
            }

            if snap.recents.values().any(|&recent| recent == signer) {
                return Err("Signer recently signed");
            }
            snap.recents.insert(number, signer.clone());

            //Discard any previous votes of the signer
            snap.votes.retain(|vote| !(vote.signer == signer && vote.address == header.coinbase()));

            //Count new votes
            let authorize = match header.nonce() {
                nonce if nonce == NONCE_AUTH_VOTE => true,
                nonce if nonce == NONCE_DROP_VOTE => false,
                _ => return Err("Invalid vote"),
            };

            if snap.cast(header.coinbase().clone(), authorize) {
                snap.votes.push(Vote {
                    signer,
                    block: number,
                    address: header.coinbase().clone(),
                    authorize,
                });
            }

            //If the vote is passed, update the list of signatories
            if let Some(tally) = snap.tally.get(header.coinbase()) {
                if tally.votes > snap.signers.len() / 2 {
                    if tally.authorize {
                        snap.signers.insert(header.coinbase().clone());
                    } else {
                        snap.signers.remove(header.coinbase());

                        //Reduce the signer list and delete any remaining recent cache
                        if number >= snap.signers.len() as u64 / 2 + 1 {
                            snap.recents.remove(&(number - snap.signers.len() as u64 / 2 + 1));
                        }

                       //Discard any previous votes of the revoked authorized signatory
                        snap.votes.retain(|vote| vote.signer != header.coinbase());
                    }

                    //Discard any previous votes that have just changed the account
                    snap.votes.retain(|vote| vote.address != header.coinbase());
                    snap.tally.remove(header.coinbase());
                }
            }

            //If the operation takes too long, notify the user regularly
            if logged.elapsed() > Duration::from_secs(8) {
                
                log::info!(
					"Reconstructing voting history: i={}, headers.len()={}, elapsed={:?}",
					i,
					headers.len(),
					start.elapsed()
				);
            }
        }

        if start.elapsed() > Duration::from_secs(8) {
            log::info!(
				"Reconstructed voting history: headers.len()={}, elapsed={:?}",
				headers.len(),
				start.elapsed()
			);
        }

        snap.number += headers.len() as u64;
        snap.hash = headers.last().unwrap().hash();

        Ok(snap)
    }

	 // signers retrieves the list of authorized signers in ascending order.
	 pub fn signers(&self) -> Vec<Address> {
        let mut sigs: Vec<Address> = self.signers.keys().cloned().collect();
        sigs.sort(); 
        sigs
    }

    // inturn returns if a signer at a given block height is in-turn or not.
    pub fn inturn(&self, number: u64, signer: &Address) -> bool {
        let signers = self.signers();
        let mut offset = 0;

        //Find the position of the given signer in the sorted list
        while offset < signers.len() && &signers[offset] != signer {
            offset += 1;
        }

        //Determine whether the signer of a given block height is an in turn signer
        (number % signers.len() as u64) == offset as u64
    }


}
