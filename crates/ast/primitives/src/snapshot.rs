
// use ethcore::snapshot::{ManifestData, SnapshotService};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::hash::Hash;
use reth_primitives::{hex, Header};


use std::sync::Arc;
use std::time::{Duration, Instant};


use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};

use tracing::info;


pub const NONCE_AUTH_VOTE: [u8; 8] = hex!("ffffffffffffffff"); // Magic nonce number to vote on adding a new signer
pub const NONCE_DROP_VOTE: [u8; 8] = hex!("0000000000000000"); // Magic nonce number to vote on removing a signer


#[derive(Debug)]
pub enum VotingError {
    InvalidVotingChain,
    UnauthorizedSigner,
    SignerRecentlySigned,
    InvalidVote,
}

//
//
impl std::fmt::Display for VotingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VotingError::InvalidVotingChain => write!(f, "Invalid voting chain"),
            VotingError::UnauthorizedSigner => write!(f, "Unauthorized signer"),
            VotingError::SignerRecentlySigned => write!(f, "Signer recently signed"),
            VotingError::InvalidVote => write!(f, "Invalid vote"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary,Default)]
pub struct Vote {
    /// Authorized signer that cast this vote
    pub signer: Address,
    /// Block number the vote was cast in (expire old votes)
    pub block: u64,
    /// Account being voted on to change its authorization
    pub address: Address,
    /// Whether to authorize or deauthorize the voted account
    pub authorize: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary,Default)]
pub struct Tally {
    /// Whether the vote is about authorizing or kicking someone
    pub authorize: bool,
    /// Number of votes until now wanting to pass the proposal
    pub votes: i32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary,Default)]
pub struct APosConfig {
    /// Number of seconds between blocks to enforce
    pub period: u64,
    /// Epoch length to reset votes and checkpoint
    pub epoch: u64,
    /// Reward epoch duration
    pub reward_epoch: u64,
    /// Maximum reward limit per epoch
    pub reward_limit: U256,
    /// Deposit contract
    pub deposit_contract: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary,Default)]
pub struct Snapshot<F>
    where
    F: Fn(Header) -> Result<Address, Box<dyn Error>> + Clone,
{
    /// Consensus engine parameters to fine tune behavior
    pub config: APosConfig,
    /// Block number where the snapshot was created
    pub number: u64,
    /// checkpoint hash where the snapshot was created
    pub hash: B256,
    /// Set of authorized signers at this moment
    pub signers: Vec<Address>,
    /// Set of recent signers for spam protections
    pub recents: HashMap<u64, Address>,
    /// List of votes cast in chronological order
    pub votes: Vec<Vote>,
    /// Current vote tally to avoid recalculating
    pub tally: HashMap<Address, Tally>,
    /// recover address
    pub ecrecover: F,
}

impl<F> Snapshot<F> {

	// 创建一个新的 Snapshot
    pub fn new_snapshot(
        config: APosConfig,
        number: u64,
        hash: B256,
        signers: Vec<Address>,
        ecrecover: F,
    ) -> Self {
        let mut snap = Snapshot {
            config,
            number,
            hash,
            signers: Vec::new(),
            recents: HashMap::new(),
            votes: Vec::new(),
            tally: HashMap::new(),
            ecrecover,
        };

        for signer in signers {
            snap.signers.insert(signer);
        }

        snap
    }


	// Create a deep copy of the snapshot
    pub fn copy(&self) -> Self {
        let mut cpy = Self {
            config: self.config.clone(),
            number: self.number,
            hash: self.hash.clone(), 
            signers: self.signers.clone(),
            recents: self.recents.clone(),
            votes: self.votes.clone(),
            tally: self.tally.clone(),
            ecrecover: self.ecrecover.clone(),
        };
        
        // No need for special handling for votes if Vec<T> implements Clone
        // Deep copy is handled by the clone method for each type.
        cpy
    }

    pub fn ecrecover(&self, header: Header) -> Result<Address, Box<dyn Error>> {
        (self.ecrecover)(header)
    }

	 // valid_vote returns whether it makes sense to cast the specified vote in the
     // given snapshot context (e.g. don't try to add an already authorized signer).
	 pub fn valid_vote(&self, address: Address, authorize: bool) -> bool {
        if self.signers.get(&address).is_some() {
            !authorize
        } else {
            authorize
        }
    }

    // cast Add a new vote to the voting statistics
    pub fn cast(&mut self, address: Address, authorize: bool) -> bool {
        // Ensure the vote is meaningful
        if !self.valid_vote(address, authorize) {
            return false;
        }
        // Cast the vote into an existing or new tally
        if let Some(tally) = self.tally.get_mut(&address) {
            tally.votes += 1;
        } else {
            self.tally.insert(address, Tally { authorize, votes: 1 });
        }
        true
    }

    // uncast removes a previously cast vote from the tally.
    pub fn uncast(&mut self, address: Address, authorize: bool) -> bool {
        if let Some(tally) = self.tally.get_mut(&address) {
            //Ensure that we only remove eligible votes
            if tally.authorize != authorize {
                return false;
            }
            //Otherwise, remove this vote
            if tally.votes > 1 {
                tally.votes -= 1;
            } else {
                self.tally.remove(&address);
            }
            true
        } else {
            // If there's no tally, it's a dangling vote, just drop
            false
        }
    }

	 //Create a new authorization snapshot using the given header information
	 pub fn apply(&self, headers: Vec<Header>) -> Result<Snapshot<F>, VotingError> {
        //If there is no header information, return the current snapshot directly
        if headers.is_empty() {
            return Ok(self.clone());
        }

        //Check the validity of header information
        for i in 0..headers.len() - 1 {
            if headers[i + 1].number() != headers[i].number() + 1 {
                return VotingError::InvalidVotingChain;
            }
        }
        if headers[0].number() != self.number + 1 {
            return VotingError::InvalidVotingChain;
        }

        //Create a new snapshot
        let mut snap = self.copy();
        let start = Instant::now();
        let mut logged = Instant::now();

        for (i, i_header) in headers.iter().enumerate() {
            let header = i_header.as_ref();
            let number = header.number;

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
            let signer = self.ecrecover(header)?;
            if !snap.signers.contains(&signer) {
                return VotingError::UnauthorizedSigner;
            }

            if snap.recents.values().any(|&recent| recent == signer) {
                return VotingError::SignerRecentlySigned;
            }
            snap.recents.insert(number, signer.clone());

            //Discard any previous votes of the signer
            snap.votes.retain(|vote| !(vote.signer == signer && vote.address == header.beneficiary));

            //Count new votes
            let authorize = match header.nonce {
                nonce if hex::encode(nonce) == hex::encode(NONCE_AUTH_VOTE) => true,
                nonce if hex::encode(nonce) == hex::encode(NONCE_DROP_VOTE) => false,
                _ => return VotingError::InvalidVote,
            };

            if snap.cast(header.beneficiary, authorize) {
                snap.votes.push(Vote {
                    signer,
                    block: number,
                    address: header.beneficiary,
                    authorize,
                });
            }

            //If the vote is passed, update the list of signatories
            if let Some(tally) = snap.tally.get(header.beneficiary) {
                if tally.votes > snap.signers.len() / 2 {
                    if tally.authorize {
                        snap.signers.insert(header.beneficiary);
                    } else {
                        snap.signers.remove(header.beneficiary);

                        //Reduce the signer list and delete any remaining recent cache
                        if number >= snap.signers.len() as u64 / 2 + 1 {
                            snap.recents.remove(&(number - snap.signers.len() as u64 / 2 + 1));
                        }

                       //Discard any previous votes of the revoked authorized signatory
                        snap.votes.retain(|vote| vote.signer != header.beneficiary);
                    }

                    //Discard any previous votes that have just changed the account
                    snap.votes.retain(|vote| vote.address != header.beneficiary);
                    snap.tally.remove(header.beneficiary);
                }
            }

            //If the operation takes too long, notify the user regularly
            if logged.elapsed() > Duration::from_secs(8) {
                
                info!(
                    target: "Apos",
					"Reconstructing voting history: i={}, headers.len()={}, elapsed={:?}",
					i,
					headers.len(),
					start.elapsed()
				);
            }
        }

        if start.elapsed() > Duration::from_secs(8) {
            info!(
                target: "Apos",
				"Reconstructed voting history: headers.len()={}, elapsed={:?}",
				headers.len(),
				start.elapsed()
			);
        }

        snap.number = headers.last().unwrap().number;
        snap.hash = headers.last().unwrap().hash_slow();

        Ok(snap)
    }

	 // signers retrieves the list of authorized signers in ascending order.
	 pub fn signers(&self) -> Vec<Address> {
        let mut sigs: Vec<Address> = self.signers.iter().cloned().collect();
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
