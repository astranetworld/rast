

use reth_chainspec::ChainSpec;
use reth_consensus::{Consensus, ConsensusError};




use std::{sync::Arc, time::{SystemTime, UNIX_EPOCH}};


use hex_literal::hex;
use ethereum_types::U256;

// Public constants for nonce values
pub const NONCE_AUTH_VOTE: [u8; 8] = hex!("ffffffffffffffff");
pub const NONCE_DROP_VOTE: [u8; 8] = hex!("0000000000000000");
pub const EXTRA_VANITY: usize = 32;
pub const EXTRA_SEAL: usize = 64+1;
pub const ADDRESS_LENGTH: usize = 20;
// Block difficulty for in-turn signatures
pub const DIFF_IN_TURN: U256 = U256::from(2);
// Block difficulty for out-of-turn signatures
pub const DIFF_NO_TURN: U256 = U256::from(1);
pub const MIN_GAS_LIMIT: u64 = 5000;                 // Minimum the gas limit may ever be.
pub const MAX_GAS_LIMIT: u64 = 0x7fffffffffffffff;   // Maximum the gas limit may ever be.
pub const GENESIS_GAS_LIMIT: u64 = 4712388;          // Gas limit of the Genesis block.
/// Minimum gas limit allowed for transactions.
pub const MINIMUM_GAS_LIMIT: u64 = 5000;

pub struct EthBeaconConsensus {
    /// Configuration
    chain_spec: Arc<ChainSpec>,
}



impl Consensus for EthBeaconConsensus {

    fn validate_header(&self,header: &reth_primitives::SealedHeader) -> Result<(),reth_consensus::ConsensusError> {

        if header.number.is_zero() {
            return Err("Unknown block".into());
        }
        let number = header.number.as_u64();
    
        // Don't waste time checking blocks from the future
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if header.time > current_time {
            return Err("Block in the future".into());
        }

        // Checkpoint blocks need to enforce zero beneficiary
        let checkpoint = (number % self.epoch_length) == 0;
        if checkpoint  {
            return Err("Invalid checkpoint beneficiary".into());
        }
          // Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
        if header.nonce != NONCE_AUTH_VOTE && header.nonce != NONCE_DROP_VOTE {
            return Err("Invalid vote".into());
        }
        if checkpoint && header.nonce != NONCE_DROP_VOTE {
            return Err("Invalid checkpoint vote".into());
        }

         // Check that the extra-data contains both the vanity and signature
        if header.extra.len() < EXTRA_VANITY {
            return Err("Missing vanity".into());
        }
        if header.extra.len() < EXTRA_VANITY + EXTRA_SEAL {
            return Err("Missing signature".into());
        }
         // Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
        let signers_bytes = header.extra.len() - EXTRA_VANITY - EXTRA_SEAL;
        if !checkpoint && signers_bytes != 0 {
            return Err("Extra signers found".into());
        }
        if checkpoint && signers_bytes % ADDRESS_LENGTH != 0 {
            return Err("Invalid checkpoint signers".into());
        }
         // Ensure that the block's difficulty is meaningful (may not be correct at this point)
        if number > 0 {
            if header.difficulty.is_zero() || 
            (header.difficulty != DIFF_IN_TURN && header.difficulty != DIFF_NO_TURN) {
                return Err("Invalid difficulty".into());
            }
        }
         // Verify that the gas limit is <= 2^63-1
        if header.gas_limit > MAX_GAS_LIMIT {
            return Err(format!("Invalid gasLimit: have {}, max {}", header.gas_limit, MAX_GAS_LIMIT).into());
        }

        Ok(())
        
    }

    fn validate_header_against_parent(&self,header: &reth_primitives::SealedHeader,parent: &reth_primitives::SealedHeader,) -> Result<(),reth_consensus::ConsensusError> {
        

         // The genesis block is the always valid dead-end
        let number = header.number.as_u64();
        if number == 0 {
            return Ok(());
        }

         // Ensure that the block's timestamp isn't too close to its parent
        // let parent: Box<dyn reth_primitives::SealedHeader>;
        // if !parent.is_empty() {
        //     parent = parents.last().unwrap().clone();
        // } else {
        //     parent = chain.get_header(&header.parent_hash, uint256::Uint256::from_u64(number - 1));
        // }

        // if parent.is_none() || parent.as_ref().unwrap().as_any().downcast_ref::<block::Header>().is_none()
        //     || parent.number().as_u64() != number - 1 || parent.hash() != header.parent_hash
        // {
        //     return Err("errUnknownBlock".to_string());
        // }

        // let raw_parent = parent.as_ref().unwrap().as_any().downcast_ref::<block::Header>().unwrap();
        // if raw_parent.time + config.period > header.time {
        //     return Err("errInvalidTimestamp".to_string());
        // }

    
    
          // Verify that the gasUsed is <= gasLimit
        if header.gas_used > header.gas_limit {
            return Err(format!(
                "invalid gasUsed: have {}, gasLimit {}",
                header.gas_used, header.gas_limit
            ));
        }

        if header.is_timestamp_in_past(parent.timestamp) {
            return Err(ConsensusError::TimestampIsInPast {
                parent_timestamp: parent.timestamp,
                timestamp: header.timestamp,
            })
        }
  
        Ok(())
    }

    fn validate_header_range(&self,headers: &[reth_primitives::SealedHeader]) -> Result<(),reth_consensus::HeaderConsensusError> {


        
        Ok(())
    }

    fn validate_header_with_total_difficulty(&self,header: &reth_primitives::Header,total_difficulty:reth_primitives::U256,) -> Result<(),ConsensusError> {
        Ok(())
    }

    fn validate_block_pre_execution(&self,block: &reth_primitives::SealedBlock) -> Result<(),ConsensusError> {
        Ok(())
    }

    fn validate_block_post_execution(&self,block: &reth_primitives::BlockWithSenders,input:reth_consensus::PostExecutionInput<'_> ,) -> Result<(),ConsensusError> {
        Ok(())
    }

    
    
}
