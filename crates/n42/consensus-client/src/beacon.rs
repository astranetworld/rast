// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloy_primitives::Sealable;
use alloy_rpc_types_beacon::requests::ExecutionRequestsV4;
use blst::min_pk::{PublicKey, Signature};
use merkle_db_rs::tree::{Tree, VecTree};
use reth_chainspec::EthereumHardforks;
use n42_tx_types::Block;
use reth_primitives_traits::Header;
// reth-primitives (deleted in reth 2.4.1) supplied this default type argument.
type SealedBlock<B = Block> = reth_primitives_traits::SealedBlock<B>;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{
    BeaconProvider, BeaconProviderWriter, BlockIdReader, BlockReader, ChainSpecProvider,
};

use alloy_eips::{
    eip4895::{Withdrawal, Withdrawals},
    eip7685::Requests,
};
use alloy_primitives::{keccak256, BlockHash, Log, B256};
use alloy_primitives::{Address, Bytes};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use n42_primitives::{
    Attestation, BeaconBlock, BeaconBlockBody, BeaconState, BlockVerifyResultAggregate,
    CommitteeIndex, Deposit, DepositData, Epoch, ExecutionRequests, Validator,
    VoluntaryExitWithSig, SLOTS_PER_EPOCH,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, error, info, trace, warn};

#[derive(Debug)]
pub struct Beacon<Provider> {
    provider: Provider,
}

impl<Provider> Beacon<Provider>
where
    Provider: BlockReader
        + BlockIdReader
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + BeaconProvider
        + BeaconProviderWriter
        + 'static
        + Clone,
{
    pub fn new(provider: Provider) -> Self {
        Self { provider }
    }

    pub fn gen_beacon_block(
        &mut self,
        old_beacon_state: BeaconState,
        parent_hash: BlockHash,
        attestations: &Vec<Attestation>,
        execution_requests: &Option<Requests>,
        eth1_sealed_block: &SealedBlock,
    ) -> eyre::Result<BeaconBlock> {
        let mut execution_requests = parse_execution_requests(execution_requests)?;

        execution_requests.deposits.retain(|deposit|
            {
                let deposit_data = DepositData {
                    pubkey: deposit.pubkey,
                    withdrawal_credentials: deposit.withdrawal_credentials,
                    signature: deposit.signature,
                    amount: deposit.amount,
                };

                let deposit_data_verify_result = deposit_data.verify_signature();
                debug!(target: "consensus-client", pubkey=?deposit_data.pubkey, ?deposit_data_verify_result, "gen_beacon_block");
                deposit_data_verify_result
            }
        );

        let mut beacon_block = BeaconBlock {
            slot: old_beacon_state.slot + 1,
            parent_hash,
            eth1_block_hash: eth1_sealed_block.hash_slow(),
            body: BeaconBlockBody {
                deposits: Default::default(),
                attestations: attestations.clone(),
                voluntary_exits: Default::default(),
                execution_requests,
            },
            ..Default::default()
        };
        let beacon_state = self.state_transition(Some(old_beacon_state), &beacon_block)?;
        beacon_block.state_root = beacon_state.hash_slow();
        Ok(beacon_block)
    }

    pub fn state_transition(
        &mut self,
        old_beacon_state: Option<BeaconState>,
        beacon_block: &BeaconBlock,
    ) -> eyre::Result<BeaconState> {
        debug!(target: "consensus-client", ?beacon_block, "state_transition");
        let beacon_state = match old_beacon_state {
            Some(v) => v,
            None => self
                .provider
                .get_beacon_state_by_hash(&beacon_block.parent_hash)?
                .ok_or(eyre::eyre!(
                    "beacon_state not found by hash, {:?}",
                    beacon_block.parent_hash
                ))?,
        };
        let new_beacon_state = BeaconState::state_transition(&beacon_state, beacon_block)?;
        let beacon_block_with_root = BeaconBlock {
            state_root: new_beacon_state.hash_slow(),
            ..beacon_block.clone()
        };
        let beacon_block_hash = beacon_block_with_root.hash_slow();
        self.provider
            .save_beacon_state_by_hash(&beacon_block_hash, new_beacon_state.clone())?;
        debug!(target: "consensus-client", ?beacon_block_hash, ?new_beacon_state, "state_transition");

        Ok(new_beacon_state)
    }

    pub fn gen_withdrawals(
        &mut self,
        eth1_block_hash: BlockHash,
    ) -> eyre::Result<(Option<Vec<Withdrawal>>, BeaconState)> {
        debug!(target: "consensus-client", ?eth1_block_hash, "gen_withdrawals");
        let beacon_block_hash = self
            .provider
            .get_beacon_block_hash_by_eth1_hash(&eth1_block_hash)?
            .ok_or(eyre::eyre!(
                "beacon block hash not found, eth1_block_hash={:?}",
                eth1_block_hash
            ))?;

        debug!(target: "consensus-client", ?beacon_block_hash, "gen_withdrawals");
        let mut beacon_state = self
            .provider
            .get_beacon_state_by_hash(&beacon_block_hash)?
            .ok_or(eyre::eyre!(
                "beacon_state not found by hash, beacon_block_hash={:?}",
                beacon_block_hash
            ))?;
        debug!(target: "consensus-client", ?beacon_state, "gen_withdrawals");

        let (expected_withdrawals, processed_partial_withdrawals_count) =
            beacon_state.process_withdrawals()?;
        Ok((Some(expected_withdrawals), beacon_state))
    }

    /// Get validator index from beacon state by pubkey
    pub fn get_validator_index_from_beacon_state(
        &self,
        block_hash: BlockHash,
        pubkey: blst::min_pk::PublicKey,
    ) -> eyre::Result<Option<u64>> {
        let beacon_block_hash = self
            .provider
            .get_beacon_block_hash_by_eth1_hash(&block_hash)?
            .ok_or(eyre::eyre!(
                "beacon_block_hash not found by eth1_hash, {:?}",
                block_hash
            ))?;
        let beacon_state = self
            .provider
            .get_beacon_state_by_hash(&beacon_block_hash)?
            .ok_or(eyre::eyre!(
                "beacon_state not found by hash, {:?}",
                beacon_block_hash
            ))?;

        // Search for validator by pubkey using validators_store
        let pubkey_bytes: [u8; 48] = pubkey.to_bytes();
        for (index, validator) in beacon_state.validators_store.iter().enumerate() {
            if validator.pubkey.0 == pubkey_bytes {
                return Ok(Some(index as u64));
            }
        }
        Ok(None)
    }
}

fn parse_execution_requests(requests: &Option<Requests>) -> eyre::Result<ExecutionRequestsV4> {
    Ok(requests.clone().unwrap_or_default().try_into()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip7685::Requests;

    #[test]
    fn test_parse_execution_requests_none() {
        let result = parse_execution_requests(&None);
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert!(requests.deposits.is_empty());
        assert!(requests.withdrawals.is_empty());
        assert!(requests.consolidations.is_empty());
    }

    #[test]
    fn test_parse_execution_requests_empty() {
        let requests = Some(Requests::default());
        let result = parse_execution_requests(&requests);
        assert!(result.is_ok());
    }
}
