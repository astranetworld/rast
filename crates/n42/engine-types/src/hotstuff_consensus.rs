// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block validation for a chain driven by HotStuff-2 — gov5's rules, so a
//! block accepted here is a block a Go member accepts, and the other way
//! round.
//!
//! What this checks that reth's Ethereum consensus does not: the header extra
//! layout (`N42H ‖ view ‖ [QC] ‖ seal`), and a receipts root computed gov5's
//! way (`hash.DeriveSha`: keccak over concatenated receipt encodings). What it
//! deliberately does not check that reth's does: the 32-byte extra-data bound
//! (gov5 headers carry at least 108 bytes), and the empty-list ommers hash
//! (gov5's producer leaves it zero). Everything fork-dependent — withdrawals,
//! blob gas, requests, base fee, gas limit ramp, timestamp ordering — is
//! Ethereum's and is checked as Ethereum checks it.
//!
//! The seal is not verified here, matching gov5's `VerifyHeader`. Whether a
//! block is *the* block is consensus's decision, made on the hash; the seal
//! is available to anyone who wants to attribute it — see
//! [`n42_h2_consensus::verify_seal`].
//!
//! This engine also plays the payload builder's consensus role: [`prepare`]
//! lays out the header a leader's block starts from, and [`seal`] leaves it
//! alone — the view and the seal are stamped by the validator process, which
//! is the only one that knows them.
//!
//! [`prepare`]: reth_consensus::Consensus::prepare
//! [`seal`]: reth_consensus::Consensus::seal

use alloy_consensus::{BlockHeader as _, Header, TxReceipt};
use alloy_primitives::{logs_bloom, Address, B256, U256};
use n42_consensus_traits::{AposError, AposResult, SignerManager};
use n42_h2_consensus::{
    gov5_receipts_root, gov5_rewards_root, is_empty_requests_hash, validate_gov5_h2_header,
    withdrawals_to_rewards,
    HeaderExtra, ReceiptView, SimulatedCommitteePool, GOV5_EMPTY_REQUESTS_HASH,
};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom};
use reth_consensus_common::validation::{
    validate_4844_header_standalone, validate_cancun_gas, validate_header_base_fee,
    validate_header_gas,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_ethereum_primitives::{Block as EthBlock, BlockBody as EthBlockBody, EthPrimitives, Receipt};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{BlockBody as _, GotExpected, RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::{Arc, RwLock};

/// gov5's HotStuff-2 block rules, for reth.
thread_local! {
    /// A transactions root already computed and checked for the block being
    /// validated on this thread, so the body check does not compute it again
    /// (163,000 encodings and a trie at the bench tier). Set only for the
    /// span of `validate_block_pre_execution_with_tx_root`.
    static KNOWN_TX_ROOT: std::cell::Cell<Option<B256>> = const { std::cell::Cell::new(None) };
}

#[derive(Debug)]
pub struct HotStuffConsensus<ChainSpec> {
    chain_spec: Arc<ChainSpec>,
    /// The Ethereum rules this shares: everything about a header that is not
    /// HotStuff's business.
    ethereum: EthBeaconConsensus<ChainSpec>,
    /// The signer address the operator configured, if any. Kept for the
    /// operator's information; on a HotStuff chain the block's beneficiary is
    /// the fee recipient the leader names, not a local key.
    signer: RwLock<Option<Address>>,
    /// The chain's committee pool, when its genesis enables one: every
    /// header's parent beacon root must be the Blake3 of the parent's
    /// committee evidence, which the pool rebuilds from the parent header.
    committee: Option<SimulatedCommitteePool>,
}

/// A header whose parent beacon root is not the parent's committee evidence.
#[derive(Debug, thiserror::Error)]
#[error("parent beacon root {got} is not the parent's committee evidence {expected}")]
pub struct CommitteeLinkError {
    /// What the header carries.
    pub got: B256,
    /// The Blake3 of the parent's evidence.
    pub expected: B256,
}

impl<ChainSpec: EthChainSpec + EthereumHardforks> HotStuffConsensus<ChainSpec> {
    /// Rules for `chain_spec`.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        let committee = match n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(chain_spec.genesis()) {
            Ok(config) => match config.committee_pool() {
                Ok(pool) => pool,
                Err(err) => {
                    tracing::warn!(target: "n42::consensus", %err, "committee pool in the genesis could not be built; headers will not be checked against it");
                    None
                }
            },
            Err(_) => None,
        };
        Self {
            ethereum: EthBeaconConsensus::new(chain_spec.clone()),
            chain_spec,
            signer: RwLock::new(None),
            committee,
        }
    }

    /// The committee pool the chain runs, if any.
    pub const fn committee_pool(&self) -> Option<&SimulatedCommitteePool> {
        self.committee.as_ref()
    }

    /// The chain.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        &self.chain_spec
    }
}

/// gov5's receipts root and the logs bloom, from what execution produced.
pub fn gov5_receipt_root_bloom(receipts: &[Receipt]) -> ReceiptRootBloom {
    let root = gov5_receipts_root(receipts.iter().map(|receipt| ReceiptView {
        success: receipt.success,
        cumulative_gas_used: receipt.cumulative_gas_used,
        logs: &receipt.logs,
    }));
    let bloom = logs_bloom(receipts.iter().flat_map(|receipt| receipt.logs().iter()));
    (root, bloom)
}

/// The header a leader's block starts from, before the builder fills in
/// execution outputs: HotStuff's fixed fields, and a view-0 extra layout the
/// validator process overwrites with the real view and seal.
pub fn prepare_hotstuff_header(parent: &SealedHeader) -> Header {
    Header {
        parent_hash: parent.hash(),
        number: parent.number + 1,
        ommers_hash: B256::ZERO,
        difficulty: U256::ZERO,
        nonce: Default::default(),
        extra_data: HeaderExtra::for_view(0).encode(),
        ..Default::default()
    }
}

impl<ChainSpec> HeaderValidator for HotStuffConsensus<ChainSpec>
where
    ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + core::fmt::Debug + Send + Sync,
{
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError> {
        let header = header.header();
        if header.number == 0 {
            // Genesis carries no consensus fields, in gov5 as here.
            return Ok(());
        }
        validate_gov5_h2_header(header).map_err(|err| ConsensusError::Other(Arc::new(err)))?;

        validate_header_gas(header)?;
        validate_header_base_fee(header, &self.chain_spec)?;

        let timestamp = header.timestamp;
        if self.chain_spec.is_shanghai_active_at_timestamp(timestamp) {
            if header.withdrawals_root.is_none() {
                return Err(ConsensusError::WithdrawalsRootMissing);
            }
        } else if header.withdrawals_root.is_some() {
            return Err(ConsensusError::WithdrawalsRootUnexpected);
        }

        if self.chain_spec.is_cancun_active_at_timestamp(timestamp) {
            validate_4844_header_standalone(
                header,
                self.chain_spec
                    .blob_params_at_timestamp(timestamp)
                    .unwrap_or_else(alloy_eips::eip7840::BlobParams::cancun),
            )?;
        } else if header.blob_gas_used.is_some() {
            return Err(ConsensusError::BlobGasUsedUnexpected);
        } else if header.excess_blob_gas.is_some() {
            return Err(ConsensusError::ExcessBlobGasUnexpected);
        } else if header.parent_beacon_block_root.is_some() {
            return Err(ConsensusError::ParentBeaconBlockRootUnexpected);
        }

        if self.chain_spec.is_prague_active_at_timestamp(timestamp) {
            if header.requests_hash.is_none() {
                return Err(ConsensusError::RequestsHashMissing);
            }
        } else if header.requests_hash.is_some() {
            return Err(ConsensusError::RequestsHashUnexpected);
        }

        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        // Hash and number linkage, timestamp strictly after the parent, gas
        // limit ramp, base fee, blob gas: gov5 checks the first two and
        // relies on every producer deriving the rest the same way, which is
        // what checking them here guarantees for blocks this node accepts.
        self.ethereum.validate_header_against_parent(header, parent)?;
        // The committee-evidence link, exactly as gov5's `VerifyHeader`
        // checks it: the parent beacon root is the Blake3 of the parent's
        // evidence, zero when the parent is genesis.
        if let Some(pool) = &self.committee {
            let expected = pool
                .parent_beacon_root(parent.number, &parent.hash(), &parent.receipts_root)
                .map_err(|err| ConsensusError::Other(Arc::new(err)))?;
            let got = header.parent_beacon_block_root.unwrap_or_default();
            if got != expected {
                return Err(ConsensusError::Other(Arc::new(CommitteeLinkError { got, expected })));
            }
        }
        Ok(())
    }
}

impl<ChainSpec> Consensus<EthBlock> for HotStuffConsensus<ChainSpec>
where
    ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + core::fmt::Debug + Send + Sync,
{
    fn validate_body_against_header(
        &self,
        body: &EthBlockBody,
        header: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        // gov5's producer leaves the ommers hash zero; its genesis, and this
        // node's Ethereum-profile history, carry the empty-list hash. A body
        // never has ommers on this chain, so either value is "none".
        let ommers_hash = body.calculate_ommers_root();
        if header.ommers_hash == B256::ZERO && !body.ommers.is_empty() {
            // Zero says "none"; a body that brings ommers under it is lying.
            return Err(ConsensusError::BodyOmmersHashDiff(
                GotExpected {
                    got: ommers_hash,
                    expected: header.ommers_hash,
                }
                .into(),
            ));
        }
        if header.ommers_hash != B256::ZERO && header.ommers_hash != ommers_hash {
            return Err(ConsensusError::BodyOmmersHashDiff(
                GotExpected {
                    got: ommers_hash,
                    expected: header.ommers_hash,
                }
                .into(),
            ));
        }

        let tx_root = match KNOWN_TX_ROOT.with(|known| known.get()) {
            // A root the caller has already computed and matched against the
            // sealed hash (the payload's conversion did): not computed twice.
            Some(root) => root,
            None => body.calculate_tx_root(),
        };
        if header.transactions_root != tx_root {
            return Err(ConsensusError::BodyTransactionRootDiff(
                GotExpected {
                    got: tx_root,
                    expected: header.transactions_root,
                }
                .into(),
            ));
        }

        // gov5 fills `withdrawalsRoot` with its rewards commitment — keccak
        // of the block's rewards, of nothing when none were paid — while
        // Ethereum's is the withdrawals trie root. The block's withdrawals
        // are its rewards (`rewards_to_withdrawals`); either spelling of the
        // same list is accepted, a header claiming another list is refused.
        match (header.withdrawals_root, body.withdrawals.as_ref()) {
            (Some(header_root), Some(withdrawals)) => {
                let trie_root = body.calculate_withdrawals_root().unwrap_or_default();
                let gov5_root = Some(gov5_rewards_root(withdrawals_to_rewards(withdrawals.as_slice())));
                if header_root != trie_root && Some(header_root) != gov5_root {
                    return Err(ConsensusError::BodyWithdrawalsRootDiff(
                        GotExpected {
                            got: trie_root,
                            expected: header_root,
                        }
                        .into(),
                    ));
                }
            }
            (Some(_), None) => return Err(ConsensusError::BodyWithdrawalsMissing),
            (None, Some(_)) => return Err(ConsensusError::WithdrawalsRootUnexpected),
            (None, None) => {}
        }
        Ok(())
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<EthBlock>) -> Result<(), ConsensusError> {
        self.validate_body_against_header(block.body(), block.sealed_header())?;
        if self.chain_spec.is_shanghai_active_at_timestamp(block.timestamp())
            && block.body().withdrawals.is_none()
        {
            return Err(ConsensusError::BodyWithdrawalsMissing);
        }
        if self.chain_spec.is_cancun_active_at_timestamp(block.timestamp()) {
            validate_cancun_gas(block)?;
        }
        Ok(())
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<EthBlock>,
        transaction_root: Option<B256>,
    ) -> Result<(), ConsensusError> {
        KNOWN_TX_ROOT.with(|known| known.set(transaction_root));
        let result = self.validate_block_pre_execution(block);
        KNOWN_TX_ROOT.with(|known| known.set(None));
        result
    }

    fn prepare(&self, parent_header: &SealedHeader) -> Result<Header, ConsensusError> {
        Ok(prepare_hotstuff_header(parent_header))
    }

    fn seal(&self, _header: &mut Header) -> Result<(), ConsensusError> {
        // The validator process stamps the view and signs the seal; the
        // execution layer has neither.
        Ok(())
    }

    fn set_eth_signer_by_key(&self, eth_signer_key: Option<String>) -> Result<(), ConsensusError> {
        self.set_signer_key(eth_signer_key)
            .map_err(|err| ConsensusError::Other(Arc::new(err)))
    }

    fn get_eth_signer_address(&self) -> Result<Option<Address>, ConsensusError> {
        Ok(*self
            .signer
            .read()
            .map_err(|_| ConsensusError::Other(Arc::new(AposError::Other("signer lock poisoned".into()))))?)
    }
}

impl<ChainSpec> FullConsensus<EthPrimitives> for HotStuffConsensus<ChainSpec>
where
    ChainSpec: EthChainSpec<Header = Header> + EthereumHardforks + core::fmt::Debug + Send + Sync,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<EthBlock>,
        result: &BlockExecutionResult<Receipt>,
        _receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        let _ = block_access_list_hash;
        let header = block.header();
        if header.gas_used != result.gas_used {
            return Err(ConsensusError::BlockGasUsed {
                gas: GotExpected {
                    got: result.gas_used,
                    expected: header.gas_used,
                },
                gas_spent_by_tx: block
                    .body()
                    .transactions
                    .iter()
                    .zip(&result.receipts)
                    .enumerate()
                    .map(|(i, (_, receipt))| (i as u64, receipt.cumulative_gas_used))
                    .collect(),
            });
        }

        // The caller's precomputed root is the Merkle-Patricia one; this
        // chain commits to gov5's. Recomputed here, cheaply: it is a keccak
        // over the receipts, not a trie.
        let (receipts_root, logs_bloom) = gov5_receipt_root_bloom(&result.receipts);
        if header.receipts_root != receipts_root {
            return Err(ConsensusError::BodyReceiptRootDiff(
                GotExpected {
                    got: receipts_root,
                    expected: header.receipts_root,
                }
                .into(),
            ));
        }
        if header.logs_bloom != logs_bloom {
            return Err(ConsensusError::BodyBloomLogDiff(
                GotExpected {
                    got: logs_bloom,
                    expected: header.logs_bloom,
                }
                .into(),
            ));
        }

        // Requests: gov5 spells "none" as the empty trie root where EIP-7685
        // says sha256 of nothing; both are accepted for a block that made no
        // requests, and a block that did is held to the EIP.
        if self.chain_spec.is_prague_active_at_timestamp(header.timestamp) {
            let Some(header_hash) = header.requests_hash else {
                return Err(ConsensusError::RequestsHashMissing);
            };
            let matches = if result.requests.is_empty() {
                is_empty_requests_hash(header_hash)
            } else {
                header_hash == result.requests.requests_hash()
            };
            if !matches {
                let expected = if result.requests.is_empty() {
                    GOV5_EMPTY_REQUESTS_HASH
                } else {
                    result.requests.requests_hash()
                };
                return Err(ConsensusError::BodyRequestsHashDiff(
                    GotExpected {
                        got: expected,
                        expected: header_hash,
                    }
                    .into(),
                ));
            }
        }
        Ok(())
    }
}

impl<ChainSpec: Send + Sync> SignerManager for HotStuffConsensus<ChainSpec> {
    fn set_signer_key(&self, key: Option<String>) -> AposResult<()> {
        let address = match key {
            None => None,
            Some(key) => {
                let signer = key
                    .parse::<alloy_signer_local::PrivateKeySigner>()
                    .map_err(|e| AposError::InvalidSignerKey(e.to_string()))?;
                Some(signer.address())
            }
        };
        *self
            .signer
            .write()
            .map_err(|_| AposError::Other("signer lock poisoned".into()))? = address;
        Ok(())
    }

    /// Always `None`: the beneficiary of a HotStuff block is the fee recipient
    /// the leader named in its payload attributes, which is what gov5's
    /// `Prepare` sets `Coinbase` to. A local key must not override it, or two
    /// execution layers would build different blocks from the same request.
    fn get_signer_address(&self) -> AposResult<Option<Address>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::EMPTY_OMMER_ROOT_HASH;
    use alloy_primitives::Log;
    use n42_h2_consensus::GOV5_NIL_HASH;

    #[test]
    fn an_empty_block_commits_to_gov5s_nil_hash_and_an_empty_bloom() {
        let (root, bloom) = gov5_receipt_root_bloom(&[]);
        assert_eq!(root, GOV5_NIL_HASH);
        assert!(bloom.is_zero());
    }

    #[test]
    fn the_bloom_still_covers_every_log() {
        let receipt: Receipt = Receipt {
            success: true,
            cumulative_gas_used: 21_000,
            logs: vec![Log::new_unchecked(
                Address::repeat_byte(1),
                vec![B256::repeat_byte(2)],
                alloy_primitives::Bytes::new(),
            )],
            ..Default::default()
        };
        let (root, bloom) = gov5_receipt_root_bloom(std::slice::from_ref(&receipt));
        assert_ne!(root, GOV5_NIL_HASH);
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(Address::repeat_byte(1).as_slice())));
    }

    #[test]
    fn a_prepared_header_is_a_gov5_header_for_view_zero() {
        let parent = SealedHeader::seal_slow(Header {
            number: 4,
            ..Default::default()
        });
        let header = prepare_hotstuff_header(&parent);
        assert_eq!(header.number, 5);
        assert_eq!(header.parent_hash, parent.hash());
        assert_eq!(header.ommers_hash, B256::ZERO);
        assert_ne!(header.ommers_hash, EMPTY_OMMER_ROOT_HASH);
        assert_eq!(validate_gov5_h2_header(&header).unwrap().view, 0);
    }
}
