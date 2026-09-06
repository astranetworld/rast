// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which consensus rules a node runs, decided by the chain it is launched on.
//!
//! A genesis that names a `hotstuff` validator set is driven by HotStuff-2
//! over the Engine API and its blocks follow gov5's header profile —
//! [`HotStuffConsensus`]. Any other genesis is an APoS chain — [`APos`].
//! Both are behind one enum so the rest of the node (the payload builder, the
//! miner, the consensus RPC extension) is written once against reth's
//! `Consensus` trait and N42's `SignerManager`, and the choice is made in
//! exactly one place.

use crate::hotstuff_consensus::HotStuffConsensus;
use alloy_consensus::Header;
use alloy_primitives::{Address, BlockHash, B256, U256};
use n42_clique::APos;
use n42_consensus_traits::{AposResult, SignerManager};
use n42_primitives::Snapshot;
use n42_qmdb_reth::HotStuffGenesisConfig;
use reth_chainspec::ChainSpec;
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderConsensusError, HeaderValidator,
    ReceiptRootBloom, TransactionRoot,
};
use n42_tx_types::{Block as EthBlock, BlockBody as EthBlockBody, N42Primitives as EthPrimitives, Receipt};
use reth_execution_types::BlockExecutionResult;
use reth_node_api::FullNodeTypes;
use reth_node_builder::components::ConsensusBuilder;
use reth_node_builder::{BuilderContext, NodeTypes};
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use reth_provider::{BlockIdReader, BlockReaderIdExt, HeaderProvider};
use reth_revm::cached::CachedReads;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Combined trait for N42 consensus that includes both FullConsensus and SignerManager.
pub trait N42FullConsensus: FullConsensus<EthPrimitives> + SignerManager {}

// Blanket implementation for any type that implements both traits
impl<T> N42FullConsensus for T where T: FullConsensus<EthPrimitives> + SignerManager {}

/// The bounds APoS puts on its provider; the enum carries them so it can
/// hold an [`APos`] at all.
pub trait ConsensusProvider:
    HeaderProvider<Header = Header> + BlockIdReader + BlockReaderIdExt + Clone + Unpin + 'static
{
}
impl<T> ConsensusProvider for T where
    T: HeaderProvider<Header = Header> + BlockIdReader + BlockReaderIdExt + Clone + Unpin + 'static
{
}

/// The consensus rules in force on this node's chain.
pub enum N42Consensus<Provider: ConsensusProvider> {
    /// An APoS (extended Clique) chain: this node seals and validates
    /// signer-authorized blocks itself. Boxed: it is far larger than the
    /// HotStuff variant and is constructed once.
    Apos(Box<APos<Provider, ChainSpec>>),
    /// A HotStuff-2 chain: a validator process drives this node over the
    /// Engine API, and blocks follow gov5's header profile.
    HotStuff(HotStuffConsensus<ChainSpec>),
}

impl<Provider: ConsensusProvider> std::fmt::Debug for N42Consensus<Provider> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Apos(apos) => f.debug_tuple("Apos").field(apos).finish(),
            Self::HotStuff(hotstuff) => f.debug_tuple("HotStuff").field(hotstuff).finish(),
        }
    }
}

impl<Provider: ConsensusProvider> N42Consensus<Provider> {
    /// Whether the chain is HotStuff-driven.
    pub const fn is_hotstuff(&self) -> bool {
        matches!(self, Self::HotStuff(_))
    }
}

/// Whether `chain_spec` names a HotStuff validator set in its genesis.
pub fn is_hotstuff_chain(chain_spec: &ChainSpec) -> bool {
    HotStuffGenesisConfig::from_genesis(&chain_spec.genesis).is_ok()
}

macro_rules! delegate {
    ($self:ident, $c:ident => $e:expr) => {
        match $self {
            Self::Apos($c) => {
                let $c = $c.as_ref();
                $e
            }
            Self::HotStuff($c) => $e,
        }
    };
}

impl<Provider> HeaderValidator for N42Consensus<Provider>
where
    Provider: ConsensusProvider,
{
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError> {
        delegate!(self, c => c.validate_header(header))
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        delegate!(self, c => c.validate_header_against_parent(header, parent))
    }

    fn validate_header_range(
        &self,
        headers: &[SealedHeader],
    ) -> Result<(), HeaderConsensusError<Header>> {
        delegate!(self, c => c.validate_header_range(headers))
    }
}

impl<Provider> Consensus<EthBlock> for N42Consensus<Provider>
where
    Provider: ConsensusProvider,
{
    fn validate_body_against_header(
        &self,
        body: &EthBlockBody,
        header: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::validate_body_against_header(c, body, header))
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<EthBlock>) -> Result<(), ConsensusError> {
        alt_sig_allowed(block)?;
        delegate!(self, c => Consensus::<EthBlock>::validate_block_pre_execution(c, block))
    }

    fn is_transient_error(&self, error: &ConsensusError) -> bool {
        delegate!(self, c => Consensus::<EthBlock>::is_transient_error(c, error))
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<EthBlock>,
        transaction_root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        alt_sig_allowed(block)?;
        delegate!(self, c => Consensus::<EthBlock>::validate_block_pre_execution_with_tx_root(c, block, transaction_root))
    }

    fn prepare(&self, parent_header: &SealedHeader) -> Result<Header, ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::prepare(c, parent_header))
    }

    fn seal(&self, header: &mut Header) -> Result<(), ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::seal(c, header))
    }

    fn set_eth_signer_by_key(&self, eth_signer_key: Option<String>) -> Result<(), ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::set_eth_signer_by_key(c, eth_signer_key))
    }

    fn get_eth_signer_address(&self) -> Result<Option<Address>, ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::get_eth_signer_address(c))
    }

    fn snapshot(
        &self,
        number: u64,
        hash: B256,
        parents: Option<Vec<Header>>,
    ) -> Result<Snapshot, ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::snapshot(c, number, hash, parents))
    }

    fn propose(&self, address: Address, auth: bool) -> Result<(), ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::propose(c, address, auth))
    }

    fn discard(&self, address: Address) -> Result<(), ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::discard(c, address))
    }

    fn proposals(&self) -> Result<HashMap<Address, bool>, ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::proposals(c))
    }

    fn total_difficulty(&self, hash: B256) -> U256 {
        delegate!(self, c => Consensus::<EthBlock>::total_difficulty(c, hash))
    }

    fn wiggle(&self, parent_number: u64, parent_hash: BlockHash, difficulty: U256) -> Duration {
        delegate!(self, c => Consensus::<EthBlock>::wiggle(c, parent_number, parent_hash, difficulty))
    }

    fn set_cached_reads(
        &self,
        block_hash: BlockHash,
        cached_reads: CachedReads,
    ) -> Result<(), ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::set_cached_reads(c, block_hash, cached_reads))
    }

    fn get_cached_reads(&self, block_hash: BlockHash) -> Result<Option<CachedReads>, ConsensusError> {
        delegate!(self, c => Consensus::<EthBlock>::get_cached_reads(c, block_hash))
    }
}

/// A block carrying a 0x50 transaction is valid only on a chain whose genesis
/// enables the type (`altSigTx: true`).
fn alt_sig_allowed(block: &SealedBlock<EthBlock>) -> Result<(), ConsensusError> {
    if !n42_tx_types::alt_sig_enabled() && block.body().transactions().any(|tx| tx.is_alt_sig()) {
        return Err(ConsensusError::Other(Arc::new(std::io::Error::other(
            "0x50 alternative-signature transactions are not enabled on this chain",
        ))));
    }
    Ok(())
}

impl<Provider> FullConsensus<EthPrimitives> for N42Consensus<Provider>
where
    Provider: ConsensusProvider,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<EthBlock>,
        result: &BlockExecutionResult<Receipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        delegate!(self, c => FullConsensus::<EthPrimitives>::validate_block_post_execution(
            c, block, result, receipt_root_bloom, block_access_list_hash
        ))
    }
}

impl<Provider> SignerManager for N42Consensus<Provider>
where
    Provider: ConsensusProvider,
{
    fn set_signer_key(&self, key: Option<String>) -> AposResult<()> {
        delegate!(self, c => c.set_signer_key(key))
    }

    fn get_signer_address(&self) -> AposResult<Option<Address>> {
        delegate!(self, c => c.get_signer_address())
    }
}

/// Builds the consensus for the chain the node is launched on.
#[derive(Debug, Default, Clone, Copy)]
pub struct N42ConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for N42ConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type Consensus = Arc<N42Consensus<<Node as FullNodeTypes>::Provider>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        let chain_spec = ctx.chain_spec();
        n42_tx_types::set_alt_sig_enabled(reth_chainspec::qmdb::alt_sig_tx_enabled(chain_spec.genesis()));
        let consensus = if is_hotstuff_chain(&chain_spec) {
            let consensus = HotStuffConsensus::new(chain_spec);
            if let Some(key) = ctx.config().dev.consensus_signer_private_key.clone() {
                consensus.set_signer_key(Some(key))?;
            }
            N42Consensus::HotStuff(consensus)
        } else {
            N42Consensus::Apos(Box::new(APos::new(
                ctx.provider().clone(),
                chain_spec,
                ctx.config().dev.consensus_signer_private_key.clone(),
            )))
        };
        Ok(Arc::new(consensus))
    }
}
