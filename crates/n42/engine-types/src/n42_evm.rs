// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's EVM configuration over [`N42Primitives`].
//!
//! reth's `EthEvmConfig` is pinned to the Ethereum envelope through its
//! receipt builder and its `Primitives`. This is the same configuration
//! (same block environments, same assembler, same executor factory, the
//! node's [`N42EvmFactory`](crate::fast_transfer::N42EvmFactory) with the
//! plain-transfer path) with [`N42TxEnvelope`] as the transaction, so a block
//! may carry 0x50 transactions.

use alloy_consensus::Header;
use alloy_eips::Decodable2718;
use alloy_evm::{
    eth::{receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx}, spec::EthExecutorSpec, EthBlockExecutionCtx, EthBlockExecutorFactory},
    FromRecoveredTx, FromTxWithEncoded,
};
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types_engine::ExecutionData;
use n42_tx_types::{AltSigSenderCache, N42Primitives, N42TxEnvelope, N42TxType, Receipt};
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, Hardforks};
use reth_evm::{
    eth::NextEvmEnvAttributes, precompiles::PrecompilesMap, ConfigureEngineEvm, ConfigureEvm, Evm,
    EvmEnv, EvmEnvFor, EvmFactory, ExecutableTxIterator, ExecutionCtxFor, NextBlockEnvAttributes,
    SenderRecoveryCache, TransactionEnvMut,
};
use reth_evm_ethereum::{revm_spec_by_timestamp_and_block_number, EthBlockAssembler};
use reth_primitives_traits::{constants::MAX_TX_GAS_LIMIT_OSAKA, SealedBlock, SealedHeader, SignedTransaction, TxTy};
use reth_storage_errors::any::AnyError;
use revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
    primitives::hardfork::SpecId,
};
use std::{borrow::Cow, convert::Infallible, fmt::Debug, sync::Arc};

/// Builds [`Receipt`]s (typed by [`N42TxType`]) from execution results.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct N42ReceiptBuilder;

impl ReceiptBuilder for N42ReceiptBuilder {
    type Transaction = N42TxEnvelope;
    type Receipt = Receipt;

    fn build_receipt<E: Evm>(&self, ctx: ReceiptBuilderCtx<'_, N42TxType, E>) -> Self::Receipt {
        let ReceiptBuilderCtx { tx_type, result, cumulative_gas_used, .. } = ctx;
        Receipt { tx_type, success: result.is_success(), cumulative_gas_used, logs: result.into_logs() }
    }
}

/// The block executor factory of [`N42EvmConfig`].
pub type N42BlockExecutorFactory<ChainSpec = reth_chainspec::ChainSpec, EvmF = crate::fast_transfer::N42EvmFactory> =
    EthBlockExecutorFactory<N42ReceiptBuilder, Arc<ChainSpec>, EvmF>;

/// Ethereum's EVM configuration with [`N42TxEnvelope`] as the transaction.
#[derive(Debug, Clone)]
pub struct N42EvmConfig<C = ChainSpec, EvmF = crate::fast_transfer::N42EvmFactory> {
    /// The executor factory.
    pub executor_factory: N42BlockExecutorFactory<C, EvmF>,
    /// The block assembler.
    pub block_assembler: EthBlockAssembler<C>,
    /// Cache of recovered senders, when the node keeps one.
    pub sender_recovery_cache: Option<SenderRecoveryCache>,
}

impl<C, EvmF> N42EvmConfig<C, EvmF> {
    /// Creates the configuration for `chain_spec` with `evm_factory`.
    pub fn new_with_evm_factory(chain_spec: Arc<C>, evm_factory: EvmF) -> Self {
        Self {
            block_assembler: EthBlockAssembler::new(chain_spec.clone()),
            sender_recovery_cache: None,
            executor_factory: EthBlockExecutorFactory::new(N42ReceiptBuilder, chain_spec, evm_factory),
        }
    }

    /// The chain spec.
    pub const fn chain_spec(&self) -> &Arc<C> {
        self.executor_factory.spec()
    }

    /// Uses `cache` for sender recovery on import.
    pub fn with_sender_recovery_cache(mut self, cache: SenderRecoveryCache) -> Self {
        self.sender_recovery_cache = Some(cache);
        self
    }
}

impl<C, EvmF> ConfigureEvm for N42EvmConfig<C, EvmF>
where
    C: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnvMut + FromRecoveredTx<N42TxEnvelope> + FromTxWithEncoded<N42TxEnvelope>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    type Primitives = N42Primitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = N42BlockExecutorFactory<C, EvmF>;
    type BlockAssembler = EthBlockAssembler<C>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv<SpecId>, Self::Error> {
        Ok(EvmEnv::for_eth_block(
            header,
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(header.timestamp),
        ))
    }

    fn next_evm_env(&self, parent: &Header, attributes: &NextBlockEnvAttributes) -> Result<EvmEnv, Self::Error> {
        Ok(EvmEnv::for_eth_next_block(
            parent,
            NextEvmEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: attributes.prev_randao,
                gas_limit: attributes.gas_limit,
                slot_number: attributes.slot_number,
            },
            self.chain_spec().next_block_base_fee(parent, attributes.timestamp).unwrap_or_default(),
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(attributes.timestamp),
        ))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<n42_tx_types::Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(block.transaction_count()),
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: block.header().extra_data.clone(),
            slot_number: block.header().slot_number,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: None,
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(|w| Cow::Owned(w.into_inner())),
            extra_data: attributes.extra_data,
            slot_number: attributes.slot_number,
        })
    }
}

impl<C, EvmF> ConfigureEngineEvm<ExecutionData> for N42EvmConfig<C, EvmF>
where
    C: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + EthereumHardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnvMut + FromRecoveredTx<N42TxEnvelope> + FromTxWithEncoded<N42TxEnvelope>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        let timestamp = payload.payload.timestamp();
        let block_number = payload.payload.block_number();

        let blob_params = self.chain_spec().blob_params_at_timestamp(timestamp);
        let spec = revm_spec_by_timestamp_and_block_number(self.chain_spec(), timestamp, block_number);

        let mut cfg_env =
            CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec_and_mainnet_gas_params(spec);

        if let Some(blob_params) = &blob_params {
            cfg_env.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        }

        if self.chain_spec().is_osaka_active_at_timestamp(timestamp) {
            cfg_env.tx_gas_limit_cap = Some(MAX_TX_GAS_LIMIT_OSAKA);
        }

        let blob_excess_gas_and_price =
            payload.payload.excess_blob_gas().zip(blob_params).map(|(excess_blob_gas, params)| {
                let blob_gasprice = params.calc_blob_fee(excess_blob_gas);
                BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }
            });

        let block_env = BlockEnv {
            number: U256::from(block_number),
            beneficiary: payload.payload.fee_recipient(),
            timestamp: U256::from(timestamp),
            difficulty: if spec >= SpecId::MERGE { U256::ZERO } else { payload.payload.as_v1().prev_randao.into() },
            prevrandao: (spec >= SpecId::MERGE).then(|| payload.payload.as_v1().prev_randao),
            gas_limit: payload.payload.gas_limit(),
            basefee: payload.payload.saturated_base_fee_per_gas(),
            blob_excess_gas_and_price,
            slot_num: payload.payload.as_v4().map(|v4| v4.slot_number).unwrap_or_default(),
        };

        Ok(EvmEnv { cfg_env, block_env })
    }

    fn context_for_payload<'a>(&self, payload: &'a ExecutionData) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(payload.payload.transactions().len()),
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            ommers: &[],
            withdrawals: payload.payload.withdrawals().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: payload.payload.as_v1().extra_data.clone(),
            slot_number: payload.payload.as_v4().map(|v4| v4.slot_number),
        })
    }

    fn tx_iterator_for_payload(&self, payload: &ExecutionData) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let txs = payload.payload.transactions().clone();
        let sender_recovery_cache = self.sender_recovery_cache.clone();
        let convert = move |tx: Bytes| {
            let tx = TxTy::<Self::Primitives>::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = match &tx {
                // Verified in a batch by whoever admitted it; a miss verifies once here.
                N42TxEnvelope::AltSig(alt) => {
                    let cache = AltSigSenderCache::global();
                    match cache.get(alt.hash()) {
                        Some(sender) => Ok(sender),
                        None => tx.try_recover().inspect(|sender| cache.insert(*alt.hash(), *sender)),
                    }
                }
                N42TxEnvelope::Eth(_) => {
                    if let Some(cache) = &sender_recovery_cache { cache.recover(&tx) } else { tx.try_recover() }
                }
            }
            .map_err(AnyError::new)?;
            Ok::<_, AnyError>(tx.with_signer(signer))
        };
        Ok((txs, convert))
    }
}
