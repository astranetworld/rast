// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The JSON-RPC type set over [`N42TxEnvelope`]: responses that can carry a
//! 0x50 transaction and its receipt, and the `eth_` API builder that uses
//! them.

use alloy_rpc_types_eth::{Log, TransactionReceipt, TransactionRequest};
use n42_tx_types::{N42RpcReceipt, N42TxEnvelope, Receipt};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeTypes, PrimitivesTy};
use reth_node_builder::rpc::{EthApiBuilder, EthApiCtx};
use reth_primitives_traits::TransactionMeta;
use reth_provider::ChainSpecProvider;
use reth_rpc::EthApi;
use reth_rpc_convert::{RpcConverter, RpcTypes};
use reth_rpc_eth_types::{receipt::EthReceiptConverter, EthApiError};

/// The RPC types of the node.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct N42RpcTypes;

impl RpcTypes for N42RpcTypes {
    type Header = alloy_rpc_types_eth::Header;
    type Receipt = TransactionReceipt<N42RpcReceipt>;
    type Log = Log;
    type TransactionResponse = alloy_rpc_types_eth::Transaction<N42TxEnvelope>;
    type TransactionRequest = TransactionRequest;
}

/// Builds the RPC receipt of a consensus receipt, giving its logs their
/// block and transaction context.
pub fn build_rpc_receipt(receipt: Receipt, next_log_index: usize, meta: TransactionMeta) -> N42RpcReceipt {
    let Receipt { tx_type, success, cumulative_gas_used, logs } = receipt;
    let logs = logs
        .into_iter()
        .enumerate()
        .map(|(i, log)| Log {
            inner: log,
            block_hash: Some(meta.block_hash),
            block_number: Some(meta.block_number),
            block_timestamp: Some(meta.timestamp),
            transaction_hash: Some(meta.tx_hash),
            transaction_index: Some(meta.index),
            log_index: Some((next_log_index + i) as u64),
            removed: false,
        })
        .collect();
    let receipt = alloy_consensus::Receipt {
        status: alloy_consensus::Eip658Value::Eip658(success),
        cumulative_gas_used,
        logs,
    };
    N42RpcReceipt::from_receipt(tx_type, receipt)
}

/// The receipt converter of the node.
pub type N42ReceiptConverter<ChainSpec> =
    EthReceiptConverter<ChainSpec, fn(Receipt, usize, TransactionMeta) -> N42RpcReceipt>;

/// The converter for `chain_spec`.
pub fn n42_receipt_converter<ChainSpec>(chain_spec: std::sync::Arc<ChainSpec>) -> N42ReceiptConverter<ChainSpec> {
    EthReceiptConverter::new(chain_spec)
        .with_builder(build_rpc_receipt as fn(Receipt, usize, TransactionMeta) -> N42RpcReceipt)
}

/// The RPC converter for a node with components `N`.
pub type N42RpcConverterFor<N> = RpcConverter<
    N42RpcTypes,
    <N as FullNodeComponents>::Evm,
    N42ReceiptConverter<<<N as FullNodeTypes>::Provider as ChainSpecProvider>::ChainSpec>,
>;

/// The `eth_` API for a node with components `N`.
pub type N42EthApiFor<N> = EthApi<N, N42RpcConverterFor<N>>;

/// Builds the `eth_` API over [`N42RpcTypes`].
#[derive(Debug, Default, Clone, Copy)]
pub struct N42EthApiBuilder;

impl<N> EthApiBuilder<N> for N42EthApiBuilder
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: reth_chainspec::Hardforks + EthereumHardforks + EthChainSpec,
            Primitives = n42_tx_types::N42Primitives,
        >,
        Evm: reth_evm::ConfigureEvm<
            NextBlockEnvCtx: reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<reth_node_api::HeaderTy<N::Types>>,
        >,
    >,
    N42RpcConverterFor<N>: reth_rpc_eth_api::RpcConvert<
        Primitives = PrimitivesTy<N::Types>,
        Error = EthApiError,
        Network = N42RpcTypes,
        Evm = N::Evm,
    >,
    EthApiError: reth_rpc_eth_types::error::FromEvmError<N::Evm>,
{
    type EthApi = N42EthApiFor<N>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        let chain_spec = ctx.components.provider().chain_spec();
        Ok(ctx
            .eth_api_builder()
            .map_converter(|_| RpcConverter::new(n42_receipt_converter(chain_spec)))
            .build())
    }
}
