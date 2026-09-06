// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the JSON-RPC layer needs of the envelope: building and signing a
//! request into it, faking one for `eth_simulateV1`, and a receipt response
//! that can say `type: 0x50`.

use crate::envelope::{N42TxEnvelope, N42TxType};
use alloy_consensus::{
    error::ValueError, Eip658Value, ReceiptEnvelope, ReceiptWithBloom, TxReceipt, Typed2718,
};
use alloy_network::TxSigner;
use alloy_primitives::{Bloom, Log as PrimitiveLog, Signature};
use alloy_rpc_types_eth::{Log, TransactionRequest};
use reth_ethereum_primitives::TransactionSigned;
use reth_rpc_traits::{SignTxRequestError, SignableTxRequest, TryIntoSimTx};
use serde::{Deserialize, Serialize};

impl SignableTxRequest<N42TxEnvelope> for TransactionRequest {
    async fn try_build_and_sign(
        self,
        signer: impl TxSigner<Signature> + Send,
    ) -> Result<N42TxEnvelope, SignTxRequestError> {
        // A request signed by the node's own secp256k1 signer is an Ethereum
        // transaction; 0x50 transactions are signed by their Ed25519 holders
        // and arrive raw.
        <Self as SignableTxRequest<TransactionSigned>>::try_build_and_sign(self, signer)
            .await
            .map(N42TxEnvelope::Eth)
    }
}

impl TryIntoSimTx<N42TxEnvelope> for TransactionRequest {
    fn try_into_sim_tx(self) -> Result<N42TxEnvelope, ValueError<Self>> {
        <Self as TryIntoSimTx<TransactionSigned>>::try_into_sim_tx(self).map(N42TxEnvelope::Eth)
    }
}

/// The receipt of a 0x50 transaction as JSON-RPC reports it: `type: 0x50`
/// with the usual status, gas, logs and bloom.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AltSigRpcReceipt {
    /// Always [`crate::ALT_SIG_TX_TYPE_ID`].
    #[serde(rename = "type", with = "alloy_serde::quantity")]
    pub tx_type: u8,
    /// Status, cumulative gas, logs and bloom.
    #[serde(flatten)]
    pub inner: ReceiptWithBloom<alloy_consensus::Receipt<Log>>,
}

/// An RPC receipt of any N42 transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum N42RpcReceipt {
    /// An Ethereum transaction's receipt, typed 0x00-0x04.
    Eth(ReceiptEnvelope<Log>),
    /// A 0x50 transaction's receipt.
    AltSig(AltSigRpcReceipt),
}

impl N42RpcReceipt {
    /// Builds the RPC receipt from a consensus receipt whose logs already
    /// carry their RPC context.
    pub fn from_receipt(tx_type: N42TxType, receipt: alloy_consensus::Receipt<Log>) -> Self {
        match tx_type {
            N42TxType::Eth(ty) => Self::Eth(ReceiptEnvelope::from_typed(ty, receipt)),
            N42TxType::AltSig => Self::AltSig(AltSigRpcReceipt {
                tx_type: crate::ALT_SIG_TX_TYPE_ID,
                inner: receipt.into_with_bloom(),
            }),
        }
    }
}

impl Typed2718 for N42RpcReceipt {
    fn ty(&self) -> u8 {
        match self {
            Self::Eth(r) => Typed2718::ty(&r.tx_type()),
            Self::AltSig(r) => r.tx_type,
        }
    }
}

impl TxReceipt for N42RpcReceipt {
    type Log = Log;

    fn status_or_post_state(&self) -> Eip658Value {
        match self {
            Self::Eth(r) => r.status_or_post_state(),
            Self::AltSig(r) => r.inner.receipt.status_or_post_state(),
        }
    }

    fn status(&self) -> bool {
        match self {
            Self::Eth(r) => r.status(),
            Self::AltSig(r) => r.inner.receipt.status(),
        }
    }

    fn bloom(&self) -> Bloom {
        match self {
            Self::Eth(r) => r.bloom(),
            Self::AltSig(r) => r.inner.logs_bloom,
        }
    }

    fn bloom_cheap(&self) -> Option<Bloom> {
        Some(self.bloom())
    }

    fn cumulative_gas_used(&self) -> u64 {
        match self {
            Self::Eth(r) => r.cumulative_gas_used(),
            Self::AltSig(r) => r.inner.receipt.cumulative_gas_used(),
        }
    }

    fn logs(&self) -> &[Log] {
        match self {
            Self::Eth(r) => r.logs(),
            Self::AltSig(r) => r.inner.receipt.logs(),
        }
    }

    fn into_logs(self) -> Vec<Log> {
        match self {
            Self::Eth(r) => r.into_logs(),
            Self::AltSig(r) => r.inner.receipt.logs,
        }
    }
}

// Keep the primitive log type in scope for the receipt conversions callers write.
#[allow(dead_code)]
type _PrimitiveLog = PrimitiveLog;
