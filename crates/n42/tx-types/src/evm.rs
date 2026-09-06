// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The EVM's view of the envelope.
//!
//! A 0x50 transaction executes as an EIP-1559 call from the address its key
//! derives: `tx_type` 2, the caller already authenticated. Nothing in
//! execution knows which algorithm signed it.

use crate::{alt_sig::AltSigTx, envelope::N42TxEnvelope};
use alloy_evm::{FromRecoveredTx, FromTxWithEncoded};
use alloy_primitives::{Address, Bytes, TxKind};
use revm::context::TxEnv;

/// The EIP-1559 type byte revm sees for a 0x50 transaction.
const EXECUTES_AS: u8 = 2;

fn alt_sig_tx_env(tx: &AltSigTx, caller: Address) -> TxEnv {
    let inner = tx.tx();
    TxEnv {
        tx_type: EXECUTES_AS,
        caller,
        gas_limit: inner.gas_limit,
        gas_price: inner.max_fee_per_gas,
        kind: TxKind::Call(inner.to),
        value: inner.value,
        data: inner.input.clone(),
        nonce: inner.nonce,
        chain_id: Some(inner.chain_id),
        access_list: inner.access_list.clone(),
        gas_priority_fee: Some(inner.max_priority_fee_per_gas),
        ..Default::default()
    }
}

impl FromRecoveredTx<AltSigTx> for TxEnv {
    fn from_recovered_tx(tx: &AltSigTx, caller: Address) -> Self {
        alt_sig_tx_env(tx, caller)
    }
}

impl FromTxWithEncoded<AltSigTx> for TxEnv {
    fn from_encoded_tx(tx: &AltSigTx, caller: Address, _encoded: Bytes) -> Self {
        alt_sig_tx_env(tx, caller)
    }
}

impl FromRecoveredTx<N42TxEnvelope> for TxEnv {
    fn from_recovered_tx(tx: &N42TxEnvelope, caller: Address) -> Self {
        match tx {
            N42TxEnvelope::Eth(tx) => Self::from_recovered_tx(tx, caller),
            N42TxEnvelope::AltSig(tx) => alt_sig_tx_env(tx, caller),
        }
    }
}

impl FromTxWithEncoded<N42TxEnvelope> for TxEnv {
    fn from_encoded_tx(tx: &N42TxEnvelope, caller: Address, encoded: Bytes) -> Self {
        match tx {
            N42TxEnvelope::Eth(tx) => Self::from_encoded_tx(tx, caller, encoded),
            N42TxEnvelope::AltSig(tx) => alt_sig_tx_env(tx, caller),
        }
    }
}
