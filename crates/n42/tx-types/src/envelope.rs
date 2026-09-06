// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's transaction envelopes: reth's Ethereum envelope with the 0x50
//! transaction beside it, in consensus and pooled form.

use crate::alt_sig::AltSigTx;
use alloy_consensus::{
    crypto::RecoveryError,
    error::ValueError,
    transaction::{SignerRecoverable, TxHashRef},
    InMemorySize, TransactionEnvelope,
};
use alloy_eips::eip7594::BlobTransactionSidecarVariant;
use alloy_primitives::{Address, B256};
use reth_ethereum_primitives::{PooledTransactionVariant, TransactionSigned};

/// A signed transaction as it appears in a block: an Ethereum transaction or
/// a 0x50 alternative-signature transaction.
#[derive(Clone, Debug, TransactionEnvelope)]
#[envelope(tx_type_name = N42TxType)]
pub enum N42TxEnvelope {
    /// reth's Ethereum envelope (types 0x00-0x04).
    #[envelope(flatten)]
    Eth(TransactionSigned),
    /// The 0x50 alternative-signature transaction.
    #[envelope(ty = 0x50)]
    AltSig(AltSigTx),
}

/// A transaction as it travels between pools: an Ethereum pooled transaction
/// (a blob transaction carries its sidecar here) or a 0x50 transaction.
#[derive(Clone, Debug, TransactionEnvelope)]
#[envelope(tx_type_name = N42PooledTxType)]
pub enum N42PooledTxEnvelope {
    /// reth's pooled Ethereum envelope.
    #[envelope(flatten)]
    Eth(PooledTransactionVariant),
    /// The 0x50 alternative-signature transaction.
    #[envelope(ty = 0x50)]
    AltSig(AltSigTx),
}

impl N42TxEnvelope {
    /// The Ethereum transaction, if this is one.
    pub const fn as_eth(&self) -> Option<&TransactionSigned> {
        match self {
            Self::Eth(tx) => Some(tx),
            Self::AltSig(_) => None,
        }
    }

    /// The 0x50 transaction, if this is one.
    pub const fn as_alt_sig(&self) -> Option<&AltSigTx> {
        match self {
            Self::Eth(_) => None,
            Self::AltSig(tx) => Some(tx),
        }
    }

    /// Whether this is a 0x50 transaction.
    pub const fn is_alt_sig(&self) -> bool {
        matches!(self, Self::AltSig(_))
    }

    /// The transaction hash.
    pub fn hash(&self) -> &B256 {
        match self {
            Self::Eth(tx) => tx.hash(),
            Self::AltSig(tx) => tx.hash(),
        }
    }

    /// Converts into the pooled form. Fails for a blob transaction, which needs
    /// its sidecar to be pooled.
    pub fn try_into_pooled(self) -> Result<N42PooledTxEnvelope, ValueError<Self>> {
        match self {
            Self::Eth(tx) => tx
                .try_into_pooled()
                .map(N42PooledTxEnvelope::Eth)
                .map_err(|err| err.map(Self::Eth)),
            Self::AltSig(tx) => Ok(N42PooledTxEnvelope::AltSig(tx)),
        }
    }

    /// Converts a blob transaction into its pooled form with `sidecar`. Fails
    /// for every other kind of transaction.
    pub fn try_into_pooled_eip4844(
        self,
        sidecar: BlobTransactionSidecarVariant,
    ) -> Result<N42PooledTxEnvelope, ValueError<Self>> {
        match self {
            Self::Eth(tx) => tx
                .try_into_pooled_eip4844(sidecar)
                .map(N42PooledTxEnvelope::Eth)
                .map_err(|err| err.map(Self::Eth)),
            this @ Self::AltSig(_) => Err(ValueError::new_static(this, "Expected 4844 transaction")),
        }
    }
}

impl N42PooledTxEnvelope {
    /// The 0x50 transaction, if this is one.
    pub const fn as_alt_sig(&self) -> Option<&AltSigTx> {
        match self {
            Self::Eth(_) => None,
            Self::AltSig(tx) => Some(tx),
        }
    }

    /// Whether this is a 0x50 transaction.
    pub const fn is_alt_sig(&self) -> bool {
        matches!(self, Self::AltSig(_))
    }

    /// The transaction hash.
    pub fn hash(&self) -> &B256 {
        match self {
            Self::Eth(tx) => tx.hash(),
            Self::AltSig(tx) => tx.hash(),
        }
    }
}

impl From<TransactionSigned> for N42TxEnvelope {
    fn from(tx: TransactionSigned) -> Self {
        Self::Eth(tx)
    }
}

impl From<AltSigTx> for N42TxEnvelope {
    fn from(tx: AltSigTx) -> Self {
        Self::AltSig(tx)
    }
}

impl From<PooledTransactionVariant> for N42PooledTxEnvelope {
    fn from(tx: PooledTransactionVariant) -> Self {
        Self::Eth(tx)
    }
}

impl From<AltSigTx> for N42PooledTxEnvelope {
    fn from(tx: AltSigTx) -> Self {
        Self::AltSig(tx)
    }
}

impl From<N42PooledTxEnvelope> for N42TxEnvelope {
    fn from(tx: N42PooledTxEnvelope) -> Self {
        match tx {
            N42PooledTxEnvelope::Eth(tx) => Self::Eth(tx.into()),
            N42PooledTxEnvelope::AltSig(tx) => Self::AltSig(tx),
        }
    }
}

impl TryFrom<N42TxEnvelope> for N42PooledTxEnvelope {
    type Error = ValueError<N42TxEnvelope>;

    fn try_from(tx: N42TxEnvelope) -> Result<Self, Self::Error> {
        tx.try_into_pooled()
    }
}

impl SignerRecoverable for N42TxEnvelope {
    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        match self {
            Self::Eth(tx) => tx.recover_signer(),
            Self::AltSig(tx) => tx.recover_signer(),
        }
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        match self {
            Self::Eth(tx) => tx.recover_signer_unchecked(),
            Self::AltSig(tx) => tx.recover_signer_unchecked(),
        }
    }

    fn recover_unchecked_with_buf(&self, buf: &mut alloc::vec::Vec<u8>) -> Result<Address, RecoveryError> {
        match self {
            Self::Eth(tx) => tx.recover_unchecked_with_buf(buf),
            Self::AltSig(tx) => tx.recover_signer_unchecked(),
        }
    }
}

impl SignerRecoverable for N42PooledTxEnvelope {
    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        match self {
            Self::Eth(tx) => tx.recover_signer(),
            Self::AltSig(tx) => tx.recover_signer(),
        }
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        match self {
            Self::Eth(tx) => tx.recover_signer_unchecked(),
            Self::AltSig(tx) => tx.recover_signer_unchecked(),
        }
    }

    fn recover_unchecked_with_buf(&self, buf: &mut alloc::vec::Vec<u8>) -> Result<Address, RecoveryError> {
        match self {
            Self::Eth(tx) => tx.recover_unchecked_with_buf(buf),
            Self::AltSig(tx) => tx.recover_signer_unchecked(),
        }
    }
}

impl TxHashRef for N42TxEnvelope {
    fn tx_hash(&self) -> &B256 {
        self.hash()
    }
}

impl TxHashRef for N42PooledTxEnvelope {
    fn tx_hash(&self) -> &B256 {
        self.hash()
    }
}

impl InMemorySize for N42TxEnvelope {
    fn size(&self) -> usize {
        match self {
            Self::Eth(tx) => tx.size(),
            Self::AltSig(tx) => tx.size(),
        }
    }
}

impl InMemorySize for N42PooledTxEnvelope {
    fn size(&self) -> usize {
        match self {
            Self::Eth(tx) => tx.size(),
            Self::AltSig(tx) => tx.size(),
        }
    }
}

/// Legacy, as `TxType`'s default is.
impl Default for N42TxType {
    fn default() -> Self {
        Self::Eth(alloy_consensus::TxType::default())
    }
}

impl InMemorySize for N42TxType {
    fn size(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}

impl InMemorySize for N42PooledTxType {
    fn size(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}
