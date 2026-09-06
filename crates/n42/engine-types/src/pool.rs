// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! reth's pool transaction over [`N42TxEnvelope`]: `EthPooledTransaction`
//! with the node's envelope as its consensus type, so a 0x50 transaction can
//! sit in the pool beside Ethereum's.

use alloy_consensus::{transaction::TxHashRef as _, BlobTransactionValidationError, Transaction as _, Typed2718};
use alloy_eips::{
    eip2718::Encodable2718, eip2930::AccessList, eip4844::env_settings::KzgSettings,
    eip7594::BlobTransactionSidecarVariant, eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, Bytes, TxHash, TxKind, B256, U256};
use n42_tx_types::{N42PooledTxEnvelope, N42TxEnvelope};
use reth_primitives_traits::{InMemorySize, Recovered, SignedTransaction};
use reth_transaction_pool::{
    blobstore::{BlobCellAvailability, PooledBlobSidecar},
    CoinbaseTipOrdering, EthBlobTransactionSidecar, EthPoolTransaction, EthTransactionValidator, Pool,
    PoolTransaction, TransactionValidationTaskExecutor,
};
use std::sync::Arc;

/// The pool of the node: reth's Ethereum pool over [`N42PooledTransaction`].
pub type N42TransactionPool<Client, S, Evm> = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<Client, N42PooledTransaction, Evm>>,
    CoinbaseTipOrdering<N42PooledTransaction>,
    S,
>;

/// A transaction in the pool, with its sender and its cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N42PooledTransaction {
    /// The transaction and its sender.
    pub transaction: Recovered<N42TxEnvelope>,
    /// `max_fee_per_gas * gas_limit + value` (+ blob cost).
    pub cost: U256,
    /// The length of the 2718 encoding.
    pub encoded_length: usize,
    /// The blob sidecar, for a blob transaction.
    pub blob_sidecar: EthBlobTransactionSidecar,
    blob_cell_availability: Option<BlobCellAvailability>,
}

impl N42PooledTransaction {
    /// Wraps a recovered transaction of `encoded_length` bytes.
    pub fn new(transaction: Recovered<N42TxEnvelope>, encoded_length: usize) -> Self {
        let mut blob_cell_availability = None;
        let mut blob_sidecar = EthBlobTransactionSidecar::None;
        let gas_cost =
            U256::from(transaction.max_fee_per_gas()).saturating_mul(U256::from(transaction.gas_limit()));
        let mut cost = gas_cost.saturating_add(transaction.value());
        if let (Some(blob_gas_used), Some(max_fee_per_blob_gas)) =
            (transaction.blob_gas_used(), transaction.max_fee_per_blob_gas())
        {
            cost = cost.saturating_add(U256::from(max_fee_per_blob_gas.saturating_mul(blob_gas_used as u128)));
            blob_sidecar = EthBlobTransactionSidecar::Missing;
            blob_cell_availability = Some(BlobCellAvailability::full());
        }
        Self { transaction, cost, encoded_length, blob_sidecar, blob_cell_availability }
    }

    /// The transaction and its sender.
    pub const fn transaction(&self) -> &Recovered<N42TxEnvelope> {
        &self.transaction
    }

    /// Which blob cells are available, for a blob transaction.
    pub const fn blob_cell_availability(&self) -> Option<&BlobCellAvailability> {
        self.blob_cell_availability.as_ref()
    }
}

impl PoolTransaction for N42PooledTransaction {
    type TryFromConsensusError = alloy_consensus::error::ValueError<N42TxEnvelope>;
    type Consensus = N42TxEnvelope;
    type Pooled = N42PooledTxEnvelope;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.transaction().clone()
    }

    fn consensus_ref(&self) -> Recovered<&Self::Consensus> {
        Recovered::new_unchecked(&*self.transaction, self.transaction.signer())
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.transaction
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        let encoded_length = tx.encode_2718_len();
        let (tx, signer) = tx.into_parts();
        match tx {
            N42PooledTxEnvelope::Eth(reth_ethereum_primitives::PooledTransactionVariant::Eip4844(tx)) => {
                let (tx, sig, hash) = tx.into_parts();
                let (tx, blob) = tx.into_parts();
                let tx = alloy_consensus::Signed::new_unchecked(tx, sig, hash);
                let tx = N42TxEnvelope::Eth(reth_ethereum_primitives::TransactionSigned::from(tx));
                let tx = Recovered::new_unchecked(tx, signer);
                let mut pooled = Self::new(tx, encoded_length);
                if let Some(availability) = pooled.blob_cell_availability.clone() {
                    pooled.blob_sidecar =
                        EthBlobTransactionSidecar::Present(PooledBlobSidecar::new(blob, availability));
                }
                pooled
            }
            tx => {
                let tx = Recovered::new_unchecked(tx.into(), signer);
                Self::new(tx, encoded_length)
            }
        }
    }

    fn hash(&self) -> &TxHash {
        self.transaction.tx_hash()
    }

    fn sender(&self) -> Address {
        self.transaction.signer()
    }

    fn sender_ref(&self) -> &Address {
        self.transaction.signer_ref()
    }

    fn cost(&self) -> &U256 {
        &self.cost
    }

    fn encoded_length(&self) -> usize {
        self.encoded_length
    }
}

impl Typed2718 for N42PooledTransaction {
    fn ty(&self) -> u8 {
        self.transaction.ty()
    }
}

impl InMemorySize for N42PooledTransaction {
    fn size(&self) -> usize {
        self.transaction.size()
    }
}

impl alloy_consensus::Transaction for N42PooledTransaction {
    fn chain_id(&self) -> Option<alloy_primitives::ChainId> {
        self.transaction.chain_id()
    }
    fn nonce(&self) -> u64 {
        self.transaction.nonce()
    }
    fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit()
    }
    fn gas_price(&self) -> Option<u128> {
        self.transaction.gas_price()
    }
    fn max_fee_per_gas(&self) -> u128 {
        self.transaction.max_fee_per_gas()
    }
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.transaction.max_priority_fee_per_gas()
    }
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.transaction.max_fee_per_blob_gas()
    }
    fn priority_fee_or_price(&self) -> u128 {
        self.transaction.priority_fee_or_price()
    }
    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.transaction.effective_gas_price(base_fee)
    }
    fn is_dynamic_fee(&self) -> bool {
        self.transaction.is_dynamic_fee()
    }
    fn kind(&self) -> TxKind {
        self.transaction.kind()
    }
    fn is_create(&self) -> bool {
        self.transaction.is_create()
    }
    fn value(&self) -> U256 {
        self.transaction.value()
    }
    fn input(&self) -> &Bytes {
        self.transaction.input()
    }
    fn access_list(&self) -> Option<&AccessList> {
        self.transaction.access_list()
    }
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.transaction.blob_versioned_hashes()
    }
    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.transaction.authorization_list()
    }
}

impl EthPoolTransaction for N42PooledTransaction {
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        if self.is_eip4844() {
            std::mem::replace(&mut self.blob_sidecar, EthBlobTransactionSidecar::Missing)
        } else {
            EthBlobTransactionSidecar::None
        }
    }

    fn blob_cell_availability(&self) -> Option<&BlobCellAvailability> {
        Self::blob_cell_availability(self)
    }

    fn try_into_pooled_eip4844(self, sidecar: Arc<BlobTransactionSidecarVariant>) -> Option<Recovered<Self::Pooled>> {
        let (signed_transaction, signer) = self.into_consensus().into_parts();
        let pooled_transaction = signed_transaction.try_into_pooled_eip4844(Arc::unwrap_or_clone(sidecar)).ok()?;
        Some(Recovered::new_unchecked(pooled_transaction, signer))
    }

    fn try_from_eip4844(tx: Recovered<Self::Consensus>, sidecar: BlobTransactionSidecarVariant) -> Option<Self> {
        let (tx, signer) = tx.into_parts();
        tx.try_into_pooled_eip4844(sidecar).ok().map(|tx| tx.with_signer(signer)).map(Self::from_pooled)
    }

    fn validate_blob(
        &self,
        sidecar: &BlobTransactionSidecarVariant,
        settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        match self.transaction.inner().as_eth().and_then(|tx| tx.as_eip4844()) {
            Some(tx) => tx.tx().validate_blob(sidecar, settings),
            _ => Err(BlobTransactionValidationError::NotBlobTransaction(self.ty())),
        }
    }
}
