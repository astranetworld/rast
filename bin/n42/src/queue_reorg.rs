// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the builder's queue gets back when the chain reorganises.
//!
//! With the direct ingest (`N42_TX_INGEST_DIRECT=1`) the queue is a
//! transaction's only holder, and the canonical pruner drops a block's
//! transactions as mined the moment the block is committed. When a
//! competing block replaces it, the reverted block's transactions that the
//! new chain does not carry have to go back, or every affected sender's
//! lane starts at a nonce ahead of the chain and the builder refuses it
//! for good (round 43: half-empty blocks for the rest of the leg).

use alloy_consensus::transaction::TxHashRef as _;
use n42_engine_types::N42PooledTransaction;
use n42_tx_types::N42Primitives;
use reth_execution_types::Chain;
use reth_primitives_traits::Recovered;
use reth_transaction_pool::PoolTransaction as _;

/// The transactions of the reverted chain `old` that the new chain `new`
/// does not carry, as pool transactions, in the order they had (block by
/// block, each block in order). One that cannot become a pool transaction
/// (a blob transaction without its sidecar) is left out.
pub fn reverted_transactions(old: &Chain<N42Primitives>, new: &Chain<N42Primitives>) -> Vec<N42PooledTransaction> {
    let carried: std::collections::HashSet<alloy_primitives::B256> =
        new.blocks_iter().flat_map(|b| b.body().transactions().map(|tx| *tx.tx_hash())).collect();
    let mut back = Vec::new();
    for block in old.blocks_iter() {
        for (sender, tx) in block.transactions_with_sender() {
            if carried.contains(tx.tx_hash()) {
                continue;
            }
            if let Ok(pooled) = N42PooledTransaction::try_from_consensus(Recovered::new_unchecked(tx.clone(), *sender)) {
                back.push(pooled);
            }
        }
    }
    back
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, Signed, TxEip1559};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
    use reth_primitives_traits::{RecoveredBlock, SealedBlock};
    use alloy_consensus::Transaction as _;

    fn addr(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    fn transfer(nonce: u64, seed: u8) -> n42_tx_types::N42TxEnvelope {
        let inner = TxEip1559 {
            chain_id: 1,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 10_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(addr(900)),
            value: U256::from(1),
            input: Bytes::new(),
            ..Default::default()
        };
        let hash = B256::repeat_byte(seed);
        n42_tx_types::N42TxEnvelope::from(reth_ethereum_primitives::TransactionSigned::from(Signed::new_unchecked(inner, Signature::test_signature(), hash)))
    }

    fn block(number: u64, txs: Vec<(Address, n42_tx_types::N42TxEnvelope)>) -> RecoveredBlock<n42_tx_types::Block> {
        let (senders, transactions): (Vec<_>, Vec<_>) = txs.into_iter().unzip();
        let header = Header { number, ..Default::default() };
        let body = n42_tx_types::BlockBody { transactions, ommers: Vec::new(), withdrawals: None };
        RecoveredBlock::new_sealed(SealedBlock::seal_slow(n42_tx_types::Block { header, body }), senders)
    }

    #[test]
    fn what_the_new_chain_does_not_carry_comes_back_in_order() {
        let (a, b) = (addr(1), addr(2));
        // The reverted chain: two blocks, a's nonces 5 and 6, b's nonce 9.
        let old = Chain::new(
            vec![block(10, vec![(a, transfer(5, 1)), (b, transfer(9, 2))]), block(11, vec![(a, transfer(6, 3))])],
            Default::default(),
            Default::default(),
        );
        // The new chain carries a's nonce 5 (same transaction) and something else.
        let new = Chain::new(vec![block(10, vec![(a, transfer(5, 1)), (b, transfer(20, 4))])], Default::default(), Default::default());
        let back = reverted_transactions(&old, &new);
        let got: Vec<(Address, u64)> = back.iter().map(|t| (t.sender(), t.nonce())).collect();
        assert_eq!(got, vec![(b, 9), (a, 6)], "b's 9 and a's 6 come back, a's 5 does not, in block order");
    }

    #[test]
    fn a_plain_revert_returns_everything() {
        let a = addr(1);
        let old = Chain::new(vec![block(10, vec![(a, transfer(1, 1)), (a, transfer(2, 2))])], Default::default(), Default::default());
        let new: Chain<N42Primitives> = Chain::default();
        let back = reverted_transactions(&old, &new);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].nonce(), 1);
        assert_eq!(back[1].nonce(), 2);
    }
}
