// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The block assembler the payload builder uses, with the roots it does not
//! need left out and the one it does computed in parallel.
//!
//! reth's assembler computes three things over the whole block before it can
//! hand a header back: the transactions root (a trie over every transaction's
//! encoding), the receipts root (a trie over every receipt) and the logs
//! bloom. Timed in the payload builder at the 163,000-transaction tier, that
//! step was 262-286 ms of a 650-780 ms build -- the largest single phase, ahead
//! of executing the transactions (184-273 ms).
//!
//! Two of the three are waste on a HotStuff chain. Its header profile is
//! gov5's, whose receipts root is a keccak over the receipts rather than a
//! trie, and the payload builder overwrites the field a moment after this
//! computes it; the bloom is kept. The transactions root is real, and half of
//! its cost is encoding 163,000 transactions one after another, which is what
//! the worker pool is for. The trie itself stays sequential.

use alloy_consensus::{proofs::calculate_receipt_root, Block, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_primitives::B256;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::{
    block::BlockExecutorFactory,
    eth::EthBlockExecutionCtx,
    execute::{BlockAssembler, BlockAssemblerInput, BlockExecutionError},
};
use reth_evm_ethereum::EthBlockAssembler;
use reth_primitives_traits::{logs_bloom, Receipt, SignedTransaction};
use std::sync::{Arc, Mutex};

/// The QMDB root, computed while the transactions trie is.
///
/// The root is over the execution's bundle, which the assembler is handed,
/// and it used to be computed by the payload builder *after* assembly: 63-113
/// ms at the 163,000-transaction tier, one after the other with a
/// transactions trie of about the same size. The two are independent, so the
/// assembler runs them side by side and leaves the result here for the
/// payload builder to collect.
pub struct QmdbRootJob {
    /// The forest to compute against.
    pub state: n42_qmdb_reth::QmdbNodeState,
    /// The block's parent, which the tree is computed on top of.
    pub parent: alloy_primitives::B256,
    /// Whether Prague is active at the block, which changes how the bundle is
    /// read.
    pub prague: bool,
    /// Where the result goes. `None` until the assembler has run.
    pub out: Arc<Mutex<Option<Result<n42_qmdb_reth::PreparedBlock, String>>>>,
}

impl std::fmt::Debug for QmdbRootJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmdbRootJob").field("parent", &self.parent).field("prague", &self.prague).finish_non_exhaustive()
    }
}

/// [`EthBlockAssembler`], with the roots precomputed the way described in the
/// module documentation.
#[derive(Debug)]
pub struct N42BlockAssembler<ChainSpec> {
    inner: EthBlockAssembler<ChainSpec>,
    /// Whether the chain's header profile replaces the receipts root, so the
    /// trie need not be built.
    hotstuff: bool,
    /// The QMDB root to compute alongside, on a QMDB chain.
    qmdb: Option<QmdbRootJob>,
}

impl<ChainSpec> N42BlockAssembler<ChainSpec> {
    /// Wraps reth's assembler. `hotstuff` says the receipts root will be
    /// replaced by the payload builder and need not be computed.
    pub const fn new(inner: EthBlockAssembler<ChainSpec>, hotstuff: bool) -> Self {
        Self { inner, hotstuff, qmdb: None }
    }

    /// Computes the QMDB root during assembly as well. See [`QmdbRootJob`].
    pub fn with_qmdb_root(mut self, job: QmdbRootJob) -> Self {
        self.qmdb = Some(job);
        self
    }
}

/// The transactions root, with the encodings produced in parallel and the
/// trie built in parallel.
///
/// Identical to `alloy_consensus::proofs::calculate_transaction_root`: the
/// trie is over each transaction's EIP-2718 encoding, keyed by index.
pub fn parallel_transaction_root<T: Encodable2718 + Sync>(transactions: &[T]) -> B256 {
    use rayon::prelude::*;
    let encoded: Vec<Vec<u8>> = transactions.par_iter().map(|tx| tx.encoded_2718()).collect();
    parallel_ordered_trie_root(&encoded)
}

/// Below this many items the sequential builder is used: the split's
/// bookkeeping is not worth it, and every ordinary Ethereum block is here.
const PARALLEL_TRIE_MIN_ITEMS: usize = 2_048;

/// The root of the ordered trie over `items` -- what `ordered_trie_root`
/// computes -- with the subtries built on the worker pool.
///
/// The keys are `rlp(index)`, so every key of the same byte length shares
/// its length byte and the items split naturally by all but their last
/// byte: 256 leaves under each such prefix. Each group's subtrie is built by
/// its own `HashBuilder` over the keys with the prefix stripped, and the
/// top-level builder is handed the group's root as a branch at that prefix,
/// which is how reth's own parallel state root joins its pieces. A group's
/// root is always a hashed node rather than an inlined one because the
/// values here are transactions, far past the 32-byte inline limit; a caller
/// with shorter values gets the sequential builder instead.
///
/// At the 163,000-transaction tier the sequential trie was ~80 ms of every
/// follower's import and ~110 ms of every leader's build; it is on both
/// critical paths, and nothing else in either overlaps with it.
pub fn parallel_ordered_trie_root<T: AsRef<[u8]> + Sync>(items: &[T]) -> B256 {
    use alloy_trie::{HashBuilder, Nibbles};
    use rayon::prelude::*;

    let sequential = || {
        alloy_trie::root::ordered_trie_root_with_encoder(items, |item, buf| buf.extend_from_slice(item.as_ref()))
    };
    if items.len() < PARALLEL_TRIE_MIN_ITEMS || items.iter().any(|v| v.as_ref().len() < 32) {
        return sequential();
    }

    // Every key, in the trie's order.
    let mut keyed: Vec<(Nibbles, usize)> = (0..items.len())
        .map(|i| (Nibbles::unpack(alloy_rlp::encode_fixed_size(&i)), i))
        .collect();
    keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    // Groups: keys of four nibbles or more, by all but their last two
    // nibbles; shorter keys stand alone as leaves.
    enum Piece {
        Leaf(Nibbles, usize),
        Group(Nibbles, Vec<(Nibbles, usize)>),
    }
    let mut pieces: Vec<Piece> = Vec::new();
    for (key, index) in keyed {
        if key.len() < 4 {
            pieces.push(Piece::Leaf(key, index));
            continue;
        }
        let prefix = key.slice(..key.len() - 2);
        match pieces.last_mut() {
            Some(Piece::Group(p, members)) if *p == prefix => members.push((key, index)),
            _ => pieces.push(Piece::Group(prefix, vec![(key, index)])),
        }
    }

    // Subtrie roots, in parallel. A group's root is handed up as a branch
    // node at its prefix, so it has to *be* one: its members must diverge at
    // the first nibble past the prefix. A group whose members all share that
    // nibble -- the last, partial group when the item count is 2 to 16 past
    // a multiple of 256 -- has an extension node for a root, and the parent
    // would put a second extension in front of it: block 319 of round
    // direct1, 8,200 transactions, sealed a root no follower could
    // reproduce. Such a group's few members go to the top-level builder as
    // leaves instead.
    let roots: Vec<Option<B256>> = pieces
        .par_iter()
        .map(|piece| match piece {
            Piece::Leaf(..) => None,
            Piece::Group(prefix, members) if members.len() > 1 => {
                let first = members[0].0.get(prefix.len());
                if members.iter().all(|(key, _)| key.get(prefix.len()) == first) {
                    return None;
                }
                let mut hb = HashBuilder::default();
                for (key, index) in members {
                    hb.add_leaf(key.slice(prefix.len()..), items[*index].as_ref());
                }
                Some(hb.root())
            }
            Piece::Group(..) => None,
        })
        .collect();

    let mut hb = HashBuilder::default();
    for (piece, root) in pieces.iter().zip(roots) {
        match (piece, root) {
            (Piece::Leaf(key, index), _) => hb.add_leaf(*key, items[*index].as_ref()),
            (Piece::Group(_, members), None) => {
                for (key, index) in members {
                    hb.add_leaf(*key, items[*index].as_ref());
                }
            }
            (Piece::Group(prefix, _), Some(root)) => hb.add_branch(*prefix, root, false),
        }
    }
    hb.root()
}

impl<F, ChainSpec> BlockAssembler<F> for N42BlockAssembler<ChainSpec>
where
    F: for<'a> BlockExecutorFactory<
        ExecutionCtx<'a> = EthBlockExecutionCtx<'a>,
        Transaction: SignedTransaction,
        Receipt: Receipt,
    >,
    ChainSpec: EthChainSpec + EthereumHardforks,
{
    type Block = Block<F::Transaction>;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, F>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let receipts = &input.output.receipts;
        let hotstuff = self.hotstuff;
        let bundle = input.bundle_state;
        let (transactions_root, (receipts_root, bloom)) = rayon::join(
            || {
                rayon::join(
                    || parallel_transaction_root(&input.transactions),
                    || {
                        if let Some(job) = &self.qmdb {
                            let changes = n42_qmdb_reth::changes_from_execution(bundle, job.prague);
                            let prepared = job.state.compute(job.parent, &changes).map_err(|e| e.to_string());
                            *job.out.lock().unwrap_or_else(|p| p.into_inner()) = Some(prepared);
                        }
                    },
                )
                .0
            },
            || {
                let bloom = logs_bloom(receipts.iter().flat_map(|r| r.logs()));
                // Replaced by gov5's keccak-of-receipts in the payload builder;
                // a placeholder here is never seen by anyone.
                let root = if hotstuff {
                    B256::ZERO
                } else {
                    calculate_receipt_root(
                        &receipts.iter().map(|r| r.with_bloom_ref()).collect::<Vec<_>>(),
                    )
                };
                (root, bloom)
            },
        );
        self.inner.assemble_block(input, Some(transactions_root), Some(receipts_root), Some(bloom))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip1559, TxEnvelope, TxLegacy};
    use alloy_primitives::{Address, Signature, TxKind, U256};

    /// The parallel trie is alloy's ordered trie, at every size where the
    /// key shape changes: one byte, two, three and four bytes of index, and
    /// the boundaries between them.
    #[test]
    fn parallel_ordered_trie_is_alloys_at_every_key_shape() {
        for n in [0usize, 1, 2, 3, 127, 128, 129, 255, 256, 257, 2_047, 2_048, 2_049, 4_096, 4_097, 65_535, 65_536, 65_537, 70_000, 163_000] {
            let items: Vec<Vec<u8>> = (0..n)
                .map(|i| {
                    let len = 40 + (i * 7) % 90;
                    (0..len).map(|j| ((i * 31 + j * 17) % 251) as u8).collect()
                })
                .collect();
            let want = alloy_trie::root::ordered_trie_root_with_encoder(&items, |item, buf| buf.extend_from_slice(item));
            assert_eq!(parallel_ordered_trie_root(&items), want, "n = {n}");
        }
    }

    /// Block 319 of round direct1 (8,200 transfers) sealed a transactions root
    /// no follower could reproduce. Every size around it, at a transfer's
    /// encoded length.
    #[test]
    fn parallel_ordered_trie_is_alloys_at_every_residue_mod_256() {
        // Every residue of the item count modulo 256 -- the size of a full
        // group -- at three-byte keys (past 2,048) and at four-byte keys
        // (past 65,536), plus the sizes around block 319's 8,200.
        let sizes = (2_048..2_048 + 300).chain(65_536 - 20..65_536 + 300).chain(8_150..8_250);
        for n in sizes {
            let items: Vec<Vec<u8>> = (0..n)
                .map(|i| {
                    let len = 108 + (i * 7) % 12;
                    (0..len).map(|j| ((i * 31 + j * 17 + n) % 251) as u8).collect()
                })
                .collect();
            let want = alloy_trie::root::ordered_trie_root_with_encoder(&items, |item, buf| buf.extend_from_slice(item));
            assert_eq!(parallel_ordered_trie_root(&items), want, "n = {n}");
        }
    }

    /// The parallel root is the sequential one, on typed and legacy
    /// transactions alike.
    #[test]
    fn parallel_root_matches_alloy() {
        let txs: Vec<TxEnvelope> = (0..500u64)
            .map(|n| {
                if n % 3 == 0 {
                    let tx = TxLegacy { chain_id: Some(1), nonce: n, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(n), ..Default::default() };
                    TxEnvelope::Legacy(Signed::new_unchecked(tx, Signature::test_signature(), Default::default()))
                } else {
                    let tx = TxEip1559 { chain_id: 1, nonce: n, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(n), ..Default::default() };
                    TxEnvelope::Eip1559(Signed::new_unchecked(tx, Signature::test_signature(), Default::default()))
                }
            })
            .collect();
        assert_eq!(parallel_transaction_root(&txs), alloy_consensus::proofs::calculate_transaction_root(&txs));
        assert_eq!(parallel_transaction_root::<TxEnvelope>(&[]), alloy_consensus::proofs::calculate_transaction_root::<TxEnvelope>(&[]));
    }
}
