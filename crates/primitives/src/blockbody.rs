use crate::block::Block;
use crate::reward::Rewards;
use crate::verifier::Verifiers;
use crate::{Header, TransactionSigned, Withdrawals, B256};
use alloy_rlp::RlpDecodable;
use alloy_rlp::RlpEncodable;
use reth_primitives_traits::Requests;
use serde::Deserialize;
use serde::Serialize;

// #[cfg(any(test, feature = "arbitrary"))]
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(rlp))]
// #[derive(
//     Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable
// )]
// pub struct Body {
//     pub txs: Vec<TransactionSigned>,
//     pub verifiers: Vec<Verify>,
//     pub rewards: Vec<Reward>,
// }

// #[derive(
//     Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
// )]
// pub struct Verifier {
//     pub address: Address,
//     pub public_key: String,//这里需要改成publickey类型
// }

// #[derive(
//     Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
// )]
// pub struct Reward {
//     pub address: Address,
//     pub amount: u128, //在ast中使用的是[u64; 4]，这里直接用了u128
// }

// const ADDRESS_LENGTH: usize = 20;
// type Address = [u8; ADDRESS_LENGTH];
// const PUBLIC_KEY_LENGTH: usize = 48;
// type PublicKey = [u8; PUBLIC_KEY_LENGTH];

// pub struct Verifiers(pub vec<Verifier>);

/// A response to `GetBlockBodies`, containing bodies if any bodies were found.
///
/// Withdrawals can be optionally included at the end of the RLP encoded message.
#[cfg_attr(
    any(test, feature = "reth-codec"),
    reth_codecs::add_arbitrary_tests(rlp, 10)
)]
#[derive(
    Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
#[rlp(trailing)]
pub struct BlockBody {
    /// Transactions in the block
    pub transactions: Vec<TransactionSigned>,
    /// Uncle headers for the given block
    pub ommers: Vec<Header>,
    /// Withdrawals in the block.
    pub withdrawals: Option<Withdrawals>,
    /// Requests in the block.
    pub requests: Option<Requests>,
    /// Verifiers in the block
    pub verifiers: Option<Verifiers>,
    /// Rewards in the block
    pub rewards: Option<Rewards>,
}

impl BlockBody {
    /// Create a [`Block`] from the body and its header.
    // todo(onbjerg): should this not just take `self`? its used in one place
    pub fn create_block(&self, header: Header) -> Block {
        Block {
            header,
            body: self.transactions.clone(),
            ommers: self.ommers.clone(),
            withdrawals: self.withdrawals.clone(),
            requests: self.requests.clone(),
            verifiers: self.verifiers.clone(),
            rewards: self.rewards.clone(),
        }
    }

    /// Calculate the transaction root for the block body.
    pub fn calculate_tx_root(&self) -> B256 {
        crate::proofs::calculate_transaction_root(&self.transactions)
    }

    /// Calculate the ommers root for the block body.
    pub fn calculate_ommers_root(&self) -> B256 {
        crate::proofs::calculate_ommers_root(&self.ommers)
    }

    /// Calculate the withdrawals root for the block body, if withdrawals exist. If there are no
    /// withdrawals, this will return `None`.
    pub fn calculate_withdrawals_root(&self) -> Option<B256> {
        self.withdrawals
            .as_ref()
            .map(|w| crate::proofs::calculate_withdrawals_root(w))
    }

    /// Calculate the requests root for the block body, if requests exist. If there are no
    /// requests, this will return `None`.
    pub fn calculate_requests_root(&self) -> Option<B256> {
        self.requests
            .as_ref()
            .map(|r| crate::proofs::calculate_requests_root(&r.0))
    }

    /// Calculates a heuristic for the in-memory size of the [`BlockBody`].
    #[inline]
    pub fn size(&self) -> usize {
        self.transactions
            .iter()
            .map(TransactionSigned::size)
            .sum::<usize>()
            + self.transactions.capacity() * core::mem::size_of::<TransactionSigned>()
            + self.ommers.iter().map(Header::size).sum::<usize>()
            + self.ommers.capacity() * core::mem::size_of::<Header>()
            + self.withdrawals.as_ref().map_or(
                core::mem::size_of::<Option<Withdrawals>>(),
                Withdrawals::total_size,
            )
    }
}

impl From<Block> for BlockBody {
    fn from(block: Block) -> Self {
        Self {
            transactions: block.body,
            ommers: block.ommers,
            withdrawals: block.withdrawals,
            requests: block.requests,
            verifiers: block.verifiers,
            rewards: block.rewards,
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for BlockBody {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // first generate up to 100 txs
        let transactions = (0..100)
            .map(|_| TransactionSigned::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;

        // then generate up to 2 ommers
        let ommers = (0..2)
            .map(|_| Header::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;

        // for now just generate empty requests, see HACK above
        Ok(Self {
            transactions,
            ommers,
            requests: None,
            withdrawals: u.arbitrary()?,
            verifiers: None,
            rewards: None,
        })
    }
}
