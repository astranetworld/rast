//! Block related models and types.

use reth_codecs::{add_arbitrary_tests, Compact};
use reth_primitives::{Header, TxNumber, Withdrawals, B256,Verifiers,Verifier,Rewards,Reward};
use serde::{Deserialize, Serialize};
use std::ops::Range;
use crate::table::{Decompress,Compress};
use reth_storage_errors::db::DatabaseError;
use reth_primitives_traits::{Address,PublicKey,Amount};
use bytes::BufMut;

/// Total number of transactions.
pub type NumTransactions = u64;

/// The storage of the block body indices.
///
/// It has the pointer to the transaction Number of the first
/// transaction in the block and the total number of transactions.
#[derive(Debug, Default, Eq, PartialEq, Clone, Serialize, Deserialize, Compact)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[add_arbitrary_tests(compact)]
pub struct StoredBlockBodyIndices {
    /// The number of the first transaction in this block
    ///
    /// Note: If the block is empty, this is the number of the first transaction
    /// in the next non-empty block.
    pub first_tx_num: TxNumber,
    /// The total number of transactions in the block
    ///
    /// NOTE: Number of transitions is equal to number of transactions with
    /// additional transition for block change if block has block reward or withdrawal.
    pub tx_count: NumTransactions,
}

impl StoredBlockBodyIndices {
    /// Return the range of transaction ids for this block.
    pub const fn tx_num_range(&self) -> Range<TxNumber> {
        self.first_tx_num..self.first_tx_num + self.tx_count
    }

    /// Return the index of last transaction in this block unless the block
    /// is empty in which case it refers to the last transaction in a previous
    /// non-empty block
    pub const fn last_tx_num(&self) -> TxNumber {
        self.first_tx_num.saturating_add(self.tx_count).saturating_sub(1)
    }

    /// First transaction index.
    ///
    /// Caution: If the block is empty, this is the number of the first transaction
    /// in the next non-empty block.
    pub const fn first_tx_num(&self) -> TxNumber {
        self.first_tx_num
    }

    /// Return the index of the next transaction after this block.
    pub const fn next_tx_num(&self) -> TxNumber {
        self.first_tx_num + self.tx_count
    }

    /// Return a flag whether the block is empty
    pub const fn is_empty(&self) -> bool {
        self.tx_count == 0
    }

    /// Return number of transaction inside block
    ///
    /// NOTE: This is not the same as the number of transitions.
    pub const fn tx_count(&self) -> NumTransactions {
        self.tx_count
    }
}

/// The storage representation of a block's ommers.
///
/// It is stored as the headers of the block's uncles.
#[derive(Debug, Default, Eq, PartialEq, Clone, Serialize, Deserialize, Compact)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[add_arbitrary_tests(compact)]
pub struct StoredBlockOmmers {
    /// The block headers of this block's uncles.
    pub ommers: Vec<Header>,
}

/// The storage representation of block withdrawals.
#[derive(Debug, Default, Eq, PartialEq, Clone, Serialize, Deserialize, Compact)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[add_arbitrary_tests(compact)]
pub struct StoredBlockWithdrawals {
    /// The block withdrawals.
    pub withdrawals: Withdrawals,
}

/// Hash of the block header.
pub type HeaderHash = B256;

/// ly
#[derive(Serialize,Debug,PartialEq)]
pub struct StoredBlockVerifiers{
    /// ly
    pub verifiers:Verifiers,
}

impl Decompress for StoredBlockVerifiers {
    fn decompress<B: AsRef<[u8]>>(value: B) -> Result<Self, DatabaseError> {
        let data = value.as_ref();
        
        // 定义我们期望的每个Verifier的大小：Address长度 + PublicKey长度
        const VERIFIER_SIZE: usize = 68;
        
        // 校验数据长度是否为Verifier的整数倍
        if data.len() % VERIFIER_SIZE != 0 {
            return Err(DatabaseError::Decode);
        }

        let mut verifiers = Vec::new();

        // 解析每个Verifier
        for chunk in data.chunks_exact(VERIFIER_SIZE) {
            let address: Address = chunk[0..20].try_into().map_err(|_| DatabaseError::Decode)?;
            let public_key_bytes: [u8; 48] = chunk[20..VERIFIER_SIZE].try_into().map_err(|_| DatabaseError::Decode)?;
            let public_key = PublicKey(public_key_bytes);

            verifiers.push(Verifier {
                address,
                public_key,
            });
        }

        Ok(StoredBlockVerifiers {
            verifiers: Verifiers(verifiers),
        })
    }
}

impl Compress for StoredBlockVerifiers {
    type Compressed = Vec<u8>; // 使用 Vec<u8> 作为压缩后的数据类型

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(self, buf: &mut B) {
        // 遍历每个 Verifier，并将其 address 和 public_key 写入 buf
        for verifier in self.verifiers.0 {
            buf.put_slice(&verifier.address); // 写入 address
            buf.put_slice(&verifier.public_key.0); // 写入 public_key (假设 public_key.0 是 [u8; PUBLIC_KEY_LENGTH])
        }
    }
}


/// ly
#[derive(Debug,Serialize)]
pub struct StoredBlockRewards{
    /// ly
    pub rewards:Rewards,
}

impl Decompress for StoredBlockRewards {
    fn decompress<B: AsRef<[u8]>>(value: B) -> Result<Self, DatabaseError> {
        let data = value.as_ref();
        
        // 定义我们期望的每个Reward的大小：Address长度 + Amount长度
        const REWARD_SIZE: usize = 20 + 32; // 32字节对应Amount大小
        
        // 校验数据长度是否为Reward的整数倍
        if data.len() % REWARD_SIZE != 0 {
            return Err(DatabaseError::Decode);
        }

        let mut rewards = Vec::new();

        // 解析每个Reward
        for chunk in data.chunks_exact(REWARD_SIZE) {
            let address: Address = chunk[0..20].try_into().map_err(|_| DatabaseError::Decode)?;
            let amount_bytes: [u8; 32] = chunk[20..REWARD_SIZE].try_into().map_err(|_| DatabaseError::Decode)?;
            let amount = Amount(amount_bytes);

            rewards.push(Reward {
                address,
                amount,
            });
        }

        Ok(StoredBlockRewards {
            rewards: Rewards(rewards),
        })
    }
}


impl Compress for StoredBlockRewards {
    type Compressed = Vec<u8>; // 使用 Vec<u8> 作为压缩后的数据类型

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(self, buf: &mut B) {
        // 遍历每个 Reward，将其 address 和 amount 写入 buf
        for reward in self.rewards.0 {
            buf.put_slice(&reward.address); // 写入 address
            buf.put_slice(&reward.amount.0); // 写入 amount (假设 amount.0 是 [u8; 32])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::{Compress, Decompress};

    #[test]
    fn test_ommer() {
        let mut ommer = StoredBlockOmmers::default();
        ommer.ommers.push(Header::default());
        ommer.ommers.push(Header::default());
        assert_eq!(
            ommer.clone(),
            StoredBlockOmmers::decompress::<Vec<_>>(ommer.compress()).unwrap()
        );
    }

    #[test]
    fn block_indices() {
        let first_tx_num = 10;
        let tx_count = 6;
        let block_indices = StoredBlockBodyIndices { first_tx_num, tx_count };

        assert_eq!(block_indices.first_tx_num(), first_tx_num);
        assert_eq!(block_indices.last_tx_num(), first_tx_num + tx_count - 1);
        assert_eq!(block_indices.next_tx_num(), first_tx_num + tx_count);
        assert_eq!(block_indices.tx_count(), tx_count);
        assert_eq!(block_indices.tx_num_range(), first_tx_num..first_tx_num + tx_count);
    }
}
