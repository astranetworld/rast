use alloy_rlp::{RlpDecodable, RlpEncodable};
use arbitrary::Arbitrary;
use reth_codecs::Compact;
use serde::{Deserialize, Serialize};

const ADDRESS_LENGTH: usize = 20;
type Address = [u8; ADDRESS_LENGTH];

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary,Default)]
pub struct Amount(pub [u8; 32]); //在ast中使用的是[u64; 4]

impl Compact for Amount {
    /// 将`Amount`实例序列化到提供的缓冲区中，并返回写入的字节长度。
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        // 将内部数组直接复制到缓冲区
        buf.put_slice(&self.0);
        // 返回写入的字节长度
        self.0.len()
    }

    /// 从提供的缓冲区中反序列化`Amount`实例，并更新缓冲区的内部游标。
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        // 检查缓冲区长度是否足够
        assert!(buf.len() >= len, "Buffer length is smaller than expected");
        
        // 创建一个新的Amount实例
        let mut array = [0u8; 32];
        array.copy_from_slice(&buf[..len]);
        
        // 返回Amount实例和剩余的缓冲区切片
        (Amount(array), &buf[len..])
    }
    
    // 如果没有特殊情况，specialized_to_compact 和 specialized_from_compact
    // 可以简单地委托给 to_compact 和 from_compact。
    fn specialized_to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        self.to_compact(buf)
    }

    fn specialized_from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        Self::from_compact(buf, len)
    }
}

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary,Default,Compact)]
pub struct Rewards(pub Vec<Reward>);

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary,Compact,Default)]
pub struct Reward {
    /// ly
    pub address: Address,
    /// ly
    pub amount: Amount,
}
