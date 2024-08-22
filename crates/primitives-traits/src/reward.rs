use alloy_rlp::{RlpDecodable, RlpEncodable};
use arbitrary::Arbitrary;
use reth_codecs::Compact;
use serde::{Deserialize, Serialize};

const ADDRESS_LENGTH: usize = 20;
type Address = [u8; ADDRESS_LENGTH];

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary,Default)]
pub struct Amount(pub [u8; 32]); //[u64; 4] in ast

impl Compact for Amount {
    /// Serialize the Amount instance into the provided buffer and return the length of the bytes written.
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        // Directly copy the internal array to the buffer.
        buf.put_slice(&self.0);
        // Return the length of the bytes written.
        self.0.len()
    }

    /// Deserialize an Amount instance from the provided buffer and update the internal cursor of the buffer.
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        // Check if the buffer length is sufficient.
        assert!(buf.len() >= len, "Buffer length is smaller than expected");
        
        // Create a new instance of Amount.
        let mut array = [0u8; 32];
        array.copy_from_slice(&buf[..len]);
        
        // Return the Amount instance and the remaining slice of the buffer.
        (Amount(array), &buf[len..])
    }

    // Unless there are special circumstances, specialized_to_compact and specialized_from_compact
    // can simply delegate to to_compact and from_compact.
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
