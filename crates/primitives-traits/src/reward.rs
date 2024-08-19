use alloy_rlp::{RlpDecodable, RlpEncodable};
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};

const ADDRESS_LENGTH: usize = 20;
type Address = [u8; ADDRESS_LENGTH];

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary)]
pub struct Amount(pub [u8; 32]); //在ast中使用的是[u64; 4]

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary)]
pub struct Rewards(pub Vec<Reward>);

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,Arbitrary)]
pub struct Reward {
    /// ly
    pub address: Address,
    /// ly
    pub amount: Amount,
}
