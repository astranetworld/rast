use alloy_rlp::RlpDecodable;
use alloy_rlp::RlpEncodable;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use arbitrary::Arbitrary;
// use reth_db_api::table::Decompress;

const ADDRESS_LENGTH: usize = 20;
/// ly
pub type Address = [u8; ADDRESS_LENGTH];

const PUBLIC_KEY_LENGTH: usize = 48;
// type PublicKey = [u8; PUBLIC_KEY_LENGTH];
// type PublicKey = Vec<u8>;

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Eq, PartialEq, Debug, Clone, RlpEncodable, RlpDecodable,Arbitrary)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

struct PublicKeyVisitor;
impl<'de> Visitor<'de> for PublicKeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of 48 bytes")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = [0u8; 48];
        for i in 0..48 {
            bytes[i] = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        Ok(PublicKey(bytes))
    }
}

/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable,Arbitrary)]
pub struct Verifiers(pub Vec<Verifier>);


/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable,Arbitrary)]
pub struct Verifier {
    /// ly
    pub address: Address,
    /// ly
    pub public_key: PublicKey, 
}

impl Serialize for PublicKey {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(PublicKeyVisitor)
    }
}
