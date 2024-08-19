use alloy_rlp::RlpDecodable;
use alloy_rlp::RlpEncodable;
use reth_codecs::Compact;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use arbitrary::Arbitrary;
use bytes::BufMut;
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

impl Default for PublicKey {
    /// 返回`PublicKey`类型的默认值。
    ///
    /// 这里我们简单地将公钥初始化为全零。
    fn default() -> Self {
        PublicKey([0u8; PUBLIC_KEY_LENGTH])
    }
}

impl Compact for PublicKey {
    /// 将公钥转换为紧凑格式并写入提供的缓冲区。
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        // 将公钥的字节数组直接复制到缓冲区
        buf.as_mut().copy_from_slice(&self.0);
        // 返回写入的字节数
        PUBLIC_KEY_LENGTH
    }

    /// 从紧凑格式中读取公钥。
    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        // 确保缓冲区长度足够
        assert!(len == PUBLIC_KEY_LENGTH, "Invalid buffer length for PublicKey");
        
        // 创建公钥实例
        let public_key = PublicKey(buf[..PUBLIC_KEY_LENGTH].try_into().expect("Slice with incorrect length"));
        
        // 返回公钥实例和剩余的缓冲区
        (public_key, &buf[PUBLIC_KEY_LENGTH..])
    }
    
    // 可以选择实现specialized_to_compact和specialized_from_compact方法
    // 如果它们与默认实现相同，可以简单地调用默认方法
    // 如果有特定的序列化或反序列化逻辑，可以在这里实现
}

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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable,Arbitrary,Default,Compact)]
pub struct Verifiers(pub Vec<Verifier>);


/// ly
// #[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable,Arbitrary,Compact,Default)]
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
