use alloy_rlp::RlpDecodable;
use alloy_rlp::RlpEncodable;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
// use reth_db_api::table::Decompress;

const ADDRESS_LENGTH: usize = 20;
type Address = [u8; ADDRESS_LENGTH];

const PUBLIC_KEY_LENGTH: usize = 48;
// type PublicKey = [u8; PUBLIC_KEY_LENGTH];
// type PublicKey = Vec<u8>;

#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Eq, PartialEq, Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);
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


#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Verifiers(pub Vec<Verifier>);


#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::derive_arbitrary(rlp 32))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Verifier {
    pub address: Address,
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

// impl Clone for PublicKey {
//     fn clone(&self) -> Self {
//         PublicKey(self.0.clone())
//     }
// }

// impl fmt::Debug for PublicKey {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         // 使用数组的 as_ptr() 方法来获取字节数组的指针，并使用 write! 宏来格式化输出
//         f.write_fmt(format_args!("{:?}", self.0.as_ptr()))
//     }
// }

// impl PartialEq for PublicKey {
//     fn eq(&self, other: &Self) -> bool {
//         // 比较两个 PublicKey 的字节数组是否相等
//         self.0 == other.0
//     }
// }


// pub enum DatabaseError {
//     DecompressionFailed,
//     // 可以添加其他错误类型，例如数据长度不匹配等
//     InvalidLength,
// }

//
// impl Decompress for PublicKey {
//     fn decompress<B: AsRef<[u8]>>(value: B) -> Result<Self, DatabaseError> {
//         let bytes = value.as_ref();
//         if bytes.len() != PUBLIC_KEY_LENGTH {
//             // 如果传入的字节序列长度不等于预期的长度，返回错误
//             return Err(DatabaseError::InvalidLength);
//         }

//         // 尝试创建 PublicKey 实例，如果字节序列长度正确，这里不会出错
//         let public_key = PublicKey(bytes.try_into().map_err(|_| DatabaseError::DecompressionFailed)?);

//         Ok(public_key)
//     }
// }