// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage encodings (`reth_codecs::Compact`) for the envelope and its type.
//!
//! An Ethereum transaction is stored exactly as reth stores it, behind one
//! tag byte, so the on-disk cost of the wider type is one byte a row. A 0x50
//! transaction is stored as its hash followed by its wire bytes: the hash
//! saves a keccak on every read, and the wire bytes are already dense.

use crate::{
    alt_sig::{AltSigTx, ALT_SIG_TX_TYPE_ID},
    envelope::{N42TxEnvelope, N42TxType},
};
use alloy_consensus::TxType;
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::B256;
use bytes::{Buf, BufMut};
use reth_codecs::{txtype::COMPACT_EXTENDED_IDENTIFIER_FLAG, Compact};
use reth_ethereum_primitives::TransactionSigned;

const TAG_ETH: u8 = 0;
const TAG_ALT_SIG: u8 = 1;

impl Compact for N42TxType {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        match self {
            Self::Eth(ty) => ty.to_compact(buf),
            Self::AltSig => {
                buf.put_u8(ALT_SIG_TX_TYPE_ID);
                COMPACT_EXTENDED_IDENTIFIER_FLAG
            }
        }
    }

    fn from_compact(buf: &[u8], identifier: usize) -> (Self, &[u8]) {
        if identifier == COMPACT_EXTENDED_IDENTIFIER_FLAG && buf.first() == Some(&ALT_SIG_TX_TYPE_ID) {
            return (Self::AltSig, &buf[1..]);
        }
        let (ty, rest) = TxType::from_compact(buf, identifier);
        (Self::Eth(ty), rest)
    }
}

impl Compact for N42TxEnvelope {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        match self {
            Self::Eth(tx) => {
                buf.put_u8(TAG_ETH);
                1 + tx.to_compact(buf)
            }
            Self::AltSig(tx) => {
                buf.put_u8(TAG_ALT_SIG);
                buf.put_slice(tx.hash().as_slice());
                let len = tx.encode_2718_len();
                buf.put_u32(len as u32);
                tx.encode_2718(buf);
                1 + 32 + 4 + len
            }
        }
    }

    fn from_compact(mut buf: &[u8], len: usize) -> (Self, &[u8]) {
        let tag = buf.get_u8();
        match tag {
            TAG_ETH => {
                let (tx, rest) = TransactionSigned::from_compact(buf, len.saturating_sub(1));
                (Self::Eth(tx), rest)
            }
            TAG_ALT_SIG => {
                let hash = B256::from_slice(&buf[..32]);
                buf.advance(32);
                let len = buf.get_u32() as usize;
                let (bytes, rest) = buf.split_at(len);
                let tx = AltSigTx::decode_2718_exact(bytes)
                    .expect("a 0x50 transaction this node stored decodes");
                debug_assert_eq!(tx.hash(), &hash);
                let (tx, sig, _) = tx.into_parts();
                (Self::AltSig(AltSigTx::new_unchecked(tx, sig, hash)), rest)
            }
            other => panic!("unknown N42 transaction storage tag {other}"),
        }
    }
}

reth_codecs::impl_compression_for_compact!(N42TxEnvelope);
