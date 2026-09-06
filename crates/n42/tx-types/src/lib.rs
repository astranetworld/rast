// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! N42's transaction types.
//!
//! reth's Ethereum envelope (`TransactionSigned`, types 0x00-0x04) plus one
//! N42 type: **0x50, the alternative-signature transaction** ([`AltSigTx`]),
//! whose sender is authenticated by Ed25519 rather than recovered from a
//! secp256k1 signature. It exists for throughput: Ed25519 signatures verify
//! in batches, and on this project's hardware a batch of 64 costs 13 us a
//! signature against 29-63 us for one `ecrecover` (`docs/sigbench/`).
//!
//! The wire format, the signing hash, the sender derivation and the validity
//! rule are `docs/spec/N42_TX_0x50.md`. The algorithm identifier and the
//! sender derivation (`keccak256(alg_type || pubkey)[12..]`) follow EIP-7932.
//!
//! [`N42TxEnvelope`] is the node's transaction type: the Ethereum envelope
//! flattened in, plus the `AltSig` variant. [`N42Primitives`] is the
//! `NodePrimitives` built on it.

extern crate alloc;

pub mod alt_sig;
mod compact;
pub mod envelope;
pub mod primitives;

pub use alt_sig::{
    verify_batch, AltSigError, AltSigTx, TxAltSig, ALG_ED25519, ALT_SIG_TX_TYPE_ID,
    ED25519_PUBKEY_LEN, ED25519_SIGNATURE_LEN,
};
pub use envelope::{N42PooledTxEnvelope, N42PooledTxType, N42TxEnvelope, N42TxType};
pub use primitives::{Block, BlockBody, N42Primitives, Receipt};

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, Transaction, TxEip1559, TxReceipt, Typed2718};
    use alloy_eips::eip2718::{Decodable2718, Encodable2718};
    use alloy_primitives::{address, hex, keccak256, Address, Bytes, Signature, B256, U256};
    use alloy_rlp::{Decodable, Encodable};
    use ed25519_dalek::SigningKey;
    use reth_codecs::Compact;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn unsigned(seed: u8, nonce: u64) -> TxAltSig {
        TxAltSig {
            chain_id: 94,
            nonce,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            to: address!("00000000000000000000000000000000000000aa"),
            value: U256::from(1_000_000u64),
            input: Bytes::new(),
            access_list: Default::default(),
            alg_type: ALG_ED25519,
            pubkey: Bytes::copy_from_slice(key(seed).verifying_key().as_bytes()),
        }
    }

    fn signed(seed: u8, nonce: u64) -> AltSigTx {
        unsigned(seed, nonce).sign_ed25519(&key(seed))
    }

    fn eth_tx() -> reth_ethereum_primitives::TransactionSigned {
        let tx = TxEip1559 {
            chain_id: 94,
            nonce: 7,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: address!("00000000000000000000000000000000000000bb").into(),
            value: U256::from(5u64),
            ..Default::default()
        };
        tx.into_signed(Signature::new(U256::from(1), U256::from(2), false)).into()
    }

    #[test]
    fn sign_verify_and_sender() {
        let tx = signed(1, 0);
        let sender = tx.verify().expect("verifies");
        assert_eq!(sender, tx.sender());
        let mut expect = Vec::new();
        expect.push(ALG_ED25519);
        expect.extend_from_slice(key(1).verifying_key().as_bytes());
        assert_eq!(sender, Address::from_slice(&keccak256(expect)[12..]));
        assert_eq!(tx.ty(), 0x50);
        assert!(!tx.is_create());
    }

    #[test]
    fn wire_round_trip_and_hash() {
        let tx = signed(2, 3);
        let bytes = tx.encoded_2718();
        assert_eq!(bytes[0], 0x50);
        assert_eq!(bytes.len(), tx.encode_2718_len());
        assert_eq!(*tx.hash(), keccak256(&bytes));
        let back = AltSigTx::decode_2718_exact(&bytes).expect("decodes");
        assert_eq!(back, tx);
        assert_eq!(back.hash(), tx.hash());

        let mut net = Vec::new();
        tx.encode(&mut net);
        assert_eq!(net.len(), tx.length());
        let back = AltSigTx::decode(&mut net.as_slice()).expect("network decodes");
        assert_eq!(back, tx);
        // 110 B for the secp256k1 transfer; ours carries the key and a 64 B signature.
        assert!(bytes.len() > 130 && bytes.len() < 160, "{}", bytes.len());
    }

    #[test]
    fn tampering_is_caught() {
        let tx = signed(3, 0);
        let (fields, sig, _) = tx.clone().into_parts();
        let mut bad = sig.to_vec();
        bad[5] ^= 1;
        assert_eq!(AltSigTx::new(fields.clone(), bad.into()).verify(), Err(AltSigError::Invalid));

        let mut other = fields.clone();
        other.value = U256::from(2u64);
        assert_eq!(AltSigTx::new(other, sig.clone()).verify(), Err(AltSigError::Invalid));

        // Another key's transaction with this signature.
        let mut wrong_key = fields.clone();
        wrong_key.pubkey = Bytes::copy_from_slice(key(4).verifying_key().as_bytes());
        assert_eq!(AltSigTx::new(wrong_key, sig.clone()).verify(), Err(AltSigError::Invalid));

        let mut alg = fields.clone();
        alg.alg_type = 0x02;
        assert_eq!(AltSigTx::new(alg, sig.clone()).verify(), Err(AltSigError::UnknownAlgorithm(2)));

        let mut short = fields.clone();
        short.pubkey = Bytes::from_static(&[1u8; 31]);
        assert_eq!(AltSigTx::new(short, sig.clone()).verify(), Err(AltSigError::PubkeyLength(31, 32)));

        // The identity point is of small order.
        let mut weak = fields.clone();
        let mut ident = [0u8; 32];
        ident[0] = 1;
        weak.pubkey = Bytes::copy_from_slice(&ident);
        assert_eq!(AltSigTx::new(weak, sig.clone()).verify(), Err(AltSigError::BadPubkey));

        // s == L is not canonical.
        let mut non_canonical = sig.to_vec();
        non_canonical[32..].copy_from_slice(&hex!("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        assert_eq!(AltSigTx::new(fields.clone(), non_canonical.into()).verify(), Err(AltSigError::BadSignature));

        assert_eq!(AltSigTx::new(fields, Bytes::from_static(&[0u8; 63])).verify(), Err(AltSigError::SignatureLength(63, 64)));
    }

    #[test]
    fn batch_verdicts_match_single() {
        let mut txs: Vec<AltSigTx> = (0..8u8).map(|i| signed(10 + i, i as u64)).collect();
        let refs: Vec<&AltSigTx> = txs.iter().collect();
        let all = verify_batch(&refs);
        assert!(all.iter().all(|r| r.is_ok()), "{all:?}");
        for (r, tx) in all.iter().zip(&txs) {
            assert_eq!(r.as_ref().unwrap(), &tx.sender());
        }

        let (fields, sig, _) = txs[3].clone().into_parts();
        let mut bad = sig.to_vec();
        bad[0] ^= 0x80;
        txs[3] = AltSigTx::new(fields, bad.into());
        let mut alg = txs[5].tx().clone();
        alg.alg_type = 0x7f;
        txs[5] = AltSigTx::new(alg, txs[5].signature().clone());
        let refs: Vec<&AltSigTx> = txs.iter().collect();
        let mixed = verify_batch(&refs);
        for (i, (r, tx)) in mixed.iter().zip(&txs).enumerate() {
            assert_eq!(*r, tx.verify(), "index {i}");
        }
        assert_eq!(mixed[3], Err(AltSigError::Invalid));
        assert_eq!(mixed[5], Err(AltSigError::UnknownAlgorithm(0x7f)));
        assert_eq!(mixed.iter().filter(|r| r.is_ok()).count(), 6);
    }

    #[test]
    fn envelope_dispatches_by_type_byte() {
        let eth = eth_tx();
        let alt = signed(20, 1);
        let e1 = N42TxEnvelope::decode_2718_exact(&eth.encoded_2718()).unwrap();
        let e2 = N42TxEnvelope::decode_2718_exact(&alt.encoded_2718()).unwrap();
        assert_eq!(e1.as_eth(), Some(&eth));
        assert_eq!(e2.as_alt_sig(), Some(&alt));
        assert_eq!(e1.ty(), 2);
        assert_eq!(e2.ty(), 0x50);
        assert_eq!(e2.hash(), alt.hash());
        assert_eq!(N42TxType::try_from(0x50u8).unwrap(), N42TxType::AltSig);
        assert_eq!(N42TxType::try_from(2u8).unwrap(), N42TxType::Eth(alloy_consensus::TxType::Eip1559));
        assert!(N42TxType::try_from(0x51u8).is_err());
        assert!(<N42TxEnvelope as alloy_eips::eip2718::IsTyped2718>::is_type(0x50));

        // Body encoding: a list of network-encoded transactions round-trips.
        let body: Vec<N42TxEnvelope> = vec![e1.clone(), e2.clone()];
        let mut rlp = Vec::new();
        body.encode(&mut rlp);
        let back: Vec<N42TxEnvelope> = Decodable::decode(&mut rlp.as_slice()).unwrap();
        assert_eq!(back, body);

        use alloy_consensus::transaction::SignerRecoverable;
        assert_eq!(e2.recover_signer().unwrap(), alt.sender());
        // The dummy secp256k1 signature is not recoverable to anything meaningful, but it must not panic.
        let _ = e1.recover_signer();

        let pooled: N42PooledTxEnvelope = e2.clone().try_into_pooled().unwrap();
        assert_eq!(pooled.ty(), 0x50);
        let consensus: N42TxEnvelope = pooled.into();
        assert_eq!(consensus, e2);
        let pooled_eth: N42PooledTxEnvelope = e1.clone().try_into().unwrap();
        assert_eq!(N42TxEnvelope::from(pooled_eth), e1);
    }

    #[test]
    fn storage_round_trips() {
        for env in [N42TxEnvelope::Eth(eth_tx()), N42TxEnvelope::AltSig(signed(30, 9))] {
            let mut buf = Vec::new();
            let n = env.to_compact(&mut buf);
            assert_eq!(n, buf.len());
            let (back, rest) = N42TxEnvelope::from_compact(&buf, buf.len());
            assert!(rest.is_empty());
            assert_eq!(back, env);
            assert_eq!(back.hash(), env.hash());
        }
        for ty in [N42TxType::AltSig, N42TxType::Eth(alloy_consensus::TxType::Eip4844), N42TxType::Eth(alloy_consensus::TxType::Legacy)] {
            let receipt = Receipt { tx_type: ty, success: true, cumulative_gas_used: 21_000, logs: vec![] };
            let mut buf = Vec::new();
            receipt.to_compact(&mut buf);
            let (back, rest) = Receipt::from_compact(&buf, buf.len());
            assert!(rest.is_empty());
            assert_eq!(back, receipt);
            assert_eq!(back.tx_type, ty);
        }
        let receipt = Receipt { tx_type: N42TxType::AltSig, success: true, cumulative_gas_used: 21_000, logs: vec![] };
        let encoded = receipt.with_bloom_ref().encoded_2718();
        assert_eq!(encoded[0], 0x50, "receipt is typed with the transaction's type");
    }

    #[test]
    fn serde_round_trips() {
        let alt = signed(40, 2);
        let json = serde_json::to_string(&alt).unwrap();
        assert!(json.contains("\"pubkey\""), "{json}");
        let back: AltSigTx = serde_json::from_str(&json).unwrap();
        assert_eq!(back, alt);
        let env = N42TxEnvelope::AltSig(alt.clone());
        let json = serde_json::to_string(&env).unwrap();
        let back: N42TxEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
        let env = N42TxEnvelope::Eth(eth_tx());
        let json = serde_json::to_string(&env).unwrap();
        let back: N42TxEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }

    /// The vectors `docs/sigbench/altsig_vectors.py` checks independently
    /// decode to the recorded hash and sender, and verify.
    #[test]
    fn spec_vectors_decode_and_verify() {
        let raw = include_str!("../testdata/altsig_vectors.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
        assert_eq!(vectors.len(), 3);
        for v in vectors {
            let encoded: Bytes = serde_json::from_value(v["encoded"].clone()).unwrap();
            let tx = AltSigTx::decode_2718_exact(&encoded).unwrap();
            let hash: B256 = serde_json::from_value(v["hash"].clone()).unwrap();
            let sender: Address = serde_json::from_value(v["sender"].clone()).unwrap();
            let signing_hash: B256 = serde_json::from_value(v["signingHash"].clone()).unwrap();
            assert_eq!(*tx.hash(), hash);
            assert_eq!(tx.tx().signing_hash(), signing_hash);
            assert_eq!(tx.verify().unwrap(), sender);
            assert_eq!(tx.encoded_2718(), encoded.to_vec());
        }
    }

    /// Prints the spec's test vectors (`docs/spec/N42_TX_0x50.md`), checked
    /// independently by `docs/sigbench/altsig_vectors.py`.
    #[test]
    #[ignore = "prints vectors"]
    fn dump_vectors() {
        let mut with_input = unsigned(51, 1);
        with_input.input = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
        with_input.gas_limit = 50_000;
        let mut with_list = unsigned(52, 2);
        with_list.access_list = alloy_eips::eip2930::AccessList(vec![alloy_eips::eip2930::AccessListItem {
            address: address!("00000000000000000000000000000000000000cc"),
            storage_keys: vec![B256::repeat_byte(1)],
        }]);
        with_list.gas_limit = 60_000;
        let mut out = Vec::new();
        for (seed, tx) in [(50u8, unsigned(50, 0)), (51, with_input), (52, with_list)] {
            let signed = tx.clone().sign_ed25519(&key(seed));
            out.push(serde_json::json!({
                "secretKey": hex::encode([seed; 32]),
                "tx": tx,
                "signingHash": tx.signing_hash(),
                "signature": signed.signature(),
                "sender": signed.sender(),
                "hash": signed.hash(),
                "encoded": Bytes::from(signed.encoded_2718()),
            }));
        }
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    }
}
