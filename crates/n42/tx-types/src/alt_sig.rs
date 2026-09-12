// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The 0x50 alternative-signature transaction.
//!
//! `0x50 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//! gas_limit, to, value, input, access_list, alg_type, pubkey, signature])`.
//! Call-only: `to` is an address, never empty. See `docs/spec/N42_TX_0x50.md`.

use alloc::vec::Vec;
use alloy_consensus::{
    crypto::RecoveryError,
    transaction::{SignerRecoverable, TxHashRef},
    InMemorySize, Transaction, Typed2718,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{keccak256, Address, Bytes, ChainId, Keccak256, TxKind, B256, U256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The EIP-2718 type byte of the alternative-signature transaction.
pub const ALT_SIG_TX_TYPE_ID: u8 = 0x50;
/// `alg_type` of Ed25519 (0x00 is secp256k1 and 0x7F invalid, per EIP-7932).
pub const ALG_ED25519: u8 = 0x01;
/// Length of an Ed25519 public key.
pub const ED25519_PUBKEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Why a 0x50 transaction's signature is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AltSigError {
    /// `alg_type` names no algorithm this node knows.
    #[error("unknown alg_type {0:#04x}")]
    UnknownAlgorithm(u8),
    /// The public key has the wrong length for the algorithm.
    #[error("public key of {0} bytes, expected {1}")]
    PubkeyLength(usize, usize),
    /// The signature has the wrong length for the algorithm.
    #[error("signature of {0} bytes, expected {1}")]
    SignatureLength(usize, usize),
    /// The public key is not a curve point, or is of small order.
    #[error("public key is not a usable curve point")]
    BadPubkey,
    /// The signature's scalar is not canonical (`s >= L`).
    #[error("signature scalar is not canonical")]
    BadSignature,
    /// The verification equation does not hold.
    #[error("signature does not verify")]
    Invalid,
}

impl From<AltSigError> for RecoveryError {
    fn from(err: AltSigError) -> Self {
        Self::from_source(err)
    }
}

/// The unsigned fields of a 0x50 transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxAltSig {
    /// EIP-155 chain id; required.
    #[serde(with = "alloy_serde::quantity")]
    pub chain_id: ChainId,
    /// Sender nonce.
    #[serde(with = "alloy_serde::quantity")]
    pub nonce: u64,
    /// EIP-1559 priority fee.
    #[serde(with = "alloy_serde::quantity")]
    pub max_priority_fee_per_gas: u128,
    /// EIP-1559 fee cap.
    #[serde(with = "alloy_serde::quantity")]
    pub max_fee_per_gas: u128,
    /// Gas limit.
    #[serde(with = "alloy_serde::quantity")]
    pub gas_limit: u64,
    /// Recipient. Contract creation is not supported by this type.
    pub to: Address,
    /// Value transferred.
    pub value: U256,
    /// Call data.
    pub input: Bytes,
    /// EIP-2930 access list.
    pub access_list: AccessList,
    /// Signature algorithm ([`ALG_ED25519`]).
    #[serde(with = "alloy_serde::quantity")]
    pub alg_type: u8,
    /// The signer's public key, in the algorithm's encoding.
    pub pubkey: Bytes,
}

impl TxAltSig {
    /// RLP length of the unsigned fields, without a list header.
    fn fields_len(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.input.0.length()
            + self.access_list.length()
            + self.alg_type.length()
            + self.pubkey.0.length()
    }

    fn encode_fields(&self, out: &mut dyn BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.0.encode(out);
        self.access_list.encode(out);
        self.alg_type.encode(out);
        self.pubkey.0.encode(out);
    }

    /// Decodes the unsigned fields from the front of a list payload.
    fn decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            chain_id: Decodable::decode(buf)?,
            nonce: Decodable::decode(buf)?,
            max_priority_fee_per_gas: Decodable::decode(buf)?,
            max_fee_per_gas: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            to: Decodable::decode(buf)?,
            value: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
            access_list: Decodable::decode(buf)?,
            alg_type: Decodable::decode(buf)?,
            pubkey: Decodable::decode(buf)?,
        })
    }

    /// The hash the signature is over:
    /// `keccak256(0x50 || rlp([unsigned fields ..., alg_type, pubkey]))`.
    pub fn signing_hash(&self) -> B256 {
        let payload_length = self.fields_len();
        let mut buf = Vec::with_capacity(1 + Header { list: true, payload_length }.length() + payload_length);
        buf.put_u8(ALT_SIG_TX_TYPE_ID);
        Header { list: true, payload_length }.encode(&mut buf);
        self.encode_fields(&mut buf);
        keccak256(&buf)
    }

    /// The account this key controls: `keccak256(alg_type || pubkey)[12..]`.
    pub fn sender(&self) -> Address {
        sender_of(self.alg_type, &self.pubkey)
    }

    /// The Ed25519 public key, if the shape of `alg_type`/`pubkey` allows one.
    ///
    /// Rejects keys of small order (a key for which every signature would
    /// verify under the cofactored equation).
    pub fn ed25519_key(&self) -> Result<VerifyingKey, AltSigError> {
        if self.alg_type != ALG_ED25519 {
            return Err(AltSigError::UnknownAlgorithm(self.alg_type));
        }
        let bytes: &[u8; ED25519_PUBKEY_LEN] = self
            .pubkey
            .as_ref()
            .try_into()
            .map_err(|_| AltSigError::PubkeyLength(self.pubkey.len(), ED25519_PUBKEY_LEN))?;
        // Decompressed once per key, not once per signature (see
        // `sender_cache::verifying_key`).
        let key = crate::sender_cache::verifying_key(bytes).ok_or(AltSigError::BadPubkey)?;
        if key.is_weak() {
            return Err(AltSigError::BadPubkey);
        }
        Ok(key)
    }

    /// Signs with an Ed25519 key, producing the signed transaction. The key
    /// must be the one `pubkey` names; if it is not, the transaction is
    /// simply invalid.
    pub fn sign_ed25519(self, key: &ed25519_dalek::SigningKey) -> AltSigTx {
        use ed25519_dalek::Signer;
        let sig = key.sign(self.signing_hash().as_slice());
        AltSigTx::new(self, Bytes::copy_from_slice(&sig.to_bytes()))
    }
}

/// The sender of an alternative-signature account: `keccak256(alg_type || pubkey)[12..]`.
pub fn sender_of(alg_type: u8, pubkey: &[u8]) -> Address {
    let mut hasher = Keccak256::new();
    hasher.update([alg_type]);
    hasher.update(pubkey);
    Address::from_slice(&hasher.finalize()[12..])
}

/// A signed 0x50 transaction: the fields, the signature, and the cached hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AltSigTx {
    #[serde(flatten)]
    tx: TxAltSig,
    signature: Bytes,
    hash: B256,
}

impl AltSigTx {
    /// Builds the signed transaction and computes its hash.
    pub fn new(tx: TxAltSig, signature: Bytes) -> Self {
        let mut this = Self { tx, signature, hash: B256::ZERO };
        this.hash = keccak256(this.encoded_2718());
        this
    }

    /// Builds from parts with a hash the caller already knows to be right
    /// (storage decode).
    pub const fn new_unchecked(tx: TxAltSig, signature: Bytes, hash: B256) -> Self {
        Self { tx, signature, hash }
    }

    /// The unsigned fields.
    pub const fn tx(&self) -> &TxAltSig {
        &self.tx
    }

    /// The signature bytes.
    pub const fn signature(&self) -> &Bytes {
        &self.signature
    }

    /// The transaction hash.
    pub const fn hash(&self) -> &B256 {
        &self.hash
    }

    /// Splits into the fields, the signature and the hash.
    pub fn into_parts(self) -> (TxAltSig, Bytes, B256) {
        (self.tx, self.signature, self.hash)
    }

    /// The account the key controls. Cheap; does not verify anything.
    pub fn sender(&self) -> Address {
        self.tx.sender()
    }

    /// The Ed25519 signature, if it has the right shape and a canonical scalar.
    pub fn ed25519_signature(&self) -> Result<EdSignature, AltSigError> {
        if self.tx.alg_type != ALG_ED25519 {
            return Err(AltSigError::UnknownAlgorithm(self.tx.alg_type));
        }
        let bytes: &[u8; ED25519_SIGNATURE_LEN] = self
            .signature
            .as_ref()
            .try_into()
            .map_err(|_| AltSigError::SignatureLength(self.signature.len(), ED25519_SIGNATURE_LEN))?;
        // `from_slice`/`from_bytes` on the external type accept any bytes; the
        // canonical-scalar check happens when dalek converts internally. Do it
        // here so a malformed signature is a shape error, not a verify failure,
        // and the batch path never sees it.
        let sig = EdSignature::from_bytes(bytes);
        if !scalar_is_canonical(&bytes[32..]) {
            return Err(AltSigError::BadSignature);
        }
        Ok(sig)
    }

    /// Verifies the signature and returns the sender.
    ///
    /// The rule is the cofactored equation, evaluated as a batch of one, so
    /// it is exactly what [`verify_batch`] checks for many.
    pub fn verify(&self) -> Result<Address, AltSigError> {
        let key = self.tx.ed25519_key()?;
        let sig = self.ed25519_signature()?;
        let hash = self.tx.signing_hash();
        ed25519_dalek::verify_batch(&[hash.as_slice()], &[sig], &[key])
            .map_err(|_| AltSigError::Invalid)?;
        Ok(self.tx.sender())
    }

    fn signed_fields_len(&self) -> usize {
        self.tx.fields_len() + self.signature.0.length()
    }

    fn header(&self) -> Header {
        Header { list: true, payload_length: self.signed_fields_len() }
    }

    /// Decodes the typed payload (after the 0x50 byte), returning the parts and
    /// the hash of the bytes consumed.
    fn decode_payload(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let original = *buf;
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();
        let tx = TxAltSig::decode_fields(buf)?;
        let signature: Bytes = Decodable::decode(buf)?;
        if remaining - buf.len() != header.payload_length {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        let consumed = original.len() - buf.len();
        let mut hasher = Keccak256::new();
        hasher.update([ALT_SIG_TX_TYPE_ID]);
        hasher.update(&original[..consumed]);
        Ok(Self { tx, signature, hash: hasher.finalize() })
    }
}

/// `s < L` for the Ed25519 group order `L`, little-endian.
fn scalar_is_canonical(s: &[u8]) -> bool {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];
    for i in (0..32).rev() {
        if s[i] < L[i] {
            return true;
        }
        if s[i] > L[i] {
            return false;
        }
    }
    false
}

/// Verifies many 0x50 transactions at once and returns each one's verdict, in
/// order.
///
/// Shape failures (unknown algorithm, bad key, non-canonical scalar) are
/// decided per transaction without curve arithmetic. The rest go through one
/// cofactored batch verification; if the batch fails, each is verified alone
/// (a batch of one), so a bad signature never taints its neighbours and every
/// verdict is the one [`AltSigTx::verify`] would give.
pub fn verify_batch(txs: &[&AltSigTx]) -> Vec<Result<Address, AltSigError>> {
    let mut out: Vec<Result<Address, AltSigError>> = Vec::with_capacity(txs.len());
    let mut keys = Vec::with_capacity(txs.len());
    let mut sigs = Vec::with_capacity(txs.len());
    let mut hashes: Vec<B256> = Vec::with_capacity(txs.len());
    let mut index = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        match tx.tx.ed25519_key().and_then(|key| tx.ed25519_signature().map(|sig| (key, sig))) {
            Ok((key, sig)) => {
                keys.push(key);
                sigs.push(sig);
                hashes.push(tx.tx.signing_hash());
                index.push(i);
                out.push(Err(AltSigError::Invalid));
            }
            Err(err) => out.push(Err(err)),
        }
    }
    if keys.is_empty() {
        return out;
    }
    let messages: Vec<&[u8]> = hashes.iter().map(|h| h.as_slice()).collect();
    if ed25519_dalek::verify_batch(&messages, &sigs, &keys).is_ok() {
        for &i in &index {
            out[i] = Ok(txs[i].tx.sender());
        }
        return out;
    }
    for (slot, &i) in index.iter().enumerate() {
        if ed25519_dalek::verify_batch(&messages[slot..=slot], &sigs[slot..=slot], &keys[slot..=slot]).is_ok() {
            out[i] = Ok(txs[i].tx.sender());
        }
    }
    out
}

impl Typed2718 for AltSigTx {
    fn ty(&self) -> u8 {
        ALT_SIG_TX_TYPE_ID
    }
}

impl Transaction for AltSigTx {
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.tx.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.tx.nonce
    }

    fn gas_limit(&self) -> u64 {
        self.tx.gas_limit
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.tx.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.tx.max_priority_fee_per_gas)
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.tx.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match base_fee {
            None => self.tx.max_fee_per_gas,
            Some(base_fee) => {
                let tip = self.tx.max_fee_per_gas.saturating_sub(base_fee as u128);
                if tip > self.tx.max_priority_fee_per_gas {
                    self.tx.max_priority_fee_per_gas + base_fee as u128
                } else {
                    self.tx.max_fee_per_gas
                }
            }
        }
    }

    fn is_dynamic_fee(&self) -> bool {
        true
    }

    fn kind(&self) -> TxKind {
        TxKind::Call(self.tx.to)
    }

    fn is_create(&self) -> bool {
        false
    }

    fn value(&self) -> U256 {
        self.tx.value
    }

    fn input(&self) -> &Bytes {
        &self.tx.input
    }

    fn access_list(&self) -> Option<&AccessList> {
        Some(&self.tx.access_list)
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

impl Encodable2718 for AltSigTx {
    fn encode_2718_len(&self) -> usize {
        1 + self.header().length_with_payload()
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        out.put_u8(ALT_SIG_TX_TYPE_ID);
        self.header().encode(out);
        self.tx.encode_fields(out);
        self.signature.0.encode(out);
    }

    fn trie_hash(&self) -> B256 {
        self.hash
    }
}

impl Decodable2718 for AltSigTx {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        if ty != ALT_SIG_TX_TYPE_ID {
            return Err(Eip2718Error::UnexpectedType(ty));
        }
        Ok(Self::decode_payload(buf)?)
    }

    fn fallback_decode(_buf: &mut &[u8]) -> Eip2718Result<Self> {
        Err(Eip2718Error::UnexpectedType(0))
    }
}

impl Encodable for AltSigTx {
    fn encode(&self, out: &mut dyn BufMut) {
        self.network_encode(out)
    }

    fn length(&self) -> usize {
        self.network_len()
    }
}

impl Decodable for AltSigTx {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self::network_decode(buf)?)
    }
}

impl InMemorySize for AltSigTx {
    fn size(&self) -> usize {
        core::mem::size_of::<Self>()
            + self.tx.input.len()
            + self.tx.access_list.size()
            + self.tx.pubkey.len()
            + self.signature.len()
    }
}

impl TxHashRef for AltSigTx {
    fn tx_hash(&self) -> &B256 {
        &self.hash
    }
}

impl SignerRecoverable for AltSigTx {
    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        Ok(self.verify()?)
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        Ok(self.verify()?)
    }
}
