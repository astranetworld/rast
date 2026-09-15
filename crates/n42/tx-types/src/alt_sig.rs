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
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha512};
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
    if batch_holds(&messages, &sigs, &keys) {
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

/// Whether a batch verifies: [`batch_equation_holds`], or ed25519-dalek's own batch
/// verification with `N42_ED25519_MERGE=0`.
fn batch_holds(messages: &[&[u8]], signatures: &[EdSignature], keys: &[VerifyingKey]) -> bool {
    static MERGE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *MERGE.get_or_init(|| std::env::var("N42_ED25519_MERGE").map_or(true, |v| v != "0")) {
        batch_equation_holds(messages, signatures, keys)
    } else {
        ed25519_dalek::verify_batch(messages, signatures, keys).is_ok()
    }
}

/// ed25519-dalek's batch verification (`ed25519_dalek::verify_batch`, 2.2) with the terms of
/// equal keys merged. It checks
/// `(-sum z_i s_i) B + sum z_i R_i + sum (z_i H(R_i || A_i || M_i)) A_i = 0`
/// with the random `z_i` drawn from the same transcript in the same order, and adds the
/// `A_i` terms of one key into one coefficient, so the sum is the same group element and the
/// verdict the same. What changes is the multiscalar multiplication: a batch from one sender
/// -- every ingest frame of a flood, a sender's run of nonces -- puts one key point into it
/// instead of one per signature, 130 points for 128 signatures rather than 257. The
/// multiplication was a quarter of a fleet node's samples (loop167's leader profile: Ed25519
/// and SHA-512 39% of the process, keccak 9%).
fn batch_equation_holds(messages: &[&[u8]], signatures: &[EdSignature], keys: &[VerifyingKey]) -> bool {
    if messages.len() != signatures.len() || keys.len() != signatures.len() {
        return false;
    }
    let mut transcript = merlin::Transcript::new(b"ed25519 batch verification");
    let hrams: Vec<[u8; 64]> = signatures
        .iter()
        .zip(keys)
        .zip(messages)
        .map(|((signature, key), message)| {
            let mut hash = Sha512::default();
            hash.update(signature.r_bytes());
            hash.update(key.as_bytes());
            hash.update(message);
            hash.finalize().into()
        })
        .collect();
    for hram in &hrams {
        transcript.append_message(b"hram", hram);
    }
    for signature in signatures {
        transcript.append_message(b"sig.s", signature.s_bytes());
    }
    let mut rng = transcript.build_rng().finalize(&mut ZeroRng);
    // As ed25519-dalek parses a signature: R taken as it is, s canonical or the batch fails.
    let mut s_values = Vec::with_capacity(signatures.len());
    for signature in signatures {
        let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes())) else {
            return false;
        };
        s_values.push(s);
    }
    let zs: Vec<Scalar> = signatures
        .iter()
        .map(|_| {
            let mut bytes = [0u8; 16];
            rand_core::RngCore::fill_bytes(&mut rng, &mut bytes);
            Scalar::from(u128::from_le_bytes(bytes))
        })
        .collect();
    let base_coefficient: Scalar = s_values.iter().zip(&zs).map(|(s, z)| z * s).sum();
    let mut key_bytes: Vec<&[u8; 32]> = Vec::new();
    let mut key_points: Vec<EdwardsPoint> = Vec::new();
    let mut key_coefficients: Vec<Scalar> = Vec::new();
    for ((key, hram), z) in keys.iter().zip(&hrams).zip(&zs) {
        let term = Scalar::from_bytes_mod_order_wide(hram) * z;
        match key_bytes.iter().position(|seen| *seen == key.as_bytes()) {
            Some(at) => key_coefficients[at] += term,
            None => {
                key_bytes.push(key.as_bytes());
                key_points.push(key.to_edwards());
                key_coefficients.push(term);
            }
        }
    }
    let scalars = core::iter::once(-base_coefficient).chain(zs.iter().copied()).chain(key_coefficients);
    let points = core::iter::once(Some(ED25519_BASEPOINT_POINT))
        .chain(signatures.iter().map(|signature| CompressedEdwardsY(*signature.r_bytes()).decompress()))
        .chain(key_points.into_iter().map(Some));
    EdwardsPoint::optional_multiscalar_mul(scalars, points).is_some_and(|sum| sum.is_identity())
}

/// The empty randomness ed25519-dalek finalizes its batch transcript with: the coefficients
/// come from the transcript of the batch alone, as there.
struct ZeroRng;

impl rand_core::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.fill(0);
        Ok(())
    }
}

impl rand_core::CryptoRng for ZeroRng {}

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

#[cfg(test)]
mod merged_batch_tests {
    use super::*;
    use alloy_primitives::address;

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn signed(seed: u8, nonce: u64) -> AltSigTx {
        TxAltSig {
            chain_id: 94,
            nonce,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            to: address!("00000000000000000000000000000000000000aa"),
            value: U256::from(1u64),
            input: Bytes::new(),
            access_list: Default::default(),
            alg_type: ALG_ED25519,
            pubkey: Bytes::copy_from_slice(key(seed).verifying_key().as_bytes()),
        }
        .sign_ed25519(&key(seed))
    }

    fn parts(txs: &[AltSigTx]) -> (Vec<B256>, Vec<EdSignature>, Vec<VerifyingKey>) {
        (
            txs.iter().map(|tx| tx.tx.signing_hash()).collect(),
            txs.iter().map(|tx| tx.ed25519_signature().expect("a signature")).collect(),
            txs.iter().map(|tx| tx.tx.ed25519_key().expect("a key")).collect(),
        )
    }

    /// The merged equation's verdict, asserted equal to ed25519-dalek's.
    fn verdict(hashes: &[B256], signatures: &[EdSignature], keys: &[VerifyingKey]) -> bool {
        let messages: Vec<&[u8]> = hashes.iter().map(|hash| hash.as_slice()).collect();
        let merged = batch_equation_holds(&messages, signatures, keys);
        let dalek = ed25519_dalek::verify_batch(&messages, signatures, keys).is_ok();
        assert_eq!(merged, dalek, "merged {merged}, ed25519-dalek {dalek}");
        merged
    }

    #[test]
    fn merged_batch_verdicts_match_ed25519_dalek() {
        let one_sender: Vec<AltSigTx> = (0..128).map(|nonce| signed(7, nonce)).collect();
        let (hashes, signatures, keys) = parts(&one_sender);
        assert!(verdict(&hashes, &signatures, &keys), "one sender");

        let five_senders: Vec<AltSigTx> = (0..64u64).map(|nonce| signed((nonce % 5) as u8 + 1, nonce)).collect();
        let (hashes, signatures, keys) = parts(&five_senders);
        assert!(verdict(&hashes, &signatures, &keys), "five senders interleaved");

        let (mut swapped, signatures, keys) = parts(&five_senders);
        swapped.swap(3, 4);
        assert!(!verdict(&swapped, &signatures, &keys), "two signatures over each other's message");

        let (hashes, mut signatures, keys) = parts(&one_sender);
        let mut undecompressable = [0u8; 32];
        while CompressedEdwardsY(undecompressable).decompress().is_some() {
            undecompressable[0] += 1;
        }
        let mut bytes = signatures[10].to_bytes();
        bytes[..32].copy_from_slice(&undecompressable);
        signatures[10] = EdSignature::from_bytes(&bytes);
        assert!(!verdict(&hashes, &signatures, &keys), "an R that does not decompress");

        let (hashes, mut signatures, keys) = parts(&one_sender);
        let mut bytes = signatures[20].to_bytes();
        bytes[32..].copy_from_slice(&[0xff; 32]);
        signatures[20] = EdSignature::from_bytes(&bytes);
        assert!(!verdict(&hashes, &signatures, &keys), "an s that is not canonical");

        assert!(verdict(&[], &[], &[]), "an empty batch");
    }

    /// Per-signature cost of ed25519-dalek's batch verification and the merged equation, for a
    /// batch from one sender and a batch from 128 senders. A measurement, not a check:
    /// `cargo test --release -p n42-tx-types --lib merged_batch_timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing; run by hand"]
    fn merged_batch_timing() {
        let shapes: [(&str, Vec<AltSigTx>); 2] = [
            ("one sender", (0..128).map(|nonce| signed(9, nonce)).collect()),
            ("128 senders", (0..128u64).map(|nonce| signed((nonce % 128) as u8 + 100, nonce)).collect()),
        ];
        for (name, txs) in shapes {
            let (hashes, signatures, keys) = parts(&txs);
            let messages: Vec<&[u8]> = hashes.iter().map(|hash| hash.as_slice()).collect();
            let per_signature = |f: &dyn Fn() -> bool| {
                let mut runs: Vec<f64> = (0..60)
                    .map(|_| {
                        let started = std::time::Instant::now();
                        assert!(f());
                        started.elapsed().as_secs_f64() * 1e6 / 128.0
                    })
                    .collect();
                runs.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
                runs[runs.len() / 2]
            };
            let dalek = per_signature(&|| ed25519_dalek::verify_batch(&messages, &signatures, &keys).is_ok());
            let merged = per_signature(&|| batch_equation_holds(&messages, &signatures, &keys));
            println!("{name}: ed25519-dalek {dalek:.1} us a signature, merged {merged:.1} us ({:.0}% less)", (1.0 - merged / dalek) * 100.0);
        }
    }

    #[test]
    fn a_batch_with_one_bad_signature_gives_each_transaction_its_own_verdict() {
        let mut txs: Vec<AltSigTx> = (0..32u64).map(|nonce| signed((nonce % 3) as u8 + 20, nonce)).collect();
        let (fields, signature, _) = txs[5].clone().into_parts();
        let mut corrupted = signature.to_vec();
        corrupted[40] ^= 1;
        txs[5] = AltSigTx::new(fields, Bytes::from(corrupted));
        let refs: Vec<&AltSigTx> = txs.iter().collect();
        let batch = verify_batch(&refs);
        for (tx, verdict) in txs.iter().zip(batch) {
            assert_eq!(verdict.is_ok(), tx.verify().is_ok());
        }
        assert!(verify_batch(&refs)[5].is_err());
    }
}
