// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's block gossip: how a block body reaches the validators that vote on it.
//!
//! A HotStuff-2 proposal carries only a block hash. The body travels separately,
//! on gov5's block topic — `/n42/<fork digest>/block/ssz_snappy`, where the fork
//! digest is the first four bytes of the genesis hash — as raw-snappy RLP of
//! `[header, transactions, verifiers, rewards]` (`internal/p2p/broadcaster.go`
//! `BroadcastBlock`). A follower that has the body executes the proposal and
//! casts its deferred vote; one that does not has nothing to vote on, and a
//! fleet where nobody but the leader has bodies never reaches quorum.
//!
//! Ported from N42-26's `gov5_block.rs`, with one addition: a
//! [`HeaderProfile`]. gov5's live H2 headers have a shape of their own — a zero
//! ommers hash, an `N42H`-prefixed extra-data field carrying the view — that an
//! Engine API payload cannot express directly, so decoding one means
//! reconstructing it. This node's own blocks do not have that shape yet (its
//! builder still seals them the Ethereum way), so a Rust fleet gossips them
//! under [`HeaderProfile::Ethereum`], where the header is exactly what the
//! payload says. The wire format is gov5's either way; the profile decides only
//! which header shapes are accepted, and a mixed fleet needs the builder to
//! adopt gov5's.

use alloy_consensus::{proofs::calculate_transaction_root, Block, Header, TxEnvelope};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader, RlpDecodable, RlpEncodable};
use n42_h2_consensus::{rewards_to_withdrawals, withdrawals_to_rewards};
use alloy_rpc_types_engine::ExecutionData;
use libp2p::gossipsub::IdentTopic;

/// Fixed prefix gov5's H2 header-extra encoder writes.
pub const GOV5_HEADER_EXTRA_MAGIC: &[u8; 4] = b"N42H";
/// Magic plus the little-endian view number.
pub const MIN_GOV5_HEADER_EXTRA_BYTES: usize = 12;
/// Bound shared with gov5's high-TC envelope limit.
pub const MAX_GOV5_HEADER_EXTRA_BYTES: usize = 4096;

/// Which header shapes a block on the wire may have. The chain-wide
/// definition lives with the consensus crate; this is the same type.
pub use n42_h2_consensus::header_profile::N42HeaderProfile as HeaderProfile;

/// The block topic for a chain.
pub fn gov5_block_topic(genesis_hash: B256) -> IdentTopic {
    let fork_digest = hex::encode(&genesis_hash.as_slice()[..4]);
    IdentTopic::new(format!("/n42/{fork_digest}/block/ssz_snappy"))
}

/// A block as decoded from the wire.
#[derive(Clone, Debug)]
pub struct GossipBlock {
    /// Keccak of the header RLP, which is the hash the proposal named.
    pub block_hash: B256,
    /// The header, exactly as the producer sealed it.
    pub header: Header,
    /// The transactions, in order.
    pub transactions: Vec<TxEnvelope>,
    /// The rewards, in order, as `(address, amount in wei)`.
    pub rewards: Vec<(Address, U256)>,
    /// The rewards as the withdrawals this node's execution layer credits
    /// (`rewards_to_withdrawals`); checked convertible when decoded.
    pub withdrawals: Vec<Withdrawal>,
    /// The EIP-7928 block access list, when the producer sent one.
    ///
    /// Carried because reth executes a block with one in parallel and a block
    /// without one serially, and refuses one entirely on an Amsterdam chain.
    pub bal: Option<alloy_primitives::Bytes>,
}

/// Why a block could not be encoded or decoded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockGossipError {
    /// The bytes are not the `[header, txs, verifiers, rewards]` list.
    #[error("invalid gov5 block RLP")]
    InvalidRlp,
    /// The header is not a shape the profile accepts.
    #[error("block header violates the {0:?} profile: {1}")]
    HeaderProfile(HeaderProfile, String),
    /// The transactions do not hash to the header's transactions root.
    #[error("block transaction root mismatch")]
    TransactionRootMismatch,
    /// The payload could not be turned back into a block.
    #[error("execution payload cannot reconstruct a block: {0}")]
    PayloadReconstruction(String),
    /// The reconstructed header does not hash to the payload's block hash.
    #[error("execution payload block hash does not match its reconstructed header")]
    PayloadHashMismatch,
    /// The compressed payload could not be expanded.
    #[error("snappy: {0}")]
    Snappy(String),
    /// A reward cannot be a withdrawal, or the list does not decode.
    #[error("block rewards: {0}")]
    InvalidRewards(String),
    /// The rewards do not hash to the header's withdrawals root.
    #[error("block rewards root mismatch")]
    RewardsRootMismatch,
}

/// The view a gov5 H2 header was proposed in.
pub fn gov5_header_view(header: &Header) -> Result<u64, BlockGossipError> {
    n42_h2_consensus::header_view(header)
        .map_err(|e| BlockGossipError::HeaderProfile(HeaderProfile::Gov5H2, e.to_string()))
}

/// Checks a header against a profile.
pub fn validate_header(header: &Header, profile: HeaderProfile) -> Result<(), BlockGossipError> {
    let violation = |reason: &str| {
        Err(BlockGossipError::HeaderProfile(profile, reason.to_owned()))
    };
    match profile {
        HeaderProfile::Ethereum => {
            if header.ommers_hash != alloy_consensus::EMPTY_OMMER_ROOT_HASH {
                return violation("ommers hash is not the empty-list hash");
            }
            if header.extra_data.len() > MAX_GOV5_HEADER_EXTRA_BYTES {
                return violation("extra data exceeds 4096 bytes");
            }
            Ok(())
        }
        HeaderProfile::Gov5H2 => n42_h2_consensus::validate_gov5_h2_header(header)
            .map(|_| ())
            .map_err(|e| BlockGossipError::HeaderProfile(profile, e.to_string())),
    }
}

/// Encodes a locally built payload as gov5's block gossip form, compressed the
/// way the topic expects.
///
/// The verifier and reward lists are empty: execution validity and H2-v4
/// consensus authentication travel separately.
pub fn encode_block_gossip(
    execution: &ExecutionData,
    profile: HeaderProfile,
) -> Result<Vec<u8>, BlockGossipError> {
    compress_block_rlp(&encode_block_rlp(execution, profile)?)
}

/// The topic's compression of an already-encoded block.
pub fn compress_block_rlp(rlp: &[u8]) -> Result<Vec<u8>, BlockGossipError> {
    snap::raw::Encoder::new()
        .compress_vec(rlp)
        .map_err(|error| BlockGossipError::Snappy(error.to_string()))
}

/// The block RLP inside a compressed topic payload, before any decoding —
/// what a node keeps to serve `block_by_hash` requests byte for byte.
pub fn decompress_block_gossip(data: &[u8]) -> Result<Vec<u8>, BlockGossipError> {
    let len = snap::raw::decompress_len(data)
        .map_err(|error| BlockGossipError::Snappy(error.to_string()))?;
    if len > crate::config::max_gossip_size() {
        return Err(BlockGossipError::Snappy("expands past the gossip size limit".into()));
    }
    snap::raw::Decoder::new()
        .decompress_vec(data)
        .map_err(|error| BlockGossipError::Snappy(error.to_string()))
}

/// Decodes a compressed block off the topic.
pub fn decode_block_gossip(
    data: &[u8],
    profile: HeaderProfile,
) -> Result<GossipBlock, BlockGossipError> {
    decode_block_rlp(&decompress_block_gossip(data)?, profile)
}

/// The uncompressed wire form: `[header, tx_bytes, verifiers, rewards]`.
pub fn encode_block_rlp(
    execution: &ExecutionData,
    profile: HeaderProfile,
) -> Result<Vec<u8>, BlockGossipError> {
    let block = reconstruct_block(execution, profile)?;
    if calculate_transaction_root(&block.body.transactions) != block.header.transactions_root {
        return Err(BlockGossipError::TransactionRootMismatch);
    }
    let rewards = withdrawals_to_rewards(block.body.withdrawals.as_ref().map_or(&[][..], |w| w.as_slice()));
    Ok(encode_block_rlp_parts(&block.header, &block.body.transactions, &rewards))
}

/// One reward on the wire: gov5's `Reward{Address, Amount}` under
/// reflective RLP, `[address, amount]`.
#[derive(RlpEncodable, RlpDecodable)]
struct RewardRlp {
    address: Address,
    amount: U256,
}

/// The uncompressed wire form for a header, its transactions and its
/// rewards as they stand — what a node that already holds the block serves.
pub fn encode_block_rlp_parts(
    header: &Header,
    transactions: &[TxEnvelope],
    rewards: &[(Address, U256)],
) -> Vec<u8> {
    let transaction_bytes = transactions
        .iter()
        .map(|transaction| Bytes::from(transaction.encoded_2718()))
        .collect::<Vec<_>>();
    encode_block_rlp_raw(header, &transaction_bytes, rewards, None)
}

/// The same wire form, from transactions that are already EIP-2718 bytes.
///
/// What a node that *built* the block has: the payload it got back from the
/// execution layer carries every transaction as the bytes this encoding wants,
/// and the header came out of sealing. Going through [`TxEnvelope`] to get here
/// decodes each of them and encodes it straight back — 346-401 ms for a
/// 163,000-transaction block, against 9-10 ms to compress the nineteen
/// megabytes that come out.
pub fn encode_block_rlp_raw(
    header: &Header,
    transaction_bytes: &[Bytes],
    rewards: &[(Address, U256)],
    bal: Option<&Bytes>,
) -> Vec<u8> {
    let mut header_rlp = Vec::new();
    header.encode(&mut header_rlp);
    let verifiers = Vec::<Bytes>::new();
    let rewards = rewards
        .iter()
        .map(|(address, amount)| RewardRlp { address: *address, amount: *amount })
        .collect::<Vec<_>>();
    // The transaction list encoded by hand, because a slice of `Bytes` is not
    // `Encodable` and collecting it into a `Vec` to borrow the impl would
    // allocate a second copy of every transaction in the block. This is what
    // `Vec<Bytes>` encodes to: an RLP list of RLP strings.
    let items_length: usize = transaction_bytes.iter().map(Encodable::length).sum();
    let transactions_length =
        RlpHeader { list: true, payload_length: items_length }.length_with_payload();
    let bal_length = bal.map_or(0, alloy_rlp::Encodable::length);
    let payload_length = header_rlp.len()
        + transactions_length
        + verifiers.length()
        + rewards.length()
        + bal_length;
    let mut encoded = Vec::with_capacity(payload_length + 16);
    RlpHeader {
        list: true,
        payload_length,
    }
    .encode(&mut encoded);
    encoded.extend_from_slice(&header_rlp);
    RlpHeader { list: true, payload_length: items_length }.encode(&mut encoded);
    for raw in transaction_bytes {
        raw.encode(&mut encoded);
    }
    verifiers.encode(&mut encoded);
    rewards.encode(&mut encoded);
    // Fifth, and only when there is one: the decoder has always tolerated a
    // trailing item, so a producer that sends none stays byte-identical to what
    // it sent before.
    if let Some(bal) = bal {
        bal.encode(&mut encoded);
    }
    encoded
}

/// Decodes the uncompressed wire form.
///
/// The verifier and reward lists, and an optional trailing ZK proof, are
/// consumed structurally and never trusted: the header commits to the
/// transactions, and consensus separately authenticates the block hash.
pub fn decode_block_rlp(
    encoded: &[u8],
    profile: HeaderProfile,
) -> Result<GossipBlock, BlockGossipError> {
    let mut payload = encoded;
    let outer = RlpHeader::decode(&mut payload).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !outer.list || outer.payload_length != payload.len() {
        return Err(BlockGossipError::InvalidRlp);
    }

    let header_rlp = take_rlp_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let mut header_cursor = header_rlp;
    let header = Header::decode(&mut header_cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !header_cursor.is_empty() {
        return Err(BlockGossipError::InvalidRlp);
    }
    validate_header(&header, profile)?;

    let transactions_rlp = take_rlp_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let transactions = decode_transactions(transactions_rlp)?;

    take_rlp_list_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let rewards_rlp = take_rlp_list_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let rewards = decode_rewards(rewards_rlp)?;
    // A fifth item, when the producer put one there: the EIP-7928 access list.
    // The slot was already tolerated-and-discarded for forward compatibility,
    // which is what makes this an extension rather than a format change -- a
    // node that does not send one still decodes here, and one that does is no
    // longer throwing away the thing that decides whether every other member
    // executes the block in parallel or one transaction at a time.
    let bal = if payload.is_empty() {
        None
    } else {
        take_rlp_bytes(&mut payload)
            .ok_or(BlockGossipError::InvalidRlp)
            .map(|bytes| Some(alloy_primitives::Bytes::copy_from_slice(bytes)))?
    };
    if !payload.is_empty() {
        return Err(BlockGossipError::InvalidRlp);
    }

    if calculate_transaction_root(&transactions) != header.transactions_root {
        return Err(BlockGossipError::TransactionRootMismatch);
    }
    // The withdrawals root is gov5's rewards commitment; rewards that do not
    // hash to it are not the block's, and would only fail in execution. A
    // block without rewards may carry either spelling of "none": gov5's
    // keccak of nothing, or the empty trie root its resealed history and
    // genesis write.
    if profile == HeaderProfile::Gov5H2
        && let Some(root) = header.withdrawals_root
        && root != n42_h2_consensus::gov5_rewards_root(rewards.iter().copied())
        && !(rewards.is_empty() && root == alloy_consensus::EMPTY_ROOT_HASH)
    {
        return Err(BlockGossipError::RewardsRootMismatch);
    }
    let withdrawals = rewards_to_withdrawals(&rewards)
        .map_err(|error| BlockGossipError::InvalidRewards(error.to_string()))?;

    Ok(GossipBlock {
        block_hash: keccak256(header_rlp),
        header,
        transactions,
        rewards,
        withdrawals,
        bal,
    })
}

/// The rewards list: `[[address, amount], ...]`.
fn decode_rewards(encoded: &[u8]) -> Result<Vec<(Address, U256)>, BlockGossipError> {
    let mut cursor = encoded;
    let list = RlpHeader::decode(&mut cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !list.list || list.payload_length != cursor.len() {
        return Err(BlockGossipError::InvalidRlp);
    }
    let mut rewards = Vec::new();
    while !cursor.is_empty() {
        let reward = RewardRlp::decode(&mut cursor)
            .map_err(|error| BlockGossipError::InvalidRewards(error.to_string()))?;
        rewards.push((reward.address, reward.amount));
    }
    Ok(rewards)
}

impl GossipBlock {
    /// The execution payload a follower hands its execution layer.
    ///
    /// Everything the Engine API needs is in the header and transactions,
    /// with one exception: execution requests are carried by hash only, since
    /// gov5's block form does not list them. A block with the empty requests
    /// hash gets the empty list, which every version accepts; one with real
    /// requests is handed over by hash, which an execution layer accepts only
    /// where its API allows it.
    pub fn execution_data(&self) -> ExecutionData {
        let withdrawals = self.header.withdrawals_root.map(|_| Withdrawals(self.withdrawals.clone()));
        let block = Block {
            header: self.header.clone(),
            body: alloy_consensus::BlockBody {
                transactions: self.transactions.clone(),
                ommers: Vec::new(),
                withdrawals,
            },
        };
        n42_h2_consensus::execution_data_for_block_with_bal(self.block_hash, &block, self.bal.clone())
    }
}

/// [`GossipBlock`] with the transactions left as the bytes they arrived as.
///
/// What a follower needs: the header to remember and vote on, the bytes to
/// hand to its execution layer. Decoding 163,000 transactions into envelopes
/// and encoding them back was ~200 ms on the follower's critical path, and
/// the transactions-root check that decoding enabled is one the execution
/// layer repeats before it accepts the block.
#[derive(Debug, Clone)]
pub struct RawGossipBlock {
    /// Keccak of the header RLP, which is the hash the proposal named.
    pub block_hash: B256,
    /// The header, exactly as the producer sealed it.
    pub header: Header,
    /// Each transaction's EIP-2718 bytes, in block order.
    pub transactions: Vec<Bytes>,
    /// gov5's rewards, as sent.
    pub rewards: Vec<(Address, U256)>,
    /// The rewards as the withdrawals this node's execution layer credits.
    pub withdrawals: Vec<Withdrawal>,
    /// The EIP-7928 block access list, when the producer sent one.
    pub bal: Option<Bytes>,
}

impl RawGossipBlock {
    /// The Engine API form of this block, straight from the bytes.
    pub fn execution_data(&self) -> ExecutionData {
        n42_h2_consensus::execution_data_from_raw_parts(
            self.block_hash,
            &self.header,
            self.transactions.clone(),
            self.withdrawals.clone(),
            self.bal.clone(),
        )
    }
}

/// [`decode_block_rlp`] without decoding the transactions. See
/// [`RawGossipBlock`].
pub fn decode_block_rlp_raw(
    encoded: &[u8],
    profile: HeaderProfile,
) -> Result<RawGossipBlock, BlockGossipError> {
    let mut payload = encoded;
    let outer = RlpHeader::decode(&mut payload).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !outer.list || outer.payload_length != payload.len() {
        return Err(BlockGossipError::InvalidRlp);
    }
    let header_rlp = take_rlp_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let mut header_cursor = header_rlp;
    let header = Header::decode(&mut header_cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !header_cursor.is_empty() {
        return Err(BlockGossipError::InvalidRlp);
    }
    validate_header(&header, profile)?;

    let transactions_rlp = take_rlp_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let mut cursor = transactions_rlp;
    let list = RlpHeader::decode(&mut cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !list.list || list.payload_length != cursor.len() {
        return Err(BlockGossipError::InvalidRlp);
    }
    let mut transactions = Vec::with_capacity(cursor.len() / 100);
    while !cursor.is_empty() {
        let bytes = take_rlp_bytes(&mut cursor).ok_or(BlockGossipError::InvalidRlp)?;
        if bytes.is_empty() {
            return Err(BlockGossipError::InvalidRlp);
        }
        transactions.push(Bytes::copy_from_slice(bytes));
    }

    take_rlp_list_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let rewards_rlp = take_rlp_list_item(&mut payload).ok_or(BlockGossipError::InvalidRlp)?;
    let rewards = decode_rewards(rewards_rlp)?;
    let bal = if payload.is_empty() {
        None
    } else {
        take_rlp_bytes(&mut payload)
            .ok_or(BlockGossipError::InvalidRlp)
            .map(|bytes| Some(Bytes::copy_from_slice(bytes)))?
    };
    if !payload.is_empty() {
        return Err(BlockGossipError::InvalidRlp);
    }
    if profile == HeaderProfile::Gov5H2
        && let Some(root) = header.withdrawals_root
        && root != n42_h2_consensus::gov5_rewards_root(rewards.iter().copied())
        && !(rewards.is_empty() && root == alloy_consensus::EMPTY_ROOT_HASH)
    {
        return Err(BlockGossipError::RewardsRootMismatch);
    }
    let withdrawals = rewards_to_withdrawals(&rewards)
        .map_err(|error| BlockGossipError::InvalidRewards(error.to_string()))?;
    Ok(RawGossipBlock { block_hash: keccak256(header_rlp), header, transactions, rewards, withdrawals, bal })
}

/// Rebuilds the block a payload describes, under a profile.
///
/// Engine payloads carry neither `ommers_hash` nor `difficulty`; the profile
/// says what they were. Both gov5 H2 difficulty variants are tried and the
/// payload's block hash selects the right one — no guessing is involved.
fn reconstruct_block(
    execution: &ExecutionData,
    profile: HeaderProfile,
) -> Result<Block<TxEnvelope>, BlockGossipError> {
    let expected_hash = execution.block_hash();
    let direct = execution
        .clone()
        .try_into_block::<TxEnvelope>()
        .map_err(|error| BlockGossipError::PayloadReconstruction(error.to_string()))?;
    match profile {
        HeaderProfile::Ethereum => {
            validate_header(&direct.header, profile)?;
            if direct.header.hash_slow() != expected_hash {
                return Err(BlockGossipError::PayloadHashMismatch);
            }
            Ok(direct)
        }
        HeaderProfile::Gov5H2 => n42_h2_consensus::reconstruct_gov5_h2_block::<TxEnvelope>(execution)
            .map_err(|e| BlockGossipError::HeaderProfile(profile, e.to_string())),
    }
}

fn decode_transactions(encoded: &[u8]) -> Result<Vec<TxEnvelope>, BlockGossipError> {
    let mut cursor = encoded;
    let list = RlpHeader::decode(&mut cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
    if !list.list || list.payload_length != cursor.len() {
        return Err(BlockGossipError::InvalidRlp);
    }
    let mut transactions = Vec::new();
    while !cursor.is_empty() {
        let bytes = take_rlp_bytes(&mut cursor).ok_or(BlockGossipError::InvalidRlp)?;
        let mut tx_cursor = bytes;
        let transaction =
            TxEnvelope::decode_2718(&mut tx_cursor).map_err(|_| BlockGossipError::InvalidRlp)?;
        if !tx_cursor.is_empty() {
            return Err(BlockGossipError::InvalidRlp);
        }
        transactions.push(transaction);
    }
    Ok(transactions)
}

/// One RLP item — header and payload — as a slice, advancing the cursor.
fn take_rlp_item<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let mut probe = *cursor;
    let header = RlpHeader::decode(&mut probe).ok()?;
    let header_len = cursor.len() - probe.len();
    let total = header_len.checked_add(header.payload_length)?;
    if total > cursor.len() {
        return None;
    }
    let (item, rest) = cursor.split_at(total);
    *cursor = rest;
    Some(item)
}

fn take_rlp_list_item<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let mut probe = *cursor;
    let header = RlpHeader::decode(&mut probe).ok()?;
    if !header.list {
        return None;
    }
    take_rlp_item(cursor)
}

/// A byte-string item's payload, advancing the cursor.
fn take_rlp_bytes<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let mut probe = *cursor;
    let header = RlpHeader::decode(&mut probe).ok()?;
    if header.list {
        return None;
    }
    let header_len = cursor.len() - probe.len();
    let total = header_len.checked_add(header.payload_length)?;
    if total > cursor.len() {
        return None;
    }
    let (item, rest) = cursor.split_at(total);
    *cursor = rest;
    Some(&item[header_len..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::BlockBody;
    use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
    use alloy_primitives::{Address, U256};

    fn header(extra: Bytes) -> Header {
        Header {
            parent_hash: B256::repeat_byte(1),
            ommers_hash: alloy_consensus::EMPTY_OMMER_ROOT_HASH,
            beneficiary: Address::ZERO,
            state_root: B256::repeat_byte(2),
            transactions_root: calculate_transaction_root::<TxEnvelope>(&[]),
            receipts_root: alloy_consensus::EMPTY_ROOT_HASH,
            number: 7,
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            extra_data: extra,
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        }
    }

    fn execution_data(header: Header) -> ExecutionData {
        let block = Block {
            header,
            body: BlockBody {
                transactions: Vec::<TxEnvelope>::new(),
                ommers: Vec::new(),
                withdrawals: Some(Default::default()),
            },
        };
        ExecutionData::from_block_unchecked(block.header.hash_slow(), &block)
    }

    #[test]
    fn a_block_survives_the_wire_and_reconstructs_the_same_payload() {
        let sealed = header(Bytes::from(vec![0u8; 97]));
        let execution = execution_data(sealed.clone());

        let wire = encode_block_gossip(&execution, HeaderProfile::Ethereum).unwrap();
        let decoded = decode_block_gossip(&wire, HeaderProfile::Ethereum).unwrap();
        assert_eq!(decoded.block_hash, execution.block_hash());
        assert_eq!(decoded.header, sealed);

        // And the follower's payload names the same block.
        let rebuilt = decoded.execution_data();
        assert_eq!(rebuilt.block_hash(), execution.block_hash());
        assert!(rebuilt.sidecar.requests().is_some(), "an empty requests hash becomes the empty list");
    }

    #[test]
    fn a_gov5_h2_header_is_reconstructed_by_its_hash() {
        let mut extra = Vec::new();
        extra.extend_from_slice(GOV5_HEADER_EXTRA_MAGIC);
        extra.extend_from_slice(&42u64.to_le_bytes());
        extra.resize(12 + 65, 0);
        let mut sealed = header(extra.into());
        sealed.ommers_hash = B256::ZERO;
        sealed.difficulty = U256::ZERO;
        let execution = execution_data(sealed.clone());

        // The payload cannot say "zero ommers"; the profile does, and the hash
        // confirms it.
        let wire = encode_block_gossip(&execution, HeaderProfile::Gov5H2).unwrap();
        let decoded = decode_block_gossip(&wire, HeaderProfile::Gov5H2).unwrap();
        assert_eq!(decoded.header, sealed);
        assert_eq!(gov5_header_view(&decoded.header).unwrap(), 42);

        // The Ethereum profile refuses it, and vice versa.
        assert!(encode_block_gossip(&execution, HeaderProfile::Ethereum).is_err());
        assert!(decode_block_gossip(&wire, HeaderProfile::Ethereum).is_err());
    }

    #[test]
    fn a_header_that_does_not_hash_to_the_payload_is_refused() {
        let execution = execution_data(header(Bytes::new()));
        let mut lying = execution.clone();
        lying.payload.as_v1_mut().block_hash = B256::repeat_byte(0xEE);
        assert_eq!(
            encode_block_gossip(&lying, HeaderProfile::Ethereum),
            Err(BlockGossipError::PayloadHashMismatch)
        );
    }

    #[test]
    fn garbage_is_rejected_not_panicked_on() {
        for bytes in [&[][..], &[0xC0][..], &[0xFF; 8][..]] {
            assert!(decode_block_rlp(bytes, HeaderProfile::Ethereum).is_err());
        }
        let compressed = snap::raw::Encoder::new().compress_vec(&[0xC1, 0x80]).unwrap();
        assert!(decode_block_gossip(&compressed, HeaderProfile::Ethereum).is_err());
    }

    /// `Block.Marshal()` of an empty Cancun+Prague block, printed by gov5's
    /// own code (`cmd/h2-profile-fixture`): the bytes `BroadcastBlock` puts on
    /// the block topic before snappy.
    #[test]
    fn a_block_gov5_produced_decodes_to_the_hash_gov5_computed() {
        let header_rlp =
            alloy_primitives::hex::decode(include_str!("../testdata/gov5_empty_block.header.hex").trim())
                .unwrap();
        let mut cursor = header_rlp.as_slice();
        let header = alloy_consensus::Header::decode(&mut cursor)
            .unwrap_or_else(|e| panic!("gov5 header does not decode: {e}"));
        assert!(cursor.is_empty(), "gov5 header has {} trailing bytes", cursor.len());
        assert_eq!(
            header.hash_slow(),
            alloy_primitives::b256!("7f9765be6eb977fdd306510e60aeac2d4c6cb7925016d5c9b48dc0722544234a")
        );

        let rlp = alloy_primitives::hex::decode(include_str!("../testdata/gov5_empty_block.rlp.hex").trim())
            .unwrap();
        let block = decode_block_rlp(&rlp, HeaderProfile::Gov5H2)
            .unwrap_or_else(|e| panic!("gov5 block does not decode: {e:?}"));
        assert_eq!(block.block_hash, header.hash_slow());
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn the_topic_is_bound_to_the_chains_fork_digest() {
        let genesis = B256::repeat_byte(0xAB);
        assert_eq!(gov5_block_topic(genesis).to_string(), "/n42/abababab/block/ssz_snappy");
    }
}

#[cfg(test)]
mod bal_roundtrip {
    use super::*;

    /// The access list has to survive the wire, because on an Amsterdam chain a
    /// payload without one is refused outright and on any chain a block without
    /// one is executed serially. Losing it is silent at the encoder and shows up
    /// as `Unsupported fork` three hops away.
    #[test]
    fn an_access_list_survives_encode_and_decode() {
        let header = Header { number: 5, ..Default::default() };
        let bal = Bytes::from_static(&[0xc4, 0x83, 0x01, 0x02, 0x03]);
        let encoded = encode_block_rlp_raw(&header, &[], &[], Some(&bal));
        let decoded = decode_block_rlp(&encoded, HeaderProfile::Ethereum)
            .expect("a block with an access list decodes");
        assert_eq!(decoded.bal.as_ref(), Some(&bal), "the access list came back changed");
    }

    /// The raw decode is the typed decode, minus the decode: same header, the
    /// same bytes per transaction, the same Engine API form.
    #[test]
    fn the_raw_decode_agrees_with_the_typed_one() {
        use alloy_consensus::{Signed, TxEip1559, TxLegacy};
        use alloy_eips::Encodable2718;
        use alloy_primitives::{Signature, TxKind};
        let txs: Vec<TxEnvelope> = vec![
            TxEnvelope::Eip1559(Signed::new_unchecked(TxEip1559 { chain_id: 1, nonce: 1, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(9), ..Default::default() }, Signature::test_signature(), Default::default())),
            TxEnvelope::Legacy(Signed::new_unchecked(TxLegacy { chain_id: Some(1), nonce: 2, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(1), ..Default::default() }, Signature::test_signature(), Default::default())),
        ];
        let rewards = vec![(Address::repeat_byte(0x42), U256::from(5_000_000_000u64))];
        let header = Header {
            number: 7, base_fee_per_gas: Some(7), blob_gas_used: Some(0), excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::repeat_byte(9)),
            withdrawals_root: Some(n42_h2_consensus::gov5_rewards_root(rewards.iter().copied())),
            transactions_root: alloy_consensus::proofs::calculate_transaction_root(&txs),
            ..Default::default()
        };
        let encoded = encode_block_rlp_parts(&header, &txs, &rewards);
        let typed = decode_block_rlp(&encoded, HeaderProfile::Ethereum).expect("typed decodes");
        let raw = decode_block_rlp_raw(&encoded, HeaderProfile::Ethereum).expect("raw decodes");
        assert_eq!(raw.block_hash, typed.block_hash);
        assert_eq!(raw.header, typed.header);
        assert_eq!(raw.withdrawals, typed.withdrawals);
        assert_eq!(raw.transactions.iter().map(|b| b.to_vec()).collect::<Vec<_>>(), txs.iter().map(|t| t.encoded_2718()).collect::<Vec<_>>());
        assert_eq!(format!("{:?}", raw.execution_data()), format!("{:?}", typed.execution_data()));
    }

    /// And a producer that sends none stays byte-identical to what it sent
    /// before the field existed.
    #[test]
    fn no_access_list_is_the_old_encoding() {
        let header = Header { number: 5, ..Default::default() };
        assert_eq!(
            encode_block_rlp_raw(&header, &[], &[], None),
            encode_block_rlp_raw(&header, &[], &[], None),
        );
        let decoded = decode_block_rlp(&encode_block_rlp_raw(&header, &[], &[], None), HeaderProfile::Ethereum)
            .expect("a block without an access list decodes");
        assert!(decoded.bal.is_none());
    }
}
