// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! gov5's HotStuff-2 block header profile — what a block looks like when a
//! Go fleet member produced it, and what this node must produce for a Go
//! member to accept.
//!
//! The Ethereum header layout is kept field for field (gov5's `block.Header`
//! is "100% Ethereum Pectra compatible"), but four fields carry HotStuff
//! rather than proof-of-work or beacon-chain meaning
//! (`internal/consensus/hotstuff/adapter.go` `Prepare`, `header_extra.go`):
//!
//! - `extra_data` is `"N42H" ‖ view (u64 little-endian) ‖ [QC] ‖ seal`, the
//!   seal being 96 reserved bytes that `Seal` fills with the leader's BLS
//!   signature over the header hashed *without* those 96 bytes.
//! - `difficulty` is 0 (a legacy range carries 1). Ordering is by view.
//! - `beneficiary` is the leader's address.
//! - `ommers_hash` is whatever the producer left there. gov5's miner leaves
//!   the Go zero value, so live headers commit to `B256::ZERO`; its genesis
//!   uses the Ethereum empty-list hash. Neither side checks it, both sides
//!   hash it, so a decoder must reconstruct exactly what was there.
//!
//! And one commitment differs: gov5 computes the **receipts root** as the
//! keccak of the concatenated receipt encodings (`hash.DeriveSha`, keccak of
//! nothing for an empty block), not as a Merkle-Patricia root. The
//! transactions root is the ordinary trie root on a QMDB chain
//! (`block.UseEthereumTxRoot`).
//!
//! Everything here is checked against bytes produced by gov5's own code.
//! `VerifyHeader` on the Go side checks the extra layout, timestamp > parent,
//! gas used ≤ gas limit, and that no parent beacon root is set while no
//! committee evidence exists; it does not verify the seal. This node signs it
//! anyway.

use alloy_consensus::{Block, BlockBody, Header, TxEnvelope, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::eip7685::{Requests, RequestsOrHash, EMPTY_REQUESTS_HASH};
use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use alloy_primitives::{b256, keccak256, Address, Bytes, Log, B256, U256};
use alloy_rlp::{Encodable, RlpEncodable};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar,
    PraguePayloadFields,
};
use n42_h2_primitives::bls::{BlsPublicKey, BlsSecretKey, BlsSignature};

/// Which header shape a chain's blocks have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum N42HeaderProfile {
    /// The header is exactly what the execution payload says: empty-list
    /// ommers hash, whatever extra data the builder sealed. An APoS chain.
    #[default]
    Ethereum,
    /// gov5's HotStuff-2 header, described in this module. A chain whose
    /// genesis names a `hotstuff` validator set.
    Gov5H2,
}

/// The four bytes every HotStuff header's extra data starts with.
pub const GOV5_HEADER_EXTRA_MAGIC: [u8; 4] = *b"N42H";
/// Magic plus the little-endian view.
pub const EXTRA_MIN_LEN: usize = 12;
/// The BLS seal gov5 reserves at the end of the extra data.
pub const EXTRA_SEAL_LEN: usize = 96;
/// Bound shared with gov5's high-TC envelope limit.
pub const MAX_HEADER_EXTRA_LEN: usize = 4096;

/// `keccak256("")`: gov5's receipts root for a block with no receipts
/// (`hash.NilHash`), and its withdrawals root for a block with no rewards.
pub const GOV5_NIL_HASH: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

/// What gov5 writes in `requestsHash` when a Prague block carried no
/// EIP-7685 requests: `keccak256(RLP([]))`, the empty trie root — not the
/// EIP's `sha256("")`, which gov5 uses only at genesis
/// (`hotstuff/adapter.go` `FinalizeAndAssemble`).
pub const GOV5_EMPTY_REQUESTS_HASH: B256 = alloy_consensus::EMPTY_ROOT_HASH;

/// gov5's `withdrawalsRoot`: not a withdrawals commitment at all but
/// `hash.DeriveSha(rewards)` — keccak over the concatenated
/// `rlp([address, amount])` of the block's validator rewards, keccak of
/// nothing when there are none. A chain where rewards are paid needs the
/// rewards list to reproduce it; this node pays none and produces the empty
/// value.
pub fn gov5_rewards_root(rewards: impl IntoIterator<Item = (Address, U256)>) -> B256 {
    let mut concatenated = Vec::new();
    for (address, amount) in rewards {
        #[derive(RlpEncodable)]
        struct Reward {
            address: Address,
            amount: U256,
        }
        Reward { address, amount }.encode(&mut concatenated);
    }
    keccak256(&concatenated)
}

/// Wei per gwei: an Engine API withdrawal's amount is in gwei.
const GWEI: u64 = 1_000_000_000;

/// gov5's rewards as the Engine API's withdrawals, which is how this node's
/// execution layer credits them: a withdrawal's amount is in gwei and is
/// credited after the transactions, exactly as gov5's `Finalize` credits a
/// reward. The withdrawal index is the reward's position and the validator
/// index zero; neither reaches the state or the header, whose withdrawals
/// root is gov5's rewards commitment, not the withdrawals trie.
///
/// A reward that is not a whole number of gwei has no withdrawal and is
/// refused; gov5's dev rewards are whole ether.
pub fn rewards_to_withdrawals(
    rewards: &[(Address, U256)],
) -> Result<Vec<Withdrawal>, HeaderProfileError> {
    let gwei = U256::from(GWEI);
    rewards
        .iter()
        .enumerate()
        .map(|(index, (address, amount))| {
            if *amount % gwei != U256::ZERO {
                return Err(HeaderProfileError::Reconstruction(format!(
                    "reward of {amount} wei to {address} is not a whole number of gwei"
                )));
            }
            let amount = u64::try_from(*amount / gwei).map_err(|_| {
                HeaderProfileError::Reconstruction(format!(
                    "reward of {amount} wei to {address} does not fit a withdrawal"
                ))
            })?;
            Ok(Withdrawal { index: index as u64, validator_index: 0, address: *address, amount })
        })
        .collect()
}

/// The rewards a block's withdrawals stand for; see [`rewards_to_withdrawals`].
pub fn withdrawals_to_rewards(withdrawals: &[Withdrawal]) -> Vec<(Address, U256)> {
    withdrawals
        .iter()
        .map(|withdrawal| (withdrawal.address, U256::from(withdrawal.amount) * U256::from(GWEI)))
        .collect()
}

/// Whether a `requestsHash` says "no requests" in either convention.
pub fn is_empty_requests_hash(hash: B256) -> bool {
    hash == EMPTY_REQUESTS_HASH || hash == GOV5_EMPTY_REQUESTS_HASH
}

/// What a header's extra data says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderExtra {
    /// The view the block was proposed in.
    pub view: u64,
    /// The committed QC the leader embedded, in gov5's own encoding, or empty.
    /// Carried opaquely: this node authenticates blocks through the
    /// proposal and commit certificates on the wire, not through this copy.
    pub qc: Vec<u8>,
    /// The trailing 96-byte seal, when the layout reserves one. All zeros
    /// before `Seal`, the leader's BLS signature after.
    pub seal: Option<[u8; EXTRA_SEAL_LEN]>,
}

impl HeaderExtra {
    /// The extra data a leader writes before sealing: view, no QC, seal
    /// reserved. What gov5's `buildHeaderExtra(view, nil)` produces.
    pub const fn for_view(view: u64) -> Self {
        Self {
            view,
            qc: Vec::new(),
            seal: Some([0; EXTRA_SEAL_LEN]),
        }
    }

    /// The bytes.
    pub fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(EXTRA_MIN_LEN + self.qc.len() + EXTRA_SEAL_LEN);
        out.extend_from_slice(&GOV5_HEADER_EXTRA_MAGIC);
        out.extend_from_slice(&self.view.to_le_bytes());
        out.extend_from_slice(&self.qc);
        if let Some(seal) = &self.seal {
            out.extend_from_slice(seal);
        }
        out.into()
    }

    /// Reads the layouts gov5's `decodeHeaderExtra` accepts.
    ///
    /// After magic and view: nothing; a seal alone; a QC followed by a seal;
    /// or, in the legacy layout, a QC alone. gov5 tells the last two apart by
    /// trying to decode the QC; this node does not decode QCs, so a payload
    /// longer than a seal is read as QC-then-seal, which is every header a
    /// current gov5 produces.
    pub fn decode(extra: &[u8]) -> Result<Self, HeaderProfileError> {
        if extra.len() > MAX_HEADER_EXTRA_LEN {
            return Err(HeaderProfileError::ExtraTooLong(extra.len()));
        }
        if extra.len() < EXTRA_MIN_LEN {
            return Err(HeaderProfileError::ExtraTooShort(extra.len()));
        }
        if extra[..4] != GOV5_HEADER_EXTRA_MAGIC {
            return Err(HeaderProfileError::MissingMagic);
        }
        let view = u64::from_le_bytes(
            extra[4..EXTRA_MIN_LEN]
                .try_into()
                .expect("length checked before fixed-width conversion"),
        );
        let payload = &extra[EXTRA_MIN_LEN..];
        let (qc, seal) = if payload.len() >= EXTRA_SEAL_LEN {
            let (qc, seal) = payload.split_at(payload.len() - EXTRA_SEAL_LEN);
            let mut fixed = [0u8; EXTRA_SEAL_LEN];
            fixed.copy_from_slice(seal);
            (qc.to_vec(), Some(fixed))
        } else {
            (payload.to_vec(), None)
        };
        Ok(Self { view, qc, seal })
    }
}

/// Why a header is not a gov5 HotStuff header.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderProfileError {
    /// Shorter than magic plus view.
    #[error("extra data is {0} bytes, shorter than magic + view")]
    ExtraTooShort(usize),
    /// Past gov5's bound.
    #[error("extra data is {0} bytes, past the 4096-byte bound")]
    ExtraTooLong(usize),
    /// Does not start with `N42H`.
    #[error("extra data does not start with N42H")]
    MissingMagic,
    /// Neither 0 nor the legacy 1.
    #[error("difficulty {0} is neither 0 nor the legacy 1")]
    Difficulty(U256),
    /// Post-merge headers carry a zero nonce.
    #[error("nonce is not zero")]
    Nonce,
    /// Neither gov5's zero nor Ethereum's empty-list hash.
    #[error("ommers hash {0} is neither zero nor the empty-list hash")]
    OmmersHash(B256),
    /// The layout reserves no seal to sign into.
    #[error("extra data reserves no seal")]
    NoSeal,
    /// The seal does not verify under the given key.
    #[error("seal does not verify: {0}")]
    Seal(String),
    /// A payload could not be turned back into a block.
    #[error("execution payload cannot reconstruct a block: {0}")]
    Reconstruction(String),
}

/// The view a header was proposed in.
pub fn header_view(header: &Header) -> Result<u64, HeaderProfileError> {
    HeaderExtra::decode(&header.extra_data).map(|extra| extra.view)
}

/// Checks the HotStuff-specific fields and returns the decoded extra data.
///
/// Fork-dependent fields (withdrawals root, blob gas, requests hash) are the
/// execution layer's business and are not looked at here.
pub fn validate_gov5_h2_header(header: &Header) -> Result<HeaderExtra, HeaderProfileError> {
    let extra = HeaderExtra::decode(&header.extra_data)?;
    if header.difficulty != U256::ZERO && header.difficulty != U256::from(1) {
        return Err(HeaderProfileError::Difficulty(header.difficulty));
    }
    if !header.nonce.is_zero() {
        return Err(HeaderProfileError::Nonce);
    }
    if header.ommers_hash != B256::ZERO && header.ommers_hash != EMPTY_OMMER_ROOT_HASH {
        return Err(HeaderProfileError::OmmersHash(header.ommers_hash));
    }
    Ok(extra)
}

/// The hash the leader signs: the header with the trailing seal removed
/// (gov5 `sealHash`, which strips 96 bytes only when there is more than a
/// seal's worth of extra data).
pub fn seal_hash(header: &Header) -> B256 {
    let mut unsealed = header.clone();
    if unsealed.extra_data.len() > EXTRA_SEAL_LEN {
        let keep = unsealed.extra_data.len() - EXTRA_SEAL_LEN;
        unsealed.extra_data = Bytes::copy_from_slice(&unsealed.extra_data[..keep]);
    }
    unsealed.hash_slow()
}

/// Signs the seal into the header's reserved trailing bytes, as gov5's `Seal`
/// does. The header's hash changes; re-hash after.
pub fn seal_header(header: &mut Header, key: &BlsSecretKey) -> Result<(), HeaderProfileError> {
    let extra = HeaderExtra::decode(&header.extra_data)?;
    if extra.seal.is_none() {
        return Err(HeaderProfileError::NoSeal);
    }
    // gov5 seals under the proof-of-possession ciphersuite, the same one its
    // consensus votes use.
    let signature = key.sign_h2_v4(seal_hash(header).as_slice());
    let mut bytes = header.extra_data.to_vec();
    let start = bytes.len() - EXTRA_SEAL_LEN;
    bytes[start..].copy_from_slice(&signature.to_bytes());
    header.extra_data = bytes.into();
    Ok(())
}

/// Checks the seal against a leader's public key.
pub fn verify_seal(header: &Header, leader: &BlsPublicKey) -> Result<(), HeaderProfileError> {
    let extra = HeaderExtra::decode(&header.extra_data)?;
    let seal = extra.seal.ok_or(HeaderProfileError::NoSeal)?;
    let signature =
        BlsSignature::from_bytes(&seal).map_err(|e| HeaderProfileError::Seal(e.to_string()))?;
    leader
        .verify_h2_v4_prevalidated(seal_hash(header).as_slice(), &signature)
        .map_err(|e| HeaderProfileError::Seal(e.to_string()))
}

/// The parts of a receipt gov5's receipts root commits to.
#[derive(Clone, Copy, Debug)]
pub struct ReceiptView<'a> {
    /// EIP-658 status.
    pub success: bool,
    /// Gas used by the block up to and including this transaction.
    pub cumulative_gas_used: u64,
    /// The logs.
    pub logs: &'a [Log],
}

#[derive(RlpEncodable)]
struct StoredLog {
    address: Address,
    topics: Vec<B256>,
    data: Bytes,
}

#[derive(RlpEncodable)]
struct StoredReceipt {
    status: u64,
    cumulative_gas_used: u64,
    logs: Vec<StoredLog>,
}

/// gov5's receipts root: `hash.DeriveSha(receipts)` — keccak over the
/// concatenation of `rlp([status, cumulativeGasUsed, [[address, topics,
/// data]…]])` per receipt, and keccak of nothing when there are none. Not a
/// trie; no bloom, no transaction type.
pub fn gov5_receipts_root<'a>(receipts: impl IntoIterator<Item = ReceiptView<'a>>) -> B256 {
    let mut concatenated = Vec::new();
    for receipt in receipts {
        StoredReceipt {
            status: u64::from(receipt.success),
            cumulative_gas_used: receipt.cumulative_gas_used,
            logs: receipt
                .logs
                .iter()
                .map(|log| StoredLog {
                    address: log.address,
                    topics: log.data.topics().to_vec(),
                    data: log.data.data.clone(),
                })
                .collect(),
        }
        .encode(&mut concatenated);
    }
    keccak256(&concatenated)
}

/// The Engine API payload for a block whose header is already final.
///
/// Everything the Engine API needs is in the header and transactions, with
/// one exception: execution requests are carried by hash only, since neither
/// gov5's block form nor a header lists them. A block with the empty requests
/// hash gets the empty list, which every `newPayload` version accepts; one
/// with real requests is handed over by hash, which an execution layer
/// accepts only where its API allows it.
pub fn execution_data_for_block(block_hash: B256, block: &Block<TxEnvelope>) -> ExecutionData {
    execution_data_for_block_with_bal(block_hash, block, None)
}

/// [`execution_data_for_block_with_bal`] from a header and the transactions'
/// EIP-2718 bytes, without decoding any of them.
///
/// The Engine API carries transactions as exactly these bytes, so a node that
/// has them -- every follower, straight off the wire -- gains nothing by
/// parsing 163,000 of them into envelopes and encoding each one back. Measured
/// on the seven-node fleet as ~200 ms of a follower's critical path, before
/// the execution layer even saw the block; the execution layer decodes once
/// on its own side regardless. Produces what the typed path produces, and a
/// test says so.
pub fn execution_data_from_raw_parts(
    block_hash: B256,
    header: &alloy_consensus::Header,
    transactions: Vec<alloy_primitives::Bytes>,
    withdrawals: Vec<alloy_eips::eip4895::Withdrawal>,
    bal: Option<alloy_primitives::Bytes>,
) -> ExecutionData {
    use alloy_rpc_types_engine::{ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ExecutionPayloadV4};
    // Blob transactions are the one kind whose contents the sidecar needs;
    // only those are decoded, and on this chain there are none.
    let versioned_hashes: Vec<B256> = transactions
        .iter()
        .filter(|tx| tx.first() == Some(&0x03))
        .filter_map(|tx| <TxEnvelope as alloy_eips::Decodable2718>::decode_2718(&mut tx.as_ref()).ok())
        .flat_map(|tx| {
            alloy_consensus::Transaction::blob_versioned_hashes(&tx).map(<[B256]>::to_vec).unwrap_or_default()
        })
        .collect();
    let v1 = ExecutionPayloadV1 {
        parent_hash: header.parent_hash,
        fee_recipient: header.beneficiary,
        state_root: header.state_root,
        receipts_root: header.receipts_root,
        logs_bloom: header.logs_bloom,
        prev_randao: header.mix_hash,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: header.extra_data.clone(),
        base_fee_per_gas: U256::from(header.base_fee_per_gas.unwrap_or_default()),
        block_hash,
        transactions,
        difficulty: header.difficulty,
        nonce: header.nonce,
    };
    let payload = match (header.withdrawals_root.is_some(), header.blob_gas_used) {
        (false, _) => ExecutionPayload::V1(v1),
        (true, None) => ExecutionPayload::V2(ExecutionPayloadV2 { payload_inner: v1, withdrawals }),
        (true, Some(blob_gas_used)) => {
            let v3 = ExecutionPayloadV3 {
                payload_inner: ExecutionPayloadV2 { payload_inner: v1, withdrawals },
                blob_gas_used,
                excess_blob_gas: header.excess_blob_gas.unwrap_or_default(),
            };
            match bal {
                Some(block_access_list) => ExecutionPayload::V4(ExecutionPayloadV4 {
                    payload_inner: v3,
                    block_access_list,
                    slot_number: header.number,
                }),
                None => ExecutionPayload::V3(v3),
            }
        }
    };
    let sidecar = match header.parent_beacon_block_root {
        None => ExecutionPayloadSidecar::none(),
        Some(parent_beacon_block_root) => {
            let cancun = CancunPayloadFields { parent_beacon_block_root, versioned_hashes };
            match header.requests_hash {
                None => ExecutionPayloadSidecar::v3(cancun),
                Some(hash) if is_empty_requests_hash(hash) => ExecutionPayloadSidecar::v4(
                    cancun,
                    PraguePayloadFields { requests: RequestsOrHash::Requests(Requests::default()) },
                ),
                Some(hash) => ExecutionPayloadSidecar::v4(cancun, PraguePayloadFields { requests: RequestsOrHash::Hash(hash) }),
            }
        }
    };
    ExecutionData::new(payload, sidecar)
}

/// [`execution_data_for_block`], carrying an EIP-7928 access list.
///
/// The list is not decoration: reth executes a block with one in parallel and a
/// block without one serially, and on an Amsterdam chain it refuses a payload
/// that has none at all. A block reconstructed from the wire therefore has to
/// carry its list or it cannot be imported.
pub fn execution_data_for_block_with_bal(
    block_hash: B256,
    block: &Block<TxEnvelope>,
    bal: Option<alloy_primitives::Bytes>,
) -> ExecutionData {
    let payload = ExecutionPayload::from_block_unchecked(block_hash, block).0;
    let sidecar = match block.header.parent_beacon_block_root {
        None => ExecutionPayloadSidecar::none(),
        Some(parent_beacon_block_root) => {
            let cancun = CancunPayloadFields {
                parent_beacon_block_root,
                versioned_hashes: block
                    .body
                    .transactions
                    .iter()
                    .flat_map(|tx| {
                        alloy_consensus::Transaction::blob_versioned_hashes(tx)
                            .map(<[B256]>::to_vec)
                            .unwrap_or_default()
                    })
                    .collect(),
            };
            match block.header.requests_hash {
                None => ExecutionPayloadSidecar::v3(cancun),
                Some(hash) if is_empty_requests_hash(hash) => ExecutionPayloadSidecar::v4(
                    cancun,
                    PraguePayloadFields {
                        requests: RequestsOrHash::Requests(Requests::default()),
                    },
                ),
                Some(hash) => ExecutionPayloadSidecar::v4(
                    cancun,
                    PraguePayloadFields {
                        requests: RequestsOrHash::Hash(hash),
                    },
                ),
            }
        }
    };
    let payload = match bal {
        Some(block_access_list) => match payload {
            ExecutionPayload::V3(v3) => ExecutionPayload::V4(
                alloy_rpc_types_engine::ExecutionPayloadV4 {
                    payload_inner: v3,
                    block_access_list,
                    slot_number: block.header.number,
                },
            ),
            // alloy's `from_block_unchecked` already produces a V4 payload for a
            // header that carries `block_access_list_hash`, with the 32-byte
            // *hash* standing in for the list it does not have. Left there, the
            // payload the leader seals and gossips carries a hash where every
            // importer expects a list: reth cannot decode it, and a follower's
            // `try_into_block` hashes the 32 bytes and never reproduces the
            // sealed header. This was gate 9, and it was on the leader.
            ExecutionPayload::V4(mut v4) => {
                v4.block_access_list = block_access_list;
                v4.slot_number = block.header.number;
                ExecutionPayload::V4(v4)
            }
            other => other,
        },
        None => payload,
    };
    ExecutionData::new(payload, sidecar)
}

/// The block a payload describes, with the header fields a payload cannot
/// carry (`ommers_hash`, `difficulty`) restored by trying gov5's variants
/// and letting the payload's block hash pick one.
///
/// A payload whose header is already the gov5 shape reconstructs; one
/// whose hash matches none of the variants is refused — the header on the
/// wire is not the block that was hashed.
pub fn reconstruct_gov5_h2_block<T: alloy_eips::Decodable2718>(
    execution: &ExecutionData,
) -> Result<Block<T>, HeaderProfileError> {
    let block = execution
        .clone()
        .try_into_block::<T>()
        .map_err(|e| HeaderProfileError::Reconstruction(e.to_string()))?;
    reconstruct_gov5_h2_block_from(block, execution)
}

/// [`reconstruct_gov5_h2_block`] for a caller that has already decoded the
/// payload into its Ethereum-shaped block.
///
/// Decoding is the expensive half — 163,000 transactions, a hash each, and
/// the transactions trie over them — and the follower's validator was doing
/// it three times per block: once here, once to learn the Ethereum-shaped
/// hash, and once inside reth's own well-formedness check. Everything this
/// function does on top is header arithmetic: a handful of candidate headers,
/// each hashed once.
pub fn reconstruct_gov5_h2_block_from<T>(
    mut block: Block<T>,
    execution: &ExecutionData,
) -> Result<Block<T>, HeaderProfileError> {
    let expected = execution.block_hash();
    validate_gov5_h2_header(&block.header)?;
    // Two more fields a payload cannot carry as gov5 wrote them: the
    // withdrawals root, which gov5 fills with its rewards commitment (the
    // payload's empty withdrawals list reconstructs to the trie's empty
    // root), and the requests hash, whose "none" gov5 spells differently
    // from EIP-7685. Each has the value the payload implies and the value
    // gov5 would have written; the hash picks.
    let withdrawals_roots: Vec<Option<B256>> = match block.header.withdrawals_root {
        Some(root) => {
            let rewards = withdrawals_to_rewards(block.body.withdrawals.as_ref().map_or(&[][..], |w| w.as_slice()));
            vec![Some(root), Some(gov5_rewards_root(rewards))]
        }
        None => vec![None],
    };
    let requests_hashes: Vec<Option<B256>> = match block.header.requests_hash {
        Some(hash) if is_empty_requests_hash(hash) => {
            vec![Some(hash), Some(GOV5_EMPTY_REQUESTS_HASH), Some(EMPTY_REQUESTS_HASH)]
        }
        other => vec![other],
    };
    // And a third the payload cannot carry: EIP-7928's access list *hash*.
    // The Engine API sends the list, not its hash — the execution layer derives
    // one from the other — so a header rebuilt from a payload has the field
    // empty while the header that was hashed had it filled.
    let bal_hashes: Vec<Option<B256>> = match &execution.payload {
        ExecutionPayload::V4(v4) => {
            // The payload carries the list RLP-encoded; the header carries its
            // hash. Decoding here is the only way to get from one to the other.
            let decoded = <alloy_eip7928::BlockAccessList as alloy_rlp::Decodable>::decode(
                &mut v4.block_access_list.as_ref(),
            )
            .ok();
            let mut candidates = vec![block.header.block_access_list_hash];
            if let Some(bal) = decoded {
                candidates
                    .push(Some(alloy_eip7928::compute_block_access_list_hash(bal.as_slice())));
            }
            candidates
        }
        _ => vec![block.header.block_access_list_hash],
    };
    for ommers_hash in [B256::ZERO, EMPTY_OMMER_ROOT_HASH] {
        for difficulty in [U256::ZERO, U256::from(1)] {
            for withdrawals_root in &withdrawals_roots {
                for requests_hash in &requests_hashes {
                    for bal_hash in &bal_hashes {
                        block.header.ommers_hash = ommers_hash;
                        block.header.difficulty = difficulty;
                        block.header.withdrawals_root = *withdrawals_root;
                        block.header.requests_hash = *requests_hash;
                        block.header.block_access_list_hash = *bal_hash;
                        if block.header.hash_slow() == expected {
                            return Ok(block);
                        }
                    }
                }
            }
        }
    }
    Err(HeaderProfileError::Reconstruction(
        "no gov5 header variant hashes to the payload's block hash".into(),
    ))
}

/// Turns a locally built payload into the block this node proposes.
///
/// The execution layer builds a block for a view it does not know, with the
/// seal unsigned; this stamps the view, seals with the leader's key when one
/// is given, forces the two fields gov5's producer sets (`ommers_hash` zero,
/// `difficulty` zero), and forms the new block hash. Execution outputs —
/// state root, receipts root, gas — are untouched: they were computed for
/// exactly these transactions and stay valid under the new header.
///
/// A payload built under the Ethereum profile is accepted as input: the
/// point is to make one that was not into one that is.
pub fn normalize_to_gov5_h2(
    execution: &ExecutionData,
    view: u64,
    sealer: Option<&BlsSecretKey>,
) -> Result<ExecutionData, HeaderProfileError> {
    normalize_to_gov5_h2_with_header(execution, view, sealer).map(|(data, _)| data)
}

/// [`normalize_to_gov5_h2_with_header`] for a caller that already has the
/// header, which is the leader on the raw payload path.
///
/// The seal changes the header alone -- extra data, ommers hash, difficulty,
/// nonce, gov5's withdrawals and requests placeholders, and through them the
/// hash -- and of those only the extra data and the hash appear in the
/// payload. So the payload is patched in place and the transactions are never
/// touched: the general path decodes 163,000 of them to construct this same
/// header and encodes them back, 130 ms at that tier, for two fields.
pub fn normalize_to_gov5_h2_from_header(
    mut header: alloy_consensus::Header,
    execution: &ExecutionData,
    view: u64,
    sealer: Option<&BlsSecretKey>,
) -> Result<(ExecutionData, alloy_consensus::Header), HeaderProfileError> {
    header.ommers_hash = B256::ZERO;
    header.difficulty = U256::ZERO;
    header.nonce = Default::default();
    header.extra_data = HeaderExtra::for_view(view).encode();
    if header.withdrawals_root.is_some() {
        let withdrawals = execution.payload.as_v2().map_or(&[][..], |v2| v2.withdrawals.as_slice());
        header.withdrawals_root = Some(gov5_rewards_root(withdrawals_to_rewards(withdrawals)));
    }
    if header.requests_hash.is_some_and(is_empty_requests_hash) {
        header.requests_hash = Some(GOV5_EMPTY_REQUESTS_HASH);
    }
    if let Some(key) = sealer {
        seal_header(&mut header, key)?;
    }
    let hash = header.hash_slow();
    let mut data = execution.clone();
    let v1 = data.payload.as_v1_mut();
    v1.extra_data = header.extra_data.clone();
    v1.block_hash = hash;
    v1.difficulty = header.difficulty;
    v1.nonce = header.nonce;
    Ok((data, header))
}

/// [`normalize_to_gov5_h2`], returning the header it built as well.
///
/// The header is a by-product of sealing and it used to be thrown away, after
/// which the caller decoded the whole payload again to get it back. At the
/// 163,000-transaction tier that second decode is a clone and a full RLP walk
/// of twelve megabytes -- measured as 648 ms between the leader finishing its
/// block and publishing the body, on a path where the seal itself is 150 ms.
/// Handing the header back costs nothing and removes it.
pub fn normalize_to_gov5_h2_with_header(
    execution: &ExecutionData,
    view: u64,
    sealer: Option<&BlsSecretKey>,
) -> Result<(ExecutionData, alloy_consensus::Header), HeaderProfileError> {
    let mut block = execution
        .clone()
        .try_into_block::<TxEnvelope>()
        .map_err(|e| HeaderProfileError::Reconstruction(e.to_string()))?;
    block.header.ommers_hash = B256::ZERO;
    block.header.difficulty = U256::ZERO;
    block.header.nonce = Default::default();
    block.header.extra_data = HeaderExtra::for_view(view).encode();
    // gov5's two non-Ethereum roots. The withdrawals field carries the
    // rewards commitment; the block's withdrawals are its rewards (see
    // `rewards_to_withdrawals`), keccak of nothing when there are none.
    if block.header.withdrawals_root.is_some() {
        let rewards = withdrawals_to_rewards(block.body.withdrawals.as_ref().map_or(&[][..], |w| w.as_slice()));
        block.header.withdrawals_root = Some(gov5_rewards_root(rewards));
    }
    if block.header.requests_hash.is_some_and(is_empty_requests_hash) {
        block.header.requests_hash = Some(GOV5_EMPTY_REQUESTS_HASH);
    }
    // The access-list hash is *not* recomputed here. An earlier version of this
    // function did, on the reading that `try_into_block` fills the field with
    // keccak of the encoding rather than EIP-7928's hash. That reading came from
    // a malformed test object -- a pre-Cancun payload wrapped in a V4 variant --
    // and the conversion is in fact correct. Overwriting it turned a right
    // answer into `None`.
    if let Some(key) = sealer {
        seal_header(&mut block.header, key)?;
    }
    let hash = block.header.hash_slow();
    let header = block.header.clone();
    // The access list survives the seal. Sealing rebuilds the payload from a
    // decoded block, so anything the payload carried and the block does not is
    // dropped unless it is carried across explicitly -- and dropping this one
    // turns a parallel import into a serial one, or on an Amsterdam chain into
    // a refusal.
    let bal = match &execution.payload {
        ExecutionPayload::V4(v4) => Some(v4.block_access_list.clone()),
        _ => None,
    };
    Ok((execution_data_for_block_with_bal(hash, &block, bal), header))
}

/// A block body with these transactions and, on a post-Shanghai header, the
/// block's rewards as its withdrawals; a header without a withdrawals root
/// gets no withdrawals list, and its rewards must be none.
pub fn block_for_header_with_rewards(
    header: Header,
    transactions: Vec<TxEnvelope>,
    rewards: &[(Address, U256)],
) -> Result<Block<TxEnvelope>, HeaderProfileError> {
    let withdrawals = match header.withdrawals_root {
        Some(_) => Some(Withdrawals(rewards_to_withdrawals(rewards)?)),
        None if rewards.is_empty() => None,
        None => {
            return Err(HeaderProfileError::Reconstruction(
                "rewards on a header without a withdrawals root".into(),
            ))
        }
    };
    Ok(Block {
        header,
        body: alloy_consensus::BlockBody { transactions, ommers: Vec::new(), withdrawals },
    })
}

/// A block body with these transactions and, on a post-Shanghai header, the
/// empty withdrawals list that its empty withdrawals root implies.
pub fn block_for_header(header: Header, transactions: Vec<TxEnvelope>) -> Block<TxEnvelope> {
    let withdrawals = header
        .withdrawals_root
        .map(|_| alloy_eips::eip4895::Withdrawals::default());
    Block {
        header,
        body: BlockBody {
            transactions,
            ommers: Vec::new(),
            withdrawals,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::EMPTY_ROOT_HASH;
    use alloy_primitives::{address, hex, LogData};

    // Every expected value below was printed by gov5's own code
    // (`hash.DeriveSha`, `buildHeaderExtra`, `sealHash`, `Header.Hash`) run
    // over the same inputs.

    #[test]
    fn rewards_round_trip_through_withdrawals() {
        let one_ether = U256::from(1_000_000_000_000_000_000u128);
        let rewards = vec![
            (address!("d2a316a1cd3a777141cb7e5aace46fb01df90eac"), one_ether),
            (address!("42e9819036f61bf665d5f727e8c03121f12f586e"), one_ether),
        ];
        let withdrawals = rewards_to_withdrawals(&rewards).unwrap();
        assert_eq!(withdrawals.len(), 2);
        assert_eq!(withdrawals[0].index, 0);
        assert_eq!(withdrawals[1].index, 1);
        assert_eq!(withdrawals[0].amount, 1_000_000_000, "one ether is 1e9 gwei");
        assert_eq!(withdrawals_to_rewards(&withdrawals), rewards);
        assert!(rewards_to_withdrawals(&[(rewards[0].0, U256::from(1))]).is_err(), "a wei is not a withdrawal");
        assert_eq!(gov5_rewards_root(withdrawals_to_rewards(&[])), GOV5_NIL_HASH);
    }

    #[test]
    fn a_normalized_block_commits_to_its_rewards_and_reconstructs() {
        let one_ether = U256::from(1_000_000_000_000_000_000u128);
        let leader = address!("d2a316a1cd3a777141cb7e5aace46fb01df90eac");
        let mut header = fixture_header();
        header.withdrawals_root = Some(EMPTY_ROOT_HASH);
        let withdrawals = rewards_to_withdrawals(&[(leader, one_ether)]).unwrap();
        let block = Block {
            header,
            body: alloy_consensus::BlockBody {
                transactions: Vec::<TxEnvelope>::new(),
                ommers: Vec::new(),
                withdrawals: Some(Withdrawals(withdrawals.clone())),
            },
        };
        let hash = block.header.hash_slow();
        let normalized = normalize_to_gov5_h2(&execution_data_for_block(hash, &block), 7, None).unwrap();
        let rebuilt = reconstruct_gov5_h2_block::<TxEnvelope>(&normalized).unwrap();
        assert_eq!(rebuilt.header.withdrawals_root, Some(gov5_rewards_root([(leader, one_ether)])));
        assert_eq!(rebuilt.body.withdrawals.as_deref(), Some(&withdrawals));
        assert_eq!(rebuilt.header.hash_slow(), normalized.block_hash());
    }

    /// A block whose header carries EIP-7928's access-list hash has to be
    /// reconstructible from the payload that describes it.
    ///
    /// This was gate 9 on the way to parallel execution, and it took a unit
    /// test to see it: the fleet only ever said "no gov5 header variant hashes
    /// to the payload's block hash", three hops from the cause. The cause was
    /// `execution_data_for_block_with_bal` handing on a V4 payload whose list
    /// field held the header's 32-byte hash (alloy's placeholder) instead of
    /// the list, so every importer hashed the placeholder.
    ///
    /// The payload carries the *list*; the header carries its *hash*, derived by
    /// the execution layer. The field-by-field print stays because it is what
    /// names a field when the assertion at the end fails.
    #[test]
    fn a_header_with_an_access_list_hash_is_reconstructible() {
        let bal_bytes = alloy_primitives::Bytes::from(alloy_rlp::encode(
            &alloy_eip7928::BlockAccessList::default(),
        ));
        let decoded = <alloy_eip7928::BlockAccessList as alloy_rlp::Decodable>::decode(
            &mut bal_bytes.as_ref(),
        )
        .expect("the list round-trips");
        let bal_hash = alloy_eip7928::compute_block_access_list_hash(decoded.as_slice());

        // Cancun-shaped, because an Amsterdam block is: leave the blob fields
        // `None` and `execution_data_for_block` builds a pre-Cancun payload,
        // which wrapped in a V4 variant is an object no execution layer would
        // ever produce. The first version of this test did exactly that and
        // spent two rounds looking like a reconstruction bug.
        let header = Header {
            number: 3,
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            block_access_list_hash: Some(bal_hash),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::repeat_byte(7)),
            ommers_hash: B256::ZERO,
            difficulty: U256::ZERO,
            ..Default::default()
        };
        let block = Block {
            header: header.clone(),
            body: alloy_consensus::BlockBody {
                transactions: Vec::<TxEnvelope>::new(),
                ommers: Vec::new(),
                withdrawals: Some(Withdrawals(Vec::new())),
            },
        };
        let hash = block.header.hash_slow();
        // Through the real sequence: a leader normalizes what its execution
        // layer built, and a follower reconstructs what the leader sealed.
        let bal_bytes2 = bal_bytes.clone();
        let data = normalize_to_gov5_h2(
            &execution_data_for_block_with_bal(hash, &block, Some(bal_bytes)),
            9,
            None,
        )
        .expect("the block normalizes");
        // A payload conversion cannot know the hashing scheme the header used —
        // it sees the list, and EIP-7928's hash is not keccak of the encoding —
        // so the field comes back wrong and the reconstruction has to try the
        // computed value alongside it. That is the whole reason this test
        // exists.

        // Field by field, because "no variant matched" names no field.
        let sealed = normalize_to_gov5_h2_with_header(
            &execution_data_for_block_with_bal(hash, &block, Some(bal_bytes2)),
            9,
            None,
        )
        .unwrap()
        .1;
        let from_payload = data.clone().try_into_block::<TxEnvelope>().unwrap().header;
        for (name, a, b) in [
            ("parent_hash", format!("{:?}", sealed.parent_hash), format!("{:?}", from_payload.parent_hash)),
            ("ommers_hash", format!("{:?}", sealed.ommers_hash), format!("{:?}", from_payload.ommers_hash)),
            ("state_root", format!("{:?}", sealed.state_root), format!("{:?}", from_payload.state_root)),
            ("tx_root", format!("{:?}", sealed.transactions_root), format!("{:?}", from_payload.transactions_root)),
            ("receipts_root", format!("{:?}", sealed.receipts_root), format!("{:?}", from_payload.receipts_root)),
            ("withdrawals_root", format!("{:?}", sealed.withdrawals_root), format!("{:?}", from_payload.withdrawals_root)),
            ("requests_hash", format!("{:?}", sealed.requests_hash), format!("{:?}", from_payload.requests_hash)),
            ("bal_hash", format!("{:?}", sealed.block_access_list_hash), format!("{:?}", from_payload.block_access_list_hash)),
            ("difficulty", format!("{:?}", sealed.difficulty), format!("{:?}", from_payload.difficulty)),
            ("nonce", format!("{:?}", sealed.nonce), format!("{:?}", from_payload.nonce)),
            ("extra_data", format!("{:?}", sealed.extra_data), format!("{:?}", from_payload.extra_data)),
            ("gas_limit", format!("{}", sealed.gas_limit), format!("{}", from_payload.gas_limit)),
            ("base_fee", format!("{:?}", sealed.base_fee_per_gas), format!("{:?}", from_payload.base_fee_per_gas)),
            ("blob_gas", format!("{:?}", sealed.blob_gas_used), format!("{:?}", from_payload.blob_gas_used)),
            ("excess_blob", format!("{:?}", sealed.excess_blob_gas), format!("{:?}", from_payload.excess_blob_gas)),
            ("beacon_root", format!("{:?}", sealed.parent_beacon_block_root), format!("{:?}", from_payload.parent_beacon_block_root)),
        ] {
            if a != b {
                eprintln!("DIFFERS {name}: sealed={a} payload={b}");
            }
        }
        let rebuilt = match reconstruct_gov5_h2_block::<TxEnvelope>(&data) {
            Ok(block) => block,
            Err(err) => panic!("reconstruction failed: {err}"),
        };
        assert_eq!(
            rebuilt.header.block_access_list_hash,
            Some(bal_hash),
            "the sealed header must carry EIP-7928's hash, not the conversion's",
        );
        assert_eq!(rebuilt.header.hash_slow(), data.block_hash());
    }

    /// The raw-parts payload is the typed payload, without the decode.
    #[test]
    fn raw_parts_build_the_typed_payload() {
        use alloy_consensus::{Signed, TxEip1559, TxLegacy};
        use alloy_eips::Encodable2718;
        use alloy_primitives::{Address, Signature, TxKind};
        let txs: Vec<TxEnvelope> = vec![
            TxEnvelope::Eip1559(Signed::new_unchecked(TxEip1559 { chain_id: 1, nonce: 1, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(9), ..Default::default() }, Signature::test_signature(), Default::default())),
            TxEnvelope::Legacy(Signed::new_unchecked(TxLegacy { chain_id: Some(1), nonce: 2, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(1), ..Default::default() }, Signature::test_signature(), Default::default())),
        ];
        let withdrawals = vec![alloy_eips::eip4895::Withdrawal { index: 0, validator_index: 0, address: Address::repeat_byte(0x42), amount: 5 }];
        for (requests_hash, bal) in [
            (None, None),
            (Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH), None),
            (Some(B256::repeat_byte(5)), None),
            (Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH), Some(alloy_primitives::Bytes::from_static(&[0xc0]))),
        ] {
            let header = Header {
                number: 7, gas_limit: 30_000_000, gas_used: 42_000, timestamp: 1_700_000_000, base_fee_per_gas: Some(7),
                withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH), blob_gas_used: Some(0), excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(B256::repeat_byte(9)), requests_hash,
                block_access_list_hash: bal.as_ref().map(|_| B256::repeat_byte(6)),
                transactions_root: alloy_consensus::proofs::calculate_transaction_root(&txs),
                ..Default::default()
            };
            let block = Block { header: header.clone(), body: alloy_consensus::BlockBody { transactions: txs.clone(), ommers: Vec::new(), withdrawals: Some(Withdrawals(withdrawals.clone())) } };
            let hash = header.hash_slow();
            let typed = execution_data_for_block_with_bal(hash, &block, bal.clone());
            let raw = execution_data_from_raw_parts(hash, &header, txs.iter().map(|t| alloy_primitives::Bytes::from(t.encoded_2718())).collect(), withdrawals.clone(), bal);
            assert_eq!(format!("{raw:?}"), format!("{typed:?}"));
        }
    }

    /// The header-only seal is the general seal, without the decode. Same
    /// hash, same payload, or the leader would be proposing a block whose
    /// body its own execution layer rebuilds under a different hash.
    #[test]
    fn sealing_from_the_header_matches_sealing_from_the_payload() {
        let header = Header {
            number: 7,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::repeat_byte(9)),
            requests_hash: Some(alloy_eips::eip7685::EMPTY_REQUESTS_HASH),
            difficulty: U256::from(1),
            ommers_hash: alloy_consensus::EMPTY_OMMER_ROOT_HASH,
            ..Default::default()
        };
        let block = Block {
            header: header.clone(),
            body: alloy_consensus::BlockBody {
                transactions: Vec::<TxEnvelope>::new(),
                ommers: Vec::new(),
                withdrawals: Some(Withdrawals(vec![alloy_eips::eip4895::Withdrawal {
                    index: 0,
                    validator_index: 0,
                    address: alloy_primitives::Address::repeat_byte(0x42),
                    amount: 5,
                }])),
            },
        };
        let data = execution_data_for_block(block.header.hash_slow(), &block);
        let (general, general_header) = normalize_to_gov5_h2_with_header(&data, 11, None).unwrap();
        let (fast, fast_header) = normalize_to_gov5_h2_from_header(header, &data, 11, None).unwrap();
        assert_eq!(fast_header, general_header, "the two seals built different headers");
        assert_eq!(fast.block_hash(), general.block_hash());
        assert_eq!(fast.payload.as_v1(), general.payload.as_v1(), "the patched payload differs from the rebuilt one");
        assert_eq!(fast.payload.as_v2().map(|v| &v.withdrawals), general.payload.as_v2().map(|v| &v.withdrawals));
    }

    #[test]
    fn empty_receipts_root_is_keccak_of_nothing() {
        assert_eq!(gov5_receipts_root([]), GOV5_NIL_HASH);
        assert_eq!(GOV5_NIL_HASH, keccak256([]));
    }

    #[test]
    fn receipts_root_matches_gov5_derive_sha() {
        let log = Log {
            address: address!("1111111111111111111111111111111111111111"),
            data: LogData::new_unchecked(
                vec![
                    b256!("2222222222222222222222222222222222222222222222222222222222222222"),
                    b256!("0000000000000000000000000000000000000000000000000000000000000033"),
                ],
                Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            ),
        };
        let logs = [log];
        let root = gov5_receipts_root([
            ReceiptView {
                success: true,
                cumulative_gas_used: 21_000,
                logs: &[],
            },
            ReceiptView {
                success: false,
                cumulative_gas_used: 63_000,
                logs: &logs,
            },
        ]);
        assert_eq!(root, GOV5_RECEIPTS_TWO);
    }

    fn fixture_header() -> Header {
        Header {
            parent_hash: B256::repeat_byte(1),
            ommers_hash: B256::ZERO,
            beneficiary: address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            state_root: B256::repeat_byte(2),
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: GOV5_NIL_HASH,
            difficulty: U256::ZERO,
            number: 7,
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            extra_data: HeaderExtra::for_view(7).encode(),
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        }
    }

    #[test]
    fn extra_data_matches_gov5_build_header_extra() {
        let extra = HeaderExtra::for_view(7).encode();
        assert_eq!(hex::encode(&extra), GOV5_EXTRA_VIEW7);
        let decoded = HeaderExtra::decode(&extra).unwrap();
        assert_eq!(decoded.view, 7);
        assert!(decoded.qc.is_empty());
        assert_eq!(decoded.seal, Some([0; 96]));
    }

    #[test]
    fn header_hash_and_seal_hash_match_gov5() {
        let header = fixture_header();
        assert_eq!(header.hash_slow(), GOV5_HEADER_HASH);
        assert_eq!(seal_hash(&header), GOV5_SEAL_HASH);
        assert_eq!(validate_gov5_h2_header(&header).unwrap().view, 7);
    }

    #[test]
    fn a_seal_signs_the_unsealed_header_and_verifies() {
        let key = BlsSecretKey::random().unwrap();
        let mut header = fixture_header();
        let before = seal_hash(&header);
        seal_header(&mut header, &key).unwrap();
        // Sealing changes the block hash but not what was signed.
        assert_ne!(header.hash_slow(), GOV5_HEADER_HASH);
        assert_eq!(seal_hash(&header), before);
        verify_seal(&header, &key.public_key()).unwrap();
        let other = BlsSecretKey::random().unwrap();
        assert!(verify_seal(&header, &other.public_key()).is_err());
    }

    #[test]
    fn gov5_layouts_decode_and_others_are_refused() {
        // QC then seal: what a gov5 leader with a committed QC writes.
        let with_qc = HeaderExtra {
            view: 3,
            qc: vec![0xAB; 40],
            seal: Some([1; 96]),
        };
        assert_eq!(HeaderExtra::decode(&with_qc.encode()).unwrap(), with_qc);
        // Bare view.
        let bare = HeaderExtra {
            view: 9,
            qc: vec![],
            seal: None,
        };
        assert_eq!(HeaderExtra::decode(&bare.encode()).unwrap(), bare);
        assert!(matches!(
            HeaderExtra::decode(b"N42"),
            Err(HeaderProfileError::ExtraTooShort(3))
        ));
        assert!(matches!(
            HeaderExtra::decode(&[0u8; 12]),
            Err(HeaderProfileError::MissingMagic)
        ));
        assert!(matches!(
            HeaderExtra::decode(&vec![0u8; 4097]),
            Err(HeaderProfileError::ExtraTooLong(4097))
        ));
    }

    #[test]
    fn normalizing_a_payload_gives_a_gov5_header_that_round_trips() {
        let key = BlsSecretKey::random().unwrap();
        let mut ethereum = fixture_header();
        ethereum.ommers_hash = EMPTY_OMMER_ROOT_HASH;
        ethereum.extra_data = Bytes::from(vec![0u8; 97]);
        let block = block_for_header(ethereum, vec![]);
        let built = execution_data_for_block(block.header.hash_slow(), &block);

        let proposed = normalize_to_gov5_h2(&built, 42, Some(&key)).unwrap();
        let reconstructed = reconstruct_gov5_h2_block::<TxEnvelope>(&proposed).unwrap();
        assert_eq!(reconstructed.header.hash_slow(), proposed.block_hash());
        assert_eq!(reconstructed.header.ommers_hash, B256::ZERO);
        assert_eq!(header_view(&reconstructed.header).unwrap(), 42);
        verify_seal(&reconstructed.header, &key.public_key()).unwrap();
        // Execution outputs survived, and the two roots gov5 spells its own
        // way took gov5's spelling.
        assert_eq!(reconstructed.header.state_root, B256::repeat_byte(2));
        assert_eq!(reconstructed.header.receipts_root, GOV5_NIL_HASH);
        assert_eq!(reconstructed.header.withdrawals_root, Some(GOV5_NIL_HASH));
        assert_eq!(reconstructed.header.requests_hash, Some(GOV5_EMPTY_REQUESTS_HASH));
        assert!(proposed.sidecar.requests().is_some());
    }

    #[test]
    fn gov5_roots_for_nothing_are_what_gov5_writes() {
        assert_eq!(gov5_rewards_root([]), GOV5_NIL_HASH);
        assert_eq!(GOV5_EMPTY_REQUESTS_HASH, alloy_consensus::EMPTY_ROOT_HASH);
        assert!(is_empty_requests_hash(EMPTY_REQUESTS_HASH));
        assert!(is_empty_requests_hash(GOV5_EMPTY_REQUESTS_HASH));
        assert!(!is_empty_requests_hash(B256::ZERO));
    }

    #[test]
    fn a_payload_that_lies_about_its_hash_does_not_reconstruct() {
        let block = block_for_header(fixture_header(), vec![]);
        let mut payload = execution_data_for_block(block.header.hash_slow(), &block);
        payload.payload.as_v1_mut().block_hash = B256::repeat_byte(0xEE);
        assert!(reconstruct_gov5_h2_block::<TxEnvelope>(&payload).is_err());
    }

    include!("header_profile_fixture.rs");
}
