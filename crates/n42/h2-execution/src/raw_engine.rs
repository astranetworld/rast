// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A binary form of the Engine API's `newPayload`, for the loopback channel
//! between this repo's validator and its execution layer.
//!
//! `engine_newPayload` carries every transaction hex-encoded inside JSON. On
//! the follower that is the largest thing between a body arriving and a vote
//! going out that is not the block's own execution: measured on the
//! seven-node fleet at the 163,000-transaction tier, ~285 ms of a 922 ms
//! receive-to-vote where the execution layer's own import is 637. Here the
//! same [`ExecutionData`] is a length-prefixed byte stream: the transactions
//! are copied once, nothing is hex, nothing is parsed twice.
//!
//! Little-endian throughout; both ends are the same host. Not a consensus
//! artefact and not versioned beyond the leading byte.

use alloy_eips::eip4895::Withdrawal;
use alloy_eips::eip7685::{Requests, RequestsOrHash};
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV1,
    ExecutionPayloadV2, ExecutionPayloadV3, ExecutionPayloadV4, PayloadStatus, PayloadStatusEnum,
    PraguePayloadFields,
};

const VERSION: u8 = 1;

/// Request kinds on the channel.
pub mod request {
    /// `u64` payload id follows; the answer is the built block.
    pub const GET_PAYLOAD: u8 = 1;
    /// `u32` length and an encoded [`super::ExecutionData`] follow; the
    /// answer is an encoded [`super::PayloadStatus`].
    pub const NEW_PAYLOAD: u8 = 2;
}

struct Writer(Vec<u8>);
impl Writer {
    fn u8(&mut self, v: u8) { self.0.push(v); }
    fn u32(&mut self, v: u32) { self.0.extend_from_slice(&v.to_le_bytes()); }
    fn u64(&mut self, v: u64) { self.0.extend_from_slice(&v.to_le_bytes()); }
    fn fixed(&mut self, v: &[u8]) { self.0.extend_from_slice(v); }
    fn bytes(&mut self, v: &[u8]) { self.u32(v.len() as u32); self.0.extend_from_slice(v); }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n { return Err(format!("truncated: wanted {n}, have {}", self.0.len())); }
        let (a, b) = self.0.split_at(n); self.0 = b; Ok(a)
    }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, String> { Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4"))) }
    fn u64(&mut self) -> Result<u64, String> { Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8"))) }
    fn b256(&mut self) -> Result<B256, String> { Ok(B256::from_slice(self.take(32)?)) }
    fn bytes(&mut self) -> Result<Bytes, String> { let n = self.u32()? as usize; Ok(Bytes::copy_from_slice(self.take(n)?)) }
}

/// Encodes an [`ExecutionData`] for the channel.
pub fn encode_execution_data(data: &ExecutionData) -> Vec<u8> {
    let v1 = data.payload.as_v1();
    let size = 512 + v1.transactions.iter().map(|t| t.len() + 4).sum::<usize>();
    let mut w = Writer(Vec::with_capacity(size));
    w.u8(VERSION);
    w.u8(match &data.payload {
        ExecutionPayload::V1(_) => 1,
        ExecutionPayload::V2(_) => 2,
        ExecutionPayload::V3(_) => 3,
        ExecutionPayload::V4(_) => 4,
    });
    w.fixed(v1.parent_hash.as_slice());
    w.fixed(v1.fee_recipient.as_slice());
    w.fixed(v1.state_root.as_slice());
    w.fixed(v1.receipts_root.as_slice());
    w.fixed(v1.logs_bloom.as_slice());
    w.fixed(v1.prev_randao.as_slice());
    w.u64(v1.block_number);
    w.u64(v1.gas_limit);
    w.u64(v1.gas_used);
    w.u64(v1.timestamp);
    w.bytes(&v1.extra_data);
    w.fixed(&v1.base_fee_per_gas.to_be_bytes::<32>());
    w.fixed(v1.block_hash.as_slice());
    w.fixed(&v1.difficulty.to_be_bytes::<32>());
    w.fixed(v1.nonce.as_slice());
    w.u32(v1.transactions.len() as u32);
    for tx in &v1.transactions {
        w.bytes(tx);
    }
    if let Some(v2) = data.payload.as_v2() {
        w.u32(v2.withdrawals.len() as u32);
        for wd in &v2.withdrawals {
            w.u64(wd.index); w.u64(wd.validator_index); w.fixed(wd.address.as_slice()); w.u64(wd.amount);
        }
    }
    if let Some(v3) = data.payload.as_v3() {
        w.u64(v3.blob_gas_used);
        w.u64(v3.excess_blob_gas);
    }
    if let ExecutionPayload::V4(v4) = &data.payload {
        w.bytes(&v4.block_access_list);
        w.u64(v4.slot_number);
    }
    match data.sidecar.cancun() {
        Some(cancun) => {
            w.u8(1);
            w.fixed(cancun.parent_beacon_block_root.as_slice());
            w.u32(cancun.versioned_hashes.len() as u32);
            for h in &cancun.versioned_hashes { w.fixed(h.as_slice()); }
        }
        None => w.u8(0),
    }
    match data.sidecar.prague() {
        Some(prague) => {
            w.u8(1);
            match &prague.requests {
                RequestsOrHash::Hash(hash) => { w.u8(0); w.fixed(hash.as_slice()); }
                RequestsOrHash::Requests(requests) => {
                    w.u8(1);
                    w.u32(requests.len() as u32);
                    for r in requests.iter() { w.bytes(r); }
                }
            }
        }
        None => w.u8(0),
    }
    w.0
}

/// Decodes what [`encode_execution_data`] produced.
pub fn decode_execution_data(buf: &[u8]) -> Result<ExecutionData, String> {
    let mut r = Reader(buf);
    if r.u8()? != VERSION { return Err("unknown raw engine version".into()); }
    let kind = r.u8()?;
    let parent_hash = r.b256()?;
    let fee_recipient = Address::from_slice(r.take(20)?);
    let state_root = r.b256()?;
    let receipts_root = r.b256()?;
    let logs_bloom = Bloom::from_slice(r.take(256)?);
    let prev_randao = r.b256()?;
    let block_number = r.u64()?;
    let gas_limit = r.u64()?;
    let gas_used = r.u64()?;
    let timestamp = r.u64()?;
    let extra_data = r.bytes()?;
    let base_fee_per_gas = U256::from_be_slice(r.take(32)?);
    let block_hash = r.b256()?;
    let difficulty = U256::from_be_slice(r.take(32)?);
    let nonce = B64::from_slice(r.take(8)?);
    let n = r.u32()? as usize;
    let mut transactions = Vec::with_capacity(n);
    for _ in 0..n { transactions.push(r.bytes()?); }
    let v1 = ExecutionPayloadV1 {
        parent_hash, fee_recipient, state_root, receipts_root, logs_bloom, prev_randao, block_number,
        gas_limit, gas_used, timestamp, extra_data, base_fee_per_gas, block_hash, transactions,
        difficulty, nonce,
    };
    let payload = if kind == 1 {
        ExecutionPayload::V1(v1)
    } else {
        let n = r.u32()? as usize;
        let mut withdrawals = Vec::with_capacity(n);
        for _ in 0..n {
            let index = r.u64()?; let validator_index = r.u64()?;
            let address = Address::from_slice(r.take(20)?); let amount = r.u64()?;
            withdrawals.push(Withdrawal { index, validator_index, address, amount });
        }
        let v2 = ExecutionPayloadV2 { payload_inner: v1, withdrawals };
        if kind == 2 {
            ExecutionPayload::V2(v2)
        } else {
            let blob_gas_used = r.u64()?; let excess_blob_gas = r.u64()?;
            let v3 = ExecutionPayloadV3 { payload_inner: v2, blob_gas_used, excess_blob_gas };
            if kind == 3 {
                ExecutionPayload::V3(v3)
            } else if kind == 4 {
                let block_access_list = r.bytes()?; let slot_number = r.u64()?;
                ExecutionPayload::V4(ExecutionPayloadV4 { payload_inner: v3, block_access_list, slot_number })
            } else {
                return Err(format!("unknown payload kind {kind}"));
            }
        }
    };
    let cancun = if r.u8()? == 1 {
        let parent_beacon_block_root = r.b256()?;
        let n = r.u32()? as usize;
        let mut versioned_hashes = Vec::with_capacity(n);
        for _ in 0..n { versioned_hashes.push(r.b256()?); }
        Some(CancunPayloadFields { parent_beacon_block_root, versioned_hashes })
    } else { None };
    let prague = if r.u8()? == 1 {
        let requests = if r.u8()? == 0 {
            RequestsOrHash::Hash(r.b256()?)
        } else {
            let n = r.u32()? as usize;
            let mut list = Vec::with_capacity(n);
            for _ in 0..n { list.push(r.bytes()?); }
            RequestsOrHash::Requests(Requests::new(list))
        };
        Some(PraguePayloadFields { requests })
    } else { None };
    let sidecar = match (cancun, prague) {
        (None, _) => ExecutionPayloadSidecar::none(),
        (Some(c), None) => ExecutionPayloadSidecar::v3(c),
        (Some(c), Some(p)) => ExecutionPayloadSidecar::v4(c, p),
    };
    Ok(ExecutionData::new(payload, sidecar))
}

/// Encodes a [`PayloadStatus`] for the channel.
pub fn encode_payload_status(status: &PayloadStatus) -> Vec<u8> {
    let mut w = Writer(Vec::with_capacity(80));
    let (kind, error) = match &status.status {
        PayloadStatusEnum::Valid => (0u8, None),
        PayloadStatusEnum::Invalid { validation_error } => (1, Some(validation_error.to_string())),
        PayloadStatusEnum::Syncing => (2, None),
        PayloadStatusEnum::Accepted => (3, None),
    };
    w.u8(kind);
    match status.latest_valid_hash { Some(h) => { w.u8(1); w.fixed(h.as_slice()); } None => w.u8(0) }
    w.bytes(error.unwrap_or_default().as_bytes());
    w.0
}

/// Decodes what [`encode_payload_status`] produced.
pub fn decode_payload_status(buf: &[u8]) -> Result<PayloadStatus, String> {
    let mut r = Reader(buf);
    let kind = r.u8()?;
    let latest_valid_hash = if r.u8()? == 1 { Some(r.b256()?) } else { None };
    let error = String::from_utf8_lossy(&r.bytes()?).into_owned();
    let status = match kind {
        0 => PayloadStatusEnum::Valid,
        1 => PayloadStatusEnum::Invalid { validation_error: error },
        2 => PayloadStatusEnum::Syncing,
        3 => PayloadStatusEnum::Accepted,
        other => return Err(format!("unknown payload status {other}")),
    };
    Ok(PayloadStatus { status, latest_valid_hash })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1() -> ExecutionPayloadV1 {
        ExecutionPayloadV1 {
            parent_hash: B256::repeat_byte(1), fee_recipient: Address::repeat_byte(2), state_root: B256::repeat_byte(3),
            receipts_root: B256::repeat_byte(4), logs_bloom: Bloom::repeat_byte(5), prev_randao: B256::repeat_byte(6),
            block_number: 7, gas_limit: 8, gas_used: 9, timestamp: 10, extra_data: Bytes::from_static(&[0xaa, 0xbb]),
            base_fee_per_gas: U256::from(11), block_hash: B256::repeat_byte(12),
            transactions: vec![Bytes::from_static(&[0x02, 0x01]), Bytes::from_static(&[0xf8, 0x00, 0x11])],
            difficulty: U256::from(13), nonce: B64::repeat_byte(14),
        }
    }

    #[test]
    fn execution_data_round_trips_in_every_shape() {
        let wd = Withdrawal { index: 1, validator_index: 2, address: Address::repeat_byte(3), amount: 4 };
        let v2 = ExecutionPayloadV2 { payload_inner: v1(), withdrawals: vec![wd] };
        let v3 = ExecutionPayloadV3 { payload_inner: v2.clone(), blob_gas_used: 5, excess_blob_gas: 6 };
        let v4 = ExecutionPayloadV4 { payload_inner: v3.clone(), block_access_list: Bytes::from_static(&[0xc0]), slot_number: 9 };
        let cancun = CancunPayloadFields { parent_beacon_block_root: B256::repeat_byte(7), versioned_hashes: vec![B256::repeat_byte(8)] };
        let prague = PraguePayloadFields { requests: RequestsOrHash::Requests(Requests::new(vec![Bytes::from_static(&[0x01, 0x02])])) };
        let cases = vec![
            ExecutionData::new(ExecutionPayload::V1(v1()), ExecutionPayloadSidecar::none()),
            ExecutionData::new(ExecutionPayload::V2(v2), ExecutionPayloadSidecar::none()),
            ExecutionData::new(ExecutionPayload::V3(v3), ExecutionPayloadSidecar::v3(cancun.clone())),
            ExecutionData::new(ExecutionPayload::V4(v4), ExecutionPayloadSidecar::v4(cancun.clone(), prague)),
            ExecutionData::new(ExecutionPayload::V1(v1()), ExecutionPayloadSidecar::v4(cancun, PraguePayloadFields { requests: RequestsOrHash::Hash(B256::repeat_byte(9)) })),
        ];
        for data in cases {
            let back = decode_execution_data(&encode_execution_data(&data)).expect("decodes");
            assert_eq!(format!("{back:?}"), format!("{data:?}"));
        }
    }

    #[test]
    fn payload_status_round_trips() {
        for status in [
            PayloadStatus::new(PayloadStatusEnum::Valid, Some(B256::repeat_byte(1))),
            PayloadStatus::new(PayloadStatusEnum::Invalid { validation_error: "bad".into() }, None),
            PayloadStatus::new(PayloadStatusEnum::Syncing, None),
            PayloadStatus::new(PayloadStatusEnum::Accepted, None),
        ] {
            let back = decode_payload_status(&encode_payload_status(&status)).unwrap();
            assert_eq!(back.status, status.status);
            assert_eq!(back.latest_valid_hash, status.latest_valid_hash);
        }
    }
}
