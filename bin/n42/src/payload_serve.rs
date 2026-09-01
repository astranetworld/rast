// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A loopback TCP channel that hands a built block to the validator as bytes.
//!
//! `n42Engine_getPayloadRaw` took the transactions out of the JSON but left
//! the block in it: a 12 MB RLP became a 24 MB hex string, serialised on this
//! side, parsed and decoded on the other. Measured at the 163,000-transaction
//! tier the validator saw a build take about 150 ms longer than the builder
//! spent on it, and this hop is most of that.
//!
//! This is the same block over a socket, length-prefixed, nothing encoded
//! twice. The RLP is produced with the transactions encoded in parallel, which
//! `alloy_rlp::encode` on a block does not do. The validator learns the address
//! from `n42Engine_payloadEndpoint` on the auth transport, so the channel needs
//! no flag on its side; on this side it is `N42_PAYLOAD_SERVE=<addr>`, loopback
//! only, because it is unauthenticated and answers with whatever this node has
//! built.
//!
//! # Wire
//!
//! ```text
//! request  := u8 kind (n42_h2_execution::raw_engine::request), then:
//!   GET_PAYLOAD: u64 payload id (the Engine API's 8 bytes, little-endian)
//!   reply    := u8 status            0 = unknown build, 1 = block follows, 2 = error (u32 len + message)
//!               u32 len, block RLP   [header, transactions, ommers, withdrawals]
//!               u8 has_requests, [u32 n, n x (u32 len, bytes)]
//!               u8 has_bal, [u32 len, bytes]
//!   NEW_PAYLOAD: u32 len, encoded ExecutionData (raw_engine::encode_execution_data)
//!   reply    := u8 status            1 = payload status follows, 2 = error (u32 len + message)
//!               u32 len, encoded PayloadStatus
//! ```
//!
//! `NEW_PAYLOAD` is the follower's half: the same `engine_newPayload`, handed
//! to the engine as the [`ExecutionData`] it wants without 39 MB of hex on the
//! way. Measured before it existed: ~285 ms between a body arriving at the
//! validator and its vote that the execution layer's own import (637 ms) did
//! not account for.

use std::net::SocketAddr;

use alloy_consensus::BlockHeader as _;
use alloy_eips::Encodable2718;
use alloy_rlp::Encodable;
use n42_h2_execution::raw_engine::{self, request};
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{BuiltPayload, PayloadKind, PayloadTypes};
use reth_primitives_traits::{Block as _, BlockBody as _, SealedBlock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// The block's RLP, `[header, transactions, ommers, withdrawals]`, with the
/// transactions encoded on the worker pool.
///
/// Byte-identical to `alloy_rlp::encode(block)`: a typed transaction is an
/// RLP string wrapping its EIP-2718 bytes, a legacy one is its own RLP list.
pub fn encode_block_parallel<B>(block: &SealedBlock<B>) -> Vec<u8>
where
    B: reth_primitives_traits::Block,
    B::Body: reth_primitives_traits::BlockBody<Transaction: Encodable2718 + Sync>,
{
    use rayon::prelude::*;
    let header = alloy_rlp::encode(block.header());
    let transactions: Vec<Vec<u8>> = block
        .body()
        .transactions()
        .par_iter()
        .map(|tx| {
            let inner = tx.encoded_2718();
            if tx.type_flag().is_some() {
                let mut out = Vec::with_capacity(inner.len() + 4);
                alloy_rlp::Header { list: false, payload_length: inner.len() }.encode(&mut out);
                out.extend_from_slice(&inner);
                out
            } else {
                inner
            }
        })
        .collect();
    let transactions_len: usize = transactions.iter().map(Vec::len).sum();
    let transactions_header = alloy_rlp::Header { list: true, payload_length: transactions_len };
    let ommers: &[u8] = &[0xc0];
    let withdrawals = block.body().withdrawals().map(|w| alloy_rlp::encode(w));
    let payload_length = header.len()
        + transactions_header.length_with_payload()
        + ommers.len()
        + withdrawals.as_ref().map_or(0, Vec::len);
    let mut out = Vec::with_capacity(payload_length + 8);
    alloy_rlp::Header { list: true, payload_length }.encode(&mut out);
    out.extend_from_slice(&header);
    transactions_header.encode(&mut out);
    for tx in &transactions {
        out.extend_from_slice(tx);
    }
    out.extend_from_slice(ommers);
    if let Some(withdrawals) = withdrawals {
        out.extend_from_slice(&withdrawals);
    }
    out
}

/// Serves built blocks and imports on `addr` until the process ends.
pub async fn serve<T>(
    addr: SocketAddr,
    payloads: PayloadBuilderHandle<T>,
    engine: ConsensusEngineHandle<T>,
) -> std::io::Result<()>
where
    T: PayloadTypes<BuiltPayload = EthBuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    info!(target: "n42.payload_serve", %addr, "raw payload channel listening");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(target: "n42.payload_serve", %err, "accept failed");
                continue;
            }
        };
        let payloads = payloads.clone();
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_connection(stream, payloads, engine).await {
                debug!(target: "n42.payload_serve", %peer, %err, "raw payload connection ended");
            }
        });
    }
}

async fn serve_connection<T>(
    mut stream: TcpStream,
    payloads: PayloadBuilderHandle<T>,
    engine: ConsensusEngineHandle<T>,
) -> std::io::Result<()>
where
    T: PayloadTypes<BuiltPayload = EthBuiltPayload, ExecutionData = alloy_rpc_types_engine::ExecutionData> + 'static,
{
    stream.set_nodelay(true)?;
    loop {
        let kind = match stream.read_u8().await {
            Ok(kind) => kind,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        if kind == request::NEW_PAYLOAD {
            let len = stream.read_u32_le().await? as usize;
            if len > 256 << 20 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "payload frame too large"));
            }
            let mut frame = vec![0u8; len];
            stream.read_exact(&mut frame).await?;
            let started = std::time::Instant::now();
            let mut out: Vec<u8> = Vec::with_capacity(96);
            match raw_engine::decode_execution_data(&frame) {
                Err(err) => {
                    out.push(2);
                    out.extend_from_slice(&(err.len() as u32).to_le_bytes());
                    out.extend_from_slice(err.as_bytes());
                }
                Ok(data) => {
                    let decoded = started.elapsed();
                    let number = data.payload.block_number();
                    let txs = data.payload.as_v1().transactions.len();
                    match engine.new_payload(data).await {
                        Ok(status) => {
                            if txs > 10_000 {
                                info!(
                                    target: "n42.payload_serve",
                                    number,
                                    txs,
                                    decode_ms = decoded.as_millis() as u64,
                                    engine_ms = started.elapsed().saturating_sub(decoded).as_millis() as u64,
                                    status = ?status.status,
                                    "raw newPayload"
                                );
                            }
                            let encoded = raw_engine::encode_payload_status(&status);
                            out.push(1);
                            out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                            out.extend_from_slice(&encoded);
                        }
                        Err(err) => {
                            let message = err.to_string();
                            out.push(2);
                            out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                            out.extend_from_slice(message.as_bytes());
                        }
                    }
                }
            }
            stream.write_all(&out).await?;
            continue;
        }
        if kind != request::GET_PAYLOAD {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("request kind {kind}")));
        }
        let id = stream.read_u64_le().await?;
        let id = alloy_rpc_types_engine::PayloadId::new(id.to_le_bytes());
        let started = std::time::Instant::now();
        let resolved = payloads.resolve_kind(id, PayloadKind::WaitForPending).await;
        let waited = started.elapsed();
        let mut out: Vec<u8> = Vec::new();
        match resolved {
            None => out.push(0),
            Some(Err(err)) => {
                let message = err.to_string();
                out.push(2);
                out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                out.extend_from_slice(message.as_bytes());
            }
            Some(Ok(payload)) => {
                let encode_at = std::time::Instant::now();
                let block = encode_block_parallel(payload.block());
                let encoded = encode_at.elapsed();
                out.reserve(block.len() + 64);
                out.push(1);
                out.extend_from_slice(&(block.len() as u32).to_le_bytes());
                out.extend_from_slice(&block);
                match payload.requests() {
                    Some(requests) => {
                        let requests = requests.take();
                        out.push(1);
                        out.extend_from_slice(&(requests.len() as u32).to_le_bytes());
                        for request in &requests {
                            out.extend_from_slice(&(request.len() as u32).to_le_bytes());
                            out.extend_from_slice(request);
                        }
                    }
                    None => out.push(0),
                }
                match payload.block_access_list() {
                    Some(bal) => {
                        out.push(1);
                        out.extend_from_slice(&(bal.len() as u32).to_le_bytes());
                        out.extend_from_slice(bal);
                    }
                    None => out.push(0),
                }
                if block.len() > 1_000_000 {
                    info!(
                        target: "n42.payload_serve",
                        number = payload.block().number(),
                        bytes = block.len(),
                        waited_ms = waited.as_millis() as u64,
                        encode_ms = encoded.as_millis() as u64,
                        "raw payload served"
                    );
                }
            }
        }
        stream.write_all(&out).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Block, BlockBody, Header, Signed, TxEip1559, TxLegacy};
    use alloy_primitives::{Address, Signature, TxKind, U256};
    use reth_ethereum_primitives::TransactionSigned;

    /// The parallel encoding is alloy's, byte for byte.
    #[test]
    fn parallel_block_rlp_is_alloys() {
        let txs: Vec<TransactionSigned> = (0..40u64)
            .map(|n| {
                if n % 3 == 0 {
                    let tx = TxLegacy { chain_id: Some(1), nonce: n, gas_price: 10, gas_limit: 21_000, to: TxKind::Call(Address::repeat_byte(3)), value: U256::from(n), ..Default::default() };
                    Signed::new_unchecked(tx, Signature::test_signature(), Default::default()).into()
                } else {
                    let tx = TxEip1559 { chain_id: 1, nonce: n, gas_limit: 21_000, max_fee_per_gas: 10, max_priority_fee_per_gas: 1, to: TxKind::Call(Address::repeat_byte(2)), value: U256::from(n), ..Default::default() };
                    Signed::new_unchecked(tx, Signature::test_signature(), Default::default()).into()
                }
            })
            .collect();
        let header = Header { number: 9, base_fee_per_gas: Some(7), withdrawals_root: Some(alloy_consensus::EMPTY_ROOT_HASH), ..Default::default() };
        let withdrawals = alloy_eips::eip4895::Withdrawals(vec![alloy_eips::eip4895::Withdrawal { index: 1, validator_index: 2, address: Address::repeat_byte(7), amount: 3 }]);
        let block = Block { header, body: BlockBody { transactions: txs, ommers: Vec::new(), withdrawals: Some(withdrawals) } };
        let sealed = SealedBlock::seal_slow(block);
        assert_eq!(encode_block_parallel(&sealed), alloy_rlp::encode(&sealed));
    }
}
