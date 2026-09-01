// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! GossipSub transport for HotStuff-2 v4 cross-client traffic.
//!
//! This is the piece that lets a Rust node join a Go (gov5) fleet's gossip mesh
//! and follow its finality. It carries the router parameters, topic strings, and
//! message-ID function gov5 uses, so a Rust member behaves like a Go one at the
//! pubsub layer; the envelope codec and the finality check live in
//! [`n42_h2_wire`] and [`n42_h2_consensus`].
//!
//! [`transport::H2V4Transport`] is the bidirectional mesh member: it subscribes,
//! decodes, and publishes, and hands envelopes up without judging them.
//! [`observer::H2V4Observer`] is the read-only use of it — follow finality,
//! never speak — which is what monitoring and sync-target consumers want.
//! Neither one runs consensus: the state machine lives in [`n42_h2_consensus`],
//! and the layer that drives it from these events is the node service.
//! See `docs/N42_26_PORT.md`.

pub mod block_gossip;
pub mod tx_gossip;
pub mod config;
pub mod message_id;
pub mod observer;
pub mod rpc;
pub mod status;
pub mod topic;
pub mod transport;

pub use block_gossip::{
    compress_block_rlp, decode_block_gossip, decode_block_rlp, decompress_block_gossip,
    decode_block_rlp_raw,
    encode_block_gossip, encode_block_rlp, encode_block_rlp_parts, encode_block_rlp_raw, gov5_block_topic, gov5_header_view, BlockGossipError,
    GossipBlock, HeaderProfile, RawGossipBlock,
};
/// The peer identity type, so consumers need not depend on libp2p.
pub use libp2p::PeerId;
pub use rpc::{
    BlockChunk, BlockReply, RangeReply, RangeRequest, BLOCK_BY_HASH_PROTOCOL,
    BLOCK_PUSH_PROTOCOL, BODIES_BY_RANGE_PROTOCOL, MAX_RANGE_BLOCKS,
};
pub use config::{gov5_gossipsub_config, max_gossip_size, max_gossip_wire_size};
pub use message_id::{gov5_message_id_fn, gov5_message_id_parts};
pub use observer::{H2V4Observer, ObserverConfig, ObserverError, ObserverEvent};
pub use status::{Status, StatusError, STATUS_PROTOCOL};
pub use topic::{h2_v4_topic, H2_V4_TOPIC, H2_V4_TOPIC_BASE};
pub use transport::{
    BlockRequestChannel, H2V4Transport, RangeRequestChannel, PublishError, TransportConfig, TransportError,
    TransportEvent,
};
pub use tx_gossip::{decode_tx_batch, encode_tx_batch, TxGossipError, TX_BATCH_MAX_BYTES, TX_BATCH_MAX_TXS};
