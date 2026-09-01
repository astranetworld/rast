// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! GossipSub parameters matching gov5's router.
//!
//! Every constant here is lifted from `internal/p2p/pubsub.go`. They are not
//! arbitrary tuning: a mesh built with different overlay degrees or heartbeat
//! timing still interoperates, but grafts and prunes land at different rates
//! and a mixed fleet behaves inconsistently under load. Matching gov5 keeps a
//! Rust member of the fleet indistinguishable from a Go one at the router
//! level.

use std::time::Duration;

use alloy_primitives::B256;
use libp2p::gossipsub;

use crate::message_id::gov5_message_id_fn;

/// gov5 `gossipSubD` — target mesh degree.
pub const GOSSIP_SUB_D: usize = 8;
/// gov5 `gossipSubDlo` — low watermark.
pub const GOSSIP_SUB_D_LO: usize = 6;
/// go-libp2p-pubsub `GossipSubDhi` default; gov5 does not override it.
pub const GOSSIP_SUB_D_HI: usize = 12;
/// gov5 `gossipSubMcacheLen` — message cache history length.
pub const GOSSIP_SUB_MCACHE_LEN: usize = 6;
/// gov5 `gossipSubMcacheGossip` — history windows gossiped about.
pub const GOSSIP_SUB_MCACHE_GOSSIP: usize = 3;
/// gov5 `gossipSubHeartbeatInterval`.
pub const GOSSIP_SUB_HEARTBEAT: Duration = Duration::from_millis(700);
/// gov5 `seenMessagesTTL` — deliberately 30s, not libp2p's 2min default, to
/// keep the seen-cache from growing to hundreds of MB at fleet throughput.
pub const SEEN_MESSAGES_TTL: Duration = Duration::from_secs(30);

/// gov5 `encoder.MaxGossipSize` default, in bytes, before `N42_MAX_GOSSIP_MB`.
pub const DEFAULT_MAX_GOSSIP_SIZE: usize = 1 << 20;

/// The largest block payload this node will publish or accept.
///
/// One mebibyte is gov5's default and it is a *block size* cap that presents as
/// a gas cap: at roughly 107 bytes a transfer it holds a block to about 8,500
/// transactions no matter what the gas limit says, and the give-away is an
/// occupancy that is constant across windows while everything else varies
/// (their `docs/QS_TPS_BENCHMARK.md`, "the block-size cap masquerading as a gas
/// cap"). A full 480M-gas block needs about 2.44 MB.
///
/// So it has to be settable, and it has to be settable *the same way*: gov5
/// reads `N42_MAX_GOSSIP_MB`, and two clients on one chain that disagree about
/// this do not merely differ in throughput — the one with the smaller cap
/// refuses to decode the other's blocks and drops out of the fleet.
///
/// Read once. A cap that changed under a running node would let it publish a
/// block it would then refuse to accept back.
pub fn max_gossip_size() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| gossip_size_from(std::env::var("N42_MAX_GOSSIP_MB").ok().as_deref()))
}

/// The cap `N42_MAX_GOSSIP_MB` names, in bytes. Anything unset, unparseable or
/// zero leaves the default: a misread variable must not silently shrink the cap
/// to nothing and take the node off the chain.
fn gossip_size_from(megabytes: Option<&str>) -> usize {
    megabytes
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|mb| *mb > 0)
        .map_or(DEFAULT_MAX_GOSSIP_SIZE, |mb| mb << 20)
}

/// gov5 `GossipMaxSize()` = `snappy.MaxEncodedLen(MaxGossipSize)`.
///
/// Go's `snappy.MaxEncodedLen(n) == 32 + n + n/6`. The router cap has to be the
/// *encoded* bound, not the raw one: gov5 learned this when a cap pinned at
/// 1 MiB silently held the network at the default while producers sized blocks
/// to a raised budget, and libp2p then refused to publish them.
pub fn max_gossip_wire_size() -> usize {
    let size = max_gossip_size();
    32 + size + size / 6
}

/// Builds a gossipsub config equivalent to gov5's router for the given chain.
///
/// `ValidationMode::Anonymous` is the counterpart of gov5's
/// `WithMessageSignaturePolicy(StrictNoSign)` + `WithNoAuthor()`: gov5 publishes
/// messages with no author, no sequence number, and no signature, and rejects
/// any that carry them. Pairing it with [`gossipsub::MessageAuthenticity::Anonymous`]
/// is required — see [`crate::observer`].
pub fn gov5_gossipsub_config(
    genesis_hash: B256,
) -> Result<gossipsub::Config, &'static str> {
    gossipsub::ConfigBuilder::default()
        .heartbeat_interval(GOSSIP_SUB_HEARTBEAT)
        .mesh_n(GOSSIP_SUB_D)
        .mesh_n_low(GOSSIP_SUB_D_LO)
        .mesh_n_high(GOSSIP_SUB_D_HI)
        .history_length(GOSSIP_SUB_MCACHE_LEN)
        .history_gossip(GOSSIP_SUB_MCACHE_GOSSIP)
        .duplicate_cache_time(SEEN_MESSAGES_TTL)
        .max_transmit_size(max_gossip_wire_size())
        .validation_mode(gossipsub::ValidationMode::Anonymous)
        .message_id_fn(gov5_message_id_fn(genesis_hash))
        .build()
        .map_err(|_| "invalid gossipsub configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_matches_go_snappy_max_encoded_len() {
        // Go: snappy.MaxEncodedLen(1<<20) == 32 + 1048576 + 174762
        assert_eq!(max_gossip_wire_size(), 32 + 1_048_576 + 174_762);
        assert_eq!(max_gossip_wire_size(), 1_223_370);
    }

    #[test]
    fn the_gossip_cap_follows_gov5s_variable_and_falls_back_safely() {
        assert_eq!(gossip_size_from(Some("8")), 8 << 20, "gov5's benchmark setting");
        assert_eq!(gossip_size_from(Some(" 4 ")), 4 << 20, "surrounding space is not an error");
        // A cap of zero, or a typo, would refuse every block on the chain. The
        // default is the only safe reading of a variable that did not parse.
        for bad in [Some("0"), Some("eight"), Some(""), None] {
            assert_eq!(gossip_size_from(bad), DEFAULT_MAX_GOSSIP_SIZE, "{bad:?}");
        }
    }

    #[test]
    fn config_builds_with_gov5_parameters() {
        let cfg = gov5_gossipsub_config(B256::ZERO).unwrap();
        assert_eq!(cfg.mesh_n(), GOSSIP_SUB_D);
        assert_eq!(cfg.mesh_n_low(), GOSSIP_SUB_D_LO);
        assert_eq!(cfg.mesh_n_high(), GOSSIP_SUB_D_HI);
        assert_eq!(cfg.history_length(), GOSSIP_SUB_MCACHE_LEN);
        assert_eq!(cfg.history_gossip(), GOSSIP_SUB_MCACHE_GOSSIP);
        assert_eq!(cfg.heartbeat_interval(), GOSSIP_SUB_HEARTBEAT);
        assert_eq!(cfg.duplicate_cache_time(), SEEN_MESSAGES_TTL);
        assert_eq!(cfg.max_transmit_size(), max_gossip_wire_size());
        assert!(matches!(
            cfg.validation_mode(),
            gossipsub::ValidationMode::Anonymous
        ));
    }
}

/// The per-substream receive window for yamux, in bytes.
///
/// yamux's default is the specification's 256 KiB, which is a sensible number
/// for a wide-area mesh of small messages and the wrong one for handing a
/// twelve-megabyte block to a peer on the same host: the sender stops every
/// 256 KiB until the receiver returns credit, so the transfer costs about
/// forty-eight round trips through the receiver's event loop.
///
/// Measured on the seven-node fleet at the 163,000-transaction tier: a 12.2 MB
/// body took 302 ms from published to received, which is 40 MB/s on loopback
/// and 248 times what touching those bytes once costs. Every other step on the
/// leader's path is 3-8 times that floor. Small bodies cross in 0.1 ms, which
/// is what rules out a stalled event loop and leaves flow control.
///
/// The cost is memory: this much may be buffered per substream per peer. At the
/// default of 16 MiB and six peers that is bounded by what the fleet already
/// spends on one block, and `N42_YAMUX_WINDOW_MB` exists so a memory-constrained
/// deployment can put it back.
pub fn yamux_receive_window() -> Option<u32> {
    const DEFAULT_MB: u32 = 16;
    let mb = std::env::var("N42_YAMUX_WINDOW_MB")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_MB);
    (mb > 0).then(|| mb.clamp(1, 256) << 20)
}

/// yamux, with the receive window raised only if a round asked for it.
///
/// `N42_YAMUX_WINDOW_MB=0` leaves libp2p's default untouched. The distinction
/// matters: libp2p-yamux 0.47 defaults to yamux 0.13, whose flow control tunes
/// itself, while `set_receive_window_size` switches the connection back to
/// yamux 0.12 and a fixed window. This is not "raise a number", it is "trade
/// auto-tuning for a constant" — and on this fleet the constant wins, in a
/// place that took two rounds each side to find.
pub fn yamux_config() -> libp2p::yamux::Config {
    let Some(window) = yamux_receive_window() else {
        return libp2p::yamux::Config::default();
    };
    let mut config = libp2p::yamux::Config::default();
    #[allow(deprecated)]
    config.set_receive_window_size(window);
    // The buffer limit has to move with the window. yamux 0.12 keeps a
    // separate per-stream buffer cap, 1 MiB by default, and closes the whole
    // *connection* when a stream's unread data grows past it. A validator's
    // loop does not poll its swarm while it awaits a block import -- 700 ms
    // at the 163,000-transaction tier -- and a peer that keeps sending into a
    // 16 MiB window fills the 1 MiB buffer in that time. Measured: 18-36
    // `buffer of stream grows beyond limit` per node per round, each followed
    // by a `dial failed` and, when it hit a proposal or a quorum's votes, a
    // six-second view timeout. That was the tail of the block cycle.
    #[allow(deprecated)]
    config.set_max_buffer_size(window as usize);
    config
}
