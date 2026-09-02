// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The loop that makes a Rust node a participating member of a gov5 fleet.
//!
//! Three pieces already existed and did not touch each other: the gossip
//! transport ([`n42_h2_net::H2V4Transport`]), the HotStuff-2 engine
//! ([`n42_h2_consensus::ConsensusEngine`]), and the execution driver
//! ([`n42_h2_execution::ExecutionDriver`]). This is the seam between them —
//! inbound envelopes become consensus events, engine outputs become published
//! envelopes and execution calls, and what the execution layer says comes back
//! as more consensus events.
//!
//! **Draining is not optional.** The engine emits into a bounded channel and
//! gives up after a fixed retry budget when nobody drains it, so an output can
//! be dropped if this loop is busy. Every branch below therefore drains the
//! engine's outputs to empty before returning to the select, rather than
//! treating the channel as one more thing to poll.
//!
//! **A leader has to be asked to build, before it waits.** The engine proposes
//! only when handed a `BlockReady`, which comes from the execution layer, which
//! needs payload attributes this layer has no business inventing. So block
//! production is opt-in: supply [`H2Service::with_payload_attributes`] and this
//! node proposes when it is leader; leave it out and it votes but never
//! proposes, which is what a member joining an existing fleet should do.
//!
//! The attempt happens at the top of each step, before blocking on anything.
//! HotStuff-2 is responsive — a leader that has just formed a QC proposes for
//! the next view straight away — and a leader that has just committed has no
//! other event coming, so an attempt made after the wait waits for a timeout it
//! should never have needed.
//!
//! **Durability comes before finality.** Committing tells the execution layer a
//! block is finalized, and the Engine API does not allow that to be taken back.
//! A node that announces finality and then dies before its own consensus state
//! reaches disk restarts believing less than its execution layer does, and every
//! forkchoice it sends afterwards is rejected as a reorg past the finalized
//! block. So a commit checkpoint, when one is configured, is written *before*
//! the commit reaches the execution layer, and a checkpoint that fails stops the
//! commit rather than proceeding undurable.
//!
//! **Startup is not a timeout.** A node that comes up before its mesh does
//! would otherwise spend its first views broadcasting timeouts to nobody and
//! arrive at the fleet already several views behind. The first view's clock
//! therefore does not start until there is at least one mesh peer to talk to.
//!
//! **Timeouts drive liveness.** A view that produces nothing advances only
//! because the pacemaker fires, so the sleep is armed from the pacemaker's own
//! deadline on every iteration. Dropping that arm is what turns a node that
//! looks connected into one that silently stops voting.

use std::collections::HashSet;
use std::time::Duration;

use alloy_consensus::Header;
use alloy_primitives::{keccak256, Bytes, B256};
use n42_h2_consensus::wire_bridge::{self, BridgeError};
use n42_h2_consensus::{ConsensusEngine, ConsensusEvent, EngineOutput};
use n42_h2_execution::{DriverAction, ExecutionDriver, ExecutionLayer};
use alloy_rpc_types_engine::PayloadAttributes;
use n42_h2_net::{
    compress_block_rlp, decode_block_rlp_raw, decode_tx_batch, decompress_block_gossip,
    encode_block_rlp, encode_tx_batch,
    encode_block_rlp_parts, BlockChunk, H2V4Transport, HeaderProfile, PeerId, RangeRequest,
    TransportEvent, MAX_RANGE_BLOCKS,
};
use n42_h2_consensus::withdrawals_to_rewards;
use n42_h2_primitives::consensus::{H2V4ChainIdentity, QuorumCertificate};
use n42_h2_wire::{H2Message, H2V4Envelope};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Decides what a leader proposes for a view, given the view number and the
/// current head. `None` declines the view — see
/// [`H2Service::with_payload_attributes`].
type PayloadAttributesBuilder =
    dyn Fn(ProposalContext) -> Option<PayloadAttributes> + Send + Sync;

/// How many views one step may propose for before going back to the network.
///
/// Bounded rather than "until the view stops moving": a fleet that commits
/// faster than the transport is polled would otherwise starve its own gossip,
/// and a node that stops reading the network stops being a fleet member.
const MAX_PROPOSALS_PER_STEP: usize = 4;

/// How far the view deadline is pushed out on each step taken before the mesh
/// exists. Small enough that a mesh forming mid-step costs almost nothing,
/// large enough that it does not have to fire on every event.
const MESH_WAIT_STEP: Duration = Duration::from_millis(200);

/// Why the service stopped.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The transport's swarm ended, which it does not do in normal operation.
    #[error("gossip transport ended")]
    TransportEnded,
    /// The engine's output channel closed while the engine was still alive.
    #[error("consensus engine output channel closed")]
    OutputChannelClosed,
    /// The consensus engine returned a fatal error.
    #[error("consensus engine: {0}")]
    Engine(#[from] n42_h2_consensus::ConsensusError),
}

/// What the service is doing, for a caller that wants to watch without owning
/// the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceEvent {
    /// A block was committed by consensus and finalised in the execution layer.
    Committed {
        /// The view it was committed in.
        view: u64,
        /// The block.
        block_hash: B256,
        /// The certificate that committed it.
        ///
        /// Carried, not dropped: it is what turns "this node says so" into a
        /// proof anyone can check, and the only thing that lets a consumer —
        /// a mobile-verification endpoint, an archive, a bridge — republish the
        /// commit as the `Decide` a fleet member would have verified. Boxed
        /// because it is far larger than the rest of the enum.
        commit_qc: Box<QuorumCertificate>,
    },
    /// This node published a consensus message.
    Published {
        /// The view the message referred to.
        view: u64,
    },
    /// Consensus wants a block whose body this node has never seen. The caller
    /// is responsible for fetching it and calling
    /// [`H2Service::cache_payload`]; until then the node cannot vote on it.
    PayloadMissing {
        /// The block that could not be executed.
        block_hash: B256,
    },
    /// A block body arrived over the block topic and is now cached. If
    /// consensus was waiting on it, execution is retried in the same step.
    BodyReceived {
        /// The block the body belongs to.
        block_hash: B256,
    },
    /// A peer's status showed it ahead of this node's execution layer, and
    /// this node started pulling the gap by range.
    Syncing {
        /// This node's height when it started.
        from: u64,
        /// The peer's height.
        to: u64,
    },
    /// The pull finished — the execution layer is at the height the peer
    /// reported — or stopped short.
    Synced {
        /// The height reached.
        height: u64,
        /// Whether the target was reached.
        complete: bool,
    },
    /// The view advanced.
    ViewChanged {
        /// The view now current.
        new_view: u64,
    },
    /// This node is behind the fleet by more than the buffering window and
    /// needs to sync before it can contribute again.
    SyncRequired {
        /// The view this node is on.
        local_view: u64,
        /// The view the fleet is on.
        target_view: u64,
    },
}

/// Ties the gossip transport, the consensus engine, and the execution layer
/// together.
pub struct H2Service<E> {
    transport: H2V4Transport,
    engine: ConsensusEngine,
    driver: ExecutionDriver<E>,
    /// Our own blocks as the execution layer takes them, from the driver's
    /// spawned import; each one is the parent of the next build ahead.
    own_imports: Option<tokio::sync::mpsc::UnboundedReceiver<B256>>,
    outputs: mpsc::Receiver<EngineOutput>,
    identity: H2V4ChainIdentity,
    /// The size the signer bitmaps on the wire are read against. A message
    /// whose certificates were signed by a differently-sized set is rejected
    /// rather than guessed at — see [`wire_bridge`].
    validator_count: usize,
    /// Messages the engine produced that the mesh would not accept yet. gossipsub
    /// refuses to publish before a mesh forms, which is the normal state of a
    /// node that started before its fleet, so these are retried rather than lost.
    outbox: Vec<n42_h2_primitives::consensus::ConsensusMessage>,
    /// Builds the payload attributes for a block this node proposes. `None`
    /// means this node never proposes — see the module docs.
    payload_attributes: Option<Box<PayloadAttributesBuilder>>,
    /// How long to wait before asking the builder again; see [`PROPOSE_RETRY`].
    propose_retry: Duration,
    /// The view this node last built a block for, so a leader does not rebuild
    /// on every event it handles while still in the same view.
    proposed_view: Option<u64>,
    /// Whether the gossip mesh has ever had a peer. Until it does, the view
    /// clock is held off — see the module docs.
    meshed: bool,
    /// Persists consensus state before a commit is announced as final.
    checkpoint: Option<Box<CheckpointWriter>>,
    /// The builder declined to propose for the current view — the period had
    /// not elapsed — so the next step must not wait for the view to time out
    /// before asking again. See [`PROPOSE_RETRY`].
    proposal_deferred: bool,
    /// Hands gossiped transactions to the pool, off this loop. See
    /// [`crate::tx_source::forward_transactions`].
    inbound_forward: Option<mpsc::Sender<Vec<Bytes>>>,
    /// When each body arrived, for the import timing log.
    body_arrived: std::collections::HashMap<B256, std::time::Instant>,
    /// Bodies arriving over the plain TCP channel. See [`crate::body_channel`].
    body_rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// The channel's senders, one per peer, for this node's own bodies.
    body_pushers: Option<crate::body_channel::BodyPushers>,
    /// Publish every body on the block topic even when the direct push
    /// reached every connected member. `N42_BLOCK_TOPIC_ALWAYS=1`; what a
    /// fleet with gov5 members needs, since they take bodies from the topic.
    always_publish_topic: bool,
    /// A block just imported, whose successor this node may be about to lead.
    /// Set where imports are observed, which is a sync path, and acted on in
    /// the step, which is not.
    prepare_on: Option<B256>,
    /// Whether to start a build before this node is leader. Off by default:
    /// it is a change to when the execution layer is asked for a payload, and
    /// the first measurement of it was a fourfold regression rather than the
    /// saving its arithmetic promised. See [`Self::with_build_ahead`].
    prepare_ahead: bool,
    /// Why this node last declined to propose, for the timeout log to quote.
    ///
    /// A view that times out has exactly two shapes and they need opposite
    /// fixes: the leader never proposed, or it proposed and the votes did not
    /// arrive. Only the leader knows which, and only at the moment it decided,
    /// so the reason is recorded there and read when the view expires. Every
    /// previous attempt to attribute this fleet's timeouts worked by
    /// subtracting medians from the cycle, which was wrong twice.
    defer_reason: Option<&'static str>,
    /// Which header shapes this node puts on, and accepts from, the block
    /// topic. See [`HeaderProfile`].
    header_profile: HeaderProfile,
    /// Whether consensus messages go out on gov5's native topic in gov5's
    /// own encoding, as a Go fleet member sends them, rather than on the
    /// chain-bound v4 topic. Inbound traffic is accepted from both either
    /// way; Decide proofs are always also published on v4 for observers.
    native_wire: bool,
    /// Blocks consensus asked to execute before their bodies arrived. A body
    /// for one of these re-runs the execution instead of waiting for the next
    /// proposal to mention the block again, which it may never do.
    awaiting_bodies: HashSet<B256>,
    /// When each block's body was last asked of every peer, so a body that
    /// arrives and still does not let the block execute cannot start the
    /// request over immediately. Bounded; insertion order in
    /// `body_requested_order`.
    /// Whether a leader also hands its body straight to each member. Off by
    /// default: it is additive on the wire, but it is this node's own protocol
    /// and a fleet should be able to run without it.
    direct_push: bool,
    body_requested_at: std::collections::HashMap<B256, std::time::Instant>,
    body_requested_order: std::collections::VecDeque<B256>,
    /// Height of the last block the execution layer is known to have
    /// imported, once read; what "far ahead" is measured from.
    imported_height: Option<u64>,
    /// Bodies held back because they run far ahead of the execution layer:
    /// on a block more than 32 past its tip reth starts a backfill it has
    /// no peers for and answers every forkchoice with SYNCING from then on.
    /// Re-examined as the pull moves the tip. Bounded.
    held_bodies: Vec<B256>,
    /// The highest height each peer is known to be at, from its status and
    /// from the blocks it gossips or serves; what a catch-up consults.
    peer_heights: std::collections::HashMap<PeerId, u64>,
    /// No new catch-up before this; set when one ends.
    catch_up_retry_after: Option<std::time::Instant>,
    /// The peer whose catch-up failed last; another is preferred.
    failed_peer: Option<PeerId>,
    /// Blocks the execution layer has imported through this service — voted
    /// on, pulled or built. A commit for any other block is not handed to
    /// the execution layer: a forkchoice to a head reth does not have starts
    /// the same peerless backfill as a far-ahead payload. Bounded; insertion
    /// order in `imported_order`.
    imported: HashSet<B256>,
    imported_order: std::collections::VecDeque<B256>,
    /// Bodies that arrived for awaited blocks, to execute on the next drain.
    /// Kept separate because the transport handler cannot await.
    ready_bodies: Vec<B256>,
    /// Every body that arrived since the last drain, for reporting.
    received_bodies: Vec<B256>,
    /// Block bodies the mesh would not accept yet; retried like `outbox`.
    body_outbox: Vec<Vec<u8>>,
    /// Peers whose status arrived since the last drain, with the height
    /// they reported, to compare against the execution layer there.
    pending_status: Vec<(PeerId, u64)>,
    /// A catch-up in progress, if any.
    catch_up: Option<CatchUp>,
    /// Range replies to import on the next drain.
    pending_imports: Vec<(PeerId, RangeRequest, Vec<BlockChunk>)>,
    /// Block requests the store could not answer, for the execution layer
    /// on the next drain.
    pending_block_requests: Vec<(String, B256, n42_h2_net::BlockRequestChannel)>,
    /// Range requests to answer from the execution layer on the next drain;
    /// kept here because the transport handler cannot await.
    pending_ranges: Vec<(String, n42_h2_net::RangeRequest, n42_h2_net::RangeRequestChannel)>,
    /// Every body this node built or received, as gov5 block RLP, to answer
    /// `block_by_hash` — gov5's fetch-on-miss, and this node's own. Bounded;
    /// insertion order in `body_store_order`.
    body_store: std::collections::HashMap<B256, Vec<u8>>,
    body_store_order: Vec<B256>,
    /// Timestamps of blocks this node has seen the body of, for
    /// [`ProposalContext::head_timestamp`]. Bounded; insertion order in
    /// `timestamp_order`.
    block_timestamps: std::collections::HashMap<B256, u64>,
    /// Transactions heard on the fleet's transaction topic, waiting to be
    /// handed to the execution layer's pool.
    inbound_transactions: std::collections::VecDeque<Bytes>,
    /// Transactions this node's own pool admitted, from the source installed
    /// with [`Self::with_transaction_source`], waiting to go out.
    outbound_transactions: Option<mpsc::Receiver<Vec<Bytes>>>,
    /// Hashes of transactions heard from the fleet, so the pool's echo of
    /// them is not gossiped back. Bounded.
    ///
    /// Searched by scanning, and measured: an index beside it was built and
    /// tried, on the argument that `contains` over 4,096 hashes once per
    /// published transaction is ~90 million comparisons a second on the
    /// consensus loop. Three rounds each say it is not -- a median round of
    /// 1,372,147 transactions against 1,411,294, ranges overlapping heavily --
    /// so the argument was arithmetic on a publish rate that was never
    /// measured. The scan stays, and the index is not carried for a benefit
    /// that does not exist.
    gossiped_transactions: std::collections::VecDeque<B256>,
    /// The headers of the same blocks.
    block_headers: std::collections::HashMap<B256, Header>,
    /// Block numbers, same bookkeeping, for the height this node advertises
    /// in the status handshake once a block commits.
    block_numbers: std::collections::HashMap<B256, u64>,
    /// When each block was first seen here, for [`ProposalContext::head_seen`].
    block_seen: std::collections::HashMap<B256, std::time::Instant>,
    timestamp_order: Vec<B256>,
}

/// How long a leader whose builder declined waits before asking it again.
///
/// A declined proposal is a pacing decision — the chain's period has not
/// elapsed since the parent — and nothing else is due to happen in a view
/// where the leader has not proposed. Without this the next ask comes at the
/// view timeout, and every other view is lost to it. gov5 paces its own
/// re-asks at `minProposeDelayMs`, 200ms on the devnet.
///
/// It is a *default*, not a constant, because it quantises the block interval:
/// a leader whose pacing deadline falls just after a re-ask waits the whole
/// retry again, so the achieved interval is the pacing rounded up to a multiple
/// of this. At gov5's three-second pacing that is invisible. At a 250 ms
/// benchmark pacing it is up to 200 ms on a 250 ms target, and it showed up as
/// a leader taking 872 ms between committing and publishing when the pacing,
/// the build and the encode together account for about 400.
const PROPOSE_RETRY: Duration = Duration::from_millis(200);

/// The re-ask interval as a fraction of the pacing, and the floor under it.
/// An eighth of a three-second period clamps back to the 200 ms default; an
/// eighth of 250 ms is 31 ms, which is small against the interval it is
/// quantising and still far more than the cost of asking (an in-memory head
/// lookup and a closure that returns `None`).
const PROPOSE_RETRY_FRACTION: u32 = 8;
const PROPOSE_RETRY_FLOOR: Duration = Duration::from_millis(10);

/// A pull of the blocks this node is missing, from one peer, by range.
///
/// Started when a peer's status shows it ahead of this node's execution
/// layer — a member restarting after an absence, or joining a chain that
/// has been running — and driven one range at a time: the reply is
/// imported through `newPayload` in order, each block becoming the
/// finalized head, and the next range asked for until the peer's height is
/// reached. Only the execution layer catches up here; the consensus engine
/// finds the current view from the messages it hears.
#[derive(Debug)]
struct CatchUp {
    peer: PeerId,
    next: u64,
    target: u64,
    started_at: u64,
    /// The target from the peer's status is reached; the pull now probes
    /// past it, a window at a time, for what the fleet produced meanwhile.
    /// The peer's first short reply is the end of its chain.
    probing: bool,
}

/// How many block requests may wait for the execution layer at once, and
/// how many range requests: past these a request is answered empty rather
/// than queued, so one peer cannot hold every other's answers behind a
/// thousand lookups.
const MAX_PENDING_SERVES: usize = 256;
const MAX_PENDING_RANGES: usize = 8;
/// A block this far past the execution layer's tip is not handed to it.
///
/// It was 32 — reth's `MIN_BLOCKS_FOR_PIPELINE_RUN`, past which a payload with
/// an unknown parent starts a backfill this node's execution layer has no
/// devp2p peers to complete. One is the distance that actually happens, and it
/// costs the same: reth parks an orphan payload whatever the gap, and with no
/// peers to reach the parent it stays parked with every later `newPayload`
/// behind it. Measured on a node that missed a single body: **43 seconds** of
/// stall, `latest_block` two behind the fleet, and every view that node led
/// timing out at six seconds — while the seven-node cycle's median phases add
/// to 438 ms. Missing one body should cost one block.
///
/// Judged by block number rather than by whether the parent's hash is known.
/// A hash-based test needs this node's bookkeeping to agree with the execution
/// layer's about what has been imported, and when it does not — a fresh driver
/// whose head is a genesis constant the blocks do not descend from, which is
/// exactly the four-node fleet test — it holds every block forever. Failing
/// closed is worse than the stall; `imported_height` is `None` until the first
/// import, so this is simply inert until it can be right.
const FAR_AHEAD_BLOCKS: u64 = 1;
/// Bodies held back at most; the oldest go first.
/// How many gossiped transactions go to the forwarder in one handoff.
const TX_FORWARD_MAX: usize = 1000;

/// How many handoffs may be in flight to the forwarder before the loop drops.
///
/// Small deliberately. The arrival rate is set by the fleet and the drain rate
/// by this node's pool, so under sustained oversupply this queue is always
/// full and the question is only what happens then. Dropping is right: a
/// gossiped transaction that has waited behind four full batches has either
/// reached the pool by another route or been mined, and buffering it costs
/// memory to deliver something stale.
const TX_FORWARD_QUEUE: usize = 4;

/// How many gossiped transactions may wait in the loop for the next handoff.
const INBOUND_TX_CAP: usize = 8000;

const MAX_HELD_BODIES: usize = 4096;
/// Imported hashes remembered; older commits never arrive.
const MAX_IMPORTED: usize = 8192;
/// Between the end of one catch-up and the start of the next.
const CATCH_UP_RETRY: Duration = Duration::from_secs(3);
/// Between one broadcast request for a block's body and the next.
///
/// Without this the two halves of the body path chase each other: consensus
/// asks for a block it cannot execute, the request goes to every connected
/// peer, a body comes back, executing it still fails — because what is missing
/// is the block's parent, not the block — and the hash leaves the awaiting set,
/// so the very next pass asks all of them again. Measured on a seven-node fleet
/// where one member missed a proposal's body while the mesh was still forming:
/// the node re-imported one block 2,531 times, wrote a gigabyte of log in six
/// minutes, and filled every peer's inbound streams to capacity
/// (`libp2p_request_response: Dropping inbound stream`). The fleet still made
/// blocks throughout, which is what made it worth finding rather than obvious.
const BODY_REQUEST_INTERVAL: Duration = Duration::from_millis(750);
/// Hashes remembered for that interval. One per block in flight is enough; the
/// bound is here so a long run cannot grow the map.
const MAX_BODY_REQUEST_TIMES: usize = 1024;
/// Transport events handled per step beyond the one the select takes.
const MAX_TRANSPORT_DRAIN: usize = 256;
/// Pulled blocks imported per step. Importing a whole window of 1024 in one
/// go kept the swarm unpolled for the fifty seconds it took; gov5's streams
/// to this node timed out meanwhile and it dropped the connection. Between
/// batches the loop polls the transport and reads consensus, which the
/// guards on far-ahead blocks and unimported commits make safe.
const PULLED_BLOCKS_PER_STEP: usize = 32;

/// How many block bodies to keep for peers that ask. gov5 asks for the
/// parent of a block it cannot place and for the block a proposal names —
/// recent blocks, both — but a member restarting after a long absence walks
/// back further, and a body is a few hundred bytes when empty.
const REMEMBERED_BODIES: usize = 4096;

/// How many block timestamps to remember. Far more than any head-selection
/// needs; the bound is against a peer flooding bodies, not a working set.
const REMEMBERED_TIMESTAMPS: usize = 256;

/// What a leader knows when deciding whether, and how, to propose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalContext {
    /// The view being proposed for.
    pub view: u64,
    /// Whether this is a build being *started* rather than a proposal being
    /// made.
    ///
    /// A builder paces its proposals; it must not pace its builds. Starting a
    /// build early is the whole point of preparing one — the execution layer
    /// needs ~90 ms to fill a block, and that time is only on the critical
    /// path because the build starts when the node becomes leader. Asked to
    /// prepare, a builder should answer with the attributes it *would* use and
    /// leave the timing to the proposal.
    ///
    /// Missing this was measured: the first version of the prepared build ran
    /// the pacing gate too, and since a build is prepared the moment a block is
    /// imported, `head_seen.elapsed()` was always ~0 and the gate always said
    /// "not yet". Fifty-nine proposals in a round, `ahead=false` on every one.
    pub preparing: bool,
    /// The block the proposal would build on.
    pub head: B256,
    /// The head's timestamp, when this node has seen the block — its own
    /// builds and every body received over the block topic. `None` after a
    /// restart, or for a head whose body never came this way. A builder paces
    /// against this: an Engine API timestamp is a whole second and must be
    /// strictly greater than the parent's, and only the parent's timestamp
    /// says what that means.
    pub head_timestamp: Option<u64>,
    /// The head's header, when this node holds it — its own builds, bodies
    /// received, or the execution layer's copy. What a builder derives the
    /// parent beacon root from on a chain with a committee pool.
    pub head_header: Option<Header>,
    /// When this node first had the head — built it, or received its body —
    /// by this node's own clock. What a builder paces against: the head's
    /// timestamp is another leader's claim about time (gov5 stamps
    /// `parent + period` however early it proposes), while this is when the
    /// block actually happened here.
    pub head_seen: Option<std::time::Instant>,
}

/// Persists the engine's state. Called before a commit reaches the execution
/// layer; an `Err` aborts the commit rather than finalising something this node
/// could not record.
type CheckpointWriter = dyn Fn(&ConsensusEngine) -> Result<(), String> + Send + Sync;

impl<E> std::fmt::Debug for H2Service<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Service")
            .field("transport", &self.transport)
            .field("validator_count", &self.validator_count)
            .field("view", &self.engine.current_view())
            .field("proposes", &self.payload_attributes.is_some())
            .field("queued_messages", &self.outbox.len())
            .finish_non_exhaustive()
    }
}

impl<E: ExecutionLayer> H2Service<E> {
    /// Assembles a service from its three parts.
    ///
    /// `outputs` must be the receiver whose sender was handed to `engine`;
    /// without it the loop sees nothing the engine produces.
    pub fn new(
        transport: H2V4Transport,
        engine: ConsensusEngine,
        mut driver: ExecutionDriver<E>,
        outputs: mpsc::Receiver<EngineOutput>,
        validator_count: usize,
    ) -> Self {
        let identity = transport.identity();
        Self {
            transport,
            engine,
            own_imports: driver.take_own_imports(),
            driver,
            outputs,
            identity,
            validator_count,
            outbox: Vec::new(),
            payload_attributes: None,
            propose_retry: PROPOSE_RETRY,
            proposed_view: None,
            meshed: false,
            checkpoint: None,
            proposal_deferred: false,
            inbound_forward: None,
            body_arrived: std::collections::HashMap::new(),
            body_rx: None,
            body_pushers: None,
            always_publish_topic: std::env::var("N42_BLOCK_TOPIC_ALWAYS").is_ok(),
            prepare_on: None,
            prepare_ahead: false,
            defer_reason: None,
            header_profile: HeaderProfile::Ethereum,
            native_wire: false,
            awaiting_bodies: HashSet::new(),
            direct_push: false,
            body_requested_at: std::collections::HashMap::new(),
            body_requested_order: std::collections::VecDeque::new(),
            imported_height: None,
            held_bodies: Vec::new(),
            peer_heights: std::collections::HashMap::new(),
            catch_up_retry_after: None,
            failed_peer: None,
            imported: HashSet::new(),
            imported_order: std::collections::VecDeque::new(),
            ready_bodies: Vec::new(),
            received_bodies: Vec::new(),
            body_outbox: Vec::new(),
            pending_status: Vec::new(),
            catch_up: None,
            pending_imports: Vec::new(),
            pending_block_requests: Vec::new(),
            pending_ranges: Vec::new(),
            body_store: std::collections::HashMap::new(),
            body_store_order: Vec::new(),
            block_timestamps: std::collections::HashMap::new(),
            inbound_transactions: std::collections::VecDeque::new(),
            outbound_transactions: None,
            gossiped_transactions: std::collections::VecDeque::new(),
            block_headers: std::collections::HashMap::new(),
            block_numbers: std::collections::HashMap::new(),
            block_seen: std::collections::HashMap::new(),
            timestamp_order: Vec::new(),
        }
    }

    /// Runs this node under gov5's `HotStuff` header profile.
    ///
    /// Blocks it builds are finished before they are proposed — the view
    /// stamped into the extra data, the seal signed with `key`, the ommers
    /// hash and difficulty set to what gov5's producer writes — and blocks it
    /// receives are decoded under the same profile. What a Go fleet member
    /// does, so the two can share a chain.
    pub fn with_gov5_h2_profile(mut self, key: n42_h2_primitives::bls::BlsSecretKey) -> Self {
        self.header_profile = HeaderProfile::Gov5H2;
        self.native_wire = true;
        self.driver.set_payload_normalizer(move |payload, header, view| {
            match header {
                Some(header) => n42_h2_consensus::normalize_to_gov5_h2_from_header(
                    header.clone(),
                    payload,
                    view,
                    Some(&key),
                ),
                None => n42_h2_consensus::normalize_to_gov5_h2_with_header(payload, view, Some(&key)),
            }
            .map(|(data, header)| (data, Some(header)))
            .map_err(|e| e.to_string())
        });
        self
    }

    /// Sets the header shape used on the block topic.
    ///
    /// [`HeaderProfile::Ethereum`] is what this node's own builder produces
    /// and is the default; a fleet shared with gov5 nodes needs
    /// [`HeaderProfile::Gov5H2`] at both ends, which the builder does not emit
    /// yet.
    pub const fn with_header_profile(mut self, profile: HeaderProfile) -> Self {
        self.header_profile = profile;
        self
    }

    /// Persists consensus state at every commit.
    ///
    /// Called *before* the commit is handed to the execution layer, because
    /// finality announced over the Engine API cannot be withdrawn: a node that
    /// finalises a block and then restarts without a record of it points its
    /// forkchoice at an earlier block and is refused. If the writer returns an
    /// error the commit does not reach the execution layer at all — better a
    /// stalled node than one whose execution layer has finalised more than its
    /// consensus can prove.
    pub fn with_checkpoint(
        mut self,
        writer: impl Fn(&ConsensusEngine) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.checkpoint = Some(Box::new(writer));
        self
    }

    /// Makes this node produce blocks when it is leader.
    ///
    /// The closure is called with a [`ProposalContext`] — the view, the head,
    /// and the head's timestamp when known — and returns the attributes to
    /// build under. Without it the node votes on other members'
    /// proposals but never makes one — a valid way to run, and the safe default,
    /// since a node that proposes garbage is worse than one that proposes
    /// nothing.
    ///
    /// Returning `None` declines to propose for this view, and the node asks
    /// again on the next step. That is the answer to the constraint below: an
    /// Engine API timestamp is a whole second, and HotStuff-2 commits in tens of
    /// milliseconds, so a leader that always proposes runs the chain's clock
    /// into the future until the execution layer refuses the blocks.
    ///
    /// **The timestamp must be strictly greater than the parent block's, and
    /// must not be ahead of wall clock.** Returning `now()` unconditionally
    /// gives two consecutive blocks the same second: the execution layer accepts
    /// the forkchoiceUpdated, never finishes the build, and `getPayload` blocks
    /// until the view times out, with nothing in the logs but a slow call.
    /// Forcing the timestamp forward instead runs it past the local clock, and
    /// the execution layer rejects the block outright. Between those two, a
    /// leader proposes about once a second and declines in between.
    pub fn with_payload_attributes(
        mut self,
        attributes: impl Fn(ProposalContext) -> Option<PayloadAttributes> + Send + Sync + 'static,
    ) -> Self {
        self.payload_attributes = Some(Box::new(attributes));
        self
    }

    /// Also hands each block body straight to every connected member, rather
    /// than only publishing it to the mesh.
    ///
    /// Measured on a seven-node fleet: a body reaches a follower in 30 ms at
    /// the median and 1.1 s at the p90, and the p90 is the mesh queueing rather
    /// than the bytes — encoding and compressing a whole 480M-gas block is
    /// 4 ms. The topic remains the fallback for members this node is not
    /// connected to and for every gov5 member.
    pub const fn with_direct_block_push(mut self, enabled: bool) -> Self {
        self.direct_push = enabled;
        self
    }

    /// Sizes the re-ask interval from the chain's block pacing.
    ///
    /// The service cannot see the pacing — it lives in the attributes builder,
    /// which answers `None` until the deadline passes — so the caller that
    /// knows it says so. Without this the re-ask is a constant and quantises
    /// the interval it is meant to be polling; see [`PROPOSE_RETRY`].
    pub fn with_block_pacing(mut self, pacing: Duration) -> Self {
        self.propose_retry = (pacing / PROPOSE_RETRY_FRACTION)
            .clamp(PROPOSE_RETRY_FLOOR, PROPOSE_RETRY);
        self
    }

    /// Gossips the transactions this node's execution layer admits to its
    /// pool, read from its public JSON-RPC at `rpc_url` — the Engine API's
    /// auth endpoint accepts transactions but does not list them. Polled
    /// with `eth_newPendingTransactionFilter`; a Go leader seals what it
    /// hears here, exactly as a Rust leader seals what it hears from the
    /// Go members.
    pub fn with_transaction_source(mut self, rpc_url: url::Url) -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(crate::tx_source::poll_pending_transactions(rpc_url.clone(), tx));
        self.outbound_transactions = Some(rx);
        // The inbound direction of the same arrangement, and the same RPC. It
        // gets its own task rather than a turn in the loop for the reason on
        // `forward_transactions`: waiting for the pool is waiting with the
        // transport unread, and this is the one piece of work here whose size
        // the fleet sets rather than the chain.
        let (forward_tx, forward_rx) = mpsc::channel(TX_FORWARD_QUEUE);
        tokio::spawn(crate::tx_source::forward_transactions(rpc_url, forward_rx));
        self.inbound_forward = Some(forward_tx);
        self
    }

    /// Hands gossiped transactions to the execution layer's binary ingest
    /// instead of its JSON-RPC. The outbound direction is unchanged, so this
    /// goes after [`Self::with_transaction_source`] and replaces only the
    /// inbound forwarder it set up. See
    /// [`crate::tx_source::forward_transactions_over_ingest`] for why.
    pub fn with_transaction_ingest(mut self, addr: String, connections: usize) -> Self {
        let (forward_tx, forward_rx) = mpsc::channel(TX_FORWARD_QUEUE * 4);
        tokio::spawn(crate::tx_source::forward_transactions_over_ingest(addr, forward_rx, connections));
        self.inbound_forward = Some(forward_tx);
        self
    }

    /// The transport, for dialing more peers or reading mesh state.
    pub const fn transport(&self) -> &H2V4Transport {
        &self.transport
    }

    /// The transport, mutably.
    pub const fn transport_mut(&mut self) -> &mut H2V4Transport {
        &mut self.transport
    }

    /// The consensus engine.
    pub const fn engine(&self) -> &ConsensusEngine {
        &self.engine
    }

    /// Hands the driver a block body it asked for via
    /// [`ServiceEvent::PayloadMissing`].
    pub fn cache_payload(
        &mut self,
        block_hash: B256,
        payload: alloy_rpc_types_engine::ExecutionData,
    ) {
        self.driver.cache_payload(block_hash, payload);
    }

    /// Runs one iteration: waits for the next thing to happen, handles it, and
    /// drains everything it caused.
    ///
    /// Returns the events worth reporting. Callers that just want the node to
    /// run can loop on this and ignore the result.
    pub async fn step(&mut self) -> Result<Vec<ServiceEvent>, ServiceError> {
        let mut events = Vec::new();
        self.hold_view_clock_until_meshed();

        // Drain, then propose, then drain again — before waiting, not after.
        //
        // HotStuff-2 is responsive: a leader that has just formed a QC proposes
        // for the next view immediately. Deferring the attempt until after the
        // select makes it wait for some unrelated event first, and a leader that
        // has just committed has none coming, so it sits until the view times
        // out and the round is lost.
        //
        // The leading drain is what makes the view current: the commit that
        // ended the last round may still be sitting in the output channel, and
        // proposing before reading it proposes for the view just finished, which
        // the guard then skips.
        let mut still_advancing = false;
        for remaining in (0..MAX_PROPOSALS_PER_STEP).rev() {
            self.drain_outputs(&mut events).await?;
            let before = self.engine.current_view();
            self.propose_if_leader(&mut events).await;
            self.drain_outputs(&mut events).await?;
            self.flush_prepare().await;
            // A commit lands in the drain *after* the proposal that caused it,
            // so one step can span several views. Stopping at one proposal per
            // step means the next view's proposal waits for the select to
            // return, and a leader that just committed has nothing else coming —
            // so it waits for a timeout it never needed.
            if self.engine.current_view() == before {
                break;
            }
            still_advancing = remaining == 0;
        }

        // A range reply half imported is finished the same way: the swarm
        // gets one poll and the step returns to import the next batch.
        if still_advancing || !self.pending_imports.is_empty() {
            // The bound stopped a leader that was still making progress.
            // Blocking now would trade the rest of its views for a timeout, so
            // look at the network without waiting and come straight back —
            // skipping the look entirely would starve the transport of a node
            // that always has something to propose.
            tokio::select! {
                biased;
                event = self.transport.next_event() => {
                    let Some(event) = event else {
                        return Err(ServiceError::TransportEnded);
                    };
                    self.handle_transport_event(event)?;
                }
                () = std::future::ready(()) => {}
            }
            self.drain_outputs(&mut events).await?;
            self.forward_inbound_transactions();
            self.flush_outbox(&mut events);
            return Ok(events);
        }

        // Arm from the pacemaker every iteration rather than holding one sleep
        // across views: a commit resets the deadline, and a sleep armed for the
        // old view would fire late or not at all.
        let timeout = self.engine.pacemaker().timeout_sleep();
        tokio::pin!(timeout);
        let outbound = self.outbound_transactions.as_mut();
        let body_rx = self.body_rx.as_mut();
        let own_imports = self.own_imports.as_mut();

        tokio::select! {
            body = async {
                match body_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(body) = body {
                    self.handle_direct_body(body);
                }
            }
            event = self.transport.next_event() => {
                let Some(event) = event else {
                    return Err(ServiceError::TransportEnded);
                };
                self.handle_transport_event(event)?;
            }
            batch = async {
                match outbound {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(batch) = batch {
                    let count = batch.len();
                    let at = std::time::Instant::now();
                    self.publish_transactions(batch);
                    let ms = at.elapsed().as_millis() as u64;
                    if ms > 30 {
                        info!(target: "n42.h2.node", count, ms, "slow: publishing the pool's transactions");
                    }
                }
            }
            output = self.outputs.recv() => {
                let Some(output) = output else {
                    return Err(ServiceError::OutputChannelClosed);
                };
                self.handle_output(output, &mut events).await?;
            }
            imported = async {
                match own_imports {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                // Our own block is in the execution layer: the parent the
                // next build ahead wants. Flushed at the end of this step.
                if let Some(hash) = imported {
                    self.prepare_on = Some(hash);
                }
            }
            () = &mut timeout => {
                // A view that produced nothing advances only because of this.
                // Logged at warn, and with its cause, because this is the
                // fleet's dominant cost rather than an exceptional event: at
                // the 480M tier the median path is 442 ms and the measured
                // cycle 1,500 ms, and 0.37 timeouts a block at a 6 s
                // `baseTimeout` is the whole of that difference. Which of the
                // two shapes below it is decides what to fix.
                let view = self.engine.current_view();
                let leader = self.engine.is_current_leader();
                warn!(
                    target: "n42.h2.node",
                    view,
                    leader,
                    proposed = self.proposed_view == Some(view),
                    reason = self.defer_reason.unwrap_or(if leader { "proposed; the votes did not arrive" } else { "not this node's view to lead" }),
                    "view timed out"
                );
                // A leader's build prepared ahead was on the block that just
                // went unanswered; the next proposal extends the last QC's
                // block, so that build is not the one it wants.
                if leader {
                    self.driver.discard_prepared();
                }
                self.engine.on_timeout()?;
            }
            () = tokio::time::sleep(self.propose_retry), if self.proposal_deferred => {
                // Nothing happened; the builder is asked again at the top of
                // the next step.
            }
        }

        // Everything the transport already has, not one event per step.
        //
        // The select above takes exactly one, and a step can spend a hundred
        // milliseconds or more awaiting the execution layer, so a node under
        // transaction gossip reads its mesh at whatever rate its own block
        // cycle runs. Block bodies then queue behind transaction batches on the
        // same mesh: measured at 6,000 senders as a median body arrival of
        // 380 ms against 32 ms at 64 senders, with the execution cost of the
        // block unchanged either way.
        // Timed in four, at info when a step is slow, because the follower's
        // import was measured to start ~180 ms after the proposal it needed had
        // been processed, with nothing logged in between. Whatever holds the
        // loop for that long is on the fleet's cycle.
        let at = std::time::Instant::now();
        let transport_events = self.drain_transport(&mut events).await?;
        let transport_ms = at.elapsed().as_millis() as u64;
        let at = std::time::Instant::now();
        self.drain_outputs(&mut events).await?;
        let outputs_ms = at.elapsed().as_millis() as u64;
        let at = std::time::Instant::now();
        self.flush_prepare().await;
        self.forward_inbound_transactions();
        self.flush_outbox(&mut events);
        let flush_ms = at.elapsed().as_millis() as u64;
        if transport_ms + flush_ms > 30 {
            info!(target: "n42.h2.node", transport_ms, transport_events, outputs_ms, flush_ms, "slow step");
        }
        Ok(events)
    }

    /// Handles every transport event already queued, up to a bound.
    ///
    /// Bounded because the transport can always have more: an unbounded drain
    /// under sustained gossip would never return to the engine, which is the
    /// same starvation this fixes, pointed the other way.
    async fn drain_transport(&mut self, events: &mut Vec<ServiceEvent>) -> Result<usize, ServiceError> {
        let mut drained = 0;
        for _ in 0..MAX_TRANSPORT_DRAIN {
            let ready = tokio::select! {
                biased;
                event = self.transport.next_event() => {
                    Some(event.ok_or(ServiceError::TransportEnded)?)
                }
                () = std::future::ready(()) => None,
            };
            match ready {
                Some(event) => {
                    self.handle_transport_event(event)?;
                    drained += 1;
                }
                None => break,
            }
        }
        let _ = events;
        Ok(drained)
    }

    /// Passes gossiped transactions to the forwarder, without waiting for it.
    ///
    /// Nothing here awaits, which is the whole point: `try_send` either takes
    /// the batch or says the forwarder is behind, and a loop that blocked on
    /// either answer would be back to being deaf to its mesh while the pool
    /// thinks. See [`crate::tx_source::forward_transactions`] for what that
    /// cost.
    fn forward_inbound_transactions(&mut self) {
        let Some(sink) = &self.inbound_forward else {
            self.inbound_transactions.clear();
            return;
        };
        while !self.inbound_transactions.is_empty() {
            let take = self.inbound_transactions.len().min(TX_FORWARD_MAX);
            let batch: Vec<Bytes> = self.inbound_transactions.drain(..take).collect();
            let offered = batch.len();
            match sink.try_send(batch) {
                Ok(()) => {
                    debug!(target: "n42.h2.node", offered, waiting = self.inbound_transactions.len(), "passed gossiped transactions to the forwarder");
                }
                Err(mpsc::error::TrySendError::Full(batch)) => {
                    // The pool is slower than the fleet. Keep what did not fit
                    // for the next step, up to the cap, and stop trying now.
                    for raw in batch.into_iter().rev() {
                        self.inbound_transactions.push_front(raw);
                    }
                    while self.inbound_transactions.len() > INBOUND_TX_CAP {
                        self.inbound_transactions.pop_front();
                    }
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.inbound_forward = None;
                    self.inbound_transactions.clear();
                    return;
                }
            }
        }
    }

    /// Gossips transactions this node's pool admitted, leaving out the ones
    /// that came from the fleet in the first place.
    fn publish_transactions(&mut self, batch: Vec<Bytes>) {
        let fresh: Vec<Bytes> = batch
            .into_iter()
            .filter(|raw| !self.gossiped_transactions.contains(&keccak256(raw)))
            .collect();
        if fresh.is_empty() {
            return;
        }
        for chunk in fresh.chunks(n42_h2_net::TX_BATCH_MAX_TXS) {
            let encoded = match encode_tx_batch(chunk).and_then(|payload| {
                compress_block_rlp(&payload).map_err(|_| n42_h2_net::TxGossipError::TooLarge(payload.len()))
            }) {
                Ok(encoded) => encoded,
                Err(err) => {
                    debug!(target: "n42.h2.node", %err, "could not encode a transaction batch");
                    continue;
                }
            };
            if let Err(err) = self.transport.publish_transactions(encoded) {
                debug!(target: "n42.h2.node", %err, "could not gossip transactions");
            } else {
                debug!(target: "n42.h2.node", count = chunk.len(), "gossiped transactions");
            }
        }
    }

    /// Runs until the transport or the engine stops.
    pub async fn run(&mut self) -> Result<(), ServiceError> {
        loop {
            for event in self.step().await? {
                match event {
                    ServiceEvent::Committed {
                        view, block_hash, ..
                    } => {
                        info!(target: "n42.h2.node", view, ?block_hash, "committed");
                    }
                    ServiceEvent::SyncRequired {
                        local_view,
                        target_view,
                    } => {
                        warn!(target: "n42.h2.node", local_view, target_view, "behind the fleet");
                    }
                    ServiceEvent::PayloadMissing { block_hash } => {
                        warn!(target: "n42.h2.node", ?block_hash, "block body not available");
                    }
                    ServiceEvent::BodyReceived { block_hash } => {
                        info!(target: "n42.h2.node", ?block_hash, "block body received");
                    }
                    _ => {}
                }
            }
        }
    }

    fn handle_transport_event(&mut self, event: TransportEvent) -> Result<(), ServiceError> {
        match event {
            TransportEvent::Envelope { envelope, .. } => self.accept_envelope(&envelope),
            TransportEvent::Native { message, .. } => {
                // The native topic is chain-scoped by its fork digest and
                // carries no envelope; give the message the envelope the
                // bridge expects, under this node's own identity. The
                // signatures inside are chain-bound regardless — a gov5
                // fleet with interopV4 signs the v4 domains on this topic.
                let envelope = H2V4Envelope {
                    identity: self.identity,
                    changes_hash: B256::ZERO,
                    message: *message,
                };
                self.accept_envelope(&envelope);
            }
            TransportEvent::Transactions { data, .. } => {
                match decompress_block_gossip(&data).and_then(|payload| {
                    decode_tx_batch(&payload).map_err(|e| n42_h2_net::BlockGossipError::InvalidRewards(e.to_string()))
                }) {
                    Ok(transactions) => {
                        for raw in transactions {
                            self.gossiped_transactions.push_back(keccak256(&raw));
                            while self.gossiped_transactions.len() > REMEMBERED_TIMESTAMPS * 16 {
                                self.gossiped_transactions.pop_front();
                            }
                            self.inbound_transactions.push_back(raw);
                            if self.inbound_transactions.len() > INBOUND_TX_CAP {
                                self.inbound_transactions.pop_front();
                            }
                        }
                    }
                    Err(err) => debug!(target: "n42.h2.node", %err, "dropped a transaction message"),
                }
            }
            TransportEvent::Block { from, data } => {
                // Nothing here is trusted beyond its own consistency: the
                // header hashes to the block hash, the transactions hash to
                // the header's root. Whether the block is *valid* is the
                // execution layer's verdict, and whether it is *the* block is
                // consensus's — both check the same hash.
                let decoded = decompress_block_gossip(&data).and_then(|rlp| {
                    decode_block_rlp_raw(&rlp, self.header_profile).map(|block| (block, rlp))
                });
                match decoded {
                    Ok((block, rlp)) => {
                        let block_hash = block.block_hash;
                        if let Some(peer) = from {
                            self.note_peer_height(peer, block.header.number);
                        }
                        self.remember_body(block_hash, rlp);
                        self.remember_block(block_hash, &block.header);
                        let convert_at = std::time::Instant::now();
                        let txs = block.transactions.len();
                        self.driver.cache_payload(block_hash, block.execution_data());
                        let convert_ms = convert_at.elapsed().as_millis() as u64;
                        self.import_eagerly(block_hash);
                        self.body_arrived.insert(block_hash, std::time::Instant::now());
                        info!(target: "n42.h2.node", ?block_hash, txs, convert_ms, "block body received");
                        self.received_bodies.push(block_hash);
                    }
                    Err(err) => {
                        // The bytes matter here: a body this node cannot read
                        // is a body it cannot vote on, and the usual cause is
                        // a wire-format difference with the producer.
                        let head = data.iter().take(256).map(|b| format!("{b:02x}")).collect::<String>();
                        debug!(target: "n42.h2.node", %err, len = data.len(), head, "dropped a block body");
                    }
                }
            }
            TransportEvent::BlockRequest { peer, hash, channel } => {
                // The store holds recent bodies byte for byte; anything older
                // is rebuilt from the execution layer on the next drain, the
                // way ranges are served.
                match self.body_store.get(&hash).cloned() {
                    Some(body) => {
                        debug!(target: "n42.h2.node", %peer, ?hash, "peer asked for a block; served from the store");
                        self.transport.respond_block(channel, Some(body));
                    }
                    None if self.pending_block_requests.len() >= MAX_PENDING_SERVES => {
                        // A queue this deep is a peer asking faster than the
                        // execution layer answers; better a prompt "not
                        // found" than a stall for everyone behind it.
                        debug!(target: "n42.h2.node", %peer, ?hash, "block request queue full; refused");
                        self.transport.respond_block(channel, None);
                    }
                    None => self.pending_block_requests.push((peer.to_string(), hash, channel)),
                }
            }
            TransportEvent::BlockFetched { peer, hash, reply } => match reply {
                Ok(chunk) => {
                    // The same path a gossiped body takes; the hash the peer
                    // sent it under is checked by the decode, not trusted.
                    match decode_block_rlp_raw(&chunk.rlp, self.header_profile) {
                        Ok(block) if block.block_hash == hash => {
                            self.remember_block(hash, &block.header);
                            self.remember_body(hash, chunk.rlp.to_vec());
                            self.driver.cache_payload(hash, block.execution_data());
                            self.import_eagerly(hash);
                            self.received_bodies.push(hash);
                        }
                        Ok(block) => {
                            debug!(target: "n42.h2.node", %peer, ?hash, got = ?block.block_hash, "peer answered a block request with the wrong block");
                        }
                        Err(err) => {
                            debug!(target: "n42.h2.node", %peer, ?hash, %err, "peer answered a block request with a body this node cannot read");
                        }
                    }
                }
                Err(reason) => {
                    debug!(target: "n42.h2.node", %peer, ?hash, reason, "peer does not have a requested block");
                }
            },
            TransportEvent::BlockPushed { peer, chunk } => {
                // A body the leader sent without being asked. It goes through
                // the same decode as a fetched one and is identified by what it
                // decodes to rather than by anything the sender claimed, so an
                // unsolicited push can introduce nothing a fetch could not.
                // Arriving twice — pushed and then gossiped — costs one decode:
                // everything below is idempotent, and `awaiting_bodies` has
                // already been emptied by whichever copy came first.
                match decode_block_rlp_raw(&chunk.rlp, self.header_profile) {
                    Ok(block) => {
                        let hash = block.block_hash;
                        if !self.body_store.contains_key(&hash) {
                            self.remember_block(hash, &block.header);
                            self.remember_body(hash, chunk.rlp.to_vec());
                            self.driver.cache_payload(hash, block.execution_data());
                            self.import_eagerly(hash);
                            self.received_bodies.push(hash);
                        }
                    }
                    Err(err) => {
                        debug!(target: "n42.h2.node", %peer, %err, "a pushed body could not be read");
                    }
                }
            }
            TransportEvent::BlockFetchFailed { peer, hash, reason } => {
                debug!(target: "n42.h2.node", %peer, ?hash, reason, "block request failed");
            }
            TransportEvent::RangeRequest { peer, request, channel } => {
                // Served from the execution layer's canonical chain, which
                // has every block, rather than from the body store, which
                // has the recent ones. As many as it has from the start, in
                // order; gov5 reads until the stream closes.
                if self.pending_ranges.len() >= MAX_PENDING_RANGES {
                    debug!(target: "n42.h2.node", %peer, ?request, "range request queue full; refused");
                    self.transport.respond_range(channel, Vec::new());
                } else {
                    self.pending_ranges.push((peer.to_string(), request, channel));
                }
            }
            TransportEvent::RangeFetched { peer, request, reply } => match reply {
                Ok(chunks) => self.pending_imports.push((peer, request, chunks)),
                Err(reason) => {
                    if self.catch_up.as_ref().is_some_and(|c| c.peer == peer) {
                        // Handed to the import loop as an empty reply: a
                        // refusal of a probe past the peer's head is the end
                        // of its chain, anything else stops the catch-up.
                        debug!(target: "n42.h2.node", %peer, ?request, reason, "range request refused");
                        self.pending_imports.push((peer, request, Vec::new()));
                    } else {
                        warn!(target: "n42.h2.node", %peer, ?request, reason, "range request refused");
                    }
                }
            },
            TransportEvent::StatusExchanged {
                peer,
                height,
                fork_matches,
                ..
            } => {
                if fork_matches {
                    debug!(target: "n42.h2.node", %peer, height, "peer on our chain");
                    self.pending_status.push((peer, height));
                } else {
                    // gov5 sends goodbye on a fork mismatch, so this connection
                    // is about to die and the operator needs to know why.
                    warn!(target: "n42.h2.node", %peer, "peer is on a different chain; it will disconnect");
                }
            }
            TransportEvent::PeerConnected(peer) => {
                debug!(target: "n42.h2.node", %peer, "peer connected");
            }
            TransportEvent::Rejected { reason, .. } => {
                debug!(target: "n42.h2.node", reason, "dropped a gossip payload");
            }
            TransportEvent::DialFailed { reason, .. } => {
                warn!(target: "n42.h2.node", reason, "dial failed");
            }
            _ => {}
        }
        Ok(())
    }

    /// Feeds a decoded consensus message to the engine.
    fn accept_envelope(&mut self, envelope: &H2V4Envelope) {
        match wire_bridge::to_engine(envelope, self.validator_count) {
            Ok(message) => {
                // A message that fails the engine's own checks is a
                // peer problem, not a local one: log it and keep the
                // node running rather than taking the fleet's word for
                // when this process should stop.
                if let Err(err) = self.engine.process_event(ConsensusEvent::Message(message))
                {
                    debug!(target: "n42.h2.node", %err, "engine rejected a message");
                }
            }
            Err(BridgeError::InvalidBitmap { .. }) => {
                // Almost always a fleet running a different validator
                // set size, which is a configuration problem worth
                // seeing rather than a malformed-packet statistic.
                warn!(
                    target: "n42.h2.node",
                    expected = self.validator_count,
                    "rejected a message whose signer bitmap does not match our validator set size",
                );
            }
            Err(err) => {
                debug!(target: "n42.h2.node", %err, "undecodable consensus message");
            }
        }
    }

    /// Drains the engine's output channel to empty.
    ///
    /// Not a `while let Some(..) = recv().await` loop: that would block waiting
    /// for the *next* output rather than stopping when the channel runs dry.
    async fn drain_outputs(&mut self, events: &mut Vec<ServiceEvent>) -> Result<(), ServiceError> {
        self.consider_catch_up(events).await;
        self.import_ranges(events).await;
        for (peer, hash, channel) in std::mem::take(&mut self.pending_block_requests) {
            let body = match self.driver.execution_layer().block_by_hash(hash).await {
                Ok(Some(block)) => Some(encode_block_rlp_parts(
                    &block.header,
                    &block.transactions,
                    &withdrawals_to_rewards(block.withdrawals.as_deref().unwrap_or(&[])),
                )),
                Ok(None) => None,
                Err(err) => {
                    debug!(target: "n42.h2.node", ?hash, %err, "execution layer could not serve a block");
                    None
                }
            };
            debug!(target: "n42.h2.node", peer, ?hash, found = body.is_some(), "peer asked for a block; execution layer consulted");
            self.transport.respond_block(channel, body);
        }
        for (peer, request, channel) in std::mem::take(&mut self.pending_ranges) {
            // Only the execution layer is held across the await: the
            // transport is not `Sync`, and a future holding all of `self`
            // could not be spawned.
            let rlps = serve_range(self.driver.execution_layer(), request).await;
            debug!(target: "n42.h2.node", peer, ?request, served = rlps.len(), "peer asked for a range");
            self.transport.respond_range(channel, rlps);
        }
        for block_hash in std::mem::take(&mut self.received_bodies) {
            events.push(ServiceEvent::BodyReceived { block_hash });
        }
        // A body that consensus already asked for re-runs the execution it
        // could not do at the time. Through the same path as the original
        // request, so the resulting BlockImported reaches the engine the same
        // way.
        for block_hash in std::mem::take(&mut self.held_bodies) {
            if self.far_ahead(block_hash) {
                self.held_bodies.push(block_hash);
            } else {
                self.ready_bodies.push(block_hash);
            }
        }
        for block_hash in std::mem::take(&mut self.ready_bodies) {
            self.handle_output(EngineOutput::ExecuteBlock(block_hash), events)
                .await?;
        }
        while let Ok(output) = self.outputs.try_recv() {
            self.handle_output(output, events).await?;
        }
        Ok(())
    }

    async fn handle_output(
        &mut self,
        output: EngineOutput,
        events: &mut Vec<ServiceEvent>,
    ) -> Result<(), ServiceError> {
        // Durability first, and only for the output that announces finality.
        // See the module docs: the Engine API has no way to un-finalise a block.
        if let (EngineOutput::BlockCommitted { view, block_hash, .. }, Some(write)) =
            (&output, self.checkpoint.as_ref())
            && let Err(error) = write(&self.engine)
        {
            warn!(
                target: "n42.h2.node",
                %error, view, ?block_hash,
                "could not persist consensus state; the commit is not being finalised",
            );
            return Ok(());
        }

        // The execution driver sees every output and decides for itself which
        // ones concern it, so this does not have to duplicate that judgement.
        if let EngineOutput::BlockCommitted { view, block_hash, .. } = &output
            && !self.imported.contains(block_hash)
        {
            // The engine commits what the fleet certifies, imported here or
            // not; the execution layer follows only what it has. The pull
            // brings the rest, and the commits after it are for blocks it
            // holds.
            debug!(target: "n42.h2.node", view, ?block_hash, "commit for a block the execution layer has not imported; not finalised here");
            return Ok(());
        }
        // A block the eager import already brought in: the engine asked because
        // the proposal has arrived, and the answer is already known. Asking the
        // execution layer again would be a round trip for a block it holds.
        if let EngineOutput::ExecuteBlock(block_hash) = &output
            && self.imported.contains(block_hash)
        {
            if let Err(err) = self.engine.process_event(ConsensusEvent::BlockImported(*block_hash)) {
                debug!(target: "n42.h2.node", %err, ?block_hash, "engine rejected an import it had already been told of");
            }
            return Ok(());
        }
        if let EngineOutput::ExecuteBlock(block_hash) = &output
            && (self.far_ahead(*block_hash))
        {
            if !self.held_bodies.contains(block_hash) {
                if self.held_bodies.len() >= MAX_HELD_BODIES {
                    self.held_bodies.remove(0);
                }
                self.held_bodies.push(*block_hash);
            }
            debug!(target: "n42.h2.node", ?block_hash, tip = ?self.imported_height, "block runs ahead of the execution layer; held until the pull reaches it");
            return Ok(());
        }
        if let EngineOutput::ExecuteBlock(block_hash) = &output
            && let Some(at) = self.body_arrived.remove(block_hash)
        {
            info!(target: "n42.h2.node", ?block_hash, since_body_ms = at.elapsed().as_millis() as u64, "import starting");
            if self.body_arrived.len() > 256 {
                self.body_arrived.clear();
            }
        }
        let action = self.driver.handle_output(&output).await;
        self.apply_driver_action(action, events)?;

        match output {
            // v4 has no direct-to-validator transport: a vote to the leader goes
            // over the same topic as everything else, and the leader picks it
            // out. Treating these differently would mean inventing a channel
            // gov5 does not have.
            EngineOutput::BroadcastMessage(message)
            | EngineOutput::SendToValidator(_, message) => {
                self.publish(message, events);
            }
            EngineOutput::BlockCommitted {
                view,
                block_hash,
                commit_qc,
                ..
            } => {
                // The status handshake advertises the committed height; a
                // peer deciding whether this node is worth syncing from reads
                // it, and gov5 waits for a peer at or above its own height.
                if let Some(number) = self.block_numbers.get(&block_hash).copied() {
                    self.transport.set_advertised_height(number);
                }
                events.push(ServiceEvent::Committed {
                    view,
                    block_hash,
                    commit_qc: Box::new(commit_qc),
                });
            }
            EngineOutput::ViewChanged { new_view } => {
                events.push(ServiceEvent::ViewChanged { new_view });
            }
            EngineOutput::SyncRequired {
                local_view,
                target_view,
            } => {
                events.push(ServiceEvent::SyncRequired {
                    local_view,
                    target_view,
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Keeps the first view from timing out before the node has anyone to talk
    /// to.
    ///
    /// A timeout vote is only useful if peers receive it. Broadcasting into an
    /// empty mesh burns views: by the time the node meshes it has already voted
    /// to abandon several, and every peer it meets is ahead of it. Once a mesh
    /// peer appears the clock starts for real, from that moment.
    fn hold_view_clock_until_meshed(&mut self) {
        if self.meshed {
            return;
        }
        // A node that reaches quorum by itself has nobody to wait for. Holding
        // the clock for a mesh peer would stop a single-validator chain dead:
        // the one member waits forever for a fleet that is already complete.
        if self.engine.quorum_size() <= 1 {
            self.meshed = true;
            return;
        }
        let view = self.engine.current_view();
        if self.transport.mesh_size() > 0 {
            self.meshed = true;
            self.engine.pacemaker_mut().reset_for_view(view, 0);
            debug!(target: "n42.h2.node", view, "mesh formed; view clock started");
            return;
        }
        self.engine.pacemaker_mut().extend_deadline(MESH_WAIT_STEP);
    }

    /// Starts a build before this node is leader, rather than when it becomes
    /// one.
    ///
    /// Off by default and kept behind a switch because the arithmetic for it
    /// is convincing and the measurement is not: a leader spends ~90 ms of a
    /// ~110 ms path waiting for the execution layer to fill a block, and
    /// starting that build a consensus round earlier should take it off the
    /// critical path. Measured, it took window 1 from 43,426 TPS to about
    /// 11,400 in three consecutive rounds. Something about asking the
    /// execution layer for a payload on a block the fleet has not committed
    /// costs far more than the wait it saves, and until that is understood
    /// this is not a default.
    /// Sends and receives bodies over the plain TCP channel, with the libp2p
    /// push kept for any peer the channel does not reach.
    pub fn with_body_channel(
        mut self,
        rx: mpsc::Receiver<Vec<u8>>,
        pushers: crate::body_channel::BodyPushers,
    ) -> Self {
        self.body_rx = Some(rx);
        self.body_pushers = Some(pushers);
        self
    }

    pub const fn with_build_ahead(mut self, enabled: bool) -> Self {
        self.prepare_ahead = enabled;
        self
    }

    /// Starts the execution layer assembling the block this node will propose
    /// next, while the fleet is still voting on the one it just imported.
    ///
    /// The parent of a leader's block is the block committed in the view
    /// before it, and this node learns that block when it imports it — which
    /// is before the votes are in. If the next view is this node's to lead,
    /// the builder can have the whole rest of the consensus round to fill the
    /// block instead of the node waiting 95 ms for it afterwards.
    ///
    /// Same attributes builder as the proposal itself, so a prepared build is
    /// either exactly the block that gets proposed or is discarded: the driver
    /// keeps the parent and the attributes it started on and refuses to
    /// collect a build that does not match what the proposal asks for.
    /// Acts on the last import, if the next view is this node's to lead.
    async fn flush_prepare(&mut self) {
        let Some(parent) = self.prepare_on.take() else { return };
        if self.prepare_ahead {
            self.prepare_next_build(parent).await;
        }
    }

    async fn prepare_next_build(&mut self, parent: B256) {
        let Some(build_attributes) = self.payload_attributes.as_ref() else {
            return;
        };
        let next = self.engine.current_view().saturating_add(1);
        if !self.engine.is_leader_for_view(next) {
            return;
        }
        let Some(header) = self.block_headers.get(&parent).cloned() else {
            info!(target: "n42.h2.node", ?parent, next, "no build ahead: the parent's header is not remembered");
            return;
        };
        let context = ProposalContext {
            view: next,
            preparing: true,
            head: parent,
            head_timestamp: self.block_timestamps.get(&parent).copied(),
            head_header: Some(header),
            head_seen: self.block_seen.get(&parent).copied(),
        };
        // The builder declines while pacing; that is a "not yet", not a "no",
        // and the proposal will ask again. Nothing to prepare in that case.
        let Some(attrs) = build_attributes(context) else {
            info!(target: "n42.h2.node", ?parent, next, "no build ahead: the attributes builder declined");
            return;
        };
        info!(target: "n42.h2.node", ?parent, next, "build ahead requested");
        if let Err(err) = self.driver.prepare_build_on(parent, attrs).await {
            warn!(target: "n42.h2.node", %err, ?parent, "could not start a build ahead of leading");
        }
    }

    /// Builds and announces a block when this node is the leader of a view it
    /// has not yet proposed for.
    async fn propose_if_leader(&mut self, events: &mut Vec<ServiceEvent>) {
        let Some(build_attributes) = self.payload_attributes.as_ref() else {
            return;
        };
        let view = self.engine.current_view();
        if self.proposed_view == Some(view) || !self.engine.is_current_leader() {
            self.proposal_deferred = false;
            self.defer_reason = None;
            return;
        }
        // The parent is the block the highest QC certifies, not whatever the
        // execution layer imported last: a proposal has to extend its justify
        // QC's block (the fleet refuses one that does not), and a leader that
        // has yet to import that block — it joined after the block went round,
        // or the QC reached it before the body — would otherwise propose a
        // sibling from a stale head. Such a leader asks for the block and
        // proposes once it has it; the genesis QC certifies nothing and leaves
        // the head in charge.
        // Timed from here to the build, because the phase analysis says a
        // leader spends 1,397 ms between committing and publishing a body while
        // building and sealing account for 887 of it. The 510 ms in between is
        // this function, and nothing here looks like 510 ms -- which is exactly
        // why it gets measured rather than reasoned about.
        let decided = std::time::Instant::now();
        let certified = self.engine.locked_qc().block_hash;
        let head = if certified == B256::ZERO { self.driver.head() } else { certified };
        let from_el = !self.block_headers.contains_key(&head);
        let head_header = match self.block_headers.get(&head) {
            Some(header) => Some(header.clone()),
            None => match self.driver.execution_layer().block_by_hash(head).await {
                Ok(Some(block)) => Some(block.header),
                Ok(None) => None,
                Err(err) => {
                    debug!(target: "n42.h2.node", ?head, %err, "execution layer could not serve the head's header");
                    None
                }
            },
        };
        if head != self.driver.head() && head_header.is_none() {
            warn!(target: "n42.h2.node", view, certified = ?head, imported = ?self.driver.head(), "the block our highest QC certifies is not imported; asking for it before proposing");
            if self.awaiting_bodies.insert(head) {
                for peer in self.transport.connected_peer_ids() {
                    self.transport.request_block(peer, head);
                }
            }
            self.proposal_deferred = true;
            self.defer_reason = Some("the QC's block is not imported here");
            return;
        }
        // Marked before the build, not after: a build that fails should not be
        // retried on every subsequent event in the same view, which would pin
        // the loop against a broken execution layer.
        let context = ProposalContext {
            view,
            preparing: false,
            head,
            head_timestamp: self.block_timestamps.get(&head).copied(),
            head_header,
            head_seen: self.block_seen.get(&head).copied(),
        };
        let header_at = decided.elapsed();
        let Some(attrs) = build_attributes(context) else {
            // Declined for now — not marked as proposed, so the next step asks
            // again. This is how a leader paces itself against a clock coarser
            // than its commit latency.
            self.proposal_deferred = true;
            self.defer_reason = Some("the attribute builder declined");
            return;
        };
        let attrs_at = decided.elapsed();
        self.proposal_deferred = false;
        self.defer_reason = None;
        self.proposed_view = Some(view);
        info!(
            target: "n42.h2.node",
            view,
            header_ms = header_at.as_millis() as u64,
            attrs_ms = attrs_at.saturating_sub(header_at).as_millis() as u64,
            from_el,
            "proposal preamble"
        );
        match self.driver.build_block_on(head, attrs, view).await {
            Ok(built) => {
                debug!(target: "n42.h2.node", view, block = ?built.hash, txs = built.tx_count, "built a block to propose");
                self.remember_imported(built.hash);
                // The proposal names the hash; the body has to get there by
                // itself, and before the proposal if the followers are to vote
                // in the first round. Publishing it first is the best order
                // gossip can offer.
                // The header the seal already built, not a second decode of
                // the block to find it again. That decode was a clone and a
                // full RLP walk of the whole payload: 648 ms between finishing
                // a 163,000-transaction block and publishing its body, against
                // 150 ms for the seal that had just constructed the same
                // header.
                if let Some(header) = built.header.clone() {
                    self.remember_block(built.hash, &header);
                } else {
                    match built.execution_data.clone().try_into_block::<alloy_consensus::TxEnvelope>() {
                        Ok(block) => self.remember_block(built.hash, &block.header),
                        Err(err) => debug!(target: "n42.h2.node", %err, "built payload has no header to remember"),
                    }
                }
                self.publish_body(&built.execution_data, built.header.as_ref());
                if let Err(err) = self
                    .engine
                    .process_event(ConsensusEvent::BlockReady(built.hash, None))
                {
                    warn!(target: "n42.h2.node", %err, view, "engine refused our own block");
                }
                // Flush before importing, and import before returning.
                //
                // Before: the flush at the end of the step meant the 80 ms of
                // re-executing our own block sat between the block existing and
                // the fleet hearing about it. Flushing here puts the proposal on
                // the wire first, so the followers spend that 80 ms executing
                // the block rather than waiting for it.
                //
                // It is still awaited rather than deferred to the end of the
                // step, because a step may propose up to MAX_PROPOSALS_PER_STEP
                // times and the next proposal builds on this block: an
                // un-imported parent makes the execution layer answer the next
                // forkchoice with SYNCING.
                // Flush, then start the import without waiting for it.
                //
                // Behind the proposal was the first half; not awaited is the
                // rest. At the 163,000-transaction tier the import is 710 ms,
                // and a loop that awaits it cannot read the votes for the block
                // it has just proposed. The engine will ask for the block to be
                // executed like any other, and that request finds it already in
                // the tree.
                self.flush_outbox(events);
                self.driver.spawn_import_own_block(&built);
            }
            Err(err) => {
                // The view will time out and move on; that is the correct
                // outcome for a leader that cannot produce.
                warn!(target: "n42.h2.node", %err, view, "could not build a block to propose");
            }
        }
    }

    fn apply_driver_action(
        &mut self,
        action: DriverAction,
        events: &mut Vec<ServiceEvent>,
    ) -> Result<(), ServiceError> {
        match action {
            DriverAction::Consensus(event) => {
                // The engine's extends rule reads the parent of an imported
                // block; every block imported here came with its header.
                if let ConsensusEvent::BlockImported(block_hash) = event.as_ref() {
                    self.remember_imported(*block_hash);
                    if let Some(header) = self.block_headers.get(block_hash) {
                        self.engine.remember_parent(*block_hash, header.parent_hash);
                        self.note_imported(header.number);
                    }
                    self.prepare_on = Some(*block_hash);
                }
                if let Err(err) = self.engine.process_event(*event) {
                    debug!(target: "n42.h2.node", %err, "engine rejected an execution event");
                }
            }
            DriverAction::PayloadMissing { block_hash } => {
                // The body may still be in flight on the block topic; ask
                // for it too, as gov5 does, from everyone connected. An
                // answer that arrives after the gossip copy is a duplicate
                // the cache absorbs.
                //
                // Once per interval, though, and not once per pass: see
                // BODY_REQUEST_INTERVAL. The event goes out on the same
                // schedule, because a caller that logs every pass is how the
                // spin was found and a gigabyte of log is not a better signal
                // than one line.
                if self.body_request_due(block_hash) {
                    self.awaiting_bodies.insert(block_hash);
                    for peer in self.transport.connected_peer_ids() {
                        self.transport.request_block(peer, block_hash);
                    }
                    events.push(ServiceEvent::PayloadMissing { block_hash });
                }
            }
            DriverAction::Rejected { block_hash, reason } => {
                // Consensus must not vote for it, and the engine learns that by
                // never receiving a BlockImported for this hash.
                warn!(target: "n42.h2.node", ?block_hash, reason, "execution layer rejected a block");
            }
            DriverAction::Finalized { .. } | DriverAction::Ignored => {}
        }
        Ok(())
    }

    /// Whether this block's body may be asked of the fleet again, recording
    /// the ask if so.
    fn body_request_due(&mut self, block_hash: B256) -> bool {
        let now = std::time::Instant::now();
        if let Some(last) = self.body_requested_at.get(&block_hash)
            && now.duration_since(*last) < BODY_REQUEST_INTERVAL
        {
            return false;
        }
        if self.body_requested_at.insert(block_hash, now).is_none() {
            self.body_requested_order.push_back(block_hash);
            while self.body_requested_order.len() > MAX_BODY_REQUEST_TIMES {
                if let Some(oldest) = self.body_requested_order.pop_front() {
                    self.body_requested_at.remove(&oldest);
                }
            }
        }
        true
    }

    /// Publishes a message, queueing it if the mesh is not ready.
    fn publish(
        &mut self,
        message: n42_h2_primitives::consensus::ConsensusMessage,
        events: &mut Vec<ServiceEvent>,
    ) {
        let view = message.view();
        // The v4 profile is static-validator, so the changes hash is zero
        // throughout. `wire_bridge` refuses a Decide that disagrees with this
        // rather than letting a mismatch onto the wire.
        let envelope = match wire_bridge::to_wire(&message, self.identity, B256::ZERO) {
            Ok(envelope) => envelope,
            Err(err) => {
                // Refusing to send is the right outcome — the alternative is a
                // message peers read differently than we meant it — but it
                // means this node is not participating, so it is not a debug
                // line.
                warn!(target: "n42.h2.node", %err, view, "cannot encode our own consensus message");
                return;
            }
        };

        let result = if self.native_wire {
            // What a Go member does: consensus on the native topic, and the
            // Decide proof additionally on the chain-bound v4 topic, where
            // observers verify finality without joining consensus.
            if matches!(envelope.message, H2Message::Decide(_)) {
                let _ = self.transport.publish(&envelope);
            }
            self.transport.publish_native(&envelope.message)
        } else {
            self.transport.publish(&envelope)
        };
        match result {
            // A duplicate is already on the wire — engines re-broadcast by
            // design, and gov5's message id is a hash of the payload.
            Ok(_) => events.push(ServiceEvent::Published { view }),
            Err(err) if err.is_already_published() => {
                events.push(ServiceEvent::Published { view });
            }
            Err(err) if err.is_transient() => {
                debug!(target: "n42.h2.node", view, "mesh not ready; queueing");
                self.outbox.push(message);
            }
            Err(err) => {
                warn!(target: "n42.h2.node", %err, view, "publish failed");
            }
        }
    }

    /// Starts a catch-up if a peer's status shows it ahead of the execution
    /// layer and none is running.
    async fn consider_catch_up(&mut self, events: &mut Vec<ServiceEvent>) {
        for (peer, height) in std::mem::take(&mut self.pending_status) {
            self.note_peer_height(peer, height);
        }
        if self.catch_up.is_some()
            || self
                .catch_up_retry_after
                .is_some_and(|after| std::time::Instant::now() < after)
        {
            return;
        }
        // The peer known to be highest — another than the one whose pull
        // failed last, when there is another. A peer's height comes from its
        // status at connect and from every block it gossips or serves since,
        // so a node that falls behind later finds a peer to pull from too.
        let failed = self.failed_peer;
        let best = |exclude: Option<PeerId>| {
            self.peer_heights
                .iter()
                .filter(|(peer, _)| Some(**peer) != exclude)
                .max_by_key(|(_, height)| **height)
                .map(|(peer, height)| (*peer, *height))
        };
        let Some((peer, height)) = best(failed).or_else(|| best(None)) else {
            return;
        };
        // The execution layer is asked only when a peer may be past what was
        // last read from it.
        if self.imported_height.is_some_and(|tip| height <= tip) {
            return;
        }
        let latest = match self.driver.execution_layer().latest_block_number().await {
            Ok(Some(latest)) => latest,
            // An execution layer that does not say cannot be caught up.
            Ok(None) => return,
            Err(err) => {
                debug!(target: "n42.h2.node", %err, "could not read the execution layer's height");
                return;
            }
        };
        self.imported_height = Some(latest);
        // Statuses arrive on connect, and a block the fleet gossiped before
        // this node connected never comes by itself — however small the gap.
        if height <= latest {
            return;
        }
        info!(target: "n42.h2.node", %peer, from = latest, to = height, "behind a peer; pulling the gap by range");
        self.catch_up = Some(CatchUp {
            peer,
            next: latest + 1,
            target: height,
            started_at: latest,
            probing: false,
        });
        self.request_next_range();
        events.push(ServiceEvent::Syncing {
            from: latest,
            to: height,
        });
    }

    fn request_next_range(&mut self) {
        let Some(catch_up) = &self.catch_up else {
            return;
        };
        let count = (catch_up.target - catch_up.next + 1).min(MAX_RANGE_BLOCKS);
        self.transport.request_range(
            catch_up.peer,
            RangeRequest {
                start: catch_up.next,
                count,
                step: 1,
            },
        );
    }

    /// Imports the ranges that came back, in order, through the execution
    /// layer, at most [`PULLED_BLOCKS_PER_STEP`] per call — what is left of a
    /// reply waits for the next step; asks for the next range while the
    /// target is not reached.
    async fn import_ranges(&mut self, events: &mut Vec<ServiceEvent>) {
        let mut budget = PULLED_BLOCKS_PER_STEP;
        let mut replies = std::mem::take(&mut self.pending_imports).into_iter();
        while let Some((peer, request, chunks)) = replies.next() {
            let Some(catch_up) = self.catch_up.as_ref() else {
                continue;
            };
            if catch_up.peer != peer || request.start != catch_up.next {
                debug!(target: "n42.h2.node", %peer, ?request, "range reply not part of the catch-up; dropped");
                continue;
            }
            if chunks.is_empty() {
                if catch_up.probing {
                    self.finish_catch_up(events, true);
                } else {
                    warn!(target: "n42.h2.node", %peer, ?request, "peer served none of the range; catch-up stopped");
                    self.finish_catch_up(events, false);
                }
                continue;
            }
            let mut chunks = std::collections::VecDeque::from(chunks);
            while budget > 0 {
                let Some(chunk) = chunks.pop_front() else {
                    break;
                };
                budget -= 1;
                let block = match decode_block_rlp_raw(&chunk.rlp, self.header_profile) {
                    Ok(block) => block,
                    Err(err) => {
                        warn!(target: "n42.h2.node", %peer, %err, "peer served a block this node cannot read; catch-up stopped");
                        self.finish_catch_up(events, false);
                        return;
                    }
                };
                let expected = self.catch_up.as_ref().map(|c| c.next).unwrap_or_default();
                if block.header.number != expected {
                    warn!(target: "n42.h2.node", %peer, got = block.header.number, expected, "peer served blocks out of order; catch-up stopped");
                    self.finish_catch_up(events, false);
                    return;
                }
                let hash = block.block_hash;
                let number = block.header.number;
                self.note_peer_height(peer, number);
                // Gossip may have got there first: bodies held back while
                // the pull was far behind are executed as it closes in, and
                // their commits finalise them. A forkchoice back to a block
                // behind the finalised one is a reorg reth refuses.
                if self.imported.contains(&hash) {
                    if let Some(c) = self.catch_up.as_mut() {
                        c.next += 1;
                    }
                    continue;
                }
                match self.driver.import_pulled(block.execution_data()).await {
                    Ok(_) => {
                        self.remember_imported(hash);
                        self.note_imported(number);
                        self.remember_block(hash, &block.header);
                        self.remember_body(hash, chunk.rlp.to_vec());
                        if let Some(c) = self.catch_up.as_mut() {
                            c.next += 1;
                        }
                    }
                    Err(err) => {
                        warn!(target: "n42.h2.node", %peer, number = block.header.number, %err, "could not import a pulled block; catch-up stopped");
                        self.finish_catch_up(events, false);
                        return;
                    }
                }
            }
            let Some(catch_up) = self.catch_up.as_mut() else {
                continue;
            };
            if !chunks.is_empty() {
                // Out of budget with this reply unfinished: back where it
                // was, under the start the catch-up now expects, ahead of the
                // replies not yet looked at.
                let rest = RangeRequest {
                    start: catch_up.next,
                    count: chunks.len() as u64,
                    step: request.step,
                };
                let mut pending = vec![(peer, rest, Vec::from(chunks))];
                pending.extend(replies);
                self.pending_imports = pending;
                return;
            }
            let window_filled = catch_up.next > catch_up.target;
            if window_filled {
                // The status's target is reached, or a probe window came back
                // full: the fleet kept producing while this pull ran, and a
                // gap of a whole window is not one gossip's future queue
                // closes. Probe on until the peer serves short.
                catch_up.probing = true;
                catch_up.target = catch_up.next + MAX_RANGE_BLOCKS - 1;
                self.request_next_range();
            } else if catch_up.probing {
                // Short of a probe window: that was the peer's head.
                self.finish_catch_up(events, true);
            } else {
                self.request_next_range();
            }
        }
    }

    fn finish_catch_up(&mut self, events: &mut Vec<ServiceEvent>, complete: bool) {
        let Some(catch_up) = self.catch_up.take() else {
            return;
        };
        let height = catch_up.next.saturating_sub(1);
        if height > catch_up.started_at {
            self.transport.set_advertised_height(height);
        }
        self.catch_up_retry_after = Some(std::time::Instant::now() + CATCH_UP_RETRY);
        self.failed_peer = (!complete).then_some(catch_up.peer);
        info!(target: "n42.h2.node", from = catch_up.started_at, height, target = catch_up.target, complete, "catch-up finished");
        events.push(ServiceEvent::Synced { height, complete });
    }

    /// Whether a block, by the header this node holds for it, runs more
    /// than [`FAR_AHEAD_BLOCKS`] past the execution layer's last known
    /// import. Unknown either way is not far.
    fn far_ahead(&self, block_hash: B256) -> bool {
        match (self.block_headers.get(&block_hash), self.imported_tip()) {
            (Some(header), Some(tip)) => header.number > tip + FAR_AHEAD_BLOCKS,
            _ => false,
        }
    }

    /// The execution layer's height, as fresh as this node can know it.
    ///
    /// `imported_height` is set when the `BlockImported` event is drained,
    /// which is one hop behind the driver's own head — and at a threshold of one
    /// there is no slack for that hop: the next block arrives looking two past a
    /// tip that has already moved, and is held. The driver's head advances
    /// synchronously with the import, so its height is the truthful answer when
    /// the header is known; `imported_height` remains the fallback for a head
    /// this node never saw a header for.
    fn imported_tip(&self) -> Option<u64> {
        self.block_headers
            .get(&self.driver.head())
            .map(|header| header.number)
            .or(self.imported_height)
    }


    /// Starts importing a body the moment it arrives, proposal or no proposal.
    ///
    /// The engine asks for a block to be executed when the *proposal* for it
    /// arrives, and a leader publishes the body before the proposal, so on
    /// every follower the body sat in the cache while the proposal crossed the
    /// mesh -- measured on the seven-node fleet as ~240 ms between a body
    /// arriving and its vote leaving that the execution layer's own import did
    /// not account for. A body is self-validating; importing it early risks
    /// nothing but the work, and the vote still waits for the proposal.
    fn import_eagerly(&mut self, block_hash: B256) {
        if let Some(at) = self.body_arrived.get(&block_hash) {
            debug!(target: "n42.h2.node", ?block_hash, waited_ms = at.elapsed().as_millis() as u64, "eager import queued");
        }
        self.awaiting_bodies.remove(&block_hash);
        if !self.imported.contains(&block_hash) && !self.ready_bodies.contains(&block_hash) {
            self.ready_bodies.push(block_hash);
        }
    }

    fn remember_imported(&mut self, block_hash: B256) {
        if self.imported.insert(block_hash) {
            self.imported_order.push_back(block_hash);
            while self.imported_order.len() > MAX_IMPORTED {
                if let Some(oldest) = self.imported_order.pop_front() {
                    self.imported.remove(&oldest);
                }
            }
        }
    }

    fn note_imported(&mut self, number: u64) {
        self.imported_height = Some(self.imported_height.map_or(number, |tip| tip.max(number)));
    }

    fn note_peer_height(&mut self, peer: PeerId, height: u64) {
        let known = self.peer_heights.entry(peer).or_insert(height);
        *known = (*known).max(height);
    }

    fn remember_body(&mut self, block_hash: B256, rlp: Vec<u8>) {
        if self.body_store.insert(block_hash, rlp).is_none() {
            self.body_store_order.push(block_hash);
            while self.body_store_order.len() > REMEMBERED_BODIES {
                let oldest = self.body_store_order.remove(0);
                self.body_store.remove(&oldest);
            }
        }
    }

    fn remember_block(&mut self, block_hash: B256, header: &Header) {
        if self.block_timestamps.insert(block_hash, header.timestamp).is_none() {
            self.block_numbers.insert(block_hash, header.number);
            self.block_headers.insert(block_hash, header.clone());
            self.block_seen.insert(block_hash, std::time::Instant::now());
            self.timestamp_order.push(block_hash);
            while self.timestamp_order.len() > REMEMBERED_TIMESTAMPS {
                let oldest = self.timestamp_order.remove(0);
                self.block_timestamps.remove(&oldest);
                self.block_numbers.remove(&oldest);
                self.block_headers.remove(&oldest);
                self.block_seen.remove(&oldest);
            }
        }
    }

    /// Publishes a block body, queueing it if the mesh is not ready.
    fn publish_body(
        &mut self,
        execution: &alloy_rpc_types_engine::ExecutionData,
        sealed: Option<&alloy_consensus::Header>,
    ) {
        let block_hash = execution.block_hash();
        // Timed in three because the gap between a leader finishing a block and
        // the fleet hearing about it is 418 ms at the 163,000-transaction tier
        // and nothing else is left in it. Encoding walks the whole block into
        // gov5's RLP; compressing walks the result again; and both are on the
        // consensus loop.
        let started = std::time::Instant::now();
        // A node that built this block does not have to take it apart to send
        // it. The payload already carries every transaction as the EIP-2718
        // bytes this encoding wants, and the header came out of sealing, so the
        // general path's decode-and-re-encode -- plus a transaction-root trie
        // rebuilt over the whole block to check our own work -- is 346-401 ms
        // at the 163,000-transaction tier against 9-10 ms to compress the
        // result. The general path stays for blocks this node did not build.
        let own = sealed.map(|header| {
            let rewards = n42_h2_consensus::withdrawals_to_rewards(
                execution.payload.as_v2().map_or(&[][..], |v2| v2.withdrawals.as_slice()),
            );
            // The access list travels with the block or the fleet cannot import
            // it: on an Amsterdam chain a payload without one is refused, and
            // on any chain a block without one is executed serially.
            let bal = match &execution.payload {
                alloy_rpc_types_engine::ExecutionPayload::V4(v4) => Some(v4.block_access_list.clone()),
                _ => None,
            };
            n42_h2_net::encode_block_rlp_raw(
                header,
                &execution.payload.as_v1().transactions,
                &rewards,
                bal.as_ref(),
            )
        });
        let mut pushed_to_all = false;
        let rlp = match own.map(Ok).unwrap_or_else(|| encode_block_rlp(execution, self.header_profile)) {
            Ok(rlp) => rlp,
            Err(err) => {
                // A block nobody else can receive is a block nobody else can
                // vote on: the view is going to time out, and this is why.
                warn!(target: "n42.h2.node", %err, ?block_hash, "cannot encode our own block for the fleet");
                return;
            }
        };
        let encoded = started.elapsed();
        pushed_to_all = self.push_body(&rlp, block_hash);
        let pushed = started.elapsed();
        // Compressed only for the topic: when the push reached every member
        // the topic is not used, and snappy over 19 MB is ~15 ms of the
        // leader's path for nothing.
        let topic = !(pushed_to_all && !self.always_publish_topic);
        let data = if topic {
            match compress_block_rlp(&rlp) {
                Ok(data) => Some(data),
                Err(err) => {
                    warn!(target: "n42.h2.node", %err, ?block_hash, "cannot compress our own block");
                    None
                }
            }
        } else {
            None
        };
        if rlp.len() > 1_000_000 {
            info!(
                target: "n42.h2.node",
                ?block_hash,
                bytes = rlp.len(),
                wire = data.as_ref().map_or(0, Vec::len),
                encode_ms = encoded.as_millis() as u64,
                push_ms = pushed.saturating_sub(encoded).as_millis() as u64,
                compress_ms = started.elapsed().saturating_sub(pushed).as_millis() as u64,
                "block body prepared"
            );
        }
        self.remember_body(block_hash, rlp);
        let Some(data) = data else {
            if topic {
                return;
            }
            self.remember_topic_skipped(block_hash);
            return;
        };
        // The topic, unless the direct push already reached every member.
        //
        // Both used to go out for every block. On a static full mesh the
        // topic then delivers each body a second time to each member, and
        // every member forwards the 15 MB message on to its mesh peers -- six
        // more copies per node per block, read and written on the consensus
        // loop, because the swarm is polled from it. Measured on the follower
        // as ~210 ms in the transport drain for one event, the body, before
        // its import could start. A member that was not pushed to (a gov5
        // node, or a peer not yet connected) still gets the topic, and any
        // member can fetch by hash.
        self.send_body(data, block_hash);
    }

    fn remember_topic_skipped(&mut self, block_hash: B256) {
        debug!(target: "n42.h2.node", ?block_hash, "body pushed to every member; topic not used");
    }

    /// Hands the body straight to every connected member, alongside the topic.
    ///
    /// The mesh is the fallback rather than the other way round: a push reaches
    /// a member in one hop, and the topic reaches the ones this node is not
    /// connected to and every gov5 member, which does not speak the protocol.
    /// A body that arrives twice costs one decode and is then recognised as
    /// held.
    /// Pushes the body straight to every connected member. Returns whether
    /// that reached the whole mesh, so the caller can skip the topic.
    ///
    /// The TCP channel first: if every one of its peers took the body, the
    /// libp2p push is not used either. Otherwise the libp2p push covers
    /// everyone, at the cost of a duplicate to the peers the channel reached,
    /// which the receiver's body store absorbs.
    fn push_body(&mut self, rlp: &[u8], block_hash: B256) -> bool {
        if !self.direct_push {
            return false;
        }
        if let Some(pushers) = &self.body_pushers
            && !pushers.is_empty()
        {
            let taken = pushers.push(std::sync::Arc::new(rlp.to_vec()));
            debug!(target: "n42.h2.node", ?block_hash, taken, peers = pushers.len(), "offered the body to the channel");
            if taken == pushers.len() {
                return true;
            }
        }
        let peers = self.transport.connected_peer_ids().len();
        let sent = self.transport.push_block_to_all(rlp);
        debug!(target: "n42.h2.node", ?block_hash, peers = sent, "pushed the body to the fleet");
        sent > 0 && sent == peers
    }

    /// A body that came over the TCP channel: the same decode and the same
    /// bookkeeping as a pushed one, identified by what it decodes to.
    fn handle_direct_body(&mut self, rlp: Vec<u8>) {
        let started = std::time::Instant::now();
        match decode_block_rlp_raw(&rlp, self.header_profile) {
            Ok(block) => {
                let hash = block.block_hash;
                if !self.body_store.contains_key(&hash) {
                    let txs = block.transactions.len();
                    self.remember_block(hash, &block.header);
                    self.driver.cache_payload(hash, block.execution_data());
                    self.remember_body(hash, rlp);
                    self.import_eagerly(hash);
                    self.body_arrived.insert(hash, std::time::Instant::now());
                    self.received_bodies.push(hash);
                    info!(target: "n42.h2.node", block_hash = ?hash, txs, decode_ms = started.elapsed().as_millis() as u64, "block body received");
                }
            }
            Err(err) => {
                debug!(target: "n42.h2.node", %err, "a body from the channel could not be read");
            }
        }
    }

    fn send_body(&mut self, data: Vec<u8>, block_hash: B256) {
        // Queue before publishing when there is no mesh, rather than cloning
        // the body so the failure path can have a copy. A full block's body is
        // megabytes -- the largest object this node handles -- and it was being
        // copied on every publish to serve a branch that only runs while the
        // mesh is still forming.
        if self.transport.mesh_size() == 0 {
            debug!(target: "n42.h2.node", ?block_hash, "mesh not ready; queueing block body");
            self.body_outbox.push(data);
            return;
        }
        let bytes = data.len();
        match self.transport.publish_block(data) {
            // Timestamped on both sides so the fleet's block-body latency is a
            // measurement rather than a residual: at the 480M tier the cycle has
            // ~173 ms in it that the leader's build, the followers' import and
            // the quorum do not account for, and encoding and compressing the
            // body is only 4 ms of that (`examples/gossip_cost`).
            Ok(_) => info!(target: "n42.h2.node", ?block_hash, bytes, "published block body"),
            Err(err) if err.is_already_published() => {}
            // A publish that fails with a mesh present is not fatal and is not
            // worth another copy of the body: peers that miss it ask for it by
            // hash, which is the path that already carries every block a
            // follower joins late for.
            Err(err) => {
                warn!(target: "n42.h2.node", %err, ?block_hash, "block body publish failed; peers will have to fetch it");
            }
        }
    }

    /// Retries queued messages once the mesh exists.
    ///
    /// Only worth attempting when there is somewhere to send: retrying into an
    /// empty mesh just re-queues everything and burns the loop.
    fn flush_outbox(&mut self, events: &mut Vec<ServiceEvent>) {
        if self.transport.mesh_size() == 0 {
            return;
        }
        for data in std::mem::take(&mut self.body_outbox) {
            self.send_body(data, B256::ZERO);
        }
        for message in std::mem::take(&mut self.outbox) {
            self.publish(message, events);
        }
    }

    /// How long the current view has left before the pacemaker fires.
    pub fn time_to_timeout(&self) -> Duration {
        self.engine.pacemaker().remaining()
    }
}

/// The blocks of a range an execution layer can produce, from the start
/// until the first it does not have.
async fn serve_range<E: ExecutionLayer>(el: &E, request: n42_h2_net::RangeRequest) -> Vec<Vec<u8>> {
    let count = request.count.min(MAX_RANGE_BLOCKS);
    let mut rlps = Vec::new();
    for number in request.start..request.start.saturating_add(count) {
        match el.block_by_number(number).await {
            Ok(Some(block)) => {
                rlps.push(encode_block_rlp_parts(
                    &block.header,
                    &block.transactions,
                    &withdrawals_to_rewards(block.withdrawals.as_deref().unwrap_or(&[])),
                ));
            }
            Ok(None) => break,
            Err(err) => {
                debug!(target: "n42.h2.node", number, %err, "execution layer could not serve a block");
                break;
            }
        }
    }
    rlps
}
