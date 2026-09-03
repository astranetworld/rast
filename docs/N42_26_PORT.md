# N42-26 → n42-rs port, and gov5 interop status

Status as of 2026-08-24. Companion to `docs/RETH_UPGRADE_GUIDE.md`.

## Why this document exists

Three N42 clients are in play on this host:

| Repo | Language | Base | Consensus | State commitment |
|---|---|---|---|---|
| `n42-rs` (this repo) | Rust | reth **v1.11.0** (edition 2021, rustc 1.86) | APoS / Clique | Ethereum MPT |
| `../N42-26` | Rust | reth **2.4.1** (edition 2024, rustc 1.97, local `../reth` path dep) | HotStuff-2 | QMDB twig-forest + JMT |
| `../N42-gov5` | Go | go-ethereum 1.17.4 / Erigon-derived | HotStuff-2 (+ APoS, APoA) | pluggable: MPT / JMT / **QMDB** / Verkle / LtHash |

gov5 runs the production `mainnet_qmdb_staggered` 7-node fleet (chainId 94,
`stateScheme: qmdb`). N42-26 is the Rust client already built against that
fleet's contracts. This repo is the older Rust client; this document tracks what
of N42-26's interop surface now exists here, and what does not.

## What was ported

Eight new crates under `crates/n42/`, all additive — nothing in the existing
APoS node wiring was touched. **199 tests pass**, including every pinned gov5
cross-client vector. The lockfile gained 68 packages (libp2p's tree) and lost
none: no existing package version was replaced, so the reth v1.11.0 build graph
resolves exactly as before.

Test count by crate: bmt-core 7, twig-core 38, h2-primitives 48, h2-wire 9,
h2-consensus 217, mobile-verify 61, h2-net 35, h2-execution 9, h2-node 3,
h2-el-rpc 15, mobile-service 26, qmdb-state 17, qmdb-reth 14, h2-node persistence 8 —
**507 total**, plus the QMDB end-to-end test in `n42-testing`.

The stack has been run end to end against a live execution layer; see
**First live block** below.

| Crate | From N42-26 | Lines | Tests | What it gives this repo |
|---|---|---|---|---|
| `n42-bmt-core` | `n42-bmt-core` | 898 | 7 | Sparse binary Merkle tree (Blake3). Zero deps beyond blake3/serde/thiserror. |
| `n42-twig-core` | `n42-twig-core` | 4,092 | 38 | QMDB twig engine + `qmdb_compat`: gov5 key derivation, account-value encoding, proof codec, and the **portable-snapshot verifier**. |
| `n42-h2-primitives` | `n42-primitives` | 1,846 | 48 | BLS12-381 keys/aggregation/batch-verify and the HotStuff-2 message types, including the chain-bound v4 signing domains. |
| `n42-h2-wire` | `n42-network/src/h2_{wire,v4}.rs` | 1,200 | 9 | The Go↔Rust wire contract: legacy H2 codec + v4 envelope, all five documented rejection paths. Carries no networking stack. |
| `n42-h2-consensus` | `n42-consensus` (all but `adapter.rs`) + `n42-consensus-service/h2_finality.rs` | 12,599 | 209 | The HotStuff-2 protocol core — state machine, proposal, voting, quorum assembly, pacemaker, view change, timeout certificates — plus validator set, epoch management, leader selection, rotor, vote log, and `VerifyH2V4Decide`. Enough to *participate*, not only observe. |
| `n42-mobile-verify` | `n42-mobile` (format half) | 2,363 | 61 | Verification receipts, BLS attestation aggregation, twig/SBMT state proofs, hot-contract code cache. |
| `n42-h2-net` | new, modelled on `n42-network` | 2,266 | 35 | gov5-compatible GossipSub transport: topic strings, router parameters, gov5's message-ID function, the `/rpc/status/1/ssz_snappy` handshake. `H2V4Transport` is the bidirectional mesh member (subscribe, decode, **publish**); `H2V4Observer` is the read-only use of it, turning wire bytes into verified finality. Ships a runnable `h2_observer` example. |
| `n42-qmdb-reth` | new | 900 | 14 | Installs the QMDB root into reth: genesis header rewrite, bundle→leaves, the shared persisted forest, and the `StateRootStrategy` for validation. |
| `n42-qmdb-state` | new | 850 | 17 | The QMDB state commitment: a block's state root and the proofs cut from it. On a QMDB chain this *is* the header's state root — see **QMDB is the header's state root** below. |
| `n42-mobile-service` | new, in the spirit of `n42-mobile` | 900 | 19 | The node's half of mobile verification: serves each commit as the `Decide` a fleet member would verify, and aggregates the receipts phones send back into a BLS attestation. `mobile_*` JSON-RPC over a minimal HTTP front end. |
| `n42-h2-el-rpc` | new, in the spirit of `n42-el-rpc` | 730 | 15 | An `ExecutionLayer` over the published Engine API (authenticated JSON-RPC), so one adapter drives reth, this repo's node, and gov5's `eth-el` — with no reth dependency on the consensus side. Transport is a trait, so the version mapping and error handling are tested against a recorded transport rather than a live node. |
| `n42-h2-node` | new | 490 | 3 | The service loop that makes the other three a fleet member: transport events become consensus events, engine outputs become published envelopes and execution calls, execution answers come back as consensus events. A four-node integration test commits a block over a real gossip mesh. |
| `n42-h2-execution` | seam from `n42-consensus-service/src/el.rs`; driver is new | 920 | 9 | The execution-layer seam (`ExecutionLayer`, Engine API in alloy types only) and the driver that services consensus's requests against it, plus an in-memory EL for testing the loop. |

### Renames

`n42-primitives` in N42-26 collides with this repo's existing `n42-primitives`
(beacon-chain primitives, `crates/n42/primitives`). The port is therefore
`n42-h2-primitives`, and imports were rewritten `n42_primitives::` →
`n42_h2_primitives::`. Likewise `n42-mobile` → `n42-mobile-verify` to sit
alongside the existing `mobile-sdk` crate, which does something different
(validator key/deposit/exit tooling).

`n42-h2-consensus` defines its own minimal `ValidatorInfo` (address, BLS pubkey,
optional peer id) rather than pulling N42-26's `n42-chainspec`, which would drag
in reth-chainspec **and** libp2p for three fields. The serde field names match
gov5 genesis `validators` entries, so chainspec JSON deserializes unchanged.

### Edition-2021 adaptations

N42-26 is edition 2024; this repo is edition 2021. Two mechanical fixes were
needed, both marked in-place:

- `n42-mobile-verify/src/verification.rs` — one let-chain (`&& let Some(..)`)
  rewritten as a nested `if let`. Same semantics.
- `n42-twig-core` tests — `rand` 0.9 here vs 0.10 there: `rand::RngExt` →
  `rand::Rng`, plus an explicit `RngCore` import for `fill_bytes`.
- The protocol core carried **11 more let-chains**, each rewritten in place and
  marked `// edition-2021: N42-26 writes this as a let-chain`. Nine had no
  `else` and became nested `if let`. Two could not: the `changes_hash` binding
  in `proposal.rs` has an `else`, so the guard moved into `Option::filter`
  inside the same expression; and the import-gated vote in `proposal.rs`
  resolves the pending view up front, which also ends the borrow of `self`
  before `send_vote`.

Everything else compiled unchanged, which is the useful signal: these modules
were written free of both the reth version and the edition.

## What was deliberately NOT ported

| Not ported | Why |
|---|---|
| `n42-consensus/adapter.rs` | The only meaningfully reth-coupled file in that crate (14 refs: `FullConsensus`, `EthBeaconConsensus`, `RecoveredBlock`, `BlockExecutionResult`). Those APIs differ between reth 1.11 and 2.4.1. Porting it means either the reth upgrade or a rewrite against 1.11. |
| `n42-consensus/{receipt,extra_data}.rs` | 175 lines. `receipt.rs` needs `alloy_consensus::EthereumReceipt` (an alloy 2.x name; this repo is on alloy 1.6), and `extra_data.rs` returns `reth_consensus::ConsensusError`. Both are execution-side glue, not protocol. |
| `n42-consensus-service` (orchestrator, ingest, persistence, EL port) | Binds consensus to the reth 2.4.1 node/engine. This is where the version wall actually is. |
| `n42-mobile/verifier.rs`, `packet.rs`, `quic_client.rs` | Re-execution verifier (reth-revm), and the QUIC transport. Format was the goal, not transport. |
| `n42-jmt` | Depends on `n42-execution` (reth-coupled) and `reth-libmdbx`. The twig/BMT engines underneath it are ported; the storage-backed tree is not. |

## Interop contract — fixture integrity

The four gov5 fixtures are byte-exact contracts. Verified on 2026-08-24 that the
copies vendored here match gov5 `main` **and** the SHAs pinned in
`../N42-gov5/docs/H2_V4_RUST_SYNC_BRIEF.md`:

```
0c5877432b8d7adb3fc60c5226564ad1d0e099b6c73f39b823703926e82d2aee  cross_client_h2_v1.json
f3f20d4641455eaf7ea6c96641fc4674134080aefcb300c219ab34a53d4d9510  h2_v4_domains_v1.json
09a98f549fcfa1b4185b78b975fa680608c73e169758cb0c052c72efbff4ff83  h2_v4_envelope_v1.json
feacd6d0d2dc3babcbe3440384021ee9291b68103baaf7d47cd0ff1c6b703488  h2_v4_finality_v1.json
```

Locations here: `crates/n42/h2-wire/testdata/` (first three),
`crates/n42/h2-consensus/testdata/` (finality), plus
`crates/n42/twig-core/testdata/cross_client_v1.json` for the QMDB vectors.

**Compare by SHA-256 of raw bytes, never text-mode content.** gov5 learned this
the hard way: a Windows checkout with `core.autocrlf=true` rewrote these files
to CRLF and produced phantom drift. gov5 pins `testdata/*.json -text` in
`.gitattributes`; do the same here if this repo is ever checked out on Windows.

Against the brief's action list for the Rust side:

- [x] 1. Verify fixture SHAs
- [x] 2. v4 domains, all eight message phases — `h2_v4::tests::matches_gov5_domains_and_binds_chain_identity`
- [x] 3. v4 envelope codec + five rejection paths — `h2_v4::tests::envelope_decoding_rejects_all_five_documented_paths`
- [x] 4. Consume finality proofs — `h2_finality::tests::verifies_gov5_finality_fixture_and_binds_domain`
- [x] 5. Transport for the observer path — `n42-h2-net`. A two-node gossip
  loopback test (`tests/gossip_loopback.rs`) publishes a fixture Decide over a
  real socket through a gov5-parameterised mesh and verifies it on the other
  side. **Partially attached to a real Go node — see below.**
- [x] 7. Publish path — `H2V4Transport::publish`. `tests/transport_publish.rs`
  sends a fixture Decide from one transport and verifies it as finality at a
  peer that did not send it, which is the direction an observer never exercises:
  without it a Rust validator can vote into the void and look healthy doing it.
  Chain-identity mismatch is refused before the wire, and an empty mesh is
  reported as transient so a node that starts before its fleet retries instead
  of giving up.
- [x] 8. Participate, not just follow — `n42-h2-node`. `tests/four_node_fleet.rs`
  runs four `H2Service`s over TCP with gov5's router parameters and envelope
  format and commits a block. Three things had to be fixed to get there, all of
  which would have bitten a real deployment:
  - **Genesis QC encoding.** `validate_bitmap` rejects an embedded signer count
    of zero, so a genesis QC crosses the wire with an *empty* bitmap while the
    rest of this crate spells it `[0, 0]`. Emitting `[0, 0]` made every first
    proposal unpublishable, reported as "non-canonical bitmap" three layers from
    the cause.
  - **Startup timeouts.** A node whose view clock starts before its mesh does
    spends its first views broadcasting timeouts to nobody and arrives already
    behind. `H2Service` holds the first view's clock until a mesh peer exists.
  - **Duplicate publishes are success.** gov5's message id is a hash of the
    payload and engines re-broadcast by design, so gossipsub's `Duplicate` means
    the fleet already has the message.
- [x] 9. Drive a real execution layer — `n42-h2-el-rpc`. Two things about the
  Engine API are easy to get wrong and silent when wrong, so both are pinned by
  tests:
  - **A Prague block is a V3 payload sent to `newPayloadV4`.** Reading the method
    version off the payload struct sends it to V3, which is rejected for a
    missing parameter — an error that reads like a payload problem.
  - **`getPayload` never echoes `parentBeaconBlockRoot`**, but re-importing the
    built block needs it. The client remembers it per build, from the
    `forkchoiceUpdated` that started it. Without that, a block is accepted
    locally and rejected by every peer one hop later.

  Amsterdam (`newPayloadV5`) is refused rather than guessed at: there is no
  execution client here to check the mapping against, and a wrong guess would
  first fail at the fork on a live chain.

  `cargo run -p n42-h2-node --example h2_validator -- --help` assembles the whole
  stack against a running execution client.
- [x] 10. Produce a block on a live chain. See **First live block**.
- [x] 11. Serve mobile verifiers — `n42-mobile-service`. What a phone gets is the
  committed `Decide` in gov5's v4 wire format, so it checks the commit QC itself
  rather than trusting the node; what it sends back is a signed receipt, which
  the node aggregates.

  Every receipt's signature is verified at the boundary, and that is not a
  formality: neither `ReceiptAggregator` nor `AttestationBuilder` checks one, and
  BLS aggregation is all-or-nothing — a single forged signature reaching the
  aggregate voids the block's attestation for every honest phone that took part.
  Unregistered verifiers and unknown blocks are refused for the same reason, the
  latter also being how a stranger would otherwise fill the node's memory.

  Verified live: `--mobile 127.0.0.1:19545` on `h2_validator`, curl standing in
  for a phone, against a node committing real blocks. The served envelope
  decodes as `N42H2V4`, chain 1143, the running chain's genesis hash, zero
  changes hash — 287 bytes a phone verifies on its own.

  Still not covered: **state proofs**. Serving one means holding the QMDB twig
  forest it is cut from, and this node keeps state in reth's MDBX. The verifier
  side (`mobile-verify::state_proof`) and the engine (`n42-twig-core`) are both
  ready; the node maintaining that state is not.
- [x] 12. State proofs — `mobile_getProof`, served from the same tree the state
  root comes from. A phone verifies the `Decide`'s signatures, those commit to a
  state root, and the proof checks against that root: nothing in the chain is
  the server's word. A proof cut from a different tree does not verify, which is
  what makes the rest worth anything.
- [x] 13. Consensus state across restarts — `h2-node::persistence`. See
  **Restarting a validator** below.
- [x] 14. QMDB in block production and validation — `n42-qmdb-reth`. See
  **Wired into block production and validation** below.
- [ ] 6. (Standing constraint) do not configure epoch validator changes on a v4 chain.

## QMDB is the header's state root

Confirmed against gov5 before building anything: `QMDBRootComputer` implements
`state.RootComputer`, `IntraBlockState.IntermediateRoot()` delegates to it when
one is installed, and `cmd/n42-state-verify` checks membership proofs against
`header.Root`. So on a QMDB chain the header's state root is the twig-forest
root, not an MPT root — a node computing the latter produces headers such a
fleet rejects, and "generate a correct header" and "serve a state proof" are the
same problem.

`n42-qmdb-state` is the Rust side of that computer. Three properties come
straight from gov5's implementation, each a fork if wrong:

- **The root depends on write order.** QMDB is append-only and every set
  consumes a slot, so gov5 sorts a block's operations by key hash before
  applying any (Go map iteration is randomized — applying dirty maps directly is
  not reproducible even on one machine). Hence `apply_block` takes a whole block.
- **An emptied account and a zeroed slot delete their leaf**, rather than
  writing one that encodes nothing.
- **A reorg cannot be handled by re-applying state.** In gov5's own words,
  executing a competing block on an un-reverted tree "appends at shifted slots
  and forks the root permanently vs nodes that only ever applied the winner" —
  even when the resulting state is correct. `revert_to` restores the tree.

### Wired into block production and validation — `n42-qmdb-reth`

A chain opts in the way gov5 does, with `"stateScheme": "qmdb"` in the genesis
config; a genesis without it is a Merkle-Patricia chain and nothing here runs.
The eth-el branch is MPT for exactly that reason. On a QMDB chain:

- **Genesis.** `N42ChainSpecParser` rebuilds the genesis header with the forest
  root of the alloc, as gov5's `genesis_qmdb.go` does. This changes the genesis
  hash — it must, since that is the hash a gov5 node on the same chain has.
  reth's `init_genesis` still populates its trie tables from the alloc but does
  not compare the result to the header, so the two coexist.
- **Building.** `N42PayloadBuilder` hands reth's block builder a zero root so it
  skips the MPT computation, turns the bundle execution left behind into leaves
  (`changes_from_bundle`), asks the forest for the root, and seals it into the
  header. The tree is filed under the block hash once that hash exists.
- **Validating.** `QmdbStateRootStrategy` is installed through
  `BasicEngineValidator::with_state_root_strategy` — reth's public seam, no
  fork. After execution it computes the same root from the same kind of bundle
  and reth compares it to the header. A block whose header disagrees gets no
  tree, so nothing can build on state consensus never accepted.
- **One forest.** `QmdbNodeState` is shared by the builder, the validator, and
  the mobile endpoint, keyed by block hash so sibling proposals at one height
  are each computed against their parent. It is persisted on every canonical
  head move and restored at startup; a snapshot that is missing or behind the
  database is refused, because a QMDB tree cannot be rebuilt from reth's state
  tables (they do not keep the append history).

**Which leaves a block writes** is gov5's dirty set, not a diff: every account a
transaction touched is written whether or not a field changed, because an
unchanged leaf still consumes a slot and still moves the root. revm's bundle
holds exactly the touched set, and its storage exactly the slots whose value
changed, which is what Erigon's `dirtyStorage` holds — so the mapping is direct.
This is the one place cross-client agreement rests on an argument rather than a
fixture; a replay of the same block on both clients is the test that closes it.

Verified live on a fresh QMDB devnet: genesis hash differs from the MPT one for
the same alloc; the forest is seeded from the alloc; a validator produced blocks
that the node's own engine validated through the strategy (13 of 13, zero
mismatches at debug level); two restarts restored the forest at the head and the
chain continued, 0 → 12 → 24 → 37, with no rejected forkchoices. In the harness
(`test_qmdb_chain__headers_carry_the_forest_root_and_validate`) a block carrying
a transfer moves the root and empty blocks leave it alone.

Three constraints, none of which this code can remove:

- **No pipeline sync.** Only the engine tree consults a strategy. Backfill
  computes MPT roots in its own stage and would reject every QMDB header. A QMDB
  node syncs by replaying blocks through the engine, or from a forest snapshot.
- **reth's trie is stale from block 1.** The outcome reports no trie updates, so
  `eth_getProof` and anything reading the stored MPT is wrong on a QMDB chain.
  Proofs come from the forest (`mobile_getProof`).
- ~~One tree copy per block.~~ Resolved: `n42-twig-core` now has gov5's undo
  records (`BlockUndo`, `apply_undo`) and the forest moves one shared tree
  between held blocks — revert to the common ancestor, re-apply down — instead
  of copying it. See **Undo records** below.

## The devnet genesis, and gov5's genesis hash reproduced

`crates/chainspec/res/genesis/n42_devnet.json` is now the native chain's devnet,
shaped after gov5's own presets — `qs_epoch_test`, which gov5 calls "the
reference for new HotStuff chains", and `h2_interop_test`, the chain built for
Rust↔Go interop:

- `"stateScheme": "qmdb"`, `"consensus": "hotstuff"`, and a `hotstuff` block
  (`period` 3, `baseTimeout` 6000, `maxTimeout` 30000, `epochLength` out of
  reach, `interopV4: true`) with four dev validators whose BLS keys derive from
  a public seed (`n42_devnet_validators.json`; `h2_keygen --seed`). Addresses
  are the first four anvil accounts.
- Every Ethereum fork through Osaka at genesis, written both ways — `*Block: 0`
  for gov5, `*Time: 0` for alloy — so one file loads in both clients. gov5's
  N42-only precompile forks (`pqPrecompilesTime` and friends) are left off: reth
  does not have them, and a mixed fleet must not diverge on a precompile call.
  `mobileAnchorTime` is off for the same reason — it adds a header field.
- `difficulty` 0 from genesis (BFT is post-merge from block 0, as
  `qs_epoch_test` notes), the Prague system contracts in the alloc with gov5's
  exact bytecode, 1 gwei base fee, 30M gas.

Both `--chain <path>` and the `N42_DEVNET` constant build the same genesis header:
`make_chain_spec` now trusts a genesis that declares its own fork schedule, and
`From<Genesis>` applies the QMDB root through `reth_chainspec::qmdb`.

**gov5's `mainnet_qmdb` genesis hash reproduces exactly.** Its 2,322-account
alloc, converted from gov5's base64 form, with `mainnetQMDBGenesisBlock()`'s
parameters (timestamp 1678174066, difficulty 131072, gas limit 4712388) and
the `mainnet_qmdb.json` schedule, gives `0x5fcf94b7…` — the value pinned as
`params.MainnetQMDBGenesisHash`. That is the whole genesis pipeline agreeing
with Go byte for byte: leaf encoding, sorted append, root, and the header
fields reth derives from the schedule (`tests/gov5_genesis.rs`).

`h2_validator --chain <genesis.json>` takes chain id, genesis hash, validator
set (in QC bitmap order), timeouts and block period from that file's `hotstuff`
block, so a Rust member and a Go member of one chain cannot disagree about the
fleet.

**Still open for mixed fleets:** this node's payload builder seals every block
with the APoS signature in `extraData`, so a produced header carries more than
the 32 bytes Ethereum permits. gov5 ignores the seal on a HotStuff chain, but
if it enforces the size limit it will reject those blocks. The genesis carries
the APoS-shaped `extraData` on purpose so this node keeps sealing; freeing the
builder from APoS on a HotStuff chain is the next step.

## Undo records

`n42-twig-core` now carries gov5's `BlockUndo`: the append cursor before the
block, every slot the block deactivated with what it held, and the keys it
appended. `apply_undo` truncates the appends (index, bits, leaves, cursor,
spilled twigs) and revives the deactivations, and afterwards the tree is
byte-identical to one that never saw the block — the test checks the whole
snapshot, not only the root, and that a sibling re-applied afterwards matches a
node that only ever applied it. Nothing is mutated until every check passes.

`QmdbForest` uses them the way gov5's `RevertBlock` does: one tree, moved
between held blocks by reverting to the common ancestor and re-applying down.
Re-application must land on the recorded root, and a disagreement is refused
rather than filed. A producer's computed-but-unfiled block stays applied as
pending work and is adopted on `insert` when the hash arrives, or reverted by
whatever moves the tree next. Cost per block is now the block's own operations,
not the size of the state.

## Restarting a validator

The vote log is a safety requirement, not a convenience: a node that restarts
without it re-votes in views it already signed, which is equivocation and
indistinguishable from deliberate double-signing. It is written before the
signature and fsynced, and an fsync failure aborts the vote.

Recovery takes the *more conservative* of the log and the checkpoint. Measured on
a live node, the checkpoint said `last_voted 13` while the vote log said 15 —
the crash landed between signing and checkpointing, and recovering from the
checkpoint alone would have re-voted in 14 and 15.

Two ordering constraints, both found by restarting a live node:

- **Durability comes before finality.** A commit tells the execution layer a
  block is finalized, and the Engine API has no way to take that back. Announcing
  it and then dying before the checkpoint reaches disk leaves the node believing
  less than its execution layer does, and every later forkchoice is refused as a
  reorg past the finalized block (`-38006`). The checkpoint is therefore written
  inside the service, before the commit reaches the driver, and a checkpoint
  that fails stops the commit.
- **The execution head has to be recovered too.** Resuming consensus at view N
  while pointing the driver at genesis sends a forkchoice thousands of blocks
  back. The last committed QC names the block that was head.

Verified: three consecutive restarts, the chain growing across all of them, no
rejected forkchoices.

## The block body channel

The four-validator devnet, once the Engine API round-trip was right, reached
exactly zero commits. Every follower logged `NO BODY for 0x…; cannot vote on
it`: a HotStuff-2 proposal carries only the block hash, the import-gated vote
waits for `BlockImported`, and nothing was delivering the body. The leader had
it; nobody else could.

gov5 delivers bodies on a second gossip topic, and this node now does the same:

- **Topic** `/n42/<fork digest>/block/ssz_snappy`, the fork digest being the
  first four bytes of the genesis hash — so a body from another chain is not
  even subscribed to.
- **Payload** raw-snappy RLP of `[header, transactions, verifiers, rewards]`
  (`internal/p2p/broadcaster.go` `BroadcastBlock`; the verifier and reward
  lists are consumed structurally and never trusted). Same message id rule as
  the consensus topic. N42-26's `gov5_block.rs` codec is ported into
  `n42-h2-net` as `block_gossip`.
- **Ordering.** The leader publishes the body *before* handing the hash to
  the engine, so the body has the best chance of preceding the proposal.
  When it does not — one `NO BODY` per hour of running, in practice — the
  service remembers the hash as awaited and re-runs the execution the moment
  the body arrives, rather than waiting for a proposal that will never repeat.
- **Trust.** Nothing in a received body is taken on faith beyond its own
  consistency: the header hashes to the block hash and the transactions to
  the header's root. Validity is the execution layer's verdict; identity is
  consensus's — both check the same hash. Requests are carried by hash only
  (gov5's form does not list them); a block with the empty requests hash gets
  the empty list, which every `newPayload` version accepts.

**The header-profile switch.** gov5's live H2 headers have a shape an Engine
API payload cannot express — zero ommers hash, difficulty 0, extra data
`N42H || view (u64 LE) || seal` — so decoding one means reconstructing it and
letting the hash pick the variant. This node's own blocks do not have that
shape yet: the builder seals them the Ethereum way (empty-list ommers hash,
APoS extra data). `HeaderProfile::Ethereum` gossips those exactly as the
payload says; `HeaderProfile::Gov5H2` is the reconstruction. The wire format is
gov5's either way. **A fleet mixing Go and Rust members needs the builder to
emit gov5's profile** (and reth's header validation to accept it, which N42-26
does through a consensus adapter); that is the one remaining piece between
this node and a Go-led fleet, and it is not in this change.

Measured on the four-validator devnet (`run-devnet.sh`: one QMDB `n42` node,
four `h2_validator --chain n42_devnet.json --propose`): 21 blocks in 60s on a
3s period, every view committed, 0 timeouts, 0 execution-layer warnings, 21
QMDB state roots. Killing validator 1 and restarting it with its data
directory: `resuming at view 29 (last voted 28)`, 11 commits in the next 30s
including 3 blocks it built as leader, and the other three never timed out.
The harness test `followers_commit_only_after_bodies_arrive_over_the_block_topic`
pins the property with one proposer: a follower that commits has necessarily
received the body over gossip. (The older four-proposer test could not show
this — the mock built the same block for everyone, which is also why the gap
went unnoticed.)

## First live block

A single-validator fleet (`n = 1`, `f = 0`, quorum 1) run against a real `n42`
node over the Engine API, on a Cancun-enabled devnet genesis. Consensus
committed views 1, 3, 5, … and the execution layer's chain grew to block 13 with
the hashes the commits named. Three things only showed up here:

- **`jwt` is not a working feature by itself.** `alloy-rpc-types-engine`'s bare
  `jwt` pulls in `jsonwebtoken` without selecting a crypto provider: it compiles
  and then panics on the first token signed. Depend on `jwt-aws-lc-rs`, which is
  what reth's own `node-core` requests.
- **The leader must import its own block.** `getPayload` builds a block without
  inserting it, and the leader never gets its own proposal back over gossip, so
  nothing else ever will. Without an explicit `newPayload`, consensus committed
  the block and the leader's own execution layer answered the commit's
  `forkchoiceUpdated` with SYNCING, leaving the chain at genesis while the logs
  showed healthy commits.
- **A node that is its own quorum must not wait for a mesh.** The startup hold
  added for fleet members stops a single-validator chain dead: the one member
  waits forever for a fleet that is already complete.

Two constraints on the setup, both worth knowing before repeating it:

- `crates/chainspec/res/genesis/n42_devnet.json` at the time had an **empty
  `config`**, so `--chain <that file>` activated no hard forks and every
  `forkchoiceUpdatedV3` was rejected with `-38003`. The checked-in devnet
  genesis now declares its schedule (see "The devnet genesis" above), and a
  genesis that declares one is trusted over the legacy hardfork list.
- N42's payload builder seals through APoS, so the node needs
  `--dev.consensus-signer-private-key` for an authorized signer even when
  HotStuff-2 is driving it — without one, every build dies and `getPayload`
  answers "unknown payload". The APoS miner used to run alongside and race the
  fleet's forkchoice (`Error advancing the chain … InvalidState`, and its
  stalled-chain watchdog re-proposing on its own); `bin/n42` now spawns no
  miner at all on a chain whose genesis names a `hotstuff` validator set. The
  signer key still seals what the fleet asks for.

### Why a leader was proposing every other view

The first live run produced a block roughly every 3.4s against a 3s view
timeout: every commit was followed by a wasted round. Three separate causes,
none visible without a live execution layer:

1. **The proposal attempt came after the wait.** HotStuff-2 is responsive — a
   leader that has formed a QC proposes for the next view immediately. Attempting
   it after the `select!` makes it wait for an unrelated event first, and a
   leader that has just committed has none coming, so it waits out the view.
   The attempt now happens at the top of each step, after draining (draining
   first is what makes the view current).
2. **One proposal per step.** A commit lands in the drain *after* the proposal
   that caused it, so one step can span several views. The loop now keeps
   proposing while the view advances, up to a bound, and when the bound stops a
   leader that is still making progress it polls the transport without blocking
   rather than going to sleep.
3. **Engine API timestamps are whole seconds.** HotStuff-2 commits in tens of
   milliseconds, so a leader that proposes every view either repeats a second —
   the execution layer accepts the forkchoiceUpdated, never finishes the build,
   and `getPayload` blocks until the view times out, with nothing in the logs
   but a slow call — or forces the timestamp forward and runs the chain's clock
   into the future until the execution layer rejects the blocks outright
   ("block timestamp N is in the future compared to our clock time M"). Both
   were observed. `with_payload_attributes` now takes a closure returning
   `Option`, so a leader can decline a view and be asked again.

Measured after: 21 blocks in 20s with no rejected builds, against 5 in 12s
before — about one block per second, which is what a whole-second timestamp
allows.

4. **Pacing has to be against the parent, and a declined leader has to be
   asked again.** On the four-validator devnet (period 3s, base timeout 6s)
   the pattern came back: commit, timeout, commit, timeout. Two causes. The
   builder paced against *this node's* last proposal, so a leader whose
   predecessor had just committed proposed at once, with a timestamp equal to
   the parent's second, and the execution layer refused the attributes
   (`-38003`). And once a builder declined, nothing woke the service before
   the view timeout — a leader that has not proposed has no events coming.
   The service now hands the builder a `ProposalContext` carrying the head's
   timestamp (learned from its own builds and from every body received over
   the block topic), the builder declines until `parent + period`, and a
   declined proposal arms a 200ms retry (gov5's `minProposeDelayMs`) instead
   of waiting for the timeout. Measured after: 21 blocks in 60s on a 3s
   period, every view committed, zero timeouts.

Consensus state across restarts is covered in "Restarting a validator" above.

## Joining a Go fleet: a Rust node in gov5's consensus

### A leader whose QC moved during its build (both clients, 2026-09-03)

Both clients choose a proposal's parent when the build starts and attach
the justify QC when the proposal is made; a QC that arrives in between
(a leader that was behind when its tenure began, at a fast cycle) pairs
a newer justify with an older parent, and every voter refuses the block
as not extending its justify QC -- repeated each view, the chain halts
(observed on this fleet at a 0.43 s cycle; gov5's window is wider, its
sync gate lets a leader two blocks behind produce and its build is
1.6-2 s). The fixes are leader-local and differ deliberately: this
client compares the parent with the block the QC certifies after the
build and **rebuilds** on a mismatch (d24618e9a; a build is ~0.4 s);
gov5 **drops** the proposal before journalling it and lets the next
leader take the view (bdc76990; a rebuild there would cost most of a
view), with a counter `hotstuff_proposal_stale_parent_total`. Nothing
crosses the wire differently, so a mixed fleet is unaffected; this
client's rebuilds show as the warn "the QC moved during the build".


Measured end state (`scripts/devnet-fleet.sh mixed 90 --gov5`: one QMDB `n42`,
three Rust validators, one gov5 validator, the checked-in devnet genesis):
90 s, 37 blocks, both clients at height 37 with the same head hash, the Go
member leading and sealing every fourth view (9 blocks), importing and voting
on every Rust block, zero errors on either side. Before this work the same
setup reached zero commits on the Go side. Everything between those two
numbers is listed here, because each item was found by the fleet refusing to
work and none was visible from the code alone.

**The header profile.** gov5's block header is Ethereum's field for field, but
four fields mean something else (`internal/consensus/hotstuff/adapter.go`
`Prepare`, `header_extra.go`): `extra_data` is `"N42H" ‖ view (LE u64) ‖ [QC]
‖ 96-byte BLS seal`, `difficulty` is 0, `beneficiary` is the leader, and
`ommers_hash` is the Go zero value — its miner never sets it. The seal is the
leader's signature over the header hashed without the last 96 bytes, under the
same proof-of-possession ciphersuite as its votes; gov5's `VerifyHeader` does
not check it, this node signs it anyway. `n42-h2-consensus::header_profile`
is the codec, checked against bytes printed by gov5's own code: extra layout,
header hash, seal hash, and — the part that could not be reasoned out —
**gov5's receipts root**, which is not a trie but the keccak of the
concatenated `rlp([status, cumulativeGas, logs])`, keccak of nothing for an
empty block (`hash.DeriveSha`). The same function spells two more roots its
own way: `withdrawalsRoot` carries the rewards commitment (keccak of nothing
without rewards), and `requestsHash` for no requests is the empty trie root,
not EIP-7685's `sha256("")`.

On the execution layer the profile is [`HotStuffConsensus`]
(`crates/n42/engine-types/src/hotstuff_consensus.rs`), installed by
`N42ConsensusBuilder` on any genesis naming a `hotstuff` validator set, in
place of APoS: gov5's header rules, gov5's receipts root in post-execution
validation, both spellings of the two roots above. `N42EngineValidator`
reconstructs the block a payload describes by trying the header values gov5
would have written — a payload carries neither `ommers_hash` nor
`difficulty`, and its withdrawals list reconstructs to the trie root — and
lets the block hash pick; nothing is guessed. The validator process finishes
each block it builds (`normalize_to_gov5_h2`: view, seal, the two roots, new
hash) before importing and proposing it.

**The consensus channel is not the v4 topic.** gov5 publishes on
`/n42/h2/4/ssz_snappy` only Decide proofs, for observers; its consensus runs
on `/n42/<fork digest>/hotstuff_consensus/ssz_snappy`, in the message
encoding `n42-h2-wire` already reads (the v4 envelope is that encoding with
an identity prefix). With `interopV4` in the genesis, gov5 signs the v4
chain-bound domains on that topic, so the engine's signing profile was
already right; the transport now speaks both topics, and a member publishes
consensus natively and the Decide proof additionally on v4.

**go-libp2p-pubsub only meshes with identified peers.** Three Rust members
sat connected to the Go node for a minute, status exchanged, gossipsub
streams negotiated in both directions, with no subscription ever crossing:
go-libp2p-pubsub v0.17 adds a peer that connected after startup only on
`EvtPeerIdentificationCompleted` (`peer_notify.go`), and this node did not
speak `/ipfs/id/1.0.0`. The transport now carries the identify behaviour.

**The system caller leaf.** With everything above in place the Go node
imported this node's block 1 and rejected it: `state root mismatch`. Tracing
both clients' QMDB write sets for the block gave two identical lists of four
leaves — the EIP-2935 and EIP-4788 contracts and their slots — and one extra
on the Go side: `0xffff…fffe`, the caller of Prague's system calls, as a live
empty account. Erigon's `SysCallContract` leaves that caller in the dirty set
as an initialised object, gov5's root computer writes every dirty object, and
its `isAccountEmpty` spares initialised accounts; reth's `SystemCaller`
removes the address after every call. `changes_from_execution` adds the leaf
on Prague blocks, and every bundle account is now written live even when
empty, since every state object gov5 holds is initialised.

**Timestamps: two clocks.** gov5 stamps `parent + period` however early it
proposes, and ignores any gossiped block stamped ahead of its own wall clock,
with no tolerance. So after a Go block a Rust leader must wait for the clock
to pass the parent's stamp, and stamp the wall clock — not `parent + period`,
which after a Go block is a period ahead and lost every such view to the
timeout, and not `parent + 1` while the clock is behind it, which the Go node
dropped as a future block. Pacing is `period` after the parent was *seen*
here (`ProposalContext::head_seen`), by this node's clock.

**One change gov5 needs.** Without committee evidence gov5 leaves
`parentBeaconRoot` nil on a Cancun chain — encoded as an empty string,
unrepresentable over the Engine API (`newPayloadV3+` requires the root), and
it skips EIP-4788 for the block, which no reth-validated block can match.
`docs/gov5-cancun-parent-beacon-root.patch` makes `Prepare` write the zero
root in that case, which is what genesis and every Engine API client write
and what gov5's own `VerifyHeader` already accepts. The mixed-fleet
measurement above was taken with it applied; it is on gov5's `main` as
`95d47b46` (with a test), so a gov5 built from `main` needs nothing further.
The patch file stays here for a checkout on an older branch.

**A Rust member that starts behind.** The other direction of the same
protocol. A member's execution layer is fed only over the Engine API, so
one joining a running chain — a fresh datadir, or a long absence — has
no blocks and no way to get them from devp2p. When a peer's status shows
it ahead of the execution layer (`eth_blockNumber`), the service pulls the
gap by range from that peer, imports each block in order through
`newPayload` and a forkchoice that finalizes it — the chain it came from is
the fleet's committed one — and asks for the next range until the peer's
height is reached; the consensus engine then finds the fleet's view from
the messages it hears. Measured: a member started 45 s late with an empty
execution layer pulled 1–12 from a peer in 160 ms, jumped from view 1 to
the fleet's 17, and committed every view after — its execution layer at 36
with the main chain's head hash when the run ended. The harness pins the
pull with mock execution layers (`a_member_that_starts_behind_pulls_the_chain_from_its_peers`).

**Fetch-on-miss.** gov5 recovers from anything it cannot place — the parent
of a gossiped block, the block a proposal names, its own speculative sibling
against the next leader's — by asking every connected peer for the block
over `/rpc/block_by_hash/1/ssz_snappy`: a bare 32-byte hash, answered with
a status byte, the fork digest, and the block RLP as one framed-snappy
chunk. The transport now serves it from the bodies the service keeps (every
block built or received, gov5's RLP, the last 4096), falling back to the
execution layer's `eth_getBlockByHash` for anything older, and asks for it
itself when a proposal names a body it has not seen. Measured: a Go member started
25 s late, eight blocks behind, asked, was served, "aligned and imported",
and went on to lead — 41 blocks in 100 s, both clients at 41 with the same
head, no errors.

**Range sync.** gov5's other way of catching up — its initial sync when
peers are ahead, and its leader-side catch-up when it finds itself behind by
more than `blockProductionSyncGate` — is `/rpc/bodies_by_range/1/ssz_snappy`:
an SSZ `{start: H256, count, step}` in one framed chunk, answered with the
blocks in order as `block_by_hash`-style chunks until the stream closes.
The transport serves it from the execution layer's canonical chain
(`eth_getBlockByNumber` over the Engine API's auth endpoint, which carries
the `eth_` methods the spec requires), up to gov5's 1024 blocks per request
and stopping at the first block it lacks. Only `bodies_by_range` exists on
the Go side; there is no headers-by-range handler.

Measured with a Go member started 240 s late (some 45 blocks behind): it
caught up and went on to lead, 65 blocks in 160 s, both clients at 65 with
the same head, no errors — through gossip's future-block queue and
fetch-on-miss, before its range catch-up had reason to fire. The range
codec is checked against gov5's SSZ and chunk layout and over a real
connection between two transports; a live gov5 range request has not been
observed yet, because on this devnet the cheaper path always won.

**Coming back after hours away.** The absence a fleet actually meets is
not a fresh member but one that took part, went away with its execution
layer, and comes back on the same datadirs to a chain that moved on
without it. `scripts/devnet-fleet.sh` does that (`ABSENT_VALIDATOR=2
ABSENT_AT=300 ABSENT_FOR=<s>`): the member resumes from its checkpoint
("resuming at view 121, last voted 120"), its execution layer is up in
1.5 s, the first status it hears shows a peer ahead, and it pulls the gap
by range. Measured on the mixed devnet, where the fleet of three times out
every fourth view while the member is away (the absent leader's), so the
chain grows about 0.25 blocks a second:

- *One hour away*: absent at 120, back with the fleet at 1002; 883 blocks
  pulled from gov5 and imported in 44.9 s (19.7 blocks/s through
  `newPayload` + forkchoice, debug build, QMDB roots); the 14 blocks the
  fleet produced meanwhile arrived by gossip and fetch-on-miss in the next
  7 s; view 121 → 1298 by the QC it heard; first commit 52 s after the
  return, on its own proposal, then 62 proposals and 231 commits in the
  14 minutes left, no timeouts anywhere in the fleet after the return,
  every client at 1234 with the same head, gov5 without an error.
- *Ninety minutes away*: absent at 119, back at 1446, 1327 blocks behind.
  The first window of 1024 came from gov5 in 49.6 s; gov5 dropped the
  connection during it (item 4 below), and 3.7 s after the refused second
  request the pull went on from a Rust member, 1143 → 1447 in 12.8 s,
  while the bodies gossip had held back were executed as the tip closed
  in. First commit 69 s after the
  return; then 60 proposals, no timeouts in the fleet, every client at
  1676 with the same head, the execution layer never in reth's syncing
  state.
- *Three hours away*: absent at 119, back at 2771, 2652 blocks behind.
  Again 1024 from gov5 in 49.9 s and the connection gone for the second
  request (item 4), then 1143 → 2800 from a Rust member in 65.4 s
  (25 blocks/s), probed to the peer's head, complete. First commit 126 s after the return, on its own
  proposal; then 55 proposals, no timeouts in the fleet, every client at
  2992 with the same head, gov5 without an error, reth never syncing.
  Three hours cost two minutes; the pull, not the absence, sets the bill.

The two three-hour runs before that one found what the hour had not.
The pull imports a window of 1024 blocks before the loop reads consensus
again, so every message that arrived during the window is handled at its
end — a member 2650 blocks behind reaches that point at block 1144 with a
few thousand views of proposals and commits waiting. Four things went
wrong there, each fixed in its own commit:

1. The eager import handed reth a proposal's payload 1600 blocks past
   its tip. A payload more than 32 blocks past the tip with an unknown
   parent (`MIN_BLOCKS_FOR_PIPELINE_RUN`) starts reth's backfill, which
   needs devp2p peers this execution layer does not have; every forkchoice
   answered SYNCING from then on, the next pulled block failed to import,
   and the member led nothing for the rest of the run. A block whose
   header puts it more than 32 past the last known import is now held,
   and re-examined as the pull moves the tip.
2. With payloads held, the same state came from the commits: the engine
   commits what a quorum certifies whether or not the node holds the
   block, and the driver's commit path sent a forkchoice with that block
   as head, safe and finalised — a head reth does not have starts the same
   backfill. A commit is handed to the execution layer only for a block
   imported through the service (voted on, pulled or built). The
   validator's driver also starts from the block the execution layer is
   actually at when the checkpoint's last committed block is one it never
   imported.
3. Once the held bodies were executed as the pull closed in, and their
   commits finalised them, the pull's next window held blocks the
   execution layer already had; a forkchoice back to one of them is a
   reorg behind the finalised block, which reth refuses (-38006). Pulled
   blocks already imported are counted and skipped.
4. The window was imported in one go, and for the fifty seconds that
   took the swarm went unpolled: gov5's streams to the node timed out
   ("direct-push stream failed: context deadline exceeded") and it dropped
   the peer, which is why the second window had to come from a Rust
   member both times. Pulled blocks are imported 32 per step now, the
   transport polled between batches: on the next run (25 minutes away,
   370 blocks behind) gov5 held the connection through the whole pull,
   served it in 3.5 s and refused the probe past its head, and the member
   committed 15 s after its return.

A catch-up that ends — complete or not — allows another after 3 s, from
the highest peer known (heights come from statuses at connect and from
every block a peer gossips or serves since; the peer whose pull failed
last is passed over when there is another), and a pull that reaches its
target goes on probing a window at a time until the peer serves short or
refuses — gov5 answers a range past its head with "code 2: invalid block
number". A chain that keeps producing during a long pull is caught up by
the pull itself, not left to gossip's future queue.

**The safety bug the first attempt found.** The first run of this
scenario did not get as far as the absence: with member 2 starting a few
seconds after the others (its own execution layer had to come up), the
fleet committed block 1 at view 1, and member 2 — leader of view 2, having
heard the view-1 QC but never imported its block — built on its stale
genesis head and proposed a *sibling* of the committed block. The two Rust
members voted for it and committed it next to the block they had committed
one view earlier; the gov5 member, whose `extendsJustify` refuses a
proposal that does not extend its justify QC's block, refused to revert its
applied chain and stopped (the "CONSENSUS STATE FORKED FROM APPLIED CHAIN"
wedge — in this case gov5 was right and the Rust quorum was wrong). The
port's safety check compared views alone (`justify.view >= locked.view`);
the extends rule had not been carried over. It is now: the engine remembers
the parent of every imported block, the import-gated vote is refused when
that parent is not the justify QC's block (a zero or unknown parent passes,
as in gov5; `test_h2_vote_refuses_a_proposal_that_does_not_extend_its_justify`),
a leader builds on the block its highest QC certifies rather than on its
execution layer's last import and asks the fleet for that block when it
lacks it, and a member whose peers are ahead at connect pulls the gap
however small.

## Live cross-client attach: how far it got

There is no gov5 fleet on this Linux host — the deployment docs point at a
Windows operator box (`E:\qs-node0..6`). So a real Go node was built and run
here instead: gov5 `v5.7.960` from source, on the purpose-built
`h2_interop_test` chainspec (chainId 96, four validators, `interopV4: true`).

What worked: **the Rust observer peered with the genuine Go node.** Noise
handshake, yamux muxing, libp2p identity negotiation, and gossipsub version
negotiation all succeeded — the Rust log reports
`peer_type=Gossipsub v1.2` for the Go peer, and the observer subscribed to
`/n42/h2/4/ssz_snappy`.

**One real bug was found and fixed only because of this run.** gov5 nodes carry
**secp256k1** libp2p identities. The first attach failed with:

```
Handshake failed: Invalid public key: cargo feature `secp256k1` is not enabled
```

`n42-h2-net` had a minimal libp2p feature set that omitted it (N42-26's dep list
includes it; it was dropped when the feature list was trimmed). Fixed, with a
comment saying why it is not optional. The observer also used to swallow dial
errors — a silent dial failure looks exactly like an idle fleet — so it now
reports `ObserverEvent::DialFailed`, which is what surfaced this at all.

**The status handshake is now implemented, and the connection is sustained.**
gov5 drops peers that cannot answer `/rpc/status/1/ssz_snappy`
(`internal/sync/service.go` wires `AddConnectionHandler(s.reValidatePeer, s.sendGoodbye)`).
`crates/n42/h2-net/src/{status,rpc}.rs` implements both directions of it, and a
run against the live Go node held for the full 75-second test with no
disconnect — the eventual drop in gov5's log is this side's timeout exiting.

Three things about that wire format are easy to get wrong, and all three are
pinned against vectors generated by gov5's own Go code
(`testdata/gov5_status_v1.json`):

- **RPC payloads are snappy-*framed*, gossip payloads are snappy-*raw*.** Mixing
  them produces bytes that look plausible and decode to nothing.
- **`sync_pb.Status` has eight protobuf fields but its SSZ codegen serialises
  two** — genesis hash and current height, both variable-length `H256`.
- **`H256` byte order.** Each 8-byte group is read big-endian into a `u64`
  (`ConvertHashToH256`) then written little-endian by SSZ, so every group appears
  reversed on the wire.

Reading is done by walking snappy frame headers to find the exact message
boundary rather than reading to EOF, because the varint declares the
*uncompressed* length and gov5 does not promise to half-close.

**A finding from the live run**: this gov5 node advertises a **zero genesis hash**
in its status (`ourGenesis: 0x0000…`), which is also why its gossip topics read
`/n42/00000000/...` rather than the real `3bec3e86` digest. Since gov5's
fork-digest check is just the first four bytes of that hash, an observer must
advertise the same value or be disconnected as a fork mismatch — confirmed from
both sides. gov5 has `--p2p.genesis-override` for exactly this class of
mismatch. Check what the fleet actually advertises before configuring
`--genesis`; it is not necessarily the chain's real genesis hash.

Also note the test node never joined the v4 topic: with no validator key
configured its HotStuff service stays idle, so `s.h2V4Identity` is nil and the
topic is never published to. A finality-carrying attach needs a chain with at
least one keyed validator producing blocks; the pinned `h2_interop_test`
validator private keys are not in the repo (they live on the operator host).

## Fleet database compatibility

The 7-node fleet is `stateScheme: qmdb`, not MPT. The supported cross-client
path is **not** opening gov5's MDBX directly — it is the portable snapshot:

```bash
# on the gov5 side
go run ./cmd/n42-qmdb-export --db <replay-target>/chaindata \
  --out <checkpoint>.n42qmdb --map.gb 512
```

The consumer checks chain/checkpoint identity and the Blake3 content digest,
then recomputes frozen leaf roots, active-bit commitments, twig roots, and the
upper root. That consumer now exists here:
`n42_twig_core::qmdb_compat::verify_portable_stream`, covered by
`verify_portable_stream_matches_in_memory_root`,
`portable_snapshot_roundtrip_checks_identity_root_and_digest`, and
`verify_portable_stream_non_power_of_two_twig_count`.

Caveat from the gov5 spec: the exporter fails if historical dead-slot rows are
missing, so production exports require replay data created with
`--qmdb-history`. A live-key-only snapshot cannot reproduce the split
commitment.

Also available here, byte-compatible with Go and cross-checked by the ported
tests (`cross_check_root_vs_gov5_go`, `cross_check_sorted_batch_vs_gov5_go`,
`cross_check_sharded16_root_vs_gov5_go`): `gov5_account_key`,
`gov5_storage_key`, `encode_gov5_account_value`, `GOV5_EMPTY_CODE_HASH`.

## Execution-layer glue

`n42-h2-consensus` decides about block *hashes*; it never touches a block body.
`n42-h2-execution` is what connects it to something that executes.

The seam (`el.rs`, ported from N42-26's `n42-consensus-service/src/el.rs`) is an
`ExecutionLayer` trait over the Engine API expressed **entirely in alloy types** —
`ExecutionData`, `ForkchoiceState`, `ForkchoiceUpdated`, `PayloadAttributes`,
`PayloadId`, `PayloadStatus`. No reth type crosses it. That is the property that
lets the consensus half of this repo stay independent of the reth version
underneath, and it is why the HotStuff-2 port landed without the 2.4.1 upgrade.

`driver.rs` services the three flows consensus actually needs:

| Consensus says | Driver does | Consensus hears |
|---|---|---|
| (leader for this view) | FCU-with-attrs, then resolve the build | `ConsensusEvent::BlockReady` |
| `EngineOutput::ExecuteBlock(hash)` | `new_payload` for that block | `ConsensusEvent::BlockImported` |
| `EngineOutput::BlockCommitted` | FCU with head = safe = finalized | — |

The middle row carries the safety property. N42 votes are **import-gated**: a
follower votes only after its own execution layer accepted the block. The tests
pin the three ways that must not be short-circuited — an `INVALID` verdict, an
EL error, and a `SYNCING`/`ACCEPTED` status (which is *not* a verdict: the EL has
not executed the block, so voting then would be voting blind). In all three the
driver withholds the import event and leaves the head where it was.

What is **not** ported is N42-26's 14.7k-line orchestrator — compact blocks,
eager import, payload caching, bad-block caches. Those are reth-2.4.1-coupled
throughput work, not protocol, and inheriting them would have re-imported the
version wall this seam exists to avoid.

What remains for a node that actually produces blocks: a concrete
`ExecutionLayer` implementation over reth v1.11.0's `ConsensusEngineHandle` and
`PayloadBuilderHandle`. That is a node-side adapter — it belongs next to
`bin/n42`, needs the reth stack to compile, and is the one piece of this path
that a reth upgrade would disturb. The trait is small (four methods) precisely so
that adapter is the only thing that has to move.

Note for that adapter: this repo's vendored `alloy-rpc-types-engine` adds
**`difficulty` and `nonce` to `ExecutionPayloadV1`** (APoS carries its
Clique-style seal there). Upstream alloy has neither, so payloads built here do
not round-trip through an unmodified alloy without those fields.

## Storage-format findings (reth side)

Checked against `../reth` (2.4.1) and this repo's vendored crates:

- **The MDBX table set has not changed between reth v1.11.0 and 2.4.1.** `git
  diff c1015022f HEAD -- crates/storage/db-api/src/tables/mod.rs` shows no table
  added or removed. This repo's 29 core tables are identical to 2.4.1's; the
  divergence is only N42's 15 extra beacon/snapshot/validator tables.
- `StorageSettings` / the `Metadata` table (reth #19384, Nov 2025) is already
  present here and is near-identical to 2.4.1's. The one local delta: `base()`
  is gated on an `edge` feature and returns `v1()` by default, where upstream
  returns `v2()`. `PartialStateTrieUnwindMarker` is absent here.
- Therefore `storage_v2` / hashed-canonical — the layout gov5's
  `modules/state/hashed_readonly.go` targets, and which its
  `internal/mptbuild` + `internal/mptproof/reth_hashed.go` read and write — is
  reachable on this reth version at the schema level. What differs is the
  provider/trie implementation: 140 files and ~23.8k inserted lines between
  v1.11.0 and 2.4.1 under `crates/storage` + `crates/trie`.

Conclusion: MPT-side storage compatibility with gov5's eth-el path is a
provider/trie question, not a schema-migration question. That is a materially
smaller problem than it first appears.

## EVM / EIP alignment

This repo's `N42_HARDFORKS` (`crates/ethereum/hardforks/src/hardforks/n42.rs`)
schedules Frontier→ArrowGlacier at block 0, Paris at TTD 0, Shanghai and Cancun
at 1746576000, Prague at 1748930400, and Osaka at **4070908800 (2099-01-01)** —
deliberately parked, per the in-file comment, to avoid Osaka's
`MAX_TX_GAS_LIMIT_OSAKA` of 2^24 on devnets. `BEIJING_FORK` is `ForkCondition::Never`.

gov5's fleet chainspec mirrors ETH mainnet forks (shanghai@305000,
cancun@3935000, pectra/osaka/fusaka by time), and gov5 reports green EEST
consume-engine shards through Osaka. So the EIP gap is Osaka/Fusaka being
scheduled-but-parked here, on a revm that predates several Osaka refinements.

Between reth v1.11.0 and 2.4.1: **1,484 commits**, revm 34 → 42 (this repo pins
revm 34.0.0, alloy 1.6.3, alloy-primitives 1.5.6; 2.4.1 pins revm 42.0.1, alloy
2.3.0, alloy-primitives 1.6.1). EL-visible items in that range include the
revm v37 bump for EIP-8037 state gas and Amsterdam header-field validation.

## Transport: matching gov5's router

`n42-h2-net` reproduces gov5's pubsub configuration from
`internal/p2p/pubsub.go`, because a mesh built with different overlay degrees or
heartbeat timing still interoperates but behaves inconsistently under load:

| Parameter | gov5 | Source |
|---|---|---|
| topic | `/n42/h2/4/ssz_snappy` | `H2V4Topic` + the encoding suffix. Note it is *not* fork-digest scoped, unlike gov5's block topic — the v4 envelope carries chain identity itself, which is what makes it cross-client. |
| D / Dlo / Dhi | 8 / 6 / 12 | `gossipSubD`, `gossipSubDlo`; Dhi is go-libp2p's default, not overridden |
| heartbeat | 700 ms | `gossipSubHeartbeatInterval` |
| history length / gossip | 6 / 3 | `gossipSubMcacheLen`, `gossipSubMcacheGossip` |
| seen-message TTL | 30 s | `seenMessagesTTL` — deliberately not libp2p's 2 min default; at fleet throughput the default measured 391 MB of live heap |
| max transmit size | 1,223,370 B | `GossipMaxSize()` = `snappy.MaxEncodedLen(1 MiB)` = `32 + n + n/6`. Must be the *encoded* bound: gov5 hit a bug where a cap pinned at the raw 1 MiB silently held the network at the default. |
| signature policy | `StrictNoSign` + `NoAuthor` | mapped to rust-libp2p `ValidationMode::Anonymous` + `MessageAuthenticity::Anonymous` |
| transport | TCP + QUIC-v1, Noise, yamux | `internal/p2p/options.go`. This crate dials TCP only; QUIC is left off because a QUIC dial to a TCP-only listener fails in a way that reads like a consensus fault. |

### Two findings worth sending back to the other repos

**gov5's `MsgID` is Keccak256, not SHA-256.** The doc comment on
`internal/p2p/message_id.go` says `SHA256(genesisHash || topic || data)[:20]`,
but `common/hash.Hash` pulls a `crypto.KeccakState`. The comment is wrong, not
the code. `crates/n42/h2-net/testdata/gov5_message_id_v1.json` pins five vectors
generated by calling gov5's own hash function through that exact byte layout, so
a future "fix" to match the comment fails a test that names the reason.

**N42-26's message-ID function does not match gov5's.**
`n42-network/src/gossipsub/handlers.rs` computes `keccak256(data || topic)` —
no genesis hash, and the topic after the data. gov5 folds the genesis hash in
and puts the topic first. The message ID is a purely local dedup key so the two
still interoperate, but they dedup differently, and gov5's genesis scoping is
load-bearing: go-libp2p-pubsub marks an ID seen globally across topics and
before validation, so without topic scoping an attacker can replay a block's
bytes on another subscribed topic to pre-seed the seen-cache and have the
genuine block dropped as a duplicate. This crate implements gov5's.

### libp2p version

N42-26 pins libp2p 0.57.0 at a git rev. Using that rev here forces a cascade of
workspace-wide bumps — `bytes` ^1.12, `regex` ^1.13, `tokio` ^1.53, `either`
^1.16, then `cc` and `rustls` — each of which would move versions under the
reth v1.11.0 build. This crate therefore uses libp2p **0.56 from crates.io**,
which resolves with no version replaced anywhere in the lockfile. The gossipsub
wire protocol is unchanged between the two, so interop is unaffected. Revisit
when the repo moves to reth 2.4.1, at which point matching N42-26's pin costs
nothing.

## Joining the production fleet: what is still missing (2026-08-28)

The devnet measurements above prove the protocol: a Rust member votes,
leads, imports, serves and catches up on a mixed fleet, on the checked-in
devnet genesis. gov5's production fleet is `mainnet_qmdb_staggered`
(`params/chainspecs/mainnet_qmdb_staggered.json`, chain id 94, seven
validators, period 3 s, head 13,013,133 replayed from mainnet history and
resealed with BLS, 35 GB). Checked item by item against that chainspec and
`internal/consensus/hotstuff/adapter.go`. `../N42-26` was checked for each
item too: it has none of the first four (no rewards, committee pool, mobile
anchor or EOF), a file-based epoch schedule and a consensus-state bootstrap
bundle rather than a state snapshot, and its live interop ran on an isolated
committee chain without rewards or a committee pool — so nothing there
shortens this list.

**Done since, each measured on the devnet genesis with a mixed fleet (one
QMDB node, three Rust validators, one gov5 member; see the commits):**

1. **Block reward and faucet credit.** `hotstuff.devBlockReward` (1 ETH)
   credits the coinbase and `devFaucetAddress` in gov5's `Finalize`, listed
   as the block's rewards and committed to in the withdrawals root — in every
   block's state root. The rewards are now the Engine API's withdrawals (a
   reward in wei is a withdrawal in gwei): a leader derives them from the
   genesis into its payload attributes, the execution layer credits them
   after the transactions as gov5 does, the normalizer writes gov5's root,
   a gov5 block's rewards become the imported payload's withdrawals, and the
   block wire form carries the list both ways. Measured: 100 s, 41 blocks,
   both clients at 41 with the same head, the Go member sealing ten, zero
   errors, the faucet holding 41 ETH on both.
2. **Committee evidence in `parentBeaconRoot`.** With
   `hotstuff.committeePool` enabled every header must carry
   `Blake3(parent's committee evidence)`, which gov5's `VerifyHeader`
   enforces. The evidence is deterministic — keys from a seed, a committee
   drawn per block, one signature of the summed secret scalars — so
   `n42_h2_consensus::committee_pool` rebuilds it from the parent header
   alone, checked byte for byte against gov5's `blspool` output for a small
   pool and for chain 94's 200,000-key pool
   (`testdata/gov5_committee_evidence.txt`). A leader derives the root from
   the head's header; the execution layer's HotStuff consensus checks every
   imported header against the evidence it rebuilds. Measured with a
   4096-key pool and 64 signers: 41 blocks, same head on both, block 5's
   root the same non-zero evidence on both, zero errors. Not ported: the
   hand-over of pool slots to real mobile validators
   (`consensus_registerCommitteeValidator`); chain 94 has none registered.
3. **Epoch boundaries** (`epochLength` 20, as `qs_epoch_test`): the epoch
   arithmetic is the same on both sides (`(view-1)/length`, boundary at
   `(view-1) % length == 0`). Measured over 150 s and 60 views, crossing
   two boundaries: same head on both, the Go member sealing fifteen, zero
   errors. Still unmeasured: a validator-set *change* at a boundary
   (gov5's `ReconfigurationManager`, fed by `hotstuff_proposeAddValidator`),
   which chain 94 has never exercised either.
4. **Bootstrapping from a snapshot.** `n42-init-snapshot init` builds an
   empty datadir at a chain's head from three files: gov5's
   `n42-reth-state-dump` output (reth `init-state` JSONL plus the head's
   header RLP) and the QMDB slot log as the cross-client portable snapshot
   (`n42-qmdb-export`, or `n42-init-snapshot export` from a Rust node). It
   writes the state the way reth 2.5 stores it — hashed accounts and storage,
   changesets in static files, history in RocksDB, dummy headers below the
   head — and rebuilds the QMDB forest from the slot log, refusing anything
   whose root is not the header's. reth's own `init-state` cannot serve here
   only because it recomputes a Merkle root the header does not carry.
   Measured: a fresh fleet run to block 25 and stopped; gov5's state dump and
   the Rust node's QMDB export taken at that block (same hash, same root);
   the fleet resumed with `LATE_VALIDATOR=2 LATE_SNAPSHOT=<dir>` — the member
   whose execution layer was initialised from the snapshot pulled blocks
   25→27 from its peers, committed 36 views, and ended at block 63 with the
   same head as the main execution layer and gov5, zero errors. Chain 94's
   35 GB will be the first real test of the sizes involved; the forest is
   held in memory, which is its own item.
5. **The chain's identity, and the fork schedule.** `n42-gov5-genesis`
   folds gov5's chainspec, allocation (decimal balances, base64 code) and
   genesis-block fields into a genesis this node loads, and checks the
   result against the hash gov5 records: chain 94 (`0xa2d2ff5d…`, a
   2762-account allocation whose QMDB root this node computes identically)
   and chain 95 both reproduce, so the fork digest on the wire is right.
   The block-number forks become timestamps with `--fork-time` — the
   timestamps of blocks 305,000 and 3,935,000, one RPC call each — which is
   the equivalent schedule on a chain whose timestamps only grow. The
   generated files are under `crates/chainspec/res/genesis/gov5/`. gov5's
   own forks stay untranslated and inert (see item 6 below).

6. **Transactions, both ways.** A validator started with `--el-rpc <url>`
   polls its execution layer's pool (`txpool_content`, every 500 ms) and
   publishes what it finds on gov5's `transaction_v2` topic in gov5's batch
   framing (`0x7e` + RLP list of raw EIP-2718 transactions, at most 256 per
   batch and 256 KiB, `n42-h2-net::tx_gossip`); every transaction arriving
   on that topic — a batch or a bare transaction — is handed to the
   execution layer with `eth_sendRawTransaction`. Measured on the mixed
   fleet with `examples/send_tx`: transactions submitted only to gov5's RPC
   were sealed by a Rust leader (block 25, validator 1), and every
   transaction submitted only to the Rust execution layer appeared in gov5's
   pool by gossip (its debug log rejects them with `nonce too low`, because
   the Rust leader had sealed them, at 1 s a block, before the batch
   arrived). `scripts/devnet-fleet.sh` passes `--el-rpc` to every validator.

**Still blocking, in the order the fleet would refuse us:**

4. **`MobileRegistryRoot`, a header field Ethereum does not have.** Under
   the `mobileAnchor` fork (active since 2026-07-18 on chain 94) gov5's
   miner stamps a 21st header field with the mobile-registry root when the
   node has an anchor provider. reth's `Header` cannot carry it, the Engine
   API cannot express it, and the alloy decoder refuses a header with it.
   Whether the seven nodes are wired with the provider decides whether this
   bites on day one; the field exists in the type either way.
5. **Execution semantics beyond reth.** gov5's EVM has EOF
   (`internal/vm/eof.go`, `eofTime` 2025-12-09, active) — Ethereum dropped
   it and revm 42 has none; any EOF contract on chain 94 diverges. Fusaka
   is active; Glamsterdam (`glamsterdamTime` 2027-01-01, gas repricing) is
   not yet. `ltHashTime` is set but nothing in gov5 reads it today.
6. **gov5's own forks.** `beijingBlock`, `ltHashTime`, `mobileAnchorTime`,
   `eofTime`, `glamsterdamTime` have no reth spelling and are carried
   through the genesis inert; only `eofTime` and `mobileAnchorTime` change
   anything executable (items 4 and 5).

And one thing that is not ours: on that fleet gov5 itself wedges after a
handful of blocks at a fork-active head (`docs/mainnet_qmdb_staggered-
7node-status.md`, "Layer 5": competing same-height blocks are never
reconciled below the head pointer). A Rust member would meet the same
wedge; whether it should tolerate or expose it is a question for when the
rest is done.

The devnet genesis now carries the production shape for everything above
that is done: a 1 ETH reward with the faucet, a 4096-key committee pool with
64 signers, epochs of 20 views.

## Roadmap

Ordered by dependency, not by value. Rewards, the committee-evidence link
and epoch boundaries are done and measured (above); what follows is the
rest of the production-fleet list in build order.

0. **Validator-set changes at a boundary** (item 3's remainder): per
   `docs/VALIDATOR_LIFECYCLE_DESIGN.md`, phases 0–1 first — a non-zero
   `changes_hash` and proposals as transactions — then the measurement.
1. **Header field and EVM parity** (items 4–6): `MobileRegistryRoot` needs
   a header extension on the reth side; EOF is a revm question.
2. **Transactions** (item 7): done (item 6 above); what remains is
   gov5's own optimisation of announcing a hash before a body, if it ever
   gets one.
3. **Rejoining after a long absence**: measured at one hour, ninety
   minutes and three hours ("Coming back after hours away", above), which
   surfaced and fixed the missing extends rule and three ways a long pull
   lost its execution layer to reth's peerless backfill. The observer against the live fleet still waits for a
   reachable one — there is no gov5 fleet on this host.
