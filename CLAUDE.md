# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

N42 is a **partial fork of [reth](https://github.com/paradigmxyz/reth)**. Most of reth is consumed as a
git dependency pinned to a tag (`reth = { git = "...", tag = "v1.11.0" }` — grep `Cargo.toml` for the tag
to confirm the current version); a subset of reth crates is vendored under `crates/` and substituted into
the whole dependency graph via `[patch.'https://github.com/paradigmxyz/reth.git']` in the root `Cargo.toml`.
N42-specific code lives under `crates/n42/` and `bin/n42/`.

Consensus is **APoS** (an extended Clique/PoA) plus a beacon/validator layer, not Ethereum's beacon chain.

## Build / test / lint

```bash
cargo build --release                  # builds default-members = bin/n42 only
cargo build --profile maxperf          # fat LTO, codegen-units=1
cargo check --workspace                # what CI gates on (.github/workflows/test.yml)
cargo test -p n42-testing              # the main test suite CI runs
cargo clippy --workspace --lib --bins --examples   # CI lint (.github/workflows/lint.yml)
```

Running one test:

```bash
cargo test -p n42-testing test_single_signer__no_votes_cast -- --nocapture
cargo test -p n42-clique --lib integration_tests::                # APoS unit/integration tests
```

Ethereum Foundation spec tests (`crates/n42/ef-tests`) are `#[ignore]`d by default and need fixtures:

```bash
EF_TESTS_PATH=/path/to/execution-spec-tests/fixtures \
  cargo test -p n42-ef-tests --test blockchain_tests -- --ignored
```

End-to-end (needs release binaries + node/npm + `jq`):

```bash
cargo build --release && cargo build --release -p mobile-sdk --example mobile-sdk-test
./tests/e2e.sh
```

Running a node:

```bash
cargo run --release --bin n42 -- node --chain crates/chainspec/res/genesis/n42_devnet.json \
  --dev.consensus-signer-private-key 0x... --dev.block-time 4s --http --ws
```

Caveat: `tests/e2e.sh` passes `--chain n42-devnet`, but the vendored
`crates/ethereum/cli/src/chainspec.rs` currently maps only `mainnet|sepolia|holesky|hoodi|dev` and falls
through to `parse_genesis()` for anything else — the `n42`/`n42-devnet` names were dropped during a reth
re-sync even though `N42` and `N42_DEVNET` still exist in `crates/chainspec`. Pass a genesis JSON path:
`--chain crates/chainspec/res/genesis/n42_devnet.json`.

`n42_devnet.json` is the native chain's devnet: `"stateScheme": "qmdb"`, `"consensus": "hotstuff"`
with four dev validators (secrets in `n42_devnet_validators.json`, derived from a public seed — dev
only), every Ethereum fork through Osaka active at genesis, the Prague system contracts in the
alloc, and gov5's production-shaped consensus settings: a 1 ETH `devBlockReward` with a faucet
(paid as withdrawals), a 4096-key `committeePool` with 64 signers (every header links to the
parent's committee evidence through `parentBeaconRoot`), and `epochLength` 20. Both `--chain <path>` and the `N42_DEVNET` constant build its genesis header the same way, with
the QMDB root of the alloc; a genesis file that declares its own fork schedule is trusted over the
legacy `N42_HARDFORKS` list. The same file is what a gov5 node is initialised from (`n42 init`).
On a chain whose genesis names a `hotstuff` validator set `bin/n42` runs `HotStuffConsensus`
(gov5's header profile and roots) instead of APoS and spawns no miner: the fleet
(`cargo run -p n42-h2-node --example h2_validator -- --chain <genesis> --propose …`) drives it over
the Engine API. `scripts/devnet-fleet.sh <tag> <secs> [--gov5]` runs the whole devnet — one QMDB
node, four Rust validators, or three plus a gov5 member from `../N42-gov5` (built from a commit that includes gov5 `95d47b46`,
the zero parent-beacon-root fix; `docs/gov5-cancun-parent-beacon-root.patch` is the same change for
an older branch). `GOV5_DELAY=<s>` starts the Go member late; `LATE_VALIDATOR=<i> LATE_DELAY=<s>`
starts one Rust member late with its own fresh execution layer, so it has to pull the chain by range;
`ABSENT_VALIDATOR=<i> ABSENT_AT=<s> ABSENT_FOR=<s>` runs one member with its own execution layer from
the start, kills both at `ABSENT_AT` keeping the datadirs, and restarts them `ABSENT_FOR` seconds later
(logs get a `-back` suffix) — the long-absence rejoin measurement;
`LATE_SNAPSHOT=<dir>` initialises that execution layer at a chain's head instead
(`n42-init-snapshot init`, from gov5's `n42-reth-state-dump` JSONL + header and a portable QMDB
snapshot — `n42-qmdb-export` or `n42-init-snapshot export`), so it pulls only what came after.
Every validator gets `--el-rpc <url>` (the execution layer's public RPC): it gossips its pool's
transactions on gov5's `transaction_v2` topic and hands gossiped ones to `eth_sendRawTransaction`
(`examples/send_tx` submits signed transfers to either client's RPC for this).
`n42-gov5-genesis` folds gov5's chainspec + alloc + genesis-block fields into a genesis this node
loads and checks the hash; `crates/chainspec/res/genesis/gov5/` holds chain 94 and 95 (see its
README for the `--fork-time` step before running on them). `docs/N42_26_PORT.md` "Joining a Go fleet"
lists every cross-client rule that had to be matched.

`scripts/fleet7.sh` runs the **all-Rust seven-node fleet** on the native chain — gov5's flagship
shape, seven independent members each with its own execution layer and validator in a static full
mesh, no discovery and no devp2p. Its genesis is `crates/chainspec/res/genesis/n42_fleet7.json`
(chain 94's consensus parameters: epoch 200, gov5's 200,000-slot committee pool with 512 signers,
but every fork at block 0, because the block reward is paid as withdrawals). Every launch argument
lives in `scripts/fleet7-env.sh` and nowhere else. `up --fresh` / `status` / `watch <secs>` /
`roll <i>` / `down`; `F7_TXGEN_RATE=<tx/s>` offers it load (200 tx/s sustained,
0 rejected, block interval held).

Throughput rounds are `scripts/fleet7-bench.sh` (one round: fresh datadirs at
the 480M bench tier on `n42_fleet7_bench.json`, base-fee decay, flood,
N x 30 s windows; `F7_BLOCK_INTERVAL_MS` paces in milliseconds and
`F7_VIEW_TIMEOUT_MS` overrides the chain's baseTimeout, but a *tighter* one is
worse: three runs each say 500 ms is 20% slower than the genesis 6,000 ms at
250 ms pacing, because the timeout has to exceed the cycle a block actually
takes), `examples/tx_flood` (funds and floods a derived
sender set, gov5's derivation so both clients draw on the same accounts),
`scripts/fleet7-measure.py` (TPS **and** occupancy and full(>=95%), because the
first is ambiguous without the others), `scripts/fleet7-phases.py` (where a
block's cycle goes — run at the END of a round and compare whole rounds only)
and `scripts/fleet7-profile.sh` (perf between windows; `--alloc` for jemalloc
heap profiles, the instrument a CPU profile cannot replace).

**Record (2026-09-04, round 39): 305,556 / 298,824 TPS** (win1/win2, 0.526 s cycle,
163,000 tx/block, every follower executing, bookended by 288/288/277 and 291/283/283 without the
puller) with `F7_LEADER_TENURE=16 F7_INGEST=1 F7_INGEST_ALL=1 F7_NO_TX_GOSSIP=1
N42_TX_INGEST_ASYNC=1 F7_DIRECT_PUSH=1 F7_BLOCK_INTERVAL_MS=400 F7_SKIP_STALE_CHECK=1 N42_TX_QUEUE=1
N42_TX_INGEST_RECOVER_NICE=10 N42_TX_INGEST_RECOVER_PARALLEL=16 N42_TX_INGEST_DIRECT=1
N42_FAST_TRANSFER=1 N42_FOLLOWER_DIRECT_IMPORT=1 F7_SENDER_CACHE_MULT=4 N42_TX_QUEUE_BATCH=1024
N42_TX_QUEUE_DRAINER=1 N42_BUILDER_PULLER=1024 F7_FLOOD_WINDOW=6
F7_EL_EXTRA="--builder.interval 60 --builder.deadline 3"` and `--gasceil 3423000000 --senders 6000
--pertx 6000 --conc 64 --rpcbatch 500`. `N42_FAST_TRANSFER=1` applies plain transfers without the
interpreter (byte-equal to revm, tested); the payload service must use the node's EVM factory for
any EVM change to reach the builder (it had its own `EthEvmConfig::new` until 9d95b8e0f). The
cycle is *own import + build ahead* on the leader (83-101 + ~350 ms) at parity with the QC chain
(followers' import ~330 ms + the vote's second round, 26-126 ms of `fsync` on the vote log --
measured in loop28); 24 recovery slots and a parallel account prefetch both measured worse.
`docs/NATIVE_FLEET7.md` "Where it stands today".

**Never draw a conclusion from one round.** `scripts/fleet7-repeat.sh <n>` runs a
configuration repeatedly and prints the spread. Measured over three runs: the
round's transaction total varies 5% and window 1 varies 4%, but window 2 varies
17% and window 3 by 89% — so the total and window 1 are the metrics, and a
difference under about 10% between single rounds is invisible. Two consecutive
runs of one configuration produced 1,024,853 and 894,094 transactions.

Profiled rounds need `cargo build --profile profiling` and
`F7_BIN=target/profiling`: `[profile.release]` strips symbols and a profile of
it names nothing. `docs/NATIVE_FLEET7.md` records what it measures, the three defects that only
appear at seven nodes, and which knobs are worth turning — plus the one set that is not (the
GossipSub parameters are a gov5 wire contract, asserted in tests, not a tuning surface).

`cargo build`/`cargo test` with no `-p` only touches `default-members` (`bin/n42`). Use `--workspace`
deliberately — it is a very large build.

## Workspace layout and the fork boundary

Three distinct kinds of crate directory exist, and they behave differently:

1. **`crates/n42/*` — original N42 code.** Workspace members, freely editable.
2. **Vendored reth forks that ARE workspace members** (`crates/chainspec`, `crates/consensus/consensus`,
   `crates/primitives-traits`, `crates/storage/{db,db-api,provider,storage-api}`, `crates/node/{core,builder}`,
   `crates/ethereum/{cli,hardforks,node}`, `crates/net/peers`, `crates/rpc/rpc-types-compat`).
3. **Vendored reth forks that are NOT workspace members but ARE patch targets**
   (`crates/revm`, `crates/ethereum/evm`, `crates/net/network`, `crates/net/network-api`,
   `crates/storage/libmdbx-rs`, `bin/reth`). They compile only as dependencies. `cargo test --workspace`
   will not run their tests.

Editing anything in (2) or (3) rewrites reth for *every* crate in the graph, including the upstream git
crates that depend on it — a signature change there can cascade into hundreds of upstream compile errors.
Prefer adding code in `crates/n42/*` and wiring it in at the node-builder level. When you must touch a
forked crate, keep the change additive (new trait method with a default impl, new table, new field with
serde defaults) so upstream call sites still compile.

The commented-out entries in `[workspace] members` and in the `[patch]` table are deliberate: they mark
crates that were previously forked and have since been reverted to upstream. Don't uncomment them casually.

### N42 customizations inside forked reth crates

- `crates/primitives-traits/src/header/clique_utils.rs` — `recover_address()` / `seal_hash()` for APoS
  signature recovery from block headers (N42-only file).
- `crates/consensus/consensus/src/lib.rs` — the `Consensus` trait is extended with APoS operations
  (`prepare`, `seal`, `snapshot`, `propose`, `discard`, `proposals`, `total_difficulty`, `wiggle`,
  signer get/set) plus N42 error variants.
- `crates/storage/{db-api,storage-api,provider}` — beacon tables (`BeaconStateRecord`, `BeaconBlockRecord`,
  `BeaconNum2Hash`, `PlainValidatorState`, `ValidatorsHistory`, `ValidatorChangeSets`) and the
  `BeaconProvider` / `BeaconProviderWriter` traits (`crates/storage/storage-api/src/beacon.rs`).
- `crates/chainspec/src/spec.rs` — `N42` (testnet, chain id 1142) and `N42_DEVNET` (1143) specs with
  genesis JSON in `crates/chainspec/res/genesis/`.
- `crates/node/core/src/args/dev.rs` — N42 CLI flags: `--dev.consensus-signer-private-key`,
  `--dev.migrate-old-chain-data-from-db`, `--dev.migrate-old-chain-data-from-rpc`.
- `crates/ethereum/evm` — uses `recover_address()` for the block beneficiary instead of `header.beneficiary`.

`N42_CUSTOMIZATIONS.md` is the maintained (Chinese) inventory of these; update it when the set changes.

Two alloy crates are also forked and patched over crates.io: `crates/n42/alloy-rpc-types-{engine,beacon}`.

## Architecture

`bin/n42/src/main.rs` is the whole wiring story and is worth reading first. It:

- builds the node from `N42Node` (`crates/n42/engine-types/src/node.rs`), a reth `ComponentsBuilder`
  that keeps reth's Ethereum pool/executor but swaps in `N42ConsensusBuilder`, `N42PayloadServiceBuilder`,
  and `N42NetworkBuilder`;
- merges two custom RPC namespaces from `bin/n42/src/consensus_ext.rs`: `consensusExt` (auth transport —
  `propose`, `discard`, `get_snapshot`, `proposals`) and `consensusBeaconExt` (public transport —
  `submitVerification`, beacon block/state/validator queries);
- spawns either `N42Miner` (normal block production) or `N42Migrate` (when a `--dev.migrate-old-chain-data-*`
  flag is set) — they are mutually exclusive;
- runs an in-process pub/sub router (`pubsub-mem`) that bridges a tokio broadcast channel of
  `(UnverifiedBlock, Vec<BLSPubkey>)` onto per-validator topics keyed by hex pubkey.

Block production/verification loop: `N42Miner` (`crates/n42/consensus-client/src/miner.rs`, the largest
and most intricate file in the repo) builds a payload, seals it via APoS, broadcasts the `UnverifiedBlock`
to the validator set over pubsub, and collects BLS verification signatures returned through the
`consensusBeaconExt.submitVerification` RPC and the `verification_rx` channel before finalizing.

Key N42 crates:

| Crate | Role |
| --- | --- |
| `crates/n42/clique` | `APos` — the consensus engine: snapshots, signer voting, seal/verify_seal, wiggle timing. Implements reth's extended `Consensus`/`FullConsensus`. |
| `crates/n42/primitives` | Beacon-chain primitives: validators, committees, shuffling, snapshots, `safe_arith`. |
| `crates/n42/consensus-client` | Miner, beacon state machine, chain-data migration, validator networking, storage. |
| `crates/n42/engine-types` | `N42Node` and the consensus/network/payload component builders. |
| `crates/n42/engine-primitives` | Payload attribute builders (`N42PayloadAttributesBuilder`). |
| `crates/n42/consensus-traits`, `consensus-core`, `storage` | Extraction layer pulling N42 logic back out of the forked reth crates (see `docs/ARCHITECTURE.md`). |
| `crates/n42/mobile-sdk` | Validator key/deposit/exit tooling; `examples/mobile-sdk-test.rs` drives the e2e script; `build-aar.sh` + `ios/` for mobile builds. |
| `crates/n42/fusaka` | Fusaka (Prague EL + Osaka CL) hardfork constants, BLS12-381 and PeerDAS checks. |
| `crates/n42/{bmt-core,twig-core}` | QMDB state commitment: sparse binary Merkle tree and twig engine (Blake3). Ported from `../N42-26`; zero reth/mdbx coupling. `twig_core::qmdb_compat` carries gov5's key derivation, account encoding, proof codec, and portable-snapshot verifier. |
| `crates/n42/{h2-primitives,h2-wire,h2-consensus}` | HotStuff-2 interop: BLS + message types, the Go↔Rust v4 wire codec, and validator-set + finality verification. Ported from `../N42-26`; tested against gov5's byte-exact fixtures. |
| `crates/n42/mobile-verify` | Mobile verification formats: receipts, BLS attestations, twig/SBMT state proofs. Distinct from `mobile-sdk`, which is validator key/deposit tooling. |
| `crates/n42/h2-execution` | Execution-layer seam (`ExecutionLayer`: Engine API in alloy types, no reth types) plus the driver connecting HotStuff-2 to it. A concrete reth adapter is not yet written — see `docs/N42_26_PORT.md`. |
| `crates/n42/h2-net` | gov5-compatible GossipSub transport, the `/rpc/status/1/ssz_snappy` handshake (without which gov5 drops the peer), gov5's block-body topic (`block_gossip`: `/n42/<fork digest>/block/ssz_snappy`, RLP `[header, txs, verifiers, rewards]` — a proposal names only a hash, so without this followers cannot vote), gov5's `block_by_hash` fetch-on-miss and `bodies_by_range` sync RPCs (both served; by-hash also used), libp2p identify (go-libp2p-pubsub meshes only with identified peers), and a read-only finality observer. `cargo run -p n42-h2-net --example h2_observer -- --help`. The libp2p `secp256k1` feature is load-bearing — gov5 nodes use secp256k1 identities and the Noise handshake fails without it. |
| `crates/n42/n42-testing` | Integration tests for APoS signer voting — the suite CI runs. Tests live in `src/dev.rs` behind `#[cfg(test)]`, not in `tests/`. |
| `crates/n42/ef-tests` | Ethereum Foundation state/blockchain/transaction spec-test runner. |

## Sibling repos and ported code

Three N42 clients live side by side on this host, and code moves between them:

- `../N42-gov5` — the Go client (go-ethereum/Erigon-derived). Runs the
  production `mainnet_qmdb_staggered` 7-node HotStuff fleet and owns the
  byte-exact interop fixtures. Also has an `eth-el` mode (`--chain eth-mainnet`)
  and writes reth-format MDBX tables for cross-client work.
- `../N42-26` — the newer Rust client, on reth **2.4.1** (edition 2024, rustc
  1.97) with HotStuff-2 and QMDB. Depends on reth by local path (`../reth`).
- `../reth` — a checkout of the n42blockchain/reth fork with upstream tags
  fetched; `scripts/reth-sync.py` reads upstream revisions from it. This repo
  itself pins upstream paradigmxyz/reth by tag (`v2.5.1` as of 2026-08-27).

The `n42-{bmt-core,twig-core,h2-primitives,h2-wire,h2-consensus,mobile-verify,h2-net,h2-execution}`
crates came from `../N42-26` (`h2-net` is new, modelled on its `n42-network`;
`h2-execution` ports its EL seam and adds a driver). They are additive and wired into nothing —
the APoS node path is untouched. Read `docs/N42_26_PORT.md` before extending
them: it records what was renamed and why, the edition-2021 adaptations, what
was deliberately left behind, and the fixture SHAs that must match gov5.

Ported crates carry gov5 cross-client fixtures under `testdata/`. Those are
byte-exact contracts — compare by SHA-256 of raw bytes, never text-mode content.

```bash
cargo test -p n42-bmt-core -p n42-twig-core -p n42-h2-primitives -p n42-h2-wire \
           -p n42-h2-consensus -p n42-mobile-verify -p n42-h2-net \
           -p n42-h2-execution                                      # 464 tests
```

## Witness replay (new direction)

`docs/WITNESS_REPLAY_RUST_PLAN.md` records what gov5's `cmd/witness-replay` does
(stateless parallel re-execution of Ethereum mainnet from per-block witnesses,
inputs under `/data/blockchain/{witness,witness-geth,code-mdbx}`), its measured
numbers (49m48s / 376k CPU-s for 25.77M blocks with verification) and the plan
to beat them in Rust. gov5's witness is a positional read stream with no keys
(zero lookups at replay), so the Rust side records its own positional witness
with reth: `docs/patches/0001-feat-witness-record-*.patch` (reth branch
`witness-record`, crate `reth-witness`) adds a `StateReadObserver` to revm's
`State` and a per-block shadow `State` that decides what a fresh replayer will
read; `reth node --debug.witness-dir <DIR>` records during sync. `../pevm`
(reth 1.10.2) records the same positional witness block-parallel from a reth
archive (`pevm evm --witness-dir`, branch `witness-verify` adds verification);
recorder and replayer must share one revm version.

## Upgrading reth

The repo is on reth **v2.5.1** (upstream tag; revm 42, alloy 2.3, edition 2024).
`docs/RETH_2_4_1_UPGRADE.md` records the 1.11.0 → 2.4.1 move (22 of 121 reth
crates deleted or relocated; `reth-primitives-traits` now comes from crates.io).

Bumping to a newer reth: `scripts/reth-sync.py <old-rev> <new-rev>` three-way
merges every vendored crate in the patch table from the upstream checkout at
`../reth` (fetch the tag there first), lists conflicts and files to look at;
then replace the `tag = "vX.Y.Z"` on every reth entry in `Cargo.toml`, align the
shared crates.io versions with upstream's `[workspace.dependencies]`, run
`cargo update`, and fix the cascade. The 2.4.1 → 2.5.1 step took one conflict
(`providers/state/mod.rs`, our `macros` module next to upstream's removed
`overlay`), one deletion (`consistent_view.rs`, removed upstream), and one
renamed feature (`reqwest` 0.13: `rustls-tls` → `rustls`).


`docs/RETH_UPGRADE_GUIDE.md` and `patches/` describe the process (note: the guide's "current version"
section lags the actual pinned tag). The workflow is: bump every `tag = "vX.Y.Z"` in `[workspace.dependencies]`,
re-sync each vendored crate against the new upstream while re-applying the N42 deltas above, then fix the
cascade. `update.sh` generates/applies diffs between a sibling `../reth` checkout and the vendored crates.
`patches/v1.4.3-base/` holds the historical baseline diffs. `.upgrade-backup/n42-custom-files/` keeps copies
of the N42-only files so they can be restored after an upstream overwrite.

Commit convention in this repo is Conventional Commits (`fix:`, `chore:`, `test:`), and upgrade work happens
on `upgrade/reth-vX.Y.Z` branches merged into `main`.

## Conventions

- `[workspace.lints]` denies `unused_must_use` and `rust_2018_idioms` and warns on `missing_docs`,
  `missing_debug_implementations`, `unreachable_pub`, plus a large clippy nursery set. New crates should
  carry `[lints] workspace = true`.
- N42-authored files start with the `// Copyright (c) 2017-2025 N42 Contributors` / SPDX header.
- Recent commits have deliberately removed `unwrap`/`panic` from consensus and SDK paths; keep new code in
  `crates/n42/clique`, `consensus-client`, and `mobile-sdk` on `Result`-based error handling.
- Several top-level `*.md`/`*.txt` reports (`EF_TESTS_*`, `UPGRADE_STATUS.md`, `TEST_SUMMARY.txt`,
  `SECURITY_*`) are point-in-time snapshots from past upgrades — treat them as history, not current state.
- Much of `docs/` and `N42_CUSTOMIZATIONS.md` is written in Chinese.
