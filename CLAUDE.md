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

**Round 43 (2026-09-07) found that the flood's ingest path had every worker's senders paying the same
recipients: a "full" 163k block touched ~13,000 accounts, so every number below through round 42 was
measured on that shape (fixed in ab3c79240; `docs/NATIVE_FLEET7.md` round 43). With the flood fixed a full
block touches ~147,000 accounts and the fleet reads 163-168k TPS at a 0.97-1.0 s cycle with the round-41
configuration, ~200k at 0.8 s with `N42_PARALLEL_BUILD=1 N42_FOLLOWER_GRAFT=1` (the leader's transfers in
parallel per-sender batches grafted onto the block's state; the follower's groups grafted the same way;
both off by default, both bookended: 201-206k against 172-182k), and **239-247k at 0.65-0.68 s, 17.4-17.7M transactions a round without a stall**, with the
parallel state commit on top (QMDB leaves and hashed post-state built on the worker pool; on by default
since loop82, `N42_PARALLEL_STATE_COMMIT=0` turns it off), the provider's chunked hashed post-state, and
**`F7_BLOCK_INTERVAL_MS=450` and `F7_STRAGGLER_GRACE_MS=600`** (both bench defaults now): at 300 ms pacing the
leader outran the two followers outside the quorum and every tenure handover stalled 10-40 s; the grace makes the
leader wait for every validator's vote (followers send a progress vote for a block imported after its view passed),
and with it 450 ms pacing read 244k with no stall on a box where plain 450 ms collapsed (loop92). The queue holds an
own block's transactions until the chain settles its height (a block consensus never committed used to lose them). The follower's import (622-657 ms:
QMDB root 190, hashed 75, convert 55, execution 183-224) is the cycle; the cycle is linear in the accounts a
block touches (0.40 s + 2.8 us per account: 393k TPS at ~400 accounts, 337k at 20k, 283k at 67k, 201k at 145k;
`docs/BLOCK_SHAPE_SURVEY.md`, which also places the shape against Ethereum, BNB, Polygon and Tron).
`F7_FLOOD_LEGACY_RECIPIENTS=1` reproduces the pre-round-43 flood for comparison. The stall near block 200-222
under load is the page cache being reclaimed for the thp:always heaps (round 43, continued).**
**Previous record (2026-09-07, round 41, Ed25519 0x50 transactions, 13k-recipient blocks): 396,601 / 342,288 TPS** (loop65C2, every block full at a 0.411 s cycle; 385,742 on loop65C3; the record configuration below plus `F7_FLOOD_ALG=ed25519 N42_ALTSIG_SENDER_CACHE=4194304 N42_ED25519_BATCH=128`, see `docs/NATIVE_FLEET7.md` rounds 40-41). Previous secp256k1 record (2026-09-05, round 39): 365,399 / 343,885 TPS (win1/win2 of loop53Q300a at pacing 300,
0.423 s cycle; pacing 350 reads 357k twice, 400 reads 349-353k; the same legs without huge pages for
the heap 310k / 293k) with the round-39 configuration plus `N42_TX_INGEST_RECOVER_PARALLEL=20
N42_TX_QUEUE_RUN=64 MALLOC_CONF=thp:always N42_FOLLOWER_PARALLEL=1 TOKIO_WORKER_THREADS=8
F7_BLOCK_INTERVAL_MS=300` and `--pertx 8000` (the parallel follower and eight tokio workers: 367k on
window 1, 338k on window 3, loop63); the
leader's own block reaches its execution layer as a sealed header (`request::OWN_BLOCK`, 57 ms
instead of 90-130).
`MALLOC_CONF=thp:always` gives the execution layer's jemalloc heap 2 MB pages under the host's THP
`madvise` (the builder's execution is 194-207 ms with them, 225-241 without); the third window is
lost to direct compaction until the host runs `defrag=defer`. Host rules that matter: THP `madvise`
(not `always`: with it the fleet's reads faulted by the million), swap empty, and
`/data/blockchain/wr-logs/BOX-CLAIM-PROTOCOL.md` for sharing the box. **The old "one warm-up leg"
rule was the huge-page pool** (round 43, loop86-98): the seven `thp:always` heaps take every free
order-9 block in the flood's first seconds, and a leg whose heaps then sit on 2 MB pages reads
239-253k on window 1 where one that fell back to 4 KB pages reads 177-196k -- the first leg after a
build, a profile, a datc run or minutes of idling was the slow kind. `fleet7-bench.sh` now runs
`scripts/dropcache.py` (stale file pages, no root) and `scripts/hugeprep.py 60` (MADV_COLLAPSE, a
~80 GB pool in 5 s) before every leg (`F7_DROP_CACHE=0` / `F7_HUGEPREP=0` turn them off) and prints
a `memory :` header line; a leg whose pool was under ~30 GB is not comparable.
`docs/NATIVE_FLEET7.md` "Where it stands today".
**Transaction type 0x50 (Ed25519, `docs/spec/N42_TX_0x50.md`)** is implemented in `crates/n42/tx-types`
(`N42TxEnvelope` = reth's envelope + `AltSig`; the node runs on `N42Primitives`, `N42EvmConfig`,
`N42EngineTypes`, `N42PooledTransaction`, `N42RpcTypes` from `crates/n42/engine-types`). It is admitted only
on a chain whose genesis `config` has `"altSigTx": true` (both fleet7 genesis files do; the devnet does not):
the pool refuses the type, the ingest drops it and block validation rejects it elsewhere. The ingest verifies
0x50 signatures in batches (`N42_ED25519_BATCH`, default 64) and records senders in a shared cache
(`N42_ALTSIG_SENDER_CACHE` entries, default 2^20) that the follower import and the engine's payload
conversion read. `tx_flood --alg ed25519` floods with 0x50 transfers; `F7_FLOOD_ALG=ed25519` passes it
through `fleet7-bench.sh`. Test vectors: `crates/n42/tx-types/testdata/altsig_vectors.json`, checked
independently by `docs/sigbench/altsig_vectors.py`.
The next step is scheduled in `docs/ROADMAP_ED25519_TX.md` (an Ed25519 transaction type with batch
verification to lift the supply bound, then the chain cycle); the research behind it, with a signature
benchmark for this host, is `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md` and `docs/sigbench/`.

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
