# Deferred execution for the N42 HotStuff-2 chain -- a proposal to the gov5 side

*2026-09-10, from the fleet7 campaign (`docs/FLEET7_PLAN_V3.md` phase D, section 5). A
cross-client rule change: nothing in it is decided by this repository alone. Numbers are the
seven-node bench on one box at the 163,000-transfer / ~147,000-account block shape.*

## 1. Why: the cycle is a sum, and the sum has a floor

Every follower executes a block before it votes on it. So a block's cycle is

    cycle = push (~35 ms) + slowest follower's import (~330-360) + vote/commit (~10)
          + proposal/seal/encode (~20-40) + straggler wait
          = ~540 ms median today (loop125: 56 blocks in 30 s, 296,936 TPS)

and the leader's build of the next block (~460 ms with build-on-seal) is hidden only because
it is shorter than that sum. Two things follow. The fixed part (~100 ms of push, votes, seal,
proposal) is a fifth of the cycle and does not shrink with per-transaction work. And the
follower's import and the leader's build are *serialised by the vote*: the leader cannot
propose N+1 until the followers have executed N, so however fast both sides become, the
cycle is import + fixed, never max(build, import).

At ~300 ms a side (plan v3 phase C) the cycle would be ~400 ms (75 blocks, ~400k); the
target is 1M, a 163 ms cycle at this block shape. No per-pass cut reaches it under the sum.

## 2. What: the header of N commits to the execution of N-1

The same idea as Ethereum's EIP-7862 (delayed execution): a block's header carries the
*post-state of its parent*, not its own.

- `stateRoot`, `receiptsRoot`, `logsBloom`, `gasUsed` (and the QMDB root the chain uses as
  `stateRoot`) in the header of block N are those of block N-1 after execution.
- Block N's own execution result appears in the header of N+1.
- The genesis header carries the genesis state (as now); block 1's header carries the genesis
  state too (nothing was executed before it); block 2's header is the first to carry an
  executed post-state (block 1's).

A follower votes on N once it has checked:

1. the proposal (leader, view, QC, committee evidence, signatures) -- as now;
2. the body is available and well-formed (transaction decode, gas limit, size) -- as now;
3. **the header's execution fields equal the follower's own result for N-1**, which it has:
   it executed N-1 during the previous round, in the time the vote round on N-1 took;
4. the transactions are *includable* without executing them: sender recovered (the Ed25519
   cache, or a batch verification), nonce is the next one for the sender in the post-state
   of N-1 plus this block's earlier transactions from the same sender, balance covers
   `gas_limit * max_fee + value` on the same basis, intrinsic gas fits. This is the check
   that keeps execution from ever failing a block (see 4).

Then it executes N while N+1 is being proposed and voted. The leader builds N+1 on its own
post-state of N the moment it seals N -- exactly what build-on-seal does today.

The cycle becomes

    cycle = max( leader build of N+1, followers' execution of N, network + votes + seal )

with the three overlapped, instead of their sum. At today's sides that is max(460, 360,
~130) = ~460 ms -> 65 blocks -> ~353k at this shape from the protocol alone; with the
phase-C sides at ~300 it is ~300 ms -> 100 blocks -> ~540k; and every further cut on
*either* side pays until the network floor.

## 3. What it changes, by component

| where | today | with deferred execution |
| --- | --- | --- |
| header profile (both clients) | execution fields of N | execution fields of N-1; block 1 repeats genesis |
| gov5 `VerifyHeader` / this node's `HotStuffConsensus` | recompute N, compare | compare against the stored result of N-1; check includability of N's transactions |
| the vote (`h2-consensus`) | "I executed N and it matches" | "N-1 executed as N says, and N is includable" |
| the leader's build | on its own post-state of N (build-on-seal) | unchanged |
| the follower's import | on the critical path before the vote | off it: after the vote, overlapped with the next round |
| finality of a transaction's *effects* | the block's commit | one block later (its post-state is committed by the header of N+1) |
| committee evidence (`parentBeaconRoot` link) | unchanged | unchanged |
| mobile receipts / state proofs (`mobile-verify`) | proof against header N's `stateRoot` for state after N | the proof for state after N is against header N+1's `stateRoot`; the receipt of a transaction in N is under `receiptsRoot` of N+1 |
| RPC `eth_getBlockByNumber` etc. | fields of N | fields describe N-1; the RPC layer can present "execution of N" from N+1 when it exists (EIP-7862 leaves them as the header has them) |
| sync / range import (`bodies_by_range`) | execute and compare per block | execute N, compare with header N+1 (one block of look-ahead; the tip's execution is unverified until the next block, as on Ethereum with 7862) |
| the invalid-block hook, `n42-init-snapshot` header/state pairing | pairs header N with state N | pairs header N with state N-1 (the snapshot tool takes the header of N+1 for state N) |

## 4. The rule that makes it safe: execution cannot fail a block

If a follower votes before executing, a block whose execution would fail must not exist, or
the chain would have committed to a state it cannot produce. EIP-7862's answer, adopted here:

- Inclusion is checked without execution (section 2, item 4): sender, nonce, balance for the
  worst case, intrinsic gas, gas limit sum. A block with a transaction that fails these is
  invalid *structurally* and is not voted for.
- Given those checks, execution of every included transaction succeeds in the sense that
  matters: it may revert, but it can be charged, its nonce advances, and the block's
  post-state is defined. A transaction that reverts is not a failure of the block.
- The block reward and the withdrawals (the flood's funding, the faucet) are applied in
  execution as now; they are part of the post-state the next header commits to.
- Base fee: unchanged, byte for byte. EIP-1559 derives `baseFeePerGas(N)` from the parent
  header's `gasUsed` and `gasLimit` fields *as the parent header carries them*; under the rule
  the parent's `gasUsed` field is the grandparent's executed gas, so the fee responds one block
  later than today and every existing base-fee check stays valid without a fork branch. The
  includability check reads the block's own `baseFeePerGas`, which the header carries as now.

The one thing deferred execution costs is that a transaction's *effects* are final one
block later than its inclusion: a wallet that waits for a commit today waits for the next
commit. At a 0.3-0.5 s cycle that is a small price; it should be stated in the mobile
receipt format (a receipt of N is proven under N+1).

## 5. What it does not change

- The QMDB root, its append semantics, the frozen-leaf commitment, the portable snapshot and
  the cross-client vectors: the root of state S is the same value; only which header carries
  it moves by one.
- The transaction types (0x50 Ed25519 included), the pool, the ingest, the gossip topics.
- The leader rotation, tenure, the straggler grace, the view timeouts.
- The committee, the evidence link, the Decide, the finality rule of HotStuff-2.

## 6. What to measure before deciding

On this bench, without any client change, the gain can be *bounded* by a follower that votes
before importing (`N42_VOTE_BEFORE_IMPORT=1` on the Rust validator: vote on the verified
proposal, import after, the commit's forkchoice deferred until the import lands -- unsafe,
for measurement only; loop128): that reads the cycle the protocol would give at today's
sides, and says whether the ~460 ms leader build then becomes the floor (in which case
phase A3's build cuts pay 1:1 again). If it reads ~65 blocks a window against 56, the
proposal is worth the cross-client work; if the leader's build or the network floor caps it
lower, the number says so before anyone changes a header profile.

**Measured (loop129, 2026-09-11):** with the import off the loop, the followers' votes are
collected in 5-40 ms instead of ~500, the commit follows within ~10 ms, and the leader's next
proposal comes at the bench's pacing: the cycle became the pacing (450 ms, 62-66 blocks a
window against 54-55) -- the coupling is exactly the difference the model predicts. What the
bench could not show is the TPS at that cadence: the box's ingest, sharing its cores with
seven followers now executing off the loop, supplied 130-150k transactions a second and the
blocks emptied (4.4M transactions over 62 blocks). The protocol's gain at full blocks is a
seven-machine measurement, or one with a supply that does not share the fleet's cores.

## 7. Open questions for the gov5 side

1. Header layout: reuse the existing fields with the shifted meaning (EIP-7862 style, no new
   fields, a fork-time switch), or add explicit `parentStateRoot` / `parentReceiptsRoot` and
   keep the old fields empty? The first keeps every tool's field names; the second keeps the
   old semantics readable.
2. The activation: a fork block number in the genesis `config` (`deferredExecutionBlock`),
   after which headers are read the new way; the block *at* the fork carries the state of
   its parent as executed under the old rule.
3. Sync: a range importer verifies N's execution against N+1; the tip's execution stays
   unverified for one block. Acceptable for the mobile verifier? (It already verifies the
   Decide, and a Decide on N+1 certifies the state after N.)
4. Whether gov5's `VerifyHeader` can cheaply produce the includability check (nonce and
   balance from the parent post-state for 163,000 senders) -- this node does it from the
   parallel sender groups it already builds.

## 8. The gov5 side's reading (2026-09-11, via the gov5 session)

Agreed in principle; their answers to section 7, and what they add:

1. **Header layout: reuse the fields, 7862 style, no new fields.** A hashed header field on
   their side lands in three codecs (RLP hash, proto/trailer, the compact storage codec) plus
   the mobile SDK, DATC and the proof tools; reuse has zero wire surface and keeps header
   hashes and every codec byte-compatible across clients. The cost is semantic and local: an
   `executed_root_of(N) = header(N+1).state_root` helper for state-as-of proofs, `eth_getProof`
   and the snapshot tool; the places that assume `header.Root` is the state after N (their
   Finalize root comparison at import, the miner's tree reload check, the QMDB applied marker,
   hotstuff-reset tooling) get the fork check. All fork-gated, all local.
2. **Activation: a timestamp fork, `deferredExecutionTime` in the genesis config** -- every
   gov5 gate is `header.Time` (MobileAnchorTime, PQPrecompilesTime, AIInferenceTime).
   **Fork invariant:** the first deferred header F carries the state after F-1 under the old
   rule, which is exactly `header(F-1).Root`, so `header(F).Root == header(F-1).Root` is the
   assert at the switch.
3. **Sync and the tip: acceptable.** Their range importer's per-block root check becomes
   "`header(N).Root` equals the executed root of N-1 I stored"; the tip's executed root sits
   unverified for one buffered header. The mobile anchor is unaffected (MobileRegistryRoot is a
   separate accumulator). One semantic shift to write down: a state divergence stops being
   "reject block N" and becomes "refuse to vote on N+1" -- N's transactions are committed, and
   the majority's execution result reaches consensus through N+1's QC. Their BAD BLOCK
   watchdog, own-unverified sibling mark and qs-hsreset assume root-at-N and need a pass;
   none is a blocker.
4. **Includability in VerifyHeader: cheap.** Sender recovery already precedes execution
   (pool sender hints + a 16M-slot sender cache: ~100 ms hinted for 163k, ~460 ms cold);
   nonce/balance from the parent post-state through their Block-STM workers' QMDB reads
   (~23k accounts across 16 goroutines in 4 ms; the worst case of 163k distinct senders
   ~30-40 ms). The pass: group by sender, nonces contiguous from the parent's, sum(value +
   gasLimit*feeCap) <= parent balance, intrinsic gas <= gasLimit, block gas sum <= limit --
   one read per sender. **The hard requirement it places on the follower: the parent
   post-state must be its own executed state of N-1, so a follower votes on N only after
   importing N-1 -- pipeline depth 1**, which is what makes the cycle max(build, import)
   rather than a deeper pipeline.

Their own numbers: the chained cycle is 1.5-1.9 s at 163k (follower import 0.8-1.1 s, seal to
QC ~1.4 s, leader build ~0.6 s), so max(build 0.6, import 1.0) instead of the sum would take it
from ~1.75 to ~1.1 s -- worth more than any single lever left on their list. gov5 already has a
chainspec gate `hotstuff.twoPhaseVoteGate` (R1 static vote, R2 commit vote held until import)
whose R1-only behaviour is the equivalent of this bench's `N42_VOTE_BEFORE_IMPORT=1`, so their
cycle floor can be measured before the rule change too. They offered to prototype the gov5 side
behind `deferredExecutionTime` on their worktree after their current round queue.

## 9. Agreed names and the split

- Genesis: `config.deferredExecutionTime` (u64 seconds; absent = never).
- Helper, both clients: `executed_root_of(n)` = the state root after block n = `header(n+1).state_root`
  once `header(n+1).timestamp >= deferredExecutionTime`, else `header(n).state_root`; likewise
  `executed_receipts_root_of`, `executed_logs_bloom_of`, `executed_gas_used_of`.
- The switch: for a header H with `H.timestamp >= deferredExecutionTime`, H's execution fields
  are the parent's executed values; the first such header F asserts `F.state_root ==
  parent.state_root` (the invariant of section 8.2). Headers before the fork are unchanged.
- The vote (both clients): a proposal for H is voted for once the follower has imported the
  parent, H's execution fields equal the follower's own result for the parent, and H's
  transactions pass the includability check against that post-state. Pipeline depth 1.
- Rust side: the chainspec field, `HotStuffConsensus` header validation, the builder's
  header assembly (the block's fields from the parent's `BuiltExecution`), the follower's
  direct import (compare against the stored result of the parent, then execute for the next
  header), the mobile receipt/proof binding (`mobile-verify`: state after N under N+1),
  `n42-init-snapshot` pairing, the RPC presentation. gov5 side: the mirror list of section 8.1,
  behind the same gate.
- A cross-client vector: a short chain across the fork (F-2 .. F+3) with every header's
  fields and roots, checked byte-for-byte by both clients' test suites.

## 10. Rust side, stage 1 (2026-09-11): the header semantics are in

Behind `config.deferredExecutionTime` (`reth_chainspec::qmdb::{deferred_execution_time,
deferred_execution_active_at}`):

- `n42_qmdb_reth::executed_fields`: a registry of what each block's execution produced
  (`ExecutedFields { state_root, receipts_root, logs_bloom, gas_used }` by block hash), fed
  by every path that executes a block -- the builder under the sealed hash, the follower's
  direct import, the engine's QMDB state-root job -- and seeded at startup from the persisted
  head (its header before the fork; the forest's root and the database's receipts after it).
- The builder (`default_n42_payload`): a header at or past the gate takes the parent's fields
  (`parent_executed_fields`: the parent's own header before the fork or for genesis, the
  registry otherwise; an unknown parent is a build error, never a guess) and records its own.
- `HotStuffConsensus::validate_header_against_parent`: at or past the gate the four fields
  must equal the parent's result (`DeferredExecutionError::{ParentUnknown, Mismatch}`);
  `validate_block_post_execution` records the block's receipt side instead of comparing it
  with its own header. The first header past the fork repeats its parent's fields by the same
  rule (section 8.2's invariant), with no special case.
- The follower's direct import and the engine's state-root job file the block's QMDB root and
  record it (`QmdbNodeState::insert_block_operations`); the engine job hands reth the header's
  root as the outcome, since reth compares the outcome with the header.
- Base fee: unchanged (section 4).
- Test: `n42-testing` `test_deferred_execution__headers_carry_the_parents_execution_across_the_fork`
  runs a QMDB dev chain with the fork at genesis: block 1 repeats the genesis fields, block N
  carries block N-1's root and gas, the registry holds each block's own result, and a restart
  restores the head's own root while its header carries its parent's.

- Cross-client vector: `crates/n42/n42-testing/testdata/deferred_execution_vectors.json`,
  written by that test with the fork two blocks in (F = 3, blocks 1..6 = F-2..F+3, transfers
  in blocks 2, 3 and 5): the genesis (header, alloc, hash), and per block its transactions
  (raw 2718), the full header as carried and the `executed` fields its own execution
  produced. Keys and timestamps are fixed, so the document is reproducible; the test
  compares every run with it (`N42_WRITE_VECTORS=1` rewrites it).

## 11. Rust side, stage 2 (2026-09-11): the vote before the import

From the fork on a follower's block goes through *check, vote, import* instead of *import,
vote*, and the next block's check overlaps this block's import:

- **Execution layer** (`bin/n42`, the direct import behind `N42_FOLLOWER_DIRECT_IMPORT=1`):
  a gated block is first checked without its parent -- header rules, body, sender recovery
  (the ingest's caches, the Ed25519 batches) -- then waits for the parent to land (a
  condvar bumped by every landing, polled every 20 ms for blocks the engine's own path
  imports, 10 s at most), checks its header's four fields against the parent's recorded
  result (`validate_header_against_parent` under the gate) and its transactions'
  includability on the parent's post-state (section 8.4's pass: per sender one account
  read on the worker pool, nonces contiguous, balance over value + gas at the fee cap,
  chain id, fee cap over the base fee, priority under the cap, a transfer's gas at least,
  the block's gas limits within the header's), and only then executes. The raw payload
  channel answers the check on a `CHECKED` frame (`raw_engine::reply::CHECKED`, an
  encoded VALID status) before the import's final answer on the same request; a block
  before the fork gets no such frame. Each request holds its own connection, so the next
  block's request goes out while this one executes.
- **Driver** (`n42-h2-execution`): `set_deferred_execution_time` from the genesis; a gated
  block is sent at once on a task, no queue -- the execution layer orders by parent -- and
  the task reports `ImportReport::Checked` when the frame arrives and `ImportReport::Done`
  with the import's verdict. Imports in flight and deferred commits are sets now. The
  execution-layer seam is `ExecutionLayer::new_payload_checked` (a oneshot for the check;
  the default drops it and the vote waits for the import, so an execution layer without
  the frame is safe, just unpipelined).
- **Consensus** (`n42-h2-consensus`): `ConsensusEvent::BlockChecked` releases the pending
  import-gated vote exactly as `BlockImported` does (the parent is remembered for the
  extends rule); the import event still follows and moves the node's head and build-ahead
  parent. `N42_VOTE_BEFORE_IMPORT=1` stays a bench flag for pre-fork chains.
- What a vote now attests: the parent's result as this node computed it, and that the block
  can execute on it. A block whose execution then fails here (an intrinsic-gas or
  state-dependent failure the includability pass does not see, EIP-8037's state gas among
  them) leaves this node without a recorded result for it, so it refuses to vote on the
  child (section 8.3's semantic shift), as an invalid block would be refused today.
- The leader's own block reaches its execution layer as a sealed header whose hash differs
  from the build's (the validator normalises the header): the handoff files the build's
  recorded result under the sealed hash too, as it already did the QMDB tree. Without it the
  leader's followers-to-be waited 10 s for a parent result that was there under the other
  hash (the first smoke run).
- Smoke test (2026-09-11, `scripts/fleet7.sh` on `n42_fleet7.json` with the fork at genesis,
  200 tx/s offered for 90 s, every node its own execution layer): 28 blocks at the 3 s
  interval, all seven at the same height and hash, every block voted for on its check (2-8
  ms after the body), 189 tx/s sealed, no rejection.
- loop132 A1 (the first bench leg with the fork at genesis) stalled at 3-6 blocks a window
  with a 10 s cycle: a follower's vote on N now precedes N's import, so the Decide for N
  arrives while N is still executing, and the validator's service dropped that commit as
  "a block the execution layer has not imported" -- N never got its forkchoice, never became
  canonical, and N+1's check waited the full parent timeout for a header the provider could
  not see. Fixed: a commit for a block whose import is in flight goes to the driver, which
  runs the forkchoice when the import lands. Blocks 1-81 (the base-fee decay, empty or small)
  had passed because their imports finished before the Decide; the smoke run passed for the
  same reason.
- Cycle: the follower's serial chain per block becomes the includability pass plus the
  execution (the stateless half of the check overlaps the previous import), and the leader
  gets the QC while the followers execute; the idle gap between a follower's import and the
  next body is gone. Measured by loop132 (`n42_fleet7_bench_deferred.json` =
  the bench genesis with `deferredExecutionTime: 0`, against the same binary on the
  ungated genesis).

## 12. Measured and adopted (2026-09-11 21:08)

loop132-135 (`NATIVE_FLEET7.md`): four defects of the pipeline, each visible only at the
bench tier -- a commit dropped while its block was importing, the far-ahead hold measuring
against a tip that moved only when an import landed, the leader's own result recorded under the
build's hash rather than the sealed one, and a new leader's build refused while its parent was
still importing -- and then, on the same binary, window 1 299,865 / 302,811 at 56 blocks against
293k ungated, window 2 +3-10%, the best round 22,200,112. The follower's check is ~130 ms, its
import ~400 ms beside the loop, the cycle's median 485 ms; the leader's build chain (~430 ms a
full block) is the cycle now. `n42_fleet7_bench.json` carries `deferredExecutionTime: 0`;
`n42_fleet7.json` and the devnet stay ungated until the gov5 side has the rule (sections 8-9).

## 13. Stage 3 (design, 2026-09-12): the leader seals before it finishes

With the follower off the critical path (section 12) the cycle is the leader's build: on a
full block ~430 ms, of which the parallel execution is ~60 and the rest is serial -- the fold
of the batches' state (~115), the finish (~110: post-execution changes, the bundle merge, the
hashed post-state, and the QMDB root ~57 beside the transactions root ~25), the assembly and
seal (~30). Under deferred execution a header carries the *parent's* execution fields, so
none of that serial work is needed to seal the block: the header needs the transactions root,
the parent's fields, the attributes and the gas limit. The leader can therefore seal right
after the parallel execution and the transactions root (~90 + 25 ms after the pull), publish,
and do the rest behind the seal.

- `default_n42_payload` takes an `early_seal` hook. With it, under the gate, when the parallel
  step filled the block (nothing for the serial loop, no blobs, no Amsterdam access list), the
  builder assembles the header itself -- `prepare` + transactions root + the parent's recorded
  fields (waited for, since the parent's own finish may still be running) + gas limit, base
  fee, withdrawals root, blob fields, `EMPTY_REQUESTS_HASH` -- seals it, files the block as
  *pending* in `built_executions`, hands the payload to the hook, and continues: the fold,
  the executor's finish (the rewards' withdrawals) and the bundle merge, then `state_ready`
  (the next build reads this post-state), then the hashed post-state, the QMDB root and the
  receipts root in parallel, then `complete` (the executed block for the engine's handoff,
  the block's own fields in `executed_fields`, the cached reads).
- `build_on_own` (build-on-seal, every block of a tenure but the first) runs the build on a
  thread and answers the validator with the early payload; the thread finishes behind it.
  The next `build_on_own` waits for the parent's `state_ready` (and its fields before the
  header), the own-block handoff for `complete`; the QMDB root of N+1 waits for N's tree.
- Expected chain per block: N's fold + merge (~150) then N+1's execution and root (~115), the
  parent's fields ready in time: ~280-300 ms a block against 480, i.e. the follower's chain
  (includability + import beside the loop, ~275) becomes the cycle again. On this box the
  supply (each node verifying every transaction at ~25 us) caps what that is worth in
  transactions; on a fleet with cores of its own it is the leader's 1.6x.
- The requests hash: a block of transfers produces no EIP-7685 requests, so the header is
  sealed with the empty hash and the finish asserts it; a chain with system-contract requests
  would defer `requests_hash` too, which section 9's rule does not yet say.
- Knob: `N42_SEAL_FIRST` (on by default since loop140; `0` turns it off; the gate is a
  precondition). Measured on loop137-140 (`NATIVE_FLEET7.md`): the seal path from the
  build's start 472 -> 398 -> 295 ms as the fold's cache inserts, the results' sort and the
  transactions root left it; window 1 306k / 317k against 297-303k, the round +2.7%, no
  failed finish in ~600 early seals; the cycle is the 450 ms pacing now.


## 14. gov5 proposal (2026-09-12): a BLAKE3 binary transactions root, fork-gated

*Left here by the gov5 session because the cross-session message was not
approved before it expired. Not decided by either side alone.*

Both clients spend ~70 ms a block on the transactions root today: the
Ethereum keccak Merkle-Patricia trie (`alloy_consensus::proofs::
calculate_transaction_root` here, `DeriveShaErigon` in gov5 since a73a7258;
NATIVE_FLEET7 notes 72-78 ms of serial keccak, gov5's follower body phase is
~100 ms). The chain's state is a BLAKE3 binary forest; the body root should
follow it.

Definition (gov5 `hash.Blake3BinaryRoot`, tests and vectors in
`common/hash/txroot_blake3_test.go`):

    leaf_i = blake3(0x00 || enc_i)          enc_i = the transaction's consensus encoding (the EIP-2718 bytes the MPT hashed)
    node   = blake3(0x01 || left || right)   pairs in list order, level by level
    an odd node at the end of a level is carried up unchanged (RFC 6962)
    root   = the last node; a one-entry list's root is its leaf
    empty  = blake3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262

Vectors: one entry `[01 02 03]` ->
`f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32`;
three entries `[01]`, `[02]`, `[03]` ->
`d304c27fcf395c7809a2733472060a0d2bc7eb7bf014d2377dc3be20f74fb098` (odd
promotion). O(n) hashes, every level parallel: 163k leaves 70 -> 6 ms.

Activation: chain config `txRootBlake3Time` (timestamp fork, absent = never);
`header.timestamp >= it` -> the binary root, else the MPT. Receipts root
unchanged for now. gov5 runs it behind the gate (`TxRootAt(txs,
header.Time)` on production and validation) with a bench-only env override
on its seven-node fleet until the chainspec carries the field. If the
domain bytes, the odd-promotion rule or the empty root should differ for
the Rust side, say so here; otherwise it goes into the shared chainspec
proposal next to `deferredExecutionTime`.

## 15. gov5 side implemented behind the gate (2026-09-12 04:00 EDT)

gov5 commit 93e31b89 on n42blockchain/N42 main: `config.deferredExecutionTime`
(`IsDeferredExecution`), the stored per-block execution result
(`rawdb.ExecutedResult`: root, receipts root, bloom, gas used, by block hash),
`ExecutedResultOfHeader` (a pre-fork header's own fields, so the fork
invariant needs no special case), the import's pre-execution header check,
the builder stamping the parent's result (own sealed record for chained
builds, stored result, or the parent header before the fork), and the vote:
the sync layer's `CheckDeferredBlock` (header vs the parent's stored result,
parent is the applied head, includability -- per sender nonces contiguous
from the state, sum(value + gas x fee cap) within the balance, intrinsic
gas within the gas limit, block gas within the limit) raises
`EventBlockChecked`; the engine votes when the block is checked AND its
JustifyQC block is imported, in either order, never twice. Not yet: the
RPC/proof presentation of `executed_root_of`, the mobile receipt binding
under N+1. First fleet round (35zzn, gov5-only) queued behind the BLAKE3
tx-root round with a bench-only gate override; the fixture (F-2..F+3) from
your side will go into our header tests as agreed.
