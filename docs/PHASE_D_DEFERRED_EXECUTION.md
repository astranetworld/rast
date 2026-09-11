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
- Fee cap and base fee: the includability check uses the block's base fee, which the header
  carries as now (it depends on the parent's `gasUsed`, which is the parent's own field; with
  deferred execution the parent's `gasUsed` is in the *grandparent's* successor... to keep
  `baseFee` computable at proposal time, the header keeps a `gasUsed` of N-1, which the
  proposer knows because it executed N-1 -- the same value the followers check).

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
