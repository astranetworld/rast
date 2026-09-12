// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The consensus/execution loop, end to end against an in-memory Engine API.
//!
//! These drive the real [`ExecutionDriver`] and assert on the Engine API calls it
//! makes, in order. What is being pinned is the *protocol* between consensus and
//! execution — most importantly that a follower's vote is released only after its
//! own execution layer accepted the block, and never when it did not.

use alloy_primitives::{B256, U256};
use alloy_rpc_types_engine::{PayloadAttributes, PayloadStatusEnum};
use n42_h2_consensus::EngineOutput;
use n42_h2_execution::{
    ElCall, ExecutionDriver, ExecutionLayer, ExecutionPath, MockBehaviour, MockExecutionLayer,
};

const GENESIS: B256 = B256::ZERO;

fn attrs() -> PayloadAttributes {
    PayloadAttributes {
        // upstream additions; N42 drives neither
        slot_number: None,
        target_gas_limit: None,
        timestamp: 1_700_000_001,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Default::default(),
        withdrawals: None,
        parent_beacon_block_root: None,
    }
}

fn execute(hash: B256) -> EngineOutput {
    EngineOutput::ExecuteBlock(hash)
}

fn committed(hash: B256) -> EngineOutput {
    EngineOutput::BlockCommitted {
        view: 1,
        block_hash: hash,
        // The driver never inspects the QC; the genesis sentinel keeps the
        // fixture honest without fabricating signatures.
        commit_qc: n42_h2_primitives::QuorumCertificate::genesis(),
        validator_changes: None,
    }
}

#[tokio::test]
async fn leader_builds_a_block_and_can_serve_its_own_execute_request() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);

    let built = driver.build_block(attrs(), 1).await.unwrap();
    assert_eq!(built.number, 1);

    // Building is FCU-with-attrs to start it (an FCU without attributes never
    // would) and resolve to collect it. Importing is a separate call, made
    // after the proposal is on the wire, because it costs a second full
    // execution of the block and the fleet should not be waiting through it.
    assert!(matches!(
        el.calls().as_slice(),
        [ElCall::ForkchoiceUpdatedWithAttrs(_), ElCall::ResolvePayload(_)]
    ));

    // But it must still happen, and this is the assertion that says so.
    // `getPayload` builds a block without inserting it, and the leader never
    // receives its own proposal back over gossip, so nothing else ever imports
    // it. Without this the block is committed by consensus and then rejected by
    // the leader's own execution layer, which answers the commit's
    // forkchoiceUpdated with SYNCING and leaves the chain stuck at the parent —
    // which is exactly what a live node did.
    driver.import_own_block(&built).await.unwrap();
    assert!(matches!(
        el.calls().as_slice(),
        [
            ElCall::ForkchoiceUpdatedWithAttrs(_),
            ElCall::ResolvePayload(_),
            ElCall::NewPayload(_)
        ]
    ));

    // Our own proposal must not require a network round trip to execute.
    assert!(driver.has_payload(&built.hash));
    let action = driver.handle_output(&execute(built.hash)).await;
    assert_eq!(action.imported_block(), Some(built.hash));
}

#[tokio::test]
async fn follower_votes_only_after_its_own_execution_layer_accepts() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0xab);

    // A proposal arrives before the body: consensus must not get an import event.
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.missing_block(), Some(hash));
    assert!(action.imported_block().is_none());
    assert!(el.calls().is_empty(), "must not call the EL without a payload");

    // Body arrives; now the block executes and the vote is released.
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.imported_block(), Some(hash));
    assert_eq!(el.calls(), vec![ElCall::NewPayload(hash)]);
    assert_eq!(driver.head(), hash);
}

#[tokio::test]
async fn an_invalid_block_never_releases_a_vote() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        new_payload_status: PayloadStatusEnum::Invalid {
            validation_error: "state root mismatch".into(),
        },
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0xcd);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));

    let action = driver.handle_output(&execute(hash)).await;
    assert!(action.imported_block().is_none(), "voted on an invalid block");
    let (rejected, reason) = action.rejection().expect("expected a rejection");
    assert_eq!(rejected, hash);
    assert!(reason.contains("state root mismatch"), "{reason}");
    // Head must not move to a block the EL rejected.
    assert_eq!(driver.head(), GENESIS);
}

#[tokio::test]
async fn a_syncing_execution_layer_defers_rather_than_voting_blind() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        new_payload_status: PayloadStatusEnum::Syncing,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el, GENESIS);
    let hash = B256::repeat_byte(0xef);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));

    // SYNCING is not a verdict: the EL has not executed the block, so voting
    // would be voting blind. The driver must ask the caller to retry.
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.missing_block(), Some(hash));
    assert!(action.imported_block().is_none());
    assert_eq!(driver.head(), GENESIS);
}

#[tokio::test]
async fn an_execution_layer_error_is_a_rejection_not_an_import() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        new_payload_error: Some("engine unavailable".into()),
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el, GENESIS);
    let hash = B256::repeat_byte(0x11);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));

    let action = driver.handle_output(&execute(hash)).await;
    assert!(action.imported_block().is_none());
    assert!(action.rejection().unwrap().1.contains("engine unavailable"));
}

#[tokio::test]
async fn unsupported_or_non_live_paths_fail_before_the_engine_adapter() {
    let el = MockExecutionLayer::new();
    let hash = B256::repeat_byte(0x12);

    let pevm = el
        .new_payload_for(
            ExecutionPath::LIVE_PEVM,
            MockExecutionLayer::payload_for(hash, 1),
        )
        .await
        .unwrap_err();
    assert!(pevm.to_string().contains("live_pevm"), "{pevm}");

    let historical_build = el
        .fork_choice_updated_with_attrs_for(
            ExecutionPath::HISTORICAL_SEQUENTIAL,
            alloy_rpc_types_engine::ForkchoiceState {
                head_block_hash: GENESIS,
                safe_block_hash: GENESIS,
                finalized_block_hash: GENESIS,
            },
            attrs(),
        )
        .await
        .unwrap_err();
    assert!(
        historical_build
            .to_string()
            .contains("historical_sequential"),
        "{historical_build}"
    );
    assert!(el.calls().is_empty(), "rejected paths reached the raw adapter");
}

#[tokio::test]
async fn commit_finalizes_head_safe_and_finalized_together() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0x22);
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    driver.handle_output(&execute(hash)).await;

    let action = driver.handle_output(&committed(hash)).await;
    assert_eq!(action.finalized_block(), Some(hash));
    assert_eq!(driver.finalized(), hash);
    assert_eq!(driver.head(), hash);

    let fcu = el
        .calls()
        .into_iter()
        .find_map(|c| match c {
            ElCall::ForkchoiceUpdated(state) => Some(state),
            _ => None,
        })
        .expect("commit must send a forkchoice update");
    // HotStuff-2 finality is immediate: a committed block is head, safe, and
    // finalized in one step — there is no separate justification round to wait for.
    assert_eq!(fcu.head_block_hash, hash);
    assert_eq!(fcu.safe_block_hash, hash);
    assert_eq!(fcu.finalized_block_hash, hash);

    // A committed block's payload is dropped: it will never be re-executed.
    assert!(!driver.has_payload(&hash));
}

#[tokio::test]
async fn a_build_that_never_starts_reports_the_status_not_a_bare_failure() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        start_builds: false,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el, GENESIS);

    let err = driver.build_block(attrs(), 1).await.unwrap_err();
    assert!(err.to_string().contains("no payload id"), "{err}");
    // An operator needs to know whether the EL said VALID or SYNCING here.
    assert!(err.to_string().contains("Valid"), "{err}");
}

#[tokio::test]
async fn outputs_that_do_not_concern_execution_are_ignored() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);

    let action = driver
        .handle_output(&EngineOutput::ViewChanged { new_view: 7 })
        .await;
    assert!(matches!(action, n42_h2_execution::DriverAction::Ignored));
    assert!(el.calls().is_empty(), "a view change must not touch the EL");
}

#[tokio::test]
async fn the_payload_cache_is_bounded() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el, GENESIS).with_max_cached_payloads(2);

    let a = B256::from(U256::from(1));
    let b = B256::from(U256::from(2));
    let c = B256::from(U256::from(3));
    for (i, h) in [a, b, c].into_iter().enumerate() {
        driver.cache_payload(h, MockExecutionLayer::payload_for(h, i as u64));
    }

    // A peer that pushes bodies we never asked for must not grow this forever.
    assert!(!driver.has_payload(&a), "oldest payload should have been evicted");
    assert!(driver.has_payload(&b));
    assert!(driver.has_payload(&c));
}

/// A follower can hear the Decide before the body channel delivers the
/// block. The commit then runs a forkchoice for a block the engine does
/// not have, which the engine answers SYNCING. That is not "done": the
/// commit waits for the import and runs once it lands (loop149: taken as
/// done, the block was imported but never canonical, the next block's
/// direct import could not see its parent, and the node fell 3 s a block
/// behind for the rest of the leg).
#[tokio::test]
async fn a_commit_the_engine_does_not_have_yet_waits_for_the_import() {
    let el = MockExecutionLayer::with_behaviour(MockBehaviour {
        forkchoice_status: PayloadStatusEnum::Syncing,
        ..Default::default()
    });
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0x33);

    // The Decide first: the forkchoice is refused with SYNCING, nothing is final.
    let action = driver.handle_output(&committed(hash)).await;
    assert_eq!(action.finalized_block(), None);
    assert_eq!(driver.head(), GENESIS);

    // The body arrives and the block imports: the engine now has it, and the
    // commit that waited runs.
    el.set_behaviour(MockBehaviour::default());
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.imported_block(), Some(hash));
    assert_eq!(driver.head(), hash);
    let forkchoices = el
        .calls()
        .into_iter()
        .filter(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
        .count();
    assert_eq!(forkchoices, 2, "the refused forkchoice and the one after the import");
}

/// The same order with an engine that answers the early forkchoice as if it
/// had the block (loop152: no SYNCING, and the block still never became
/// canonical): the import that follows a commit of the same block runs the
/// forkchoice again.
#[tokio::test]
async fn a_commit_that_ran_before_the_import_is_repeated_when_the_import_lands() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let hash = B256::repeat_byte(0x44);
    let action = driver.handle_output(&committed(hash)).await;
    assert_eq!(action.finalized_block(), Some(hash));
    driver.cache_payload(hash, MockExecutionLayer::payload_for(hash, 1));
    let action = driver.handle_output(&execute(hash)).await;
    assert_eq!(action.imported_block(), Some(hash));
    let forkchoices = el
        .calls()
        .into_iter()
        .filter(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
        .count();
    assert_eq!(forkchoices, 2, "the early forkchoice and the one after the import");
}

/// Block after block with the Decide ahead of the body (loop154: the
/// follower's forkchoice for the next block ran before this one's import
/// landed, so no forkchoice ever ran after an import): every commit that
/// ran before its block arrived is repeated when that block's import lands.
#[tokio::test]
async fn commits_ahead_of_their_imports_are_each_repeated_when_the_import_lands() {
    let el = MockExecutionLayer::new();
    let mut driver = ExecutionDriver::new(el.clone(), GENESIS);
    let a = B256::repeat_byte(0x55);
    let b = B256::repeat_byte(0x56);
    driver.handle_output(&committed(a)).await;
    driver.handle_output(&committed(b)).await;
    driver.cache_payload(a, MockExecutionLayer::payload_for(a, 1));
    driver.cache_payload(b, MockExecutionLayer::payload_for(b, 2));
    assert_eq!(driver.handle_output(&execute(a)).await.imported_block(), Some(a));
    assert_eq!(driver.handle_output(&execute(b)).await.imported_block(), Some(b));
    let forkchoices_to = |hash: B256| {
        el.calls()
            .into_iter()
            .filter(|c| matches!(c, ElCall::ForkchoiceUpdated(state) if state.head_block_hash == hash))
            .count()
    };
    assert_eq!(forkchoices_to(a), 2, "A: the early forkchoice and the one after its import");
    assert_eq!(forkchoices_to(b), 2, "B: the same, although A's import landed after B's commit");
}
