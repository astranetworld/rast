//! A basic Ethereum payload builder implementation.

/*
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
*/
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![allow(clippy::useless_let_if_seq)]

use alloy_consensus::{Transaction, Typed2718};
use alloy_primitives::{B256, U256};
use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_errors::{BlockExecutionError, BlockValidationError};
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome},
    ConfigureEvm, Evm, NextBlockEnvAttributes,
};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig};
use reth_payload_builder::EthBuiltPayload;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_revm::{database::StateProviderDatabase, db::State};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    error::{Eip4844PoolTransactionError, InvalidPoolTransactionError},
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction,
};
use revm::context_interface::Block as _;
use revm::Database as _;
use std::sync::Arc;
use tracing::{debug, trace, warn};

//mod config;
//pub use config::*;

//pub mod validator;
//pub use validator::EthereumExecutionPayloadValidator;

use reth_primitives_traits::SealedBlock;
//use n42_engine_primitives::{N42PayloadAttributes, N42PayloadBuilderAttributes};
use reth_basic_payload_builder::{BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig};
use reth_chain_state::CanonStateSubscriptions;
use n42_consensus_traits::SignerManager;
use n42_qmdb_reth::{changes_from_execution, QmdbNodeState};
use reth_trie::updates::TrieUpdates;
use reth_consensus::{ConsensusError, FullConsensus};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_node_api::PayloadBuilderFor;
use reth_node_api::PrimitivesTy;
use reth_node_builder::{
    components::{ConsensusBuilder, PayloadBuilderBuilder, PayloadServiceBuilder},
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use std::future::Future;

// Historical catch-up never enters the payload builder. Until a qualified
// live PEVM builder exists, every invocation here is the live sequential path.
const LIVE_EVM_PATH: &str = "live_sequential";

// wrapper

// Payload component configuration for the Ethereum node.

//use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_node_api::TxTy;
use reth_node_builder::{PayloadBuilderConfig, PayloadTypes};

/// A basic ethereum payload service builder marker.
///
/// Note: In v1.5.0, consensus is built separately and shared via NodeComponents.
/// The actual consensus instance will be passed through the N42PayloadServiceBuilder.
#[derive(Clone, Debug, Default)]
pub struct EthereumPayloadBuilderWrapper;

impl EthereumPayloadBuilderWrapper {
    /// Create a new wrapper.
    pub fn new() -> Self {
        Self
    }
}
// wrapper

// reth/crates/ethereum/payload/src/config.rs
use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M;
use reth_primitives_traits::constants::GAS_LIMIT_BOUND_DIVISOR;

/*
/// Settings for the Ethereum builder.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EthereumBuilderConfig {
    /// Desired gas limit.
    pub desired_gas_limit: u64,
    /// Waits for the first payload to be built if there is no payload built when the payload is
    /// being resolved.
    pub await_payload_on_missing: bool,
}

impl Default for EthereumBuilderConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EthereumBuilderConfig {
    /// Create new payload builder config.
    pub const fn new() -> Self {
        Self { desired_gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M, await_payload_on_missing: true }
    }

    /// Set desired gas limit.
    pub const fn with_gas_limit(mut self, desired_gas_limit: u64) -> Self {
        self.desired_gas_limit = desired_gas_limit;
        self
    }

    /// Configures whether the initial payload should be awaited when the payload job is being
    /// resolved and no payload has been built yet.
    pub const fn with_await_payload_on_missing(mut self, await_payload_on_missing: bool) -> Self {
        self.await_payload_on_missing = await_payload_on_missing;
        self
    }
}

impl EthereumBuilderConfig {
    /// Returns the gas limit for the next block based
    /// on parent and desired gas limits.
    pub fn gas_limit(&self, parent_gas_limit: u64) -> u64 {
        calculate_block_gas_limit(parent_gas_limit, self.desired_gas_limit)
    }
}
*/

/// Calculate the gas limit for the next block based on parent and desired gas limits.
/// Ref: <https://github.com/ethereum/go-ethereum/blob/88cbfab332c96edfbe99d161d9df6a40721bd786/core/block_validator.go#L166>
pub fn calculate_block_gas_limit(parent_gas_limit: u64, desired_gas_limit: u64) -> u64 {
    let delta = (parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR).saturating_sub(1);
    let min_gas_limit = parent_gas_limit - delta;
    let max_gas_limit = parent_gas_limit + delta;
    desired_gas_limit.clamp(min_gas_limit, max_gas_limit)
}
// reth/crates/ethereum/payload/src/config.rs

type BestTransactionsIter<Pool> = Box<
    dyn BestTransactions<Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>>,
>;

/// Ethereum payload builder
#[derive(Debug, Clone, PartialEq, Eq)]
//pub struct N42PayloadBuilder<Pool, Client, EvmConfig = EthEvmConfig, Cons>
pub struct N42PayloadBuilder<Pool, Client, EvmConfig, Cons> {
    /// Client providing access to node state.
    client: Client,
    /// Transaction pool.
    pool: Pool,
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
    /// Payload builder configuration.
    builder_config: EthereumBuilderConfig,
    /// consensus
    cons: Cons,
    /// The QMDB state this node commits to. `None` means the chain is a
    /// Merkle-Patricia chain and reth computes the root.
    qmdb: Option<QmdbNodeState>,
}

impl<Pool, Client, EvmConfig, Cons> N42PayloadBuilder<Pool, Client, EvmConfig, Cons> {
    /// `N42PayloadBuilder` constructor.
    pub const fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        builder_config: EthereumBuilderConfig,
        cons: Cons,
    ) -> Self {
        Self {
            client,
            pool,
            evm_config,
            builder_config,
            cons,
            qmdb: None,
        }
    }

    /// Commits built blocks to `qmdb` instead of the Merkle-Patricia trie.
    ///
    /// Must be the same state the engine validator checks against: the block
    /// this builds is validated by this node's own execution layer next, and a
    /// root computed from one forest and checked against another disagrees
    /// even when both are right.
    pub fn with_qmdb(mut self, qmdb: Option<QmdbNodeState>) -> Self {
        self.qmdb = qmdb;
        self
    }
}

// Default implementation of [PayloadBuilder] for unit type
impl<Pool, Client, EvmConfig, Cons> PayloadBuilder
    for N42PayloadBuilder<Pool, Client, EvmConfig, Cons>
where
    EvmConfig: ConfigureEvm<
        Primitives = EthPrimitives,
        NextBlockEnvCtx = NextBlockEnvAttributes,
        BlockAssembler = EthBlockAssembler<Client::ChainSpec>,
        BlockExecutorFactory = reth_evm::eth::EthBlockExecutorFactory<
            reth_evm_ethereum::RethReceiptBuilder,
            Arc<Client::ChainSpec>,
            reth_evm::eth::EthEvmFactory,
        >,
    >,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks + reth_chainspec::EthChainSpec + reth_evm::eth::spec::EthExecutorSpec>
        + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    Cons: FullConsensus<EthPrimitives> + SignerManager + Clone + Unpin + 'static,
{
    // upstream: PayloadBuilder::Attributes is now a PayloadAttributes
    type Attributes = EthPayloadAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        let started = std::time::Instant::now();
        let result = default_n42_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
            self.cons.clone(),
            self.qmdb.clone(),
        );
        let outcome = if result.is_ok() { "ok" } else { "error" };
        metrics::histogram!(
            "n42_evm_path_duration_ms",
            "path" => LIVE_EVM_PATH,
            "phase" => "payload_build",
        )
        .record(started.elapsed().as_secs_f64() * 1_000.0);
        metrics::counter!(
            "n42_evm_path_calls_total",
            "path" => LIVE_EVM_PATH,
            "phase" => "payload_build",
            "outcome" => outcome,
        )
        .increment(1);
        result
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        if self.builder_config.await_payload_on_missing {
            MissingPayloadBehaviour::AwaitInProgress
        } else {
            MissingPayloadBehaviour::RaceEmptyPayload
        }
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<EthBuiltPayload, PayloadBuilderError> {
        // upstream added execution_cache and state_root_handle; this path shares
        // neither with the engine, so both are None.
        let args = BuildArguments::new(
            Default::default(),
            None,
            None,
            config,
            Default::default(),
            None,
        );

        default_n42_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
            self.cons.clone(),
            self.qmdb.clone(),
        )?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// Constructs an Ethereum transaction payload using the best transactions from the pool.
///
/// Given build arguments including an Ethereum client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
#[inline]
pub fn default_n42_payload<EvmConfig, Client, Pool, F, Cons>(
    evm_config: EvmConfig,
    client: Client,
    pool: Pool,
    builder_config: EthereumBuilderConfig,
    args: BuildArguments<EthPayloadAttributes, EthBuiltPayload>,
    best_txs: F,
    cons: Cons,
    qmdb: Option<QmdbNodeState>,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<
        Primitives = EthPrimitives,
        NextBlockEnvCtx = NextBlockEnvAttributes,
        BlockAssembler = EthBlockAssembler<Client::ChainSpec>,
        BlockExecutorFactory = reth_evm::eth::EthBlockExecutorFactory<
            reth_evm_ethereum::RethReceiptBuilder,
            Arc<Client::ChainSpec>,
            reth_evm::eth::EthEvmFactory,
        >,
    >,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks + reth_chainspec::EthChainSpec + reth_evm::eth::spec::EthExecutorSpec>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    F: FnOnce(BestTransactionsAttributes) -> BestTransactionsIter<Pool>,
    Cons: FullConsensus<EthPrimitives> + SignerManager + Clone + Unpin + 'static,
{
    // From the very top: the state provider and the cached reads are fetched
    // before anything is executed, and were outside every earlier timing.
    let build_started = std::time::Instant::now();
    let BuildArguments {
        mut cached_reads,
        config,
        cancel,
        best_payload,
        // upstream additions this builder does not use
        execution_cache: _,
        state_root_handle: _,
    } = args;
    let PayloadConfig {
        parent_header,
        // upstream additions: the payload id moved off the attributes onto the config
        parent_block_info: _,
        payload_id,
        attributes,
    } = config;

    let state_provider = client.state_by_block_hash(parent_header.hash())?;
    let state = StateProviderDatabase::new(&state_provider);
    // The block access list, when the chain is past Amsterdam.
    //
    // EIP-7928, and the reason to build one here is not the EIP: reth executes
    // an incoming block in parallel when it carries an access list and serially
    // when it does not (`payload_validator.rs::bal_path_eligible`). A builder
    // that omits it produces blocks every node then validates one transaction
    // at a time.
    //
    // This is the line reth's own `default_ethereum_payload` has and this
    // builder did not, which is why `getPayloadV6` answered
    // `MissingBlockAccessList` on a chain where Amsterdam was demonstrably
    // active -- the forkchoice had already refused attributes without EIP-7843's
    // slot number.
    let is_amsterdam = client.chain_spec().is_amsterdam_active_at_timestamp(attributes.timestamp);
    let mut db = State::builder()
        .with_database(cached_reads.as_db_mut(state))
        .with_bundle_update()
        .with_bal_builder_if(is_amsterdam)
        .build();

    // Get signer address from consensus to use as coinbase (beneficiary)
    // This ensures consistency between payload builder and engine tree execution
    let coinbase = match cons.get_signer_address() {
        Ok(Some(addr)) => {
            debug!(target: "payload_builder", signer_address=?addr, "using signer address as coinbase");
            addr
        }
        Ok(None) => {
            // The normal case on a HotStuff chain: the leader names the
            // beneficiary, and a local signer key must not override it.
            debug!(target: "payload_builder", "no signer address configured; using suggested_fee_recipient");
            attributes.suggested_fee_recipient
        }
        Err(e) => {
            warn!(target: "payload_builder", error=?e, "Failed to get signer address, using suggested_fee_recipient");
            attributes.suggested_fee_recipient
        }
    };
    debug!(target: "payload_builder", ?coinbase, suggested_fee_recipient=?attributes.suggested_fee_recipient, "using coinbase for payload building");

    let chain_spec = client.chain_spec();
    // A HotStuff chain's blocks follow gov5's header profile: the beneficiary
    // is the fee recipient the leader named (gov5 sets Coinbase to the
    // signer), the ommers hash and difficulty are zero, and the receipts
    // root is gov5's keccak-of-receipts rather than a trie. The view and
    // the seal are stamped by the validator process after the build.
    let hotstuff = n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(chain_spec.genesis()).is_ok();

    // What `builder_for_next_block` does, with this repo's assembler in place
    // of reth's: see `assembler` for what that saves and why.
    let next_attributes = NextBlockEnvAttributes {
        // EIP-7843; APoS does not drive slots
        slot_number: None,
        timestamp: attributes.timestamp,
        suggested_fee_recipient: coinbase,
        prev_randao: attributes.prev_randao,
        gas_limit: builder_config.gas_limit(parent_header.gas_limit),
        parent_beacon_block_root: attributes.parent_beacon_block_root,
        withdrawals: attributes.withdrawals.clone().map(Into::into),
        extra_data: Default::default(),
    };
    let evm_env = evm_config
        .next_evm_env(&parent_header, &next_attributes)
        .map_err(PayloadBuilderError::other)?;
    let evm = evm_config.evm_with_env(&mut db, evm_env);
    let block_ctx = evm_config
        .context_for_next_block(&parent_header, next_attributes)
        .map_err(PayloadBuilderError::other)?;
    // The QMDB root is computed inside assembly, beside the transactions
    // trie, and collected from here afterwards.
    let qmdb_root: Arc<std::sync::Mutex<Option<Result<n42_qmdb_reth::PreparedBlock, String>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let mut assembler = crate::assembler::N42BlockAssembler::new(EthBlockAssembler::new(chain_spec.clone()), hotstuff);
    if let Some(state) = &qmdb {
        assembler = assembler.with_qmdb_root(crate::assembler::QmdbRootJob {
            state: state.clone(),
            parent: parent_header.hash(),
            prague: chain_spec.is_prague_active_at_timestamp(attributes.timestamp),
            out: qmdb_root.clone(),
        });
    }
    let mut builder: reth_evm::execute::BasicBlockBuilder<'_, EvmConfig::BlockExecutorFactory, _, _, EthPrimitives> = reth_evm::execute::BasicBlockBuilder {
        executor: evm_config.create_executor(evm, block_ctx.clone()),
        ctx: block_ctx,
        assembler,
        parent: &parent_header,
        transactions: Vec::new(),
    };

    debug!(target: "payload_builder", id=%payload_id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");
    // Timed in phases, because at the 163,000-transaction tier this function
    // is the largest single item on the fleet's serial chain (~740 ms of a
    // 2.3 s cycle) and "execution" was assumed to be most of it. The sibling
    // Rust client's breakdown at the same tier says otherwise: EVM 229 ms,
    // pool 57, block assembly 162. Which of those this builder spends its time
    // on decides what to fix, and guessing has been wrong before.
    let mut pool_ns: u128 = 0;
    let mut exec_ns: u128 = 0;
    let setup_took = build_started.elapsed();
    let mut stale_txs: u64 = 0;
    let mut cumulative_gas_used = 0;
    let block_gas_limit: u64 = builder.evm_mut().block().gas_limit();
    let base_fee = builder.evm_mut().block().basefee();

    debug!(target: "payload_builder", ?block_gas_limit, ?base_fee, "payload builder block config");

    let mut best_txs = best_txs(BestTransactionsAttributes::new(
        base_fee,
        builder
            .evm_mut()
            .block()
            .blob_gasprice()
            .map(|gasprice| gasprice as u64),
    ));
    // Tried and measured inert: `best_txs.no_updates()`, dropping the
    // iterator's live feed of new transactions. The pool phase stayed at
    // 66-82 ms a block either way, so the cost is the ordered sets
    // themselves, not what arrives during the build.
    let mut tx_count = 0u64;
    let mut total_fees = U256::ZERO;

    let mut header = cons
        .prepare(&parent_header)
        .map_err(|err| PayloadBuilderError::Internal(err.into()))?;
    if hotstuff {
        header.beneficiary = coinbase;
    }

    builder.apply_pre_execution_changes().map_err(|err| {
        warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
        PayloadBuilderError::Internal(err.into())
    })?;

    let mut block_blob_count = 0;
    let blob_params = chain_spec.blob_params_at_timestamp(attributes.timestamp);
    let max_blob_count = blob_params
        .as_ref()
        .map(|params| params.max_blob_count)
        .unwrap_or_default();

    loop {
        let pool_at = std::time::Instant::now();
        let Some(pool_tx) = best_txs.next() else { break };
        pool_ns += pool_at.elapsed().as_nanos();
        tx_count += 1;
        debug!(target: "payload_builder", tx_count, tx_hash=?pool_tx.hash(), gas_limit=pool_tx.gas_limit(), "processing transaction from pool");

        // ensure we still have capacity for this transaction
        if cumulative_gas_used + pool_tx.gas_limit() > block_gas_limit {
            // we can't fit this transaction into the block, so we need to mark it as invalid
            // which also removes all dependent transaction from the iterator before we can
            // continue
            best_txs.mark_invalid(
                &pool_tx,
                InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit),
            );
            continue;
        }

        // check if the job was cancelled, if so we can exit early
        if cancel.is_cancelled() {
            return Ok(BuildOutcome::Cancelled);
        }

        // A transaction the chain has already mined, still in the pool because
        // the pool hears of a canonical block a little after the execution
        // layer has it. A build started the moment its parent was imported --
        // the build a leader with a tenure runs ahead of its next view --
        // finds every one of the parent's transactions still pending, and
        // executing each only to fail on its nonce cost 1.5-3 s at 163,000 a
        // block. The account is read from the same state the execution would
        // read it from, cached after the first transaction of each sender.
        // Skipped rather than marked invalid: marking drops the sender's later
        // transactions with it, and those are exactly the ones this block wants.
        if let Ok(Some(account)) = builder.evm_mut().db_mut().basic(pool_tx.sender()) {
            if pool_tx.nonce() < account.nonce {
                stale_txs += 1;
                continue;
            }
        }

        // convert tx to a signed transaction
        let tx = pool_tx.to_consensus();

        // There's only limited amount of blob space available per block, so we need to check if
        // the EIP-4844 can still fit in the block
        if let Some(blob_tx) = tx.as_eip4844() {
            let tx_blob_count = blob_tx.tx().blob_versioned_hashes.len() as u64;

            if block_blob_count + tx_blob_count > max_blob_count {
                // we can't fit this _blob_ transaction into the block, so we mark it as
                // invalid, which removes its dependent transactions from
                // the iterator. This is similar to the gas limit condition
                // for regular transactions above.
                trace!(target: "payload_builder", tx=?tx.hash(), ?block_blob_count, "skipping blob transaction because it would exceed the max blob count per block");
                best_txs.mark_invalid(
                    &pool_tx,
                    InvalidPoolTransactionError::Eip4844(
                        Eip4844PoolTransactionError::TooManyEip4844Blobs {
                            have: block_blob_count + tx_blob_count,
                            permitted: max_blob_count,
                        },
                    ),
                );
                continue;
            }
        }

        let exec_at = std::time::Instant::now();
        let executed = builder.execute_transaction(tx.clone());
        exec_ns += exec_at.elapsed().as_nanos();
        let gas_used = match executed {
            Ok(gas_used) => gas_used,
            Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                error, ..
            })) => {
                if error.is_nonce_too_low() {
                    // if the nonce is too low, we can skip this transaction
                    trace!(target: "payload_builder", %error, ?tx, "skipping nonce too low transaction");
                } else {
                    // if the transaction is invalid, we can skip it and all of its
                    // descendants
                    trace!(target: "payload_builder", %error, ?tx, "skipping invalid transaction and its descendants");
                    best_txs.mark_invalid(
                        &pool_tx,
                        InvalidPoolTransactionError::Consensus(
                            InvalidTransactionError::TxTypeNotSupported,
                        ),
                    );
                }
                continue;
            }
            // this is an error that we should treat as fatal for this attempt
            Err(err) => return Err(PayloadBuilderError::evm(err)),
        };

        // add to the total blob gas used if the transaction successfully executed
        if let Some(blob_tx) = tx.as_eip4844() {
            block_blob_count += blob_tx.tx().blob_versioned_hashes.len() as u64;

            // if we've reached the max blob count, we can skip blob txs entirely
            if block_blob_count == max_blob_count {
                best_txs.skip_blobs();
            }
        }

        // update add to total fees
        let miner_fee = tx
            .effective_tip_per_gas(base_fee)
            .expect("fee is always valid; execution succeeded");
        // EIP-8037 split gas into execution and state components; fees and the
        // block's cumulative counter both track the execution gas.
        let tx_gas_used = gas_used.tx_gas_used();
        total_fees += U256::from(miner_fee) * U256::from(tx_gas_used);
        cumulative_gas_used += tx_gas_used;
    }

    debug!(target: "payload_builder", tx_count, ?cumulative_gas_used, ?total_fees, "payload builder finished processing transactions");
    let loop_done = build_started.elapsed();

    // check if we have a better block
    if !is_better_payload(best_payload.as_ref(), total_fees) {
        // Release db
        drop(builder);
        // can skip building the block
        return Ok(BuildOutcome::Aborted {
            fees: total_fees,
            cached_reads,
        });
    }

    // On a QMDB chain the state root is not reth's to compute. The builder is
    // handed a zero root so it skips the Merkle-Patricia computation; the real
    // root comes from the forest, over the bundle execution left behind, and
    // replaces the zero in the header below. The block hash follows from the
    // sealed header, so the tree is filed under it only once that is known.
    let (
        BlockBuilderOutcome {
            execution_result,
            block,
            block_access_list,
            hashed_state,
            trie_updates,
        },
        qmdb_prepared,
        finish_took,
        root_took,
    ) = match &qmdb {
        Some(state) => {
            let finish_at = std::time::Instant::now();
            let outcome =
                builder.finish(&state_provider, Some((B256::ZERO, TrieUpdates::default())))?;
            let finish_took = finish_at.elapsed();
            let root_at = std::time::Instant::now();
            // Computed during assembly (see `assembler`); the fallback below
            // is for an assembler that did not run the job, which does not
            // happen, and it is cheaper to keep than to reason about.
            let prepared = match qmdb_root.lock().unwrap_or_else(|p| p.into_inner()).take() {
                Some(Ok(prepared)) => prepared,
                Some(Err(err)) => return Err(PayloadBuilderError::other(std::io::Error::other(err))),
                None => state
                    .compute(
                        parent_header.hash(),
                        &changes_from_execution(
                            &db.bundle_state,
                            chain_spec.is_prague_active_at_timestamp(attributes.timestamp),
                        ),
                    )
                    .map_err(PayloadBuilderError::other)?,
            };
            (outcome, Some(prepared), finish_took, root_at.elapsed())
        }
        None => {
            let finish_at = std::time::Instant::now();
            let outcome = builder.finish(&state_provider, None)?;
            (outcome, None, finish_at.elapsed(), std::time::Duration::ZERO)
        }
    };
    let finished_at = build_started.elapsed();

    let requests = chain_spec
        .is_prague_active_at_timestamp(attributes.timestamp)
        .then(|| execution_result.requests.clone());
    // The bundle and the receipts, kept for the sealed block's import. Taken
    // here, after the QMDB changes were read from it, and moved rather than
    // cloned: 163,000 receipts are not free to copy on the build's own path.
    let execution_output = Arc::new(reth_execution_types::BlockExecutionOutput {
        state: db.take_bundle(),
        result: execution_result,
    });

    // Blob sidecars, in whichever variant the pool holds them. Kept as the
    // variant and not flattened to EIP-4844: the Osaka `getPayload` envelope
    // carries cell proofs and refuses an EIP-4844-shaped bundle outright — even
    // an empty one — and reth reports that refusal as "unknown payload", which
    // reads like the build never happened.
    let mut blob_sidecars = reth_ethereum_engine_primitives::BlobSidecars::Empty;
    if chain_spec.is_cancun_active_at_timestamp(attributes.timestamp) {
        let raw_sidecars = pool
            .get_all_blobs_exact(
                block
                    .body()
                    .transactions()
                    .filter(|tx| tx.is_eip4844())
                    .map(|tx| *tx.tx_hash())
                    .collect(),
            )
            .map_err(PayloadBuilderError::other)?;
        for sidecar in raw_sidecars {
            blob_sidecars.push_sidecar_variant(Arc::unwrap_or_clone(sidecar));
        }
    }

    header.state_root = match &qmdb_prepared {
        Some(prepared) => prepared.root,
        None => block.header().state_root,
    };
    header.transactions_root = block.header().transactions_root;
    header.receipts_root = if hotstuff {
        crate::hotstuff_consensus::gov5_receipt_root_bloom(&execution_output.result.receipts).0
    } else {
        block.header().receipts_root
    };
    if hotstuff {
        header.ommers_hash = B256::ZERO;
        header.difficulty = U256::ZERO;
    }
    header.logs_bloom = block.header().logs_bloom;
    header.gas_limit = block.header().gas_limit;
    header.gas_used = block.header().gas_used;
    header.base_fee_per_gas = block.header().base_fee_per_gas;
    header.withdrawals_root = block.header().withdrawals_root;
    header.blob_gas_used = block.header().blob_gas_used;
    header.excess_blob_gas = block.header().excess_blob_gas;
    header.requests_hash = block.header().requests_hash;

    header.timestamp = attributes.timestamp;
    header.mix_hash = attributes.prev_randao;
    header.parent_beacon_block_root = attributes.parent_beacon_block_root;

    let block_number = header.number;

    // seal
    cons.seal(&mut header)
        .map_err(|err| PayloadBuilderError::Internal(err.into()))?;

    // Keep the recovered senders: EthBuiltPayload now takes a RecoveredBlock, and
    // re-recovering them from signatures here would be pure waste.
    let senders = block.senders().to_vec();
    let sealed_block = SealedBlock::seal_parts(header, block.into_block().body);
    let block_hash = SealedBlock::hash(&sealed_block);
    if let (Some(state), Some(prepared)) = (&qmdb, qmdb_prepared) {
        // Now the hash is known, the tree can be filed. Validation of this same
        // block, moments from now, finds it there and agrees by construction.
        state
            .insert(block_hash, block_number, prepared)
            .map_err(PayloadBuilderError::other)?;
    }
    let _ = cons.set_cached_reads(block_hash, cached_reads.clone());

    let recovered: Arc<reth_primitives_traits::RecoveredBlock<reth_ethereum_primitives::Block>> =
        Arc::new(reth_primitives_traits::RecoveredBlock::new_sealed(sealed_block, senders));
    crate::built_executions::remember(
        block_hash,
        crate::built_executions::BuiltExecution {
            block: recovered.clone(),
            execution_output,
            hashed_state: Arc::new(hashed_state),
            trie_updates: Arc::new(trie_updates),
        },
    );

    // The EIP-7928 access list, RLP-encoded, when the builder made one.
    //
    // This used to be `None` with a comment saying APoS does not produce one,
    // which was true until the state above was given a BAL builder. Leaving it
    // `None` after that is worse than not building it: the list exists, is
    // thrown away here, `getPayloadV6` answers `MissingBlockAccessList`, and on
    // an Amsterdam chain the leader cannot produce a block at all.
    //
    // It is also what decides how every node executes the block. reth takes the
    // parallel path for a block that carries one and the serial path for a
    // block that does not, and says nothing either way.
    let block_access_list: Option<alloy_primitives::Bytes> =
        block_access_list.map(|bal| alloy_rlp::encode(&bal).into());
    // At info only for blocks big enough to matter; an empty block every
    // 250 ms would otherwise be a line every 250 ms.
    let total = build_started.elapsed();
    let assemble_ms = total.saturating_sub(finished_at).as_millis() as u64;
    if tx_count >= 1000 {
        tracing::info!(
            target: "payload_builder",
            txs = tx_count,
            gas = cumulative_gas_used,
            stale = stale_txs,
            setup_ms = setup_took.as_millis() as u64,
            pool_ms = (pool_ns / 1_000_000) as u64,
            exec_ms = (exec_ns / 1_000_000) as u64,
            loop_ms = loop_done.as_millis() as u64,
            finish_ms = finish_took.as_millis() as u64,
            root_ms = root_took.as_millis() as u64,
            assemble_ms,
            total_ms = total.as_millis() as u64,
            "payload build phases"
        );
    }
    let payload = EthBuiltPayload::new(recovered, total_fees, requests, block_access_list)
        // add blob sidecars from the executed txs
        .with_sidecars(blob_sidecars);

    Ok(BuildOutcome::Better {
        payload,
        cached_reads,
    })
}

/// A custom payload service builder that supports the custom engine types
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct N42PayloadServiceBuilder<CB> {
    /// The consensus builder to create consensus instances.
    consensus_builder: CB,
    /// The QMDB state built blocks commit to, on a chain that declares it.
    qmdb: Option<QmdbNodeState>,
}

impl<CB: Default> Default for N42PayloadServiceBuilder<CB> {
    fn default() -> Self {
        Self {
            consensus_builder: CB::default(),
            qmdb: None,
        }
    }
}

impl<CB> N42PayloadServiceBuilder<CB> {
    /// Create a new [`N42PayloadServiceBuilder`] with a consensus builder.
    pub const fn new(consensus_builder: CB) -> Self {
        Self {
            consensus_builder,
            qmdb: None,
        }
    }

    /// Commits built blocks to `qmdb`. See [`N42PayloadBuilder::with_qmdb`].
    pub fn with_qmdb(mut self, qmdb: Option<QmdbNodeState>) -> Self {
        self.qmdb = qmdb;
        self
    }
}

impl<Node, Pool, EvmConfig, CB> PayloadServiceBuilder<Node, Pool, EvmConfig>
    for N42PayloadServiceBuilder<CB>
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
    <Node::Types as NodeTypes>::Payload: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = EthPayloadAttributes,
    >,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    CB: ConsensusBuilder<Node> + Clone + Send + Sync,
    CB::Consensus: FullConsensus<EthPrimitives> + SignerManager + Clone + Unpin + 'static,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: EvmConfig,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>> {
        // Build consensus using the consensus builder
        let consensus = self.consensus_builder.clone().build_consensus(ctx).await?;

        // Build payload builder with consensus
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let gas_limit = conf.gas_limit_for(chain);

        let payload_builder = N42PayloadBuilder::new(
            ctx.provider().clone(),
            pool.clone(),
            EthEvmConfig::new(ctx.chain_spec()),
            EthereumBuilderConfig::new().with_gas_limit(gas_limit),
            consensus,
        )
        .with_qmdb(self.qmdb.clone());

        let builder_conf = ctx.config().builder.clone();

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(builder_conf.interval)
            .deadline(builder_conf.deadline)
            .max_payload_tasks(builder_conf.max_payload_tasks);

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
        );
        let (payload_service, payload_service_handle) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor()
            .spawn_critical_task("payload builder service", Box::pin(payload_service));

        Ok(payload_service_handle)
    }
}

/*
/// The type responsible for building custom payloads
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct N42PayloadBuilder<EvmConfig = EthEvmConfig> {
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
}

impl<EvmConfig> N42PayloadBuilder<EvmConfig> {
    /// `N42PayloadBuilder` constructor.
    pub const fn new(evm_config: EvmConfig) -> Self {
        Self { evm_config }
    }
}
*/
