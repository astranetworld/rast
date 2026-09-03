#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use consensus_client::migrate::N42Migrate;
use consensus_client::miner::N42Miner;
use n42::engine_ext::{N42EngineApiServer, N42EngineExt};
use n42::consensus_ext::{
    ConsensusBeaconExt, ConsensusBeaconExtApiServer, ConsensusExt, ConsensusExtApiServer,
};
use n42::cli::Cli;
use n42_clique::UnverifiedBlock;
use n42_engine_primitives::N42PayloadAttributesBuilder;
use n42_engine_types::N42Node;
use n42_primitives::BLSPubkey;
use pubsub_mem::{publish, router_loop, Event, RouterMsg};
use n42_qmdb_reth::{state_scheme, N42ChainSpecParser, QmdbNodeState, StateScheme};
use reth_provider::{BlockHashReader, BlockNumReader, CanonStateSubscriptions};
use reth_node_builder::{FullNodeComponents, NodeHandle};
use reth_node_core::primitives::AlloyBlockHeader;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

const DEFAULT_BLOCK_TIME_SECS: u64 = 8;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    let (verification_tx, verification_rx) = mpsc::channel(100);
    let (broadcast_tx, _broadcast_rx) = broadcast::channel::<(UnverifiedBlock, Arc<Vec<BLSPubkey>>)>(100);
    let broadcast_tx_clone_for_miner = broadcast_tx.clone();

    // Create router channel for pubsub
    let (router_tx, router_rx) = mpsc::channel::<RouterMsg<UnverifiedBlock>>(100);
    let router_tx_clone = router_tx.clone();
    let router_tx_for_bridge = router_tx.clone();
    let broadcast_rx_for_bridge = broadcast_tx.subscribe();

    // Shared consensus instance holder
    let consensus_holder: std::sync::Arc<
        std::sync::Mutex<
            Option<
                std::sync::Arc<
                    dyn reth_consensus::FullConsensus<reth_ethereum_primitives::EthPrimitives>
                        + Send
                        + Sync,
                >,
            >,
        >,
    > = std::sync::Arc::new(std::sync::Mutex::new(None));
    let consensus_holder_clone = consensus_holder.clone();

    if let Err(err) =
        Cli::<N42ChainSpecParser>::parse().run(async move |builder, _extra_args| {
            info!(target: "reth::cli", "Launching node");

            // Start the pubsub router loop (must be inside async context)
            tokio::spawn(async move {
                debug!(target: "reth::cli", "Starting pubsub router loop");
                router_loop(router_rx).await;
            });

            // Bridge: forward messages from broadcast channel to pubsub router
            let mut broadcast_rx_for_bridge = broadcast_rx_for_bridge;
            tokio::spawn(async move {
                debug!(target: "reth::cli", "Starting broadcast-to-pubsub bridge");
                while let Ok((unverified_block, target_pubkeys)) = broadcast_rx_for_bridge.recv().await {
                    debug!(
                        target: "reth::cli",
                        block_number = unverified_block.blockbody.header().number(),
                        num_validators = target_pubkeys.len(),
                        "Broadcasting block to validators"
                    );
                    // Send to each validator's topic (pubkey hex)
                    for pubkey in target_pubkeys.iter() {
                        let topic = hex::encode(pubkey);
                        let event = Event {
                            topic: topic.clone(),
                            payload: unverified_block.clone(),
                        };
                        publish(&router_tx_for_bridge, event).await;
                        debug!(target: "reth::cli", ?topic, "Published block to validator topic");
                    }
                }
                debug!(target: "reth::cli", "Broadcast-to-pubsub bridge ended");
            });

            // Which state commitment this chain uses is declared in its genesis,
            // the same way gov5 reads it. A QMDB chain gets one forest, shared by
            // the payload builder and the engine validator, and persisted under
            // the datadir so a restart continues the same append history.
            let chain = builder.config().chain.clone();
            let qmdb = match state_scheme(&chain.genesis) {
                StateScheme::Qmdb => {
                    let dir = builder.config().datadir().data_dir().join("qmdb");
                    info!(target: "reth::cli", dir = %dir.display(), "chain declares the QMDB state commitment");
                    Some(QmdbNodeState::new(chain, dir))
                }
                StateScheme::Mpt => None,
            };
            let qmdb_for_startup = qmdb.clone();

            let NodeHandle {
                node,
                node_exit_future,
            } = builder
                .node(N42Node::with_qmdb(qmdb))
                .extend_rpc_modules(move |ctx| {
                    let consensus = ctx.node().consensus().clone();
                    let provider = ctx.provider().clone();

                    // Store consensus reference for later use
                    *consensus_holder_clone.lock().unwrap() =
                        Some(std::sync::Arc::new(consensus.clone()));

                    let beacon_ext = ConsensusBeaconExt {
                        consensus: consensus.clone(),
                        provider: provider.clone(),
                        verification_tx,
                        router_tx: router_tx_clone,
                    };
                    let ext = ConsensusExt {
                        consensus,
                        provider,
                    };

                    // The raw getPayload, beside the Engine API on the auth
                    // transport. See `engine_ext`.
                    let raw_endpoint = std::env::var("N42_PAYLOAD_SERVE")
                        .ok()
                        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok());
                    let engine_ext = N42EngineExt {
                        payloads: ctx.node().payload_builder_handle().clone(),
                        raw_endpoint,
                    };

                    // now we merge our extension namespace into all configured transports
                    ctx.auth_module.merge_auth_methods(ext.into_rpc())?;
                    ctx.auth_module.merge_auth_methods(engine_ext.into_rpc())?;
                    ctx.modules.merge_configured(beacon_ext.into_rpc())?;

                    info!(target: "reth::cli", "consensus rpc extension enabled");

                    Ok(())
                })
                .launch_with_debug_capabilities()
                .await?;

            // Get the stored consensus instance
            let consensus = consensus_holder
                .lock()
                .unwrap()
                .clone()
                .expect("consensus should be set");

            let node_config_dev = node.config.clone().dev();
            // The forest can only be restored once the database is open and the
            // head is known, which is now; and it has to be ready before anything
            // produces or validates a block, which is what follows.
            if let Some(qmdb) = &qmdb_for_startup {
                let info = node.provider.chain_info()?;
                let head_hash = node
                    .provider
                    .block_hash(info.best_number)?
                    .ok_or_else(|| eyre::eyre!("no hash for head block {}", info.best_number))?;
                qmdb.initialize((info.best_number, head_hash))?;
                info!(target: "reth::cli", block = info.best_number, %head_hash, "QMDB state ready");

                // Follow the canonical chain so the persisted head keeps up with
                // the database's. Lagging is tolerable — only the tip matters,
                // and every tree in between was filed at validation.
                let mut canonical = node.provider.subscribe_to_canonical_state();
                let follower = qmdb.clone();
                tokio::spawn(async move {
                    loop {
                        match canonical.recv().await {
                            Ok(notification) => {
                                let behind = canonical.len();
                                if behind > 8 {
                                    warn!(target: "reth::cli", behind, "canonical subscriber lag: qmdb head follower");
                                }
                                let tip = notification.tip().hash();
                                if let Err(error) = follower.on_canonical(tip) {
                                    error!(target: "reth::cli", %error, "QMDB head could not follow the canonical chain");
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(target: "reth::cli", skipped, "QMDB head follower fell behind canonical notifications");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }

            let consensus_signer_private_key = node_config_dev.dev.consensus_signer_private_key;
            let signer_address = if let Some(signer_private_key) = &consensus_signer_private_key {
                let eth_signer: PrivateKeySigner = signer_private_key.to_string().parse().unwrap();
                Some(eth_signer.address())
            } else {
                None
            };

            // The raw payload channel for the validator, loopback only. See
            // `payload_serve`.
            if let Ok(addr) = std::env::var("N42_PAYLOAD_SERVE") {
                match addr.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let payloads = node.payload_builder_handle.clone();
                        let engine = node.add_ons_handle.beacon_engine_handle.clone();
                        // Our own sealed blocks go in with the build's execution
                        // rather than being executed again; see payload_serve.
                        let reuse = (std::env::var("N42_NO_OWN_BLOCK_REUSE").is_err()).then(|| {
                            let chain_spec = node.chain_spec();
                            let profile = n42_engine_types::engine_validator::header_profile_for(&chain_spec);
                            n42::payload_serve::OwnBlockReuse {
                                validator: std::sync::Arc::new(
                                    n42_engine_types::engine_validator::N42EngineValidator::new(chain_spec, profile),
                                ),
                                qmdb: qmdb_for_startup.clone(),
                                inserts: reth_node_builder::executed_inserts::sender(),
                                // Opt-in (N42_PRUNE_POOL_ON_IMPORT=1), measured and not
                                // adopted: removing a block's 163,000 transactions from
                                // reth's pool costs 260-293 ms under its write lock -- the
                                // same per-transaction removal the pool's own maintenance
                                // pays later -- so doing it on the import path moves the
                                // cost onto the critical path rather than removing it.
                                import_foreign: (std::env::var("N42_FOLLOWER_DIRECT_IMPORT").is_ok()).then(|| {
                                    let provider = node.provider.clone();
                                    let evm_config = node.evm_config.clone();
                                    let senders_cache = node.evm_config.sender_recovery_cache.clone();
                                    let carry: std::sync::Arc<n42::follower_import::CarriedReads> = Default::default();
                                    let qmdb = qmdb_for_startup.clone();
                                    let consensus = consensus.clone();
                                    let chain_spec = node.chain_spec();
                                    std::sync::Arc::new(move |sealed: reth_primitives_traits::SealedBlock<reth_ethereum_primitives::Block>| {
                                        n42::follower_import::import_foreign_block(
                                            sealed, &provider, &evm_config, senders_cache.as_ref(), &carry, qmdb.as_ref(), consensus.as_ref(), &chain_spec,
                                        )
                                    }) as std::sync::Arc<n42::payload_serve::ForeignImport>
                                }),
                                exec_probe: (std::env::var("N42_FOLLOWER_EXEC_PROBE").is_ok()).then(|| {
                                    let provider = node.provider.clone();
                                    let evm_config = node.evm_config.clone();
                                    std::sync::Arc::new(move |block: reth_primitives_traits::RecoveredBlock<reth_ethereum_primitives::Block>| {
                                        use reth_evm::execute::Executor as _;
                                        use reth_evm::ConfigureEvm as _;
                                        use reth_provider::StateProviderFactory as _;
                                        let state = provider.state_by_block_hash(block.parent_hash).map_err(|e| e.to_string())?;
                                        let db = reth_revm::database::StateProviderDatabase::new(&state);
                                        let started = std::time::Instant::now();
                                        let mut executor = evm_config.executor(db);
                                        let out = executor.execute_one(&block).map_err(|e| e.to_string())?;
                                        Ok((started.elapsed().as_millis() as u64, out.gas_used, out.receipts.len()))
                                    }) as std::sync::Arc<dyn Fn(reth_primitives_traits::RecoveredBlock<reth_ethereum_primitives::Block>) -> Result<(u64, u64, usize), String> + Send + Sync>
                                }),
                                prune_pool: (std::env::var("N42_PRUNE_POOL_ON_IMPORT").is_ok()).then(|| {
                                    let pool = node.pool.clone();
                                    std::sync::Arc::new(move |hashes: Vec<alloy_primitives::B256>| {
                                        let _ = reth_transaction_pool::TransactionPool::remove_transactions(&pool, hashes);
                                    }) as std::sync::Arc<dyn Fn(Vec<alloy_primitives::B256>) + Send + Sync>
                                }),
                            }
                        });
                        tokio::spawn(async move {
                            if let Err(err) = n42::payload_serve::serve(addr, payloads, engine, reuse).await {
                                error!(target: "reth::cli", %err, "raw payload channel stopped");
                            }
                        });
                    }
                    Err(err) => error!(target: "reth::cli", %err, %addr, "N42_PAYLOAD_SERVE is not an address"),
                }
            }

            // The builder-side transaction queue, beside the pool. See
            // n42_tx_queue. Fed by the ingest, drained by the builder, pruned
            // here by every canonical block on every node.
            if std::env::var("N42_TX_QUEUE").is_ok() {
                let queue: n42_tx_queue::TxQueue<reth_transaction_pool::EthPooledTransaction> = n42_tx_queue::TxQueue::new();
                if n42_tx_queue::install(queue.clone()) {
                    info!(target: "reth::cli", "builder-side transaction queue installed");
                }
                // Fed by the pool's own arrivals, whichever door they came in
                // by, so what the builder sees is what the pool validated.
                let mut arrivals = reth_transaction_pool::TransactionPool::new_transactions_listener_for(
                    &node.pool,
                    reth_transaction_pool::TransactionListenerKind::All,
                );
                let feed = queue.clone();
                let pool_for_gaps = node.pool.clone();
                tokio::spawn(async move {
                    let mut batch = Vec::with_capacity(256);
                    loop {
                        // Holes the builder ran into: the pool's listener drops
                        // events on a full channel, so a nonce can be in the
                        // pool and not here. Look those up; one still on its
                        // way in is simply not found yet.
                        for (sender, from, to) in feed.take_gaps() {
                            let to = to.min(from.saturating_add(256));
                            let found: Vec<_> = (from..to)
                                .filter_map(|nonce| {
                                    reth_transaction_pool::TransactionPool::get_transaction_by_sender_and_nonce(
                                        &pool_for_gaps,
                                        sender,
                                        nonce,
                                    )
                                })
                                .collect();
                            if !found.is_empty() {
                                feed.push_valid(found);
                            }
                        }
                        let event = match tokio::time::timeout(std::time::Duration::from_millis(50), arrivals.recv()).await {
                            Ok(Some(event)) => event,
                            Ok(None) => break,
                            Err(_) => continue,
                        };
                        batch.push(event.transaction);
                        while let Ok(event) = arrivals.try_recv() {
                            batch.push(event.transaction);
                            if batch.len() >= 4096 {
                                break;
                            }
                        }
                        feed.push_valid(batch.drain(..));
                    }
                });
                let mut canonical = node.provider.subscribe_to_canonical_state();
                tokio::spawn(async move {
                    loop {
                        match canonical.recv().await {
                            Ok(notification) => {
                                let behind = canonical.len();
                                if behind > 8 {
                                    warn!(target: "reth::cli", behind, "canonical subscriber lag: queue pruner");
                                }
                                let started = std::time::Instant::now();
                                let mut mined = 0usize;
                                for (_, block) in notification.committed().blocks_iter().map(|b| (b.number(), b)) {
                                    let pairs: Vec<(alloy_primitives::Address, u64)> = block
                                        .transactions_with_sender()
                                        .map(|(sender, tx)| (*sender, alloy_consensus::Transaction::nonce(tx)))
                                        .collect();
                                    mined += pairs.len();
                                    queue.remove_mined_batch(pairs);
                                }
                                if mined > 10_000 {
                                    info!(target: "n42.tx_queue", mined, queued = queue.len(), prune_ms = started.elapsed().as_millis() as u64, "canonical blocks pruned from the queue");
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(target: "n42.tx_queue", skipped, "queue pruning fell behind canonical notifications");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }

            // A binary path into the pool, for load generators. Off unless
            // asked for, and meant for loopback: it admits nothing
            // `eth_sendRawTransaction` would not, but it is unauthenticated,
            // so binding it anywhere reachable would be a mistake.
            if let Ok(addr) = std::env::var("N42_TX_INGEST") {
                match addr.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let pool = node.pool.clone();
                        // The sender-recovery cache, so a transaction admitted
                        // here is not recovered again when its block arrives.
                        let cache = node.evm_config().sender_recovery_cache.clone();
                        // The canonical head's number, for the ingest's gate to
                        // know how far the pool lags the chain.
                        let head = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                        {
                            use futures::StreamExt as _;
                            use reth_provider::CanonStateSubscriptions as _;
                            let head = head.clone();
                            let mut canonical = node.provider.canonical_state_stream();
                            tokio::spawn(async move {
                                while let Some(notification) = canonical.next().await {
                                    head.store(notification.tip().number, std::sync::atomic::Ordering::Relaxed);
                                }
                                // (a stream over the broadcast; its lag is not readable here)
                            });
                        }
                        tokio::spawn(async move {
                            if let Err(err) = n42_tx_ingest::serve(addr, pool, cache, head).await {
                                error!(target: "reth::cli", %err, "transaction ingest stopped");
                            }
                        });
                    }
                    Err(err) => {
                        error!(target: "reth::cli", %err, %addr, "N42_TX_INGEST is not an address");
                    }
                }
            }

            // A chain whose genesis names a HotStuff-2 validator set is driven
            // over the Engine API by those validators (`h2_validator`); the
            // signer key still seals the blocks they ask for, but APoS block
            // production would race their forkchoice and lose.
            let hotstuff_chain =
                n42_qmdb_reth::HotStuffGenesisConfig::from_genesis(node.chain_spec().genesis())
                    .is_ok();
            let mining_mode = if hotstuff_chain {
                info!(target: "reth::cli", "chain declares a HotStuff-2 validator set; APoS mining is off");
                consensus_client::miner::MiningMode::NoMining
            } else if let Some(_) = consensus_signer_private_key {
                let block_time = node_config_dev
                    .dev
                    .block_time
                    .unwrap_or_else(|| Duration::from_secs(DEFAULT_BLOCK_TIME_SECS));
                consensus_client::miner::MiningMode::interval(block_time)
            } else {
                consensus_client::miner::MiningMode::NoMining
            };
            info!(target: "reth::cli", ?mining_mode);

            if node_config_dev.dev.migrate_old_chain_data_from_db.is_some()
                || node_config_dev
                    .dev
                    .migrate_old_chain_data_from_rpc
                    .is_some()
            {
                let migrate_from_db_path =
                    node_config_dev.dev.migrate_old_chain_data_from_db.clone();
                let migrate_from_db_rpc =
                    node_config_dev.dev.migrate_old_chain_data_from_rpc.clone();
                N42Migrate::spawn_new(
                    node.provider.clone(),
                    N42PayloadAttributesBuilder::new_add_signer(node.chain_spec(), signer_address),
                    node.add_ons_handle.beacon_engine_handle.clone(),
                    node.payload_builder_handle.clone(),
                    node.pool.clone(),
                    migrate_from_db_path,
                    migrate_from_db_rpc,
                );
            } else if hotstuff_chain {
                // No miner at all, not merely a miner with mining off: the
                // miner also re-proposes when the chain looks stalled, which
                // on a HotStuff-2 chain is just the fleet pacing itself.
            } else {
                N42Miner::spawn_new(
                    node.provider.clone(),
                    N42PayloadAttributesBuilder::new_add_signer(node.chain_spec(), signer_address),
                    node.add_ons_handle.beacon_engine_handle.clone(),
                    mining_mode,
                    node.payload_builder_handle.clone(),
                    node.network.clone(),
                    consensus,
                    broadcast_tx_clone_for_miner,
                    verification_rx,
                );
            }

            // Install ress subprotocol.
            // Disabled: ress protocol deps not yet available in v1.11.0
            // if ress_args.enabled {
            //     install_ress_subprotocol(
            //         ress_args,
            //         node.provider,
            //         node.evm_config,
            //         node.network,
            //         node.task_executor,
            //         node.add_ons_handle.engine_events.new_listener(),
            //     )?;
            // }

            node_exit_future.await
        })
    {
        error!(target: "reth::cli", "Error: {err:?}");
        std::process::exit(1);
    }
}
