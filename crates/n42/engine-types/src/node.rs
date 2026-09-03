// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ethereum Node types config.

//pub use crate::{payload::EthereumPayloadBuilder, EthereumEngineValidator};
//use crate::{EthEngineTypes, EthEvmConfig};
//use n42_engine_primitives::{N42PayloadAttributes, N42PayloadBuilderAttributes};
use alloy_eips::{eip7840::BlobParams, merge::EPOCH_SLOTS};
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
pub use reth_node_ethereum::EthereumEngineValidator;
use n42_qmdb_reth::{QmdbEngineValidatorBuilder, QmdbNodeState};
use reth_node_ethereum::{EthEngineTypes, EthEvmConfig};
//use reth_ethereum_consensus::EthBeaconConsensus;
use crate::consensus::N42ConsensusBuilder;
use crate::network::N42NetworkBuilder;
//use crate::{N42EngineTypes, N42NodeAddOns, N42PayloadServiceBuilder};
use crate::N42PayloadServiceBuilder;
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthPayloadAttributes,
};
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{ConfigureEvm, EvmFactory, EvmFactoryFor, NextBlockEnvAttributes};
use reth_network::{NetworkHandle, PeersInfo};
use reth_node_api::{
    AddOnsContext, FullNodeComponents, NodeAddOns, NodePrimitives, PrimitivesTy, TxTy,
};
use reth_node_builder::{
    components::{
        ComponentsBuilder, ExecutorBuilder,
        NetworkBuilder, PoolBuilder,
    },
    node::{FullNodeTypes, NodeTypes},
    rpc::{
        BasicEngineApiBuilder, BasicEngineValidatorBuilder, EngineValidatorAddOn, EthApiBuilder,
        EthApiCtx, PayloadValidatorBuilder, RethRpcAddOns, RpcAddOns, RpcHandle,
    },
    BuilderContext, DebugNode, Node, NodeAdapter, PayloadTypes,
};
use reth_provider::{providers::ProviderFactoryBuilder, CanonStateSubscriptions, EthStorage};
use reth_rpc::eth::core::EthApiFor;
use reth_rpc_eth_types::{error::FromEvmError, EthApiError};
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    blobstore::{DiskFileBlobStore, DiskFileBlobStoreConfig},
    EthTransactionPool, PoolTransaction, TransactionPool, TransactionValidationTaskExecutor,
};
use revm::context::TxEnv;
use std::{default::Default, sync::Arc, time::SystemTime};

/// Type configuration for a regular Ethereum node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct N42Node {
    /// The QMDB state this node commits to, on a chain that declares it.
    ///
    /// Shared by the payload builder and the engine validator, which is the
    /// point: a block this node builds is validated by this node next, and the
    /// two must read the same trees.
    qmdb: Option<QmdbNodeState>,
}

impl N42Node {
    /// A node committing to `qmdb`, or to reth's Merkle-Patricia trie when `None`.
    pub const fn with_qmdb(qmdb: Option<QmdbNodeState>) -> Self {
        Self { qmdb }
    }

    /// The QMDB state, if this node commits to one.
    pub const fn qmdb(&self) -> Option<&QmdbNodeState> {
        self.qmdb.as_ref()
    }

    /// Returns a [`ComponentsBuilder`] configured for a regular Ethereum node.
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        N42PayloadServiceBuilder<N42ConsensusBuilder>,
        N42NetworkBuilder,
        EthereumExecutorBuilder,
        N42ConsensusBuilder,
    >
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
        <Node::Types as NodeTypes>::Payload: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = EthPayloadAttributes,
        >,
    {
        Self::components_with(None)
    }

    /// Like [`Self::components`], with built blocks committing to `qmdb`.
    pub fn components_with<Node>(qmdb: Option<QmdbNodeState>) -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        N42PayloadServiceBuilder<N42ConsensusBuilder>,
        N42NetworkBuilder,
        EthereumExecutorBuilder,
        N42ConsensusBuilder,
    >
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
        <Node::Types as NodeTypes>::Payload: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = EthPayloadAttributes,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .consensus(N42ConsensusBuilder::default())
            .payload(
                N42PayloadServiceBuilder::new(N42ConsensusBuilder::default()).with_qmdb(qmdb),
            )
            .network(N42NetworkBuilder::default())
    }

    /// Instantiates the [`ProviderFactoryBuilder`] for an ethereum node.
    ///
    /// # Open a Providerfactory in read-only mode from a datadir
    ///
    /// See also: [`ProviderFactoryBuilder`] and
    /// [`ReadOnlyConfig`](reth_provider::providers::ReadOnlyConfig).
    ///
    /// ```ignore
    /// use reth_chainspec::MAINNET;
    /// use n42_engine_types::N42Node;
    ///
    /// let factory = N42Node::provider_factory_builder()
    ///     .open_read_only(MAINNET.clone(), "datadir")
    ///     .unwrap();
    /// ```
    ///
    /// # Open a Providerfactory manually with all required components
    ///
    /// ```ignore
    /// use reth_chainspec::ChainSpecBuilder;
    /// use reth_db::open_db_read_only;
    /// use n42_engine_types::N42Node;
    /// use reth_provider::providers::StaticFileProvider;
    /// use std::sync::Arc;
    ///
    /// let factory = N42Node::provider_factory_builder()
    ///     .db(Arc::new(open_db_read_only("db", Default::default()).unwrap()))
    ///     .chainspec(ChainSpecBuilder::mainnet().build().into())
    ///     .static_file(StaticFileProvider::read_only("db/static_files", false).unwrap())
    ///     .build_provider_factory();
    /// ```
    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }
}

impl NodeTypes for N42Node {
    type Primitives = EthPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = EthStorage;
    type Payload = EthEngineTypes;
}

/// Builds [`EthApi`](reth_rpc::EthApi) for Ethereum.
///
/// This builder creates the Ethereum RPC API implementation using the default
/// Ethereum network types.
#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumEthApiBuilder;

impl<N> EthApiBuilder<N> for EthereumEthApiBuilder
where
    N: FullNodeComponents<
        Types: NodeTypes<ChainSpec: reth_chainspec::Hardforks + EthereumHardforks>,
        Evm: ConfigureEvm<
            NextBlockEnvCtx: reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<
                reth_node_api::HeaderTy<N::Types>,
            >,
        >,
    >,
    reth_rpc::eth::core::EthRpcConverterFor<N, alloy_network::Ethereum>:
        reth_rpc_eth_api::RpcConvert<
            Primitives = PrimitivesTy<N::Types>,
            Error = EthApiError,
            Network = alloy_network::Ethereum,
            Evm = N::Evm,
        >,
    EthApiError: FromEvmError<N::Evm>,
    alloy_rpc_types_eth::TransactionRequest: reth_rpc_eth_api::SignableTxRequest<TxTy<N::Types>>,
{
    type EthApi = EthApiFor<N, alloy_network::Ethereum>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        Ok(ctx
            .eth_api_builder()
            .map_converter(|r| r.with_network())
            .build())
    }
}

/// Add-ons w.r.t. l1 ethereum.
///
/// `ValB` is the engine validator builder. reth's stock one is the default;
/// this node installs [`QmdbEngineValidatorBuilder`] so block validation checks
/// QMDB roots on a chain that declares them.
#[derive(Debug)]
pub struct EthereumAddOns<
    N: FullNodeComponents,
    EthB: EthApiBuilder<N>,
    PVB,
    ValB = BasicEngineValidatorBuilder<PVB>,
> {
    inner: RpcAddOns<N, EthB, PVB, BasicEngineApiBuilder<PVB>, ValB>,
}

impl<N: FullNodeComponents, EthB: EthApiBuilder<N>, PVB, ValB> EthereumAddOns<N, EthB, PVB, ValB> {
    /// Create new add-ons with given RPC add-ons.
    pub fn new(inner: RpcAddOns<N, EthB, PVB, BasicEngineApiBuilder<PVB>, ValB>) -> Self {
        Self { inner }
    }
}

impl<N> Default for EthereumAddOns<N, EthereumEthApiBuilder, EthereumEngineValidatorBuilder>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: EthereumHardforks + Clone + 'static,
            Payload: reth_engine_primitives::EngineTypes<
                ExecutionData = alloy_rpc_types_engine::ExecutionData,
            > + PayloadTypes<PayloadAttributes = EthPayloadAttributes>,
            Primitives = EthPrimitives,
        >,
    >,
    EthereumEthApiBuilder: EthApiBuilder<N>,
{
    fn default() -> Self {
        Self::new(RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            EthereumEngineValidatorBuilder::default(),
            BasicEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            // upstream split the middleware argument into rpc + auth-http
            Default::default(),
            Default::default(),
        ))
    }
}

impl<N, EthB, PVB, ValB> NodeAddOns<N> for EthereumAddOns<N, EthB, PVB, ValB>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: EthChainSpec + EthereumHardforks,
            Primitives = EthPrimitives,
            Payload: reth_engine_primitives::EngineTypes<
                ExecutionData = alloy_rpc_types_engine::ExecutionData,
            >,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    EthB: EthApiBuilder<N>,
    PVB: PayloadValidatorBuilder<N> + Clone,
    ValB: reth_node_builder::rpc::EngineValidatorBuilder<N>,
    BasicEngineApiBuilder<PVB>: reth_node_builder::rpc::EngineApiBuilder<N>,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
{
    type Handle = RpcHandle<N, EthB::EthApi>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        self.inner.launch_add_ons(ctx).await
    }
}

impl<N, EthB, PVB, ValB> RethRpcAddOns<N> for EthereumAddOns<N, EthB, PVB, ValB>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: EthChainSpec + EthereumHardforks,
            Primitives = EthPrimitives,
            Payload: reth_engine_primitives::EngineTypes<
                ExecutionData = alloy_rpc_types_engine::ExecutionData,
            >,
        >,
        Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
    >,
    EthB: EthApiBuilder<N>,
    PVB: PayloadValidatorBuilder<N> + Clone,
    ValB: reth_node_builder::rpc::EngineValidatorBuilder<N>,
    BasicEngineApiBuilder<PVB>: reth_node_builder::rpc::EngineApiBuilder<N>,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
{
    type EthApi = EthB::EthApi;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N, EthB, PVB, ValB> EngineValidatorAddOn<N> for EthereumAddOns<N, EthB, PVB, ValB>
where
    N: FullNodeComponents,
    EthB: EthApiBuilder<N>,
    PVB: Send,
    BasicEngineApiBuilder<PVB>: reth_node_builder::rpc::EngineApiBuilder<N>,
    ValB: reth_node_builder::rpc::EngineValidatorBuilder<N>,
{
    type ValidatorBuilder = ValB;

    fn engine_validator_builder(&self) -> Self::ValidatorBuilder {
        self.inner.engine_validator_builder()
    }
}

impl<N> Node<N> for N42Node
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        N42PayloadServiceBuilder<N42ConsensusBuilder>,
        N42NetworkBuilder,
        EthereumExecutorBuilder,
        N42ConsensusBuilder,
    >;

    type AddOns = EthereumAddOns<
        NodeAdapter<N>,
        EthereumEthApiBuilder,
        crate::engine_validator::N42EngineValidatorBuilder,
        QmdbEngineValidatorBuilder<crate::engine_validator::N42EngineValidatorBuilder>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components_with(self.qmdb.clone())
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::new(RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            crate::engine_validator::N42EngineValidatorBuilder,
            BasicEngineApiBuilder::default(),
            QmdbEngineValidatorBuilder::new(self.qmdb.clone()),
            Default::default(),
            Default::default(),
        ))
    }
}

impl<N: FullNodeComponents<Types = Self>> DebugNode<N> for N42Node {
    type RpcBlock = alloy_rpc_types_eth::Block;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_ethereum_primitives::Block {
        rpc_block.into_consensus().convert_transactions()
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl reth_node_api::PayloadAttributesBuilder<
        <Self::Payload as PayloadTypes>::PayloadAttributes,
        reth_node_api::HeaderTy<Self>,
    > {
        n42_engine_primitives::N42PayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

/// A regular ethereum evm and executor builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct EthereumExecutorBuilder;

impl<Types, Node> ExecutorBuilder<Node> for EthereumExecutorBuilder
where
    Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = EthEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        // The sender-recovery cache, as upstream's Ethereum node attaches it.
        // This builder never did, which is why `--engine.sender-recovery-cache`
        // measured inert twice on the seven-node fleet: reth consults the
        // cache on the EVM config at import, and this config had none, so
        // every transaction was recovered again on the worker pool -- the
        // same pool the ingest and the prewarmer recover on.
        let mut evm_config = EthEvmConfig::new(ctx.chain_spec());
        if let Some(cache) = ctx.sender_recovery_cache() {
            evm_config = evm_config.with_sender_recovery_cache(cache.clone());
        }
        Ok(evm_config)
    }
}

/// A basic ethereum transaction pool.
///
/// This contains various settings that can be configured and take precedence over the node's
/// config.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct EthereumPoolBuilder {
    // TODO add options for txpool args
}

impl<Types, Node, Evm> PoolBuilder<Node, Evm> for EthereumPoolBuilder
where
    Types: NodeTypes<
        ChainSpec: EthereumHardforks,
        Primitives: NodePrimitives<SignedTx = TransactionSigned>,
    >,
    Node: FullNodeTypes<Types = Types>,
    Evm: ConfigureEvm<Primitives = reth_node_api::PrimitivesTy<Types>> + Clone + 'static,
{
    type Pool = EthTransactionPool<Node::Provider, DiskFileBlobStore, Evm>;

    async fn build_pool(self, ctx: &BuilderContext<Node>, evm_config: Evm) -> eyre::Result<Self::Pool> {
        let data_dir = ctx.config().datadir();
        let pool_config = ctx.pool_config();

        let blob_cache_size = if let Some(blob_cache_size) = pool_config.blob_cache_size {
            blob_cache_size
        } else {
            // get the current blob params for the current timestamp, fallback to default Cancun
            // params
            let current_timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs();
            let blob_params = ctx
                .chain_spec()
                .blob_params_at_timestamp(current_timestamp)
                .unwrap_or_else(BlobParams::cancun);

            // Derive the blob cache size from the target blob count, to auto scale it by
            // multiplying it with the slot count for 2 epochs: 384 for pectra
            (blob_params.target_blob_count * EPOCH_SLOTS * 2) as u32
        };

        let custom_config =
            DiskFileBlobStoreConfig::default().with_max_cached_entries(blob_cache_size);

        let blob_store = DiskFileBlobStore::open(data_dir.blobstore(), custom_config)?;
        let validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
            .kzg_settings(ctx.kzg_settings()?)
            .with_local_transactions_config(pool_config.local_transactions_config.clone())
            .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
            .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        let transaction_pool =
            reth_transaction_pool::Pool::eth_pool(validator, blob_store, pool_config);
        info!(target: "reth::cli", "Transaction pool initialized");

        // spawn txpool maintenance task
        {
            let pool = transaction_pool.clone();
            // The same stream `canonical_state_stream()` would give, over a
            // receiver whose backlog is visible: a follower's heap held the
            // decoded transactions of every block of a flood (4.2 GB), and
            // tokio's broadcast keeps a value for its slowest receiver. This
            // says when the maintenance task is that receiver.
            let chain_events = {
                let rx = ctx.provider().subscribe_to_canonical_state();
                let stream = futures_util::stream::unfold(rx, |mut rx| async move {
                    loop {
                        match rx.recv().await {
                            Ok(notification) => {
                                let behind = rx.len();
                                if behind > 8 {
                                    tracing::warn!(target: "reth::cli", behind, "canonical subscriber lag: txpool maintenance");
                                }
                                return Some((notification, rx));
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                tracing::warn!(target: "reth::cli", skipped, "txpool maintenance fell behind canonical notifications");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                        }
                    }
                });
                futures_util::StreamExt::boxed(stream)
            };
            let client = ctx.provider().clone();
            // Only spawn backup task if not disabled
            if !ctx.config().txpool.disable_transactions_backup {
                // Use configured backup path or default to data dir
                let transactions_path = ctx
                    .config()
                    .txpool
                    .transactions_backup_path
                    .clone()
                    .unwrap_or_else(|| data_dir.txpool_transactions());

                let transactions_backup_config =
                    reth_transaction_pool::maintain::LocalTransactionBackupConfig::with_local_txs_backup(transactions_path);

                ctx.task_executor()
                    .spawn_critical_with_graceful_shutdown_signal(
                        "local transactions backup task",
                        |shutdown| {
                            reth_transaction_pool::maintain::backup_local_transactions_task(
                                shutdown,
                                pool.clone(),
                                transactions_backup_config,
                            )
                        },
                    );
            }

            // spawn the maintenance task
            ctx.task_executor().spawn_critical_task(
                "txpool maintenance task",
                reth_transaction_pool::maintain::maintain_transaction_pool_future(
                    client,
                    pool,
                    chain_events,
                    ctx.task_executor().clone(),
                    reth_transaction_pool::maintain::MaintainPoolConfig {
                        max_tx_lifetime: transaction_pool.config().max_queued_lifetime,
                        no_local_exemptions: transaction_pool
                            .config()
                            .local_transactions_config
                            .no_exemptions,
                        ..Default::default()
                    },
                ),
            );
            debug!(target: "reth::cli", "Spawned txpool maintenance task");
        }

        Ok(transaction_pool)
    }
}

/// A basic ethereum network builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumNetworkBuilder {
    // TODO add closure to modify network
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for EthereumNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: reth_chainspec::Hardforks>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type Network = NetworkHandle<
        reth_eth_wire_types::BasicNetworkPrimitives<
            PrimitivesTy<Node::Types>,
            reth_transaction_pool::PoolPooledTx<Pool>,
        >,
    >;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let network = ctx.network_builder().await?;
        let handle = ctx.start_network(network, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking initialized");
        Ok(handle)
    }
}

/// Builder for [`EthereumEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct EthereumEngineValidatorBuilder;

impl<Node, Types> PayloadValidatorBuilder<Node> for EthereumEngineValidatorBuilder
where
    Types: NodeTypes<ChainSpec = ChainSpec, Payload = EthEngineTypes, Primitives = EthPrimitives>,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = EthereumEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(EthereumEngineValidator::new(ctx.config.chain.clone()))
    }
}
