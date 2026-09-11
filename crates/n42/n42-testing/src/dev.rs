#![allow(non_snake_case)]
use alloy_primitives::{FixedBytes, Sealable};
use alloy_rpc_types_engine::ExecutionPayloadV3;
use alloy_signer_local::PrivateKeySigner;
use reth_chainspec::make_genesis_header;
use reth_chainspec::{ChainSpec, N42};
use reth_consensus::Consensus;
use reth_ethereum_engine_primitives::ExecutionPayloadEnvelopeV3;
use reth_ethereum_forks::N42_HARDFORKS_FOR_CLIQUE_TEST;
use reth_node_api::{EngineTypes, FullNodeComponents, FullNodeTypes, PayloadTypes};
use reth_node_builder::node::NodeTypes;
use reth_payload_primitives::{BuiltPayload, PayloadKind};
use reth_primitives_traits::{NodePrimitives, SealedHeader};
use reth_provider::{BlockHashReader, BlockNumReader, BlockReaderIdExt};
use zerocopy::AsBytes;

#[cfg(test)]
use crate::{snapshot_test_utils::TesterAccountPool, utils::n42_payload_attributes};

use alloy_genesis::CliqueConfig;
use alloy_primitives::{Address, Bytes, B256, U256};
use futures::StreamExt;
use n42_engine_types::N42Node;
use reth::{
    args::{DevArgs, DiscoveryArgs, NetworkArgs, RpcServerArgs},
    builder::Node,
    rpc::types::engine::ForkchoiceState,
};
use reth_node_builder::{rpc::RethRpcAddOns, FullNode, NodeBuilder, NodeConfig, NodeHandle};
use reth_tasks::Runtime;

use n42_clique::{EXTRA_SEAL, EXTRA_VANITY};
use n42_clique_utils::SIGNATURE_LENGTH;
use reth_primitives_traits::AlloyBlockHeader;
use reth_rpc_api::EngineApiClient;
use std::{
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Types representing tester votes and test structure
#[cfg(test)]
#[derive(Debug, Default)]
pub struct TesterVote {
    pub signer: String,
    pub voted: Option<String>,
    pub auth: Option<bool>,
    //pub checkpoint: Option<Vec<String>>,
    //pub newbatch: Option<bool>,
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct CliqueTest {
    pub epoch: Option<u64>,
    pub signers: Vec<String>,
    pub votes: Vec<TesterVote>,
    pub results: Vec<String>,
    pub failure: Option<String>,
}

#[cfg(test)]
fn get_addresses_from_extra_data(extra_data: Bytes) -> Vec<Address> {
    let signers_count = (extra_data.len() - EXTRA_VANITY - SIGNATURE_LENGTH) / Address::len_bytes();

    let mut signers = Vec::with_capacity(signers_count);

    for i in 0..signers_count {
        let start = EXTRA_VANITY + i * Address::len_bytes();
        let end = start + Address::len_bytes();
        signers.push(Address::from_slice(&extra_data[start..end]));
    }

    signers
}

/// Applies a test action to one consensus instance: sets the signer key, then
/// replaces the pending proposals with `vote`.
#[cfg(test)]
type ConsensusSetup =
    Arc<dyn Fn(String, Option<(Address, bool)>) -> eyre::Result<()> + Send + Sync>;

/// Reads the APoS snapshot at a block from one consensus instance.
#[cfg(test)]
type SnapshotReader =
    Arc<dyn Fn(u64, B256) -> eyre::Result<n42_primitives::Snapshot> + Send + Sync>;

/// Wraps [`N42ConsensusBuilder`] and publishes setters for every consensus it builds.
///
/// The node's consensus is not reachable from `FullNode`, and these tests re-sign each
/// block with a different authorized signer, so the key cannot just be baked into
/// `DevArgs` once at launch. Capturing each consensus as it is built keeps that on the
/// test side instead of widening the reth fork.
///
/// A node builds consensus twice — once for the consensus component and once inside
/// [`N42PayloadServiceBuilder`] — and the two instances hold independent signer state.
/// Payload building reads the second one, so every captured instance has to be set.
#[cfg(test)]
#[derive(Default, Clone)]
struct CapturingConsensusBuilder {
    setups: Arc<std::sync::Mutex<Vec<ConsensusSetup>>>,
    snapshots: Arc<std::sync::Mutex<Vec<SnapshotReader>>>,
}

#[cfg(test)]
impl CapturingConsensusBuilder {
    /// Arms every consensus instance this builder produced for the next block: signs
    /// with `key` and casts `vote` (an authorization vote on an address), if any.
    fn arm(&self, key: &str, vote: Option<(Address, bool)>) -> eyre::Result<()> {
        let setups = self
            .setups
            .lock()
            .map_err(|e| eyre::eyre!("consensus setups lock poisoned: {e}"))?
            .clone();
        eyre::ensure!(!setups.is_empty(), "consensus builder never ran");
        for setup in setups {
            setup(key.to_string(), vote)?;
        }
        Ok(())
    }

    /// Reads the APoS snapshot at `(number, hash)`. All captured instances share the
    /// same provider, so the first one is representative.
    fn snapshot(&self, number: u64, hash: B256) -> eyre::Result<n42_primitives::Snapshot> {
        let reader = self
            .snapshots
            .lock()
            .map_err(|e| eyre::eyre!("snapshot readers lock poisoned: {e}"))?
            .first()
            .cloned()
            .ok_or_else(|| eyre::eyre!("consensus builder never ran"))?;
        reader(number, hash)
    }
}

#[cfg(test)]
impl std::fmt::Debug for CapturingConsensusBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturingConsensusBuilder").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl<Node> reth_node_builder::components::ConsensusBuilder<Node> for CapturingConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = n42_tx_types::N42Primitives>>,
{
    type Consensus = Arc<n42_engine_types::N42Consensus<<Node as FullNodeTypes>::Provider>>;

    async fn build_consensus(
        self,
        ctx: &reth_node_builder::BuilderContext<Node>,
    ) -> eyre::Result<Self::Consensus> {
        let consensus = <n42_engine_types::N42ConsensusBuilder as reth_node_builder::components::ConsensusBuilder<Node>>::build_consensus(
            n42_engine_types::N42ConsensusBuilder::default(),
            ctx,
        )
        .await?;
        let handle = consensus.clone();
        self.setups
            .lock()
            .map_err(|e| eyre::eyre!("consensus setups lock poisoned: {e}"))?
            .push(Arc::new(move |key: String, vote: Option<(Address, bool)>| {
                type Block = n42_tx_types::Block;
                <_ as Consensus<Block>>::set_eth_signer_by_key(&*handle, Some(key))?;
                // Each block casts at most one vote, so clear whatever the previous
                // block left pending before arming the next one.
                for address in
                    <_ as Consensus<Block>>::proposals(&*handle)?.keys().copied().collect::<Vec<_>>()
                {
                    <_ as Consensus<Block>>::discard(&*handle, address)?;
                }
                if let Some((address, auth)) = vote {
                    <_ as Consensus<Block>>::propose(&*handle, address, auth)?;
                }
                Ok(())
            }));
        let handle = consensus.clone();
        self.snapshots
            .lock()
            .map_err(|e| eyre::eyre!("snapshot readers lock poisoned: {e}"))?
            .push(Arc::new(move |number: u64, hash: B256| {
                Ok(<_ as Consensus<n42_tx_types::Block>>::snapshot(
                    &*handle, number, hash, None,
                )?)
            }));
        Ok(consensus)
    }
}

#[cfg(test)]
async fn new_block<Node: FullNodeComponents, AddOns: RethRpcAddOns<Node>>(
    node: &FullNode<Node, AddOns>,
    eth_signer_key: String,
    vote: Option<(Address, bool)>,
    consensus: &CapturingConsensusBuilder,
) -> eyre::Result<()>
    where
    // replaces the old PayloadBuilderAttributes: From<EthPayloadBuilderAttributes>
    // bound; upstream removed that associated type
    <<<Node as FullNodeTypes>::Types as NodeTypes>::Payload as PayloadTypes>::PayloadAttributes:
        From<reth::rpc::types::engine::PayloadAttributes>,
    <<Node as FullNodeTypes>::Types as NodeTypes>::Primitives: NodePrimitives<Block = n42_tx_types::Block>,
    <<Node as FullNodeTypes>::Types as NodeTypes>::Payload: EngineTypes,
{
    let best_number = node.provider.chain_info().unwrap().best_number;
    println!("best_number={best_number}");
    println!("eth_signer_key={eth_signer_key}");
    let parent_hash = node.provider.latest_header().unwrap().unwrap().hash();
    println!("parent_hash={parent_hash:?}");
    println!(
        "header={:?}",
        node.provider.latest_header().unwrap().unwrap().header()
    );
    println!(
        "header hash={:?}",
        node.provider
            .latest_header()
            .unwrap()
            .unwrap()
            .header()
            .hash_slow()
    );
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let eth_signer =
        PrivateKeySigner::from_bytes(&FixedBytes::from_str(&eth_signer_key).unwrap()).unwrap();
    let eth_signer_address = eth_signer.address();
    let attributes = n42_payload_attributes(timestamp, parent_hash, eth_signer_address);
    // Without a signer APoS cannot seal, the payload job fails, and every test here
    // dies on "missing payload".
    consensus.arm(&eth_signer_key, vote)?;
    let payload_id = node
        .payload_builder_handle
        .send_new_payload(reth_payload_builder::BuildNewPayload {
            attributes: attributes.clone().into(),
            parent_hash,
            resources: Default::default(),
        })
        .await
        .unwrap()?;
    println!("payload_id={payload_id}");

    let payload_type = node
        .payload_builder_handle
        .resolve_kind(payload_id, PayloadKind::default())
        .await
        .unwrap()?;
    println!("payload_type={payload_type:?}");
    let extra_data = payload_type.block().header().extra_data().clone();
    println!("header={:?}", payload_type.block().header());
    println!("extra_data={extra_data:?}");
    let signer_addresses = get_addresses_from_extra_data(extra_data);
    println!("signer_addresses={signer_addresses:?}");

    let payload = payload_type.clone();

    let client = node.engine_http_client();
    let execution_payload =
        ExecutionPayloadV3::from_block_slow(&payload.block().clone().into_block());
    let submission =
        EngineApiClient::new_payload_v3(&client, execution_payload, vec![], B256::ZERO).await?;
    println!("submission={submission:?}");

    let current_head = parent_hash;
    let new_head = payload_type.block().hash();
    EngineApiClient::fork_choice_updated_v1(
        &client,
        ForkchoiceState {
            head_block_hash: new_head,
            safe_block_hash: current_head,
            finalized_block_hash: current_head,
        },
        None,
    )
    .await?;
    println!(
        "latest block_hash={:?}",
        node.provider.latest_header().unwrap().unwrap().hash()
    );
    Ok(())
}

#[cfg(test)]
impl CliqueTest {
    fn gen_chainspec(&self, accounts: &mut TesterAccountPool) -> ChainSpec {
        let signers: Vec<Address> = self.signers.iter().map(|s| accounts.address(s)).collect();

        let mut chainspec = (**N42).clone();
        let mut extra_data =
            vec![0u8; EXTRA_VANITY + self.signers.len() * Address::len_bytes() + EXTRA_SEAL];
        for (j, signer) in signers.iter().enumerate() {
            let start = EXTRA_VANITY + j * Address::len_bytes();
            let end = start + Address::len_bytes();
            extra_data[start..end].copy_from_slice(signer.as_bytes());
        }
        chainspec.genesis.extra_data = extra_data.into();
        let hardforks = N42_HARDFORKS_FOR_CLIQUE_TEST.clone();
        let genesis_header = SealedHeader::new_unhashed(
            make_genesis_header(&chainspec.genesis, &hardforks),
            //genesis_hash,
        );
        if let Some(epoch) = self.epoch {
            chainspec.genesis.config.clique = Some(CliqueConfig {
                epoch: Some(epoch),
                period: None,
            });
        }

        chainspec.hardforks = hardforks;
        chainspec.genesis_header = genesis_header;
        chainspec
    }

    async fn happy_path(&self) -> eyre::Result<()> {
        reth_tracing::init_test_tracing();
        // upstream removed with_existing_handle; Runtime::test() is the test constructor
        let runtime = Runtime::test();

        let network_config = NetworkArgs {
            discovery: DiscoveryArgs {
                disable_discovery: true,
                ..DiscoveryArgs::default()
            },
            ..NetworkArgs::default()
        };
        let mut accounts = TesterAccountPool::new();
        let chainspec = self.gen_chainspec(&mut accounts);

        let node_config = NodeConfig::new(Arc::new(chainspec))
            .with_network(network_config.clone())
            .with_unused_ports()
            .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
            .with_dev(DevArgs {
                dev: false,
                consensus_signer_private_key: Some(B256::random().to_string()),
                ..Default::default()
            });

        let capturing_consensus = CapturingConsensusBuilder::default();
        let NodeHandle { node, .. } = NodeBuilder::new(node_config.clone())
            .testing_node(runtime.clone())
            .with_types::<N42Node>()
            .with_components(
                N42Node::default()
                    .components_builder()
                    .consensus(capturing_consensus.clone())
                    .payload(n42_engine_types::N42PayloadServiceBuilder::new(
                        capturing_consensus.clone(),
                    )),
            )
            .with_add_ons(N42Node::default().add_ons())
            .launch()
            .await?;

        let payload_events = node.payload_builder_handle.subscribe().await?;
        let mut payload_event_stream = payload_events.into_stream();

        // TODO: In reth v1.5.0, consensus is not directly accessible from FullNode.
        // For now, skip the consensus-related tests and just verify block production.
        // This needs to be fixed by implementing a proper way to access consensus through NodeAddOns.

        for vote in &self.votes {
            let vote_cast = vote
                .voted
                .as_ref()
                .map(|voted| (accounts.address(voted), vote.auth.unwrap_or(true)));
            let eth_signer_key = hex::encode(accounts.secret_key(&vote.signer).secret_bytes());
            println!("signer={} eth_signer_key={eth_signer_key:?}", vote.signer);
            new_block(&node, eth_signer_key, vote_cast, &capturing_consensus).await?;
        }
        let best_number = node.provider.chain_info().unwrap().best_number;
        let block_hash = node.provider.block_hash(best_number).unwrap().unwrap();
        println!("best_number={best_number:?}, block_hash={block_hash:?}");

        let snapshot = capturing_consensus.snapshot(best_number, block_hash)?;
        println!("snapshot={snapshot:?}");
        let mut expected_signers: Vec<Address> =
            self.results.iter().map(|a| accounts.address(a)).collect();
        expected_signers.sort_unstable();
        let mut actual_signers = snapshot.signers.clone();
        actual_signers.sort_unstable();
        assert_eq!(actual_signers, expected_signers);

        let first_event = payload_event_stream.next().await.unwrap()?;
        let second_event = payload_event_stream.next().await.unwrap()?;
        println!("first_event={first_event:?}");
        println!("second_event={second_event:?}");

        Ok(())
    }

    async fn run(&self) -> eyre::Result<()> {
        match self.happy_path().await {
            Ok(_) => (),
            Err(e) => {
                println!("error: {e:?}");
                assert_eq!(e.to_string(), self.failure.clone().unwrap());
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_single_signer__no_votes_cast() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string()],
        votes: vec![TesterVote {
            signer: "A".to_string(),
            ..Default::default()
        }],
        results: vec!["A".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_single_signer__voting_to_add_two_others__only_accept_first__second_needs_2_votes(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_two_signers__voting_to_add_three_others__only_accept_first_two__third_needs_3_votes_already(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("E".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("E".to_string()),
                auth: Some(true),
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_single_signer__dropping_itself__weird__but_one_less_cornercase_by_explicitly_allowing_this(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string()],
        votes: vec![TesterVote {
            signer: "A".to_string(),
            voted: Some("A".to_string()),
            auth: Some(false),
        }],
        results: vec![],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_two_signers__actually_needing_mutal_consent_to_drop_either_of_them__not_fulfilled(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string()],
        votes: vec![TesterVote {
            signer: "A".to_string(),
            voted: Some("B".to_string()),
            auth: Some(false),
            ..Default::default()
        }],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_two_signers__actually_needing_mutal_consent_to_drop_either_of_them__fulfilled(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec!["A".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_three_signers__two_of_them_deciding_to_drop_the_third() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string(), "C".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_four_signers__consensus_of_two_not_being_enough_to_drop_anyone() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_four_signers__consensus_of_three_already_being_enough_to_drop_someone(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec!["A".to_string(), "B".to_string(), "C".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_authorizations_are_counted_once_per_signer_per_target() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_authorizing_multiple_accounts_concurrently_is_permitted() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
                ..Default::default()
            },
        ],
        results: vec![
            "A".to_string(),
            "B".to_string(),
            "D".to_string(),
            "C".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_deauthorizations_are_counted_once_per_signer_per_target() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_deauthorizing_multiple_accounts_concurrently_is_permitted() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_votes_from_deauthorized_signers_are_discarded_immediately__deauth_votes(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string(), "C".to_string()],
        votes: vec![
            TesterVote {
                signer: "C".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("B".to_string()),
                auth: Some(false),
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_votes_from_deauthorized_signers_are_discarded_immediately__auth_votes(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string(), "C".to_string()],
        votes: vec![
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(true),
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_cascading_changes_are_not_allowed__only_the_account_being_voted_on_may_change(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
                ..Default::default()
            },
        ],
        results: vec!["A".to_string(), "B".to_string(), "C".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_changes_reaching_consensus_out_of_bounds__via_a_deauth__execute_on_touch(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_changes_reaching_consensus_out_of_bounds__via_a_deauth__may_go_out_of_consensus_on_first_touch(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("D".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
            },
        ],
        results: vec!["A".to_string(), "B".to_string(), "C".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_ensure_that_pending_votes_dont_survive_authorization_status_changes(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec![
            "A".to_string(),
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
            "E".to_string(),
        ],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "E".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("F".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "E".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "C".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "D".to_string(),
                voted: Some("A".to_string()),
                auth: Some(false),
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("F".to_string()),
                auth: Some(true),
            },
        ],
        results: vec![
            "B".to_string(),
            "C".to_string(),
            "D".to_string(),
            "E".to_string(),
            "F".to_string(),
        ],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_epoch_transitions_reset_all_votes_to_allow_chain_checkpointing() -> eyre::Result<()> {
    let test = CliqueTest {
        epoch: Some(3),
        signers: vec!["A".to_string(), "B".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                // checkpoint is done on this block per epoch setting
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                voted: Some("C".to_string()),
                auth: Some(true),
            },
        ],
        results: vec!["A".to_string(), "B".to_string()],
        failure: None,
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_an_unauthorized_signer_should_not_be_able_to_sign_blocks() -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string()],
        votes: vec![TesterVote {
            signer: "B".to_string(),
            ..Default::default()
        }],
        //failure: Some("unauthorized signer".to_string()),
        failure: Some("missing payload".to_string()),
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_an_authorized_signer_that_signed_recently_should_not_be_able_to_sign_again(
) -> eyre::Result<()> {
    let test = CliqueTest {
        signers: vec!["A".to_string(), "B".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
        ],
        //failure: Some("recently signed".to_string()),
        failure: Some("missing payload".to_string()),
        ..Default::default()
    };
    test.run().await
}

#[tokio::test]
async fn test_recent_signatures_should_not_reset_on_checkpoint_blocks_imported() -> eyre::Result<()>
{
    let test = CliqueTest {
        epoch: Some(3),
        signers: vec!["A".to_string(), "B".to_string(), "C".to_string()],
        votes: vec![
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "B".to_string(),
                ..Default::default()
            },
            TesterVote {
                // checkpoint is done on this block per epoch setting
                signer: "A".to_string(),
                ..Default::default()
            },
            TesterVote {
                signer: "A".to_string(),
                ..Default::default()
            },
        ],
        //failure: Some("recently signed".to_string()),
        failure: Some("missing payload".to_string()),
        ..Default::default()
    };
    test.run().await
}


/// On a QMDB chain every header this node produces carries the forest root, its
/// own engine validates each block against the same forest, and a restart picks
/// the forest up where the chain is.
///
/// This goes through the real paths: the payload builder computes the root, the
/// block is handed back over the Engine API, and reth's engine tree validates it
/// with the QMDB strategy installed. A mismatch anywhere and the engine rejects
/// the block, so the chain not advancing is the failure signal.
#[tokio::test(flavor = "multi_thread")]
async fn test_qmdb_chain__headers_carry_the_forest_root_and_validate() -> eyre::Result<()> {
    use n42_qmdb_reth::{with_declared_state_scheme, QmdbNodeState};

    reth_tracing::init_test_tracing();
    let runtime = Runtime::test();
    let mut accounts = TesterAccountPool::new();
    let base = CliqueTest {
        signers: vec!["A".to_string()],
        ..Default::default()
    };
    let mut chainspec = base.gen_chainspec(&mut accounts);
    let mpt_genesis_root = chainspec.genesis_header.state_root;

    // A funded sender, so one block can carry a transaction and actually move
    // the root. Empty blocks leave a QMDB root where it was, which would let a
    // builder that never appended anything pass every assertion below.
    let sender = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x42))?;
    chainspec.genesis.alloc.insert(
        sender.address(),
        alloy_genesis::GenesisAccount {
            balance: U256::from(10u128.pow(18)),
            ..Default::default()
        },
    );

    // Declare the scheme the way gov5 does, in the genesis config.
    chainspec
        .genesis
        .config
        .extra_fields
        .insert_value("stateScheme".to_string(), "qmdb")?;
    let chainspec = with_declared_state_scheme(chainspec)?;
    assert_ne!(
        chainspec.genesis_header.state_root, mpt_genesis_root,
        "a QMDB genesis has a different root than the same alloc on MPT",
    );
    let chainspec = Arc::new(chainspec);

    let dir = std::env::temp_dir().join(format!("n42-qmdb-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let qmdb = QmdbNodeState::new(chainspec.clone(), &dir);

    let node_config = NodeConfig::new(chainspec.clone())
        .with_network(NetworkArgs {
            discovery: DiscoveryArgs {
                disable_discovery: true,
                ..DiscoveryArgs::default()
            },
            ..NetworkArgs::default()
        })
        .with_unused_ports()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
        .with_dev(DevArgs {
            dev: false,
            consensus_signer_private_key: Some(B256::random().to_string()),
            ..Default::default()
        });

    let capturing_consensus = CapturingConsensusBuilder::default();
    let types = N42Node::with_qmdb(Some(qmdb.clone()));
    let NodeHandle { node, .. } = NodeBuilder::new(node_config)
        .testing_node(runtime.clone())
        .with_types::<N42Node>()
        .with_components(
            types
                .components_builder()
                .consensus(capturing_consensus.clone())
                .payload(
                    n42_engine_types::N42PayloadServiceBuilder::new(capturing_consensus.clone())
                        .with_qmdb(Some(qmdb.clone())),
                ),
        )
        .with_add_ons(types.add_ons())
        .launch()
        .await?;

    let genesis_hash = node.provider.block_hash(0)?.expect("genesis is stored");
    assert_eq!(genesis_hash, chainspec.genesis_hash(), "the database holds the QMDB genesis");
    qmdb.initialize((0, genesis_hash))?;
    assert_eq!(qmdb.root_of(&genesis_hash), Some(chainspec.genesis_header.state_root));

    let key = hex::encode(accounts.secret_key("A").secret_bytes());
    let mut previous_root = chainspec.genesis_header.state_root;
    for expected in 1..=3u64 {
        // Block 2 carries a transfer; the others are empty.
        if expected == 2 {
            let tx = alloy_consensus::TxEip1559 {
                chain_id: chainspec.chain().id(),
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: 10_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                to: alloy_primitives::TxKind::Call(Address::with_last_byte(0x77)),
                value: U256::from(1_000u64),
                ..Default::default()
            };
            let signature = alloy_signer::SignerSync::sign_hash_sync(
                &sender,
                &alloy_consensus::SignableTransaction::signature_hash(&tx),
            )?;
            let signed = n42_tx_types::N42TxEnvelope::from(reth_ethereum_primitives::TransactionSigned::new_unhashed(
                tx.into(),
                signature,
            ));
            let encoded_len = alloy_eips::eip2718::Encodable2718::encode_2718_len(&signed);
            let recovered =
                reth_primitives_traits::Recovered::new_unchecked(signed, sender.address());
            let pooled = n42_engine_types::N42PooledTransaction::new(recovered, encoded_len);
            reth_transaction_pool::TransactionPool::add_transaction(
                &node.pool,
                reth_transaction_pool::TransactionOrigin::Local,
                pooled,
            )
            .await?;
        }

        new_block(&node, key.clone(), None, &capturing_consensus).await?;
        let header = node.provider.latest_header()?.expect("a head");
        assert_eq!(
            header.number, expected,
            "block {expected} was not accepted by the engine — its QMDB root did not validate",
        );
        let root = qmdb
            .root_of(&header.hash())
            .expect("validating the block filed its tree");
        assert_eq!(header.state_root, root, "the header carries the forest root");
        assert_ne!(header.state_root, B256::ZERO);
        if expected == 2 {
            assert!(header.gas_used > 0, "block 2 must have included the transfer");
            assert_ne!(
                header.state_root, previous_root,
                "a block that writes state must move the QMDB root",
            );
        } else {
            assert_eq!(header.state_root, previous_root, "an empty block leaves the root alone");
        }
        previous_root = header.state_root;
        qmdb.on_canonical(header.hash())?;
    }

    // A restart at the same head restores the forest and continues the same
    // append history, which is what a QMDB chain cannot rebuild from state.
    let head = node.provider.latest_header()?.expect("a head");
    let restarted = QmdbNodeState::new(chainspec.clone(), &dir);
    restarted.initialize((head.number, head.hash()))?;
    assert_eq!(restarted.root_of(&head.hash()), Some(head.state_root));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_deferred_execution__headers_carry_the_parents_execution_across_the_fork() -> eyre::Result<()> {
    use n42_qmdb_reth::{with_declared_state_scheme, QmdbNodeState};

    reth_tracing::init_test_tracing();
    let runtime = Runtime::test();
    let mut accounts = TesterAccountPool::new();
    let base = CliqueTest {
        signers: vec!["A".to_string()],
        ..Default::default()
    };
    let mut chainspec = base.gen_chainspec(&mut accounts);
    let mpt_genesis_root = chainspec.genesis_header.state_root;

    // A funded sender, so one block can carry a transaction and actually move
    // the root. Empty blocks leave a QMDB root where it was, which would let a
    // builder that never appended anything pass every assertion below.
    let sender = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x42))?;
    chainspec.genesis.alloc.insert(
        sender.address(),
        alloy_genesis::GenesisAccount {
            balance: U256::from(10u128.pow(18)),
            ..Default::default()
        },
    );

    // Declare the scheme the way gov5 does, in the genesis config.
    chainspec
        .genesis
        .config
        .extra_fields
        .insert_value("stateScheme".to_string(), "qmdb")?;
    // Deferred execution from the genesis on (docs/PHASE_D_DEFERRED_EXECUTION.md):
    // every header past this time carries its parent's execution, and the
    // first one repeats the genesis header's fields.
    chainspec
        .genesis
        .config
        .extra_fields
        .insert_value("deferredExecutionTime".to_string(), chainspec.genesis.timestamp)?;
    let chainspec = with_declared_state_scheme(chainspec)?;
    assert_ne!(
        chainspec.genesis_header.state_root, mpt_genesis_root,
        "a QMDB genesis has a different root than the same alloc on MPT",
    );
    let chainspec = Arc::new(chainspec);

    let dir = std::env::temp_dir().join(format!("n42-deferred-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let qmdb = QmdbNodeState::new(chainspec.clone(), &dir);

    let node_config = NodeConfig::new(chainspec.clone())
        .with_network(NetworkArgs {
            discovery: DiscoveryArgs {
                disable_discovery: true,
                ..DiscoveryArgs::default()
            },
            ..NetworkArgs::default()
        })
        .with_unused_ports()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
        .with_dev(DevArgs {
            dev: false,
            consensus_signer_private_key: Some(B256::random().to_string()),
            ..Default::default()
        });

    let capturing_consensus = CapturingConsensusBuilder::default();
    let types = N42Node::with_qmdb(Some(qmdb.clone()));
    let NodeHandle { node, .. } = NodeBuilder::new(node_config)
        .testing_node(runtime.clone())
        .with_types::<N42Node>()
        .with_components(
            types
                .components_builder()
                .consensus(capturing_consensus.clone())
                .payload(
                    n42_engine_types::N42PayloadServiceBuilder::new(capturing_consensus.clone())
                        .with_qmdb(Some(qmdb.clone())),
                ),
        )
        .with_add_ons(types.add_ons())
        .launch()
        .await?;

    let genesis_hash = node.provider.block_hash(0)?.expect("genesis is stored");
    assert_eq!(genesis_hash, chainspec.genesis_hash(), "the database holds the QMDB genesis");
    qmdb.initialize((0, genesis_hash))?;
    assert_eq!(qmdb.root_of(&genesis_hash), Some(chainspec.genesis_header.state_root));

    let key = hex::encode(accounts.secret_key("A").secret_bytes());
    let mut previous_root = chainspec.genesis_header.state_root;
    for expected in 1..=3u64 {
        // Block 2 carries a transfer; the others are empty.
        if expected == 2 {
            let tx = alloy_consensus::TxEip1559 {
                chain_id: chainspec.chain().id(),
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: 10_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                to: alloy_primitives::TxKind::Call(Address::with_last_byte(0x77)),
                value: U256::from(1_000u64),
                ..Default::default()
            };
            let signature = alloy_signer::SignerSync::sign_hash_sync(
                &sender,
                &alloy_consensus::SignableTransaction::signature_hash(&tx),
            )?;
            let signed = n42_tx_types::N42TxEnvelope::from(reth_ethereum_primitives::TransactionSigned::new_unhashed(
                tx.into(),
                signature,
            ));
            let encoded_len = alloy_eips::eip2718::Encodable2718::encode_2718_len(&signed);
            let recovered =
                reth_primitives_traits::Recovered::new_unchecked(signed, sender.address());
            let pooled = n42_engine_types::N42PooledTransaction::new(recovered, encoded_len);
            reth_transaction_pool::TransactionPool::add_transaction(
                &node.pool,
                reth_transaction_pool::TransactionOrigin::Local,
                pooled,
            )
            .await?;
        }

        new_block(&node, key.clone(), None, &capturing_consensus).await?;
        let header = node.provider.latest_header()?.expect("a head");
        assert_eq!(
            header.number, expected,
            "block {expected} was not accepted by the engine — its QMDB root did not validate",
        );
        let own_root = qmdb
            .root_of(&header.hash())
            .expect("validating the block filed its tree");
        let parent = reth_provider::HeaderProvider::sealed_header(&node.provider, expected - 1)?.expect("the parent");
        // The header carries the parent's execution: its root is the parent's
        // forest root (the genesis root for block 1, the invariant at the
        // switch), never its own, and the block's own root is what the next
        // header will carry.
        let parent_root = qmdb.root_of(&parent.hash()).expect("the parent's tree");
        assert_eq!(header.state_root, parent_root, "block {expected}'s header carries its parent's root");
        if expected == 1 {
            assert_eq!(header.state_root, chainspec.genesis_header.state_root, "block 1 repeats the genesis root");
            assert_eq!(header.receipts_root, chainspec.genesis_header.receipts_root);
            assert_eq!(header.gas_used, 0);
        }
        let fields = n42_engine_types::executed_fields::get(&header.hash())
            .expect("the block's own execution is remembered under its hash");
        assert_eq!(fields.state_root, own_root, "the remembered root is the forest's");
        if expected == 2 {
            assert!(fields.gas_used > 0, "block 2 must have included the transfer");
            assert_eq!(header.gas_used, 0, "block 2's header carries block 1's (empty) gas");
            assert_ne!(own_root, previous_root, "a block that writes state must move the QMDB root");
        } else if expected == 3 {
            assert!(header.gas_used > 0, "block 3's header carries block 2's gas");
            assert_eq!(own_root, previous_root, "an empty block leaves the root alone");
        } else {
            assert_eq!(own_root, previous_root, "an empty block leaves the root alone");
        }
        previous_root = own_root;
        qmdb.on_canonical(header.hash())?;
    }

    // A restart at the same head restores the forest and continues the same
    // append history, which is what a QMDB chain cannot rebuild from state.
    let head = node.provider.latest_header()?.expect("a head");
    let restarted = QmdbNodeState::new(chainspec.clone(), &dir);
    restarted.initialize((head.number, head.hash()))?;
    assert_eq!(restarted.root_of(&head.hash()), Some(previous_root), "the forest restores the head's own root");
    // The head's header carries block 2's root, which block 3 (empty) left
    // alone: the two are equal by value here, and distinct by meaning.

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}


/// A 0x50 (Ed25519) transfer on a chain whose genesis enables the type: the
/// pool admits it, the builder mines it, the stored block and receipt carry
/// the type. This is the path the fleet smoke test exercises, in one process.
#[tokio::test(flavor = "multi_thread")]
async fn test_altsig_transfer__is_mined_and_typed_0x50() -> eyre::Result<()> {
    use n42_qmdb_reth::{with_declared_state_scheme, QmdbNodeState};
    use n42_tx_types::{alt_sig::sender_of, ALG_ED25519};
    use reth_provider::{BlockReader, ReceiptProvider};

    reth_tracing::init_test_tracing();
    let runtime = Runtime::test();
    let mut accounts = TesterAccountPool::new();
    let base = CliqueTest {
        signers: vec!["A".to_string()],
        ..Default::default()
    };
    let mut chainspec = base.gen_chainspec(&mut accounts);

    let ed_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = alloy_primitives::Bytes::copy_from_slice(ed_key.verifying_key().as_bytes());
    let ed_sender = sender_of(ALG_ED25519, &pubkey);
    chainspec.genesis.alloc.insert(
        ed_sender,
        alloy_genesis::GenesisAccount {
            balance: U256::from(10u128.pow(18)),
            ..Default::default()
        },
    );
    chainspec
        .genesis
        .config
        .extra_fields
        .insert_value("stateScheme".to_string(), "qmdb")?;
    chainspec
        .genesis
        .config
        .extra_fields
        .insert_value("altSigTx".to_string(), true)?;
    let chainspec = with_declared_state_scheme(chainspec)?;
    assert!(reth_chainspec::qmdb::alt_sig_tx_enabled(&chainspec.genesis), "the flag is read back");
    let chainspec = Arc::new(chainspec);

    let dir = std::env::temp_dir().join(format!("n42-altsig-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let qmdb = QmdbNodeState::new(chainspec.clone(), &dir);

    let node_config = NodeConfig::new(chainspec.clone())
        .with_network(NetworkArgs {
            discovery: DiscoveryArgs {
                disable_discovery: true,
                ..DiscoveryArgs::default()
            },
            ..NetworkArgs::default()
        })
        .with_unused_ports()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
        .with_dev(DevArgs {
            dev: false,
            consensus_signer_private_key: Some(B256::random().to_string()),
            ..Default::default()
        });

    let capturing_consensus = CapturingConsensusBuilder::default();
    let types = N42Node::with_qmdb(Some(qmdb.clone()));
    let NodeHandle { node, .. } = NodeBuilder::new(node_config)
        .testing_node(runtime.clone())
        .with_types::<N42Node>()
        .with_components(
            types
                .components_builder()
                .consensus(capturing_consensus.clone())
                .payload(
                    n42_engine_types::N42PayloadServiceBuilder::new(capturing_consensus.clone())
                        .with_qmdb(Some(qmdb.clone())),
                ),
        )
        .with_add_ons(types.add_ons())
        .launch()
        .await?;
    let genesis_hash = node.provider.block_hash(0)?.expect("genesis is stored");
    qmdb.initialize((0, genesis_hash))?;
    assert!(n42_tx_types::alt_sig_enabled(), "the node read the genesis flag");

    let tx = n42_tx_types::TxAltSig {
        chain_id: chainspec.chain().id(),
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 10_000_000_000,
        gas_limit: 21_000,
        to: Address::with_last_byte(0x77),
        value: U256::from(1_000u64),
        input: Default::default(),
        access_list: Default::default(),
        alg_type: ALG_ED25519,
        pubkey,
    }
    .sign_ed25519(&ed_key);
    let tx_hash = *tx.hash();
    let signed = n42_tx_types::N42TxEnvelope::from(tx);
    let encoded_len = alloy_eips::eip2718::Encodable2718::encode_2718_len(&signed);
    let recovered = reth_primitives_traits::Recovered::new_unchecked(signed, ed_sender);
    let pooled = n42_engine_types::N42PooledTransaction::new(recovered, encoded_len);
    let outcome = reth_transaction_pool::TransactionPool::add_transaction(
        &node.pool,
        reth_transaction_pool::TransactionOrigin::Local,
        pooled,
    )
    .await;
    assert!(outcome.is_ok(), "the pool admits a 0x50 transaction on this chain: {outcome:?}");
    let status = reth_transaction_pool::TransactionPool::pool_size(&node.pool);
    assert_eq!(status.pending, 1, "the transaction is pending, not queued: {status:?}");

    let key = hex::encode(accounts.secret_key("A").secret_bytes());
    new_block(&node, key, None, &capturing_consensus).await?;
    let header = node.provider.latest_header()?.expect("a head");
    assert_eq!(header.number, 1);
    assert_eq!(header.gas_used, 21_000, "block 1 must have included the 0x50 transfer");
    let block = node.provider.block(1u64.into())?.expect("block 1 is stored");
    assert_eq!(block.body.transactions.len(), 1);
    assert!(block.body.transactions[0].is_alt_sig());
    assert_eq!(*block.body.transactions[0].hash(), tx_hash);
    let receipts = node.provider.receipts_by_block(1u64.into())?.expect("receipts of block 1");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].tx_type, n42_tx_types::N42TxType::AltSig);
    assert!(receipts[0].success);
    qmdb.on_canonical(header.hash())?;

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
